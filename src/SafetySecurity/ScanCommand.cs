using System.Diagnostics;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;
using SafetySecurity.Core.Rules;
using SafetySecurity.Install;
using SafetySecurity.Notify;
using SafetySecurity.Runtime;
using SafetySecurity.Windows;

namespace SafetySecurity;

internal sealed class ScanOptions
{
    public ScanReason Reason { get; set; } = ScanReason.Manual;

    public ScanScope Scope { get; set; } = ScanScope.User;

    public bool Quick { get; set; }

    public bool Force { get; set; }

    public bool NoToast { get; set; }

    public bool Open { get; set; }

    /// <summary>직접 검사(더블클릭·시작 메뉴)할 때 "검사하고 있어요" 알림을 띄우고 끝나면 지워요.</summary>
    public bool ProgressToast { get; set; }

    public string? ReportDir { get; set; }
}

internal static class ExitCodes
{
    public const int Ok = 0;
    public const int Error = 1;
    public const int Deferred = 2;
    public const int Aborted = 3;
    public const int AlreadyRunning = 4;
    public const int NothingToDo = 0;
}

internal static class ScanCommand
{
    private static readonly TimeSpan UserSafetyNet = TimeSpan.FromHours(26);
    private static readonly TimeSpan AdminInterval = TimeSpan.FromHours(23);
    private static readonly TimeSpan Budget = TimeSpan.FromMinutes(12);

    public static int Run(ScanOptions o, DataStore store, Output output)
    {
        var config = store.LoadConfig();
        var state = store.LoadState(o.Scope);
        var now = DateTimeOffset.UtcNow;

        // Retry: 미뤄둔 검사가 있을 때만 (또는 하루 넘게 검사를 못 했을 때만) 검사하고, 아니면 바로 끝내요.
        if (o.Reason == ScanReason.Retry)
        {
            if (state.Pending is { } pending)
            {
                o.Reason = pending.Reason;
                o.Quick = pending.Quick;
            }
            else if (state.LastFullScanUtc is null || now - state.LastFullScanUtc > (o.Scope == ScanScope.Admin ? AdminInterval : UserSafetyNet))
            {
                o.Reason = ScanReason.Daily;
                o.Quick = false;
            }
            else
            {
                return ExitCodes.NothingToDo;
            }
        }

        using var scanLock = ScanLock.TryAcquire(o.Scope.ToString());
        if (scanLock is null)
        {
            output.Line("다른 검사가 이미 실행 중이에요. 잠시 뒤에 다시 해 주세요.");
            return ExitCodes.AlreadyRunning;
        }

        if (o.Scope == ScanScope.Admin && !Environment.IsPrivilegedProcess)
        {
            output.Line("관리자 범위 검사는 관리자 권한이 필요해요.");
            return ExitCodes.Error;
        }

        Throttle.EnterBackgroundMode();
        var detector = new GameDetector(config);
        if (!o.Force && detector.Check(includeCpu: true) is { } busy)
        {
            Defer(state, o, busy, now);
            store.SaveState(o.Scope, state);
            store.Log($"{o.Scope}/{o.Reason}: 미룸 — {busy}");
            output.Line($"지금은 {busy}이라 검사를 미뤘어요. 30분마다 다시 확인해요.");
            return ExitCodes.Deferred;
        }

        // 메서드가 끝날 때(보고서를 연 뒤, 중단·오류 포함) 알림을 지워요.
        using var progress = o.ProgressToast ? ScanningToast.TryShow() : null;

        var sigCache = store.LoadSignatureCache(o.Scope);
        var files = new WinFileSystemView();
        var signatures = new CachingSignatureVerifier(new AuthenticodeVerifier(), files, sigCache, () => DateTimeOffset.UtcNow);
        var paths = new SystemPaths(Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(e => (string)e.Key, e => LongPath((string?)e.Value ?? string.Empty), StringComparer.OrdinalIgnoreCase));
        var classifier = new PathClassifier(paths);
        var self = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in new[] { Environment.ProcessPath, Path.Combine(TaskInstaller.UserInstallDir, TaskInstaller.ExeName), Path.Combine(TaskInstaller.AdminInstallDir, TaskInstaller.ExeName) })
        {
            if (p is not null)
            {
                self.Add(classifier.Normalize(p));
            }
        }

        var ctx = new ScanContext
        {
            Registry = new WinRegistryView(),
            Files = files,
            Signatures = signatures,
            Classifier = classifier,
            Pacer = o.Force && o.Reason == ScanReason.Manual ? new Pacer(null, Budget) : new Pacer(detector, Budget),
            Now = now,
            Tasks = new SchtasksSource(),
            Wmi = new PowerShellWmiSource(),
            SelfPaths = self,
            IsElevated = Environment.IsPrivilegedProcess,
            Scope = o.Scope,
        };

        var sw = Stopwatch.StartNew();
        output.Line(o.Quick ? "빠른 검사 중이에요 (서비스·예약 작업)…" : "검사 중이에요. 컴퓨터 사용에 방해되지 않게 천천히 검사해요…");
        var result = ScanEngine.Run(ctx, ScanEngine.AllScanners(), o.Reason, o.Quick, () => DateTimeOffset.UtcNow);
        signatures.Trim();
        store.SaveSignatureCache(o.Scope, sigCache);

        if (result.Aborted)
        {
            Defer(state, o, result.AbortReason ?? "중단됨", now);
            store.SaveState(o.Scope, state);
            store.Log($"{o.Scope}/{o.Reason}: 중단 — {result.AbortReason} ({sw.Elapsed.TotalSeconds:0.0}s)");
            output.Line($"검사 중에 {result.AbortReason}(이)라 멈췄어요. 나중에 다시 검사해요.");
            return ExitCodes.Aborted;
        }

        var decision = BaselineEvaluator.Apply(result, state, config);
        var doc = ReportDocument.From(result, decision, Program.Version, Environment.MachineName);
        var html = store.WriteReport(doc, o.ReportDir, TaskInstaller.ExeName, runDialog: RunDialogNameRegistered());

        state.LastScanUtc = now;
        state.LastReportPath = html;
        if (!o.Quick)
        {
            state.LastFullScanUtc = now;
        }

        if (!o.Quick || state.Pending?.Quick == true)
        {
            state.Pending = null;
        }

        store.SaveState(o.Scope, state);

        var high = result.Findings.Count(f => f.Severity == Severity.High);
        var medium = result.Findings.Count(f => f.Severity == Severity.Medium);
        store.Log($"{o.Scope}/{o.Reason}{(o.Quick ? "/quick" : string.Empty)}: 완료 {sw.Elapsed.TotalSeconds:0.0}s, 항목 {result.Findings.Count} (높음 {high}, 보통 {medium}), 알림 {decision.ToNotify.Count}, 서명 캐시 {signatures.Hits}/{signatures.Hits + signatures.Misses}");

        output.Line($"검사 완료 ({sw.Elapsed.TotalSeconds:0.0}초): 높음 {high}, 보통 {medium}, 낮음·참고 {result.Findings.Count - high - medium}");
        foreach (var f in result.Findings.Where(f => f.Severity >= Severity.Medium).Take(15))
        {
            output.Line($"  [{f.Severity.ToKorean()}]{(f.IsNew ? "[새 항목]" : string.Empty)} {f.Title}");
            output.Line($"      {f.Location}");
        }

        foreach (var note in result.Coverage)
        {
            output.Line("  (확인 못 함) " + note);
        }

        output.Line("보고서: " + html);

        if (decision.ToNotify.Count > 0 && !o.NoToast)
        {
            if (!ToastNotifier.TryShow(decision.ToNotify, html, decision.FirstRun, out var error))
            {
                store.Log("알림 실패: " + error);
                if (o.Reason == ScanReason.Manual)
                {
                    o.Open = true;
                }
            }
        }

        if (o.Open)
        {
            OpenFile(html);
        }

        return ExitCodes.Ok;
    }

    private static void Defer(ScanState state, ScanOptions o, string because, DateTimeOffset now)
    {
        var existing = state.Pending;
        state.Pending = new PendingScan
        {
            Reason = existing?.Reason ?? o.Reason,
            Quick = (existing?.Quick ?? true) && o.Quick,
            SinceUtc = existing?.SinceUtc ?? now,
            DeferredBecause = because,
            Attempts = (existing?.Attempts ?? 0) + 1,
        };
    }

    /// <summary>
    /// 환경 변수 값이 8.3 짧은 이름(예: %TEMP% = C:\Users\RUNNER~1\...)이면 긴 이름으로 바꿔요.
    /// 안 바꾸면 같은 폴더를 다른 곳으로 보고 위치 분류가 틀려져요.
    /// </summary>
    private static unsafe string LongPath(string value)
    {
        if (!value.Contains('~') || value.Contains(';') || value.Length < 3 || value[1] != ':')
        {
            return value;
        }

        var buffer = stackalloc char[1024];
        var len = Native.NativeMethods.GetLongPathName(value, buffer, 1024);
        return len is > 0 and < 1024 ? new string(buffer, 0, (int)len) : value;
    }

    /// <summary>
    /// 설치 프로그램이 Win+R 실행 이름(App Paths\SafetySecurity.exe)을 등록했는지 읽기만 해서 확인해요.
    /// 등록돼 있으면 보고서의 숨기기 안내를 PowerShell 없이 Win+R로 보여줘요.
    /// </summary>
    private static bool RunDialogNameRegistered()
    {
        const string key = @"Software\Microsoft\Windows\CurrentVersion\App Paths\" + TaskInstaller.ExeName;
        try
        {
            using var user = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(key);
            if (user is not null)
            {
                return true;
            }

            using var machine = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(key);
            return machine is not null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    public static void OpenFile(string path)
    {
        try
        {
            using var _ = Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // 연결된 프로그램이 없으면 무시
        }
    }
}
