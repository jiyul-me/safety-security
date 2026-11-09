using System.Diagnostics;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Install;
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

    /// <summary>자동 검사의 시간 제한. 작업 스케줄러의 15분 제한(ExecutionTimeLimit)보다 짧아야 해요.</summary>
    private static readonly TimeSpan Budget = TimeSpan.FromMinutes(12);

    /// <summary>
    /// 사용자가 직접 시작한 검사(더블클릭·시작 메뉴·바탕화면)의 시간 제한. 작업 스케줄러 제한이 없어서 더 길게 둬요
    /// (느린 하드디스크의 첫 검사도 끝나게). 낮은 우선순위와 쉬어 가며 검사하는 것은 그대로예요.
    /// </summary>
    private static readonly TimeSpan ManualBudget = TimeSpan.FromMinutes(30);

    public static int Run(ScanOptions o, DataStore store, Output output)
    {
        var now = DateTimeOffset.UtcNow;
        var retry = o.Reason == ScanReason.Retry;

        // 사용자가 직접 시작한 검사인지 (Retry가 미뤄둔 검사의 이유로 바꾸기 전에 기억해요).
        // 직접 검사만 보고서를 저절로 열 수 있어요. 작업 스케줄러가 대신 하는 검사는 브라우저를 열지 않아요.
        var interactive = o.Reason == ScanReason.Manual;

        if (o.Scope == ScanScope.Admin && !Environment.IsPrivilegedProcess)
        {
            output.Line("관리자 범위 검사는 관리자 권한이 필요해요.");
            return ExitCodes.Error;
        }

        // Retry: 미뤄둔 검사가 있을 때만 (또는 하루 넘게 검사를 못 했을 때만) 검사하고, 아니면 바로 끝내요.
        // 30분마다 도는 작업이라 잠금을 잡기 전에 먼저 가볍게 확인해요. 로그온·하루 한 번 검사도 방금 전체 검사를 했으면 바로 끝내요.
        if (retry ? !ResolveRetry(o, store.LoadState(o.Scope), now) : SkippedAsRecent(o, store.LoadState(o.Scope), now, store, output))
        {
            return ExitCodes.NothingToDo;
        }

        using var scanLock = ScanLock.TryAcquire(o.Scope.ToString());
        if (scanLock is null)
        {
            if (retry)
            {
                // 다른 검사가 지금 하고 있으니 Retry가 할 일은 없어요 (작업 스케줄러에 실패로 남기지 않아요).
                store.Log($"{o.Scope}/retry: 다른 검사가 실행 중이라 넘어가요");
                return ExitCodes.NothingToDo;
            }

            if (interactive)
            {
                store.Log($"{o.Scope}/manual: 다른 검사가 실행 중이라 시작하지 않았어요");
                output.Line("다른 검사가 이미 실행 중이에요. 잠시 뒤에 다시 해 주세요.");
                return ExitCodes.AlreadyRunning;
            }

            // 자동 검사(로그온·하루 한 번·서비스 설치)는 버리지 않고 미뤄둔 검사로 남겨요. 30분마다 깨는 Retry가 해요.
            // (예: 로그온 검사 중에 새 서비스가 설치되면, 그 검사는 서비스 목록을 이미 지나갔을 수 있어요.)
            RecordWhileOtherScanRuns(o, store);
            output.Line("다른 검사가 실행 중이라 이 검사를 미뤄 뒀어요. 30분 안에 다시 검사해요.");
            return ExitCodes.Deferred;
        }

        // 잠금을 잡은 뒤에 기록을 읽어요. 그래야 방금 끝난 다른 검사가 저장한 베이스라인을 놓치지 않아서,
        // 같은 항목을 '새 항목'으로 다시 알리지 않아요.
        var config = store.LoadConfig();
        var state = store.LoadState(o.Scope);
        if (retry)
        {
            o.Reason = ScanReason.Retry;
            if (!ResolveRetry(o, state, now))
            {
                return ExitCodes.NothingToDo;
            }
        }
        else if (SkippedAsRecent(o, state, now, store, output))
        {
            return ExitCodes.NothingToDo;
        }

        Throttle.EnterBackgroundMode();
        var detector = new GameDetector(config);
        var overdueRun = false;
        if (!o.Force)
        {
            var busy = detector.Check(includeCpu: true);
            var action = ScanSchedule.Decide(busy, state.Pending, now);
            if (action is DeferAction.Defer or DeferAction.DeferAndWarn)
            {
                state.Pending = ScanSchedule.Defer(state.Pending, o.Reason, o.Quick, busy!.Text, now);
                if (action == DeferAction.DeferAndWarn)
                {
                    WarnOverdue(o, state.Pending, store, now);
                }

                SaveState(store, o.Scope, state, [], now, completedFull: false);
                store.Log($"{o.Scope}/{o.Reason}: 미룸 — {busy}");
                output.Line($"지금은 {busy}이라 검사를 미뤘어요. 30분마다 다시 확인해요.");
                return ExitCodes.Deferred;
            }

            if (action == DeferAction.RunOverdue)
            {
                // CPU·전체 화면 때문에 하루 넘게 밀렸어요. 낮은 우선순위로 천천히 검사하고, 게임이 시작되면 바로 멈춰요.
                overdueRun = true;
                state.Pending!.OverdueRunUtc = now;
                store.Log($"{o.Scope}/{o.Reason}: 하루 넘게 밀려서 {busy}이어도 백그라운드로 천천히 검사해요");
                output.Line($"검사가 하루 넘게 밀려서, {busy}이지만 낮은 우선순위로 천천히 검사해요. 게임이 시작되면 바로 멈춰요.");
            }
        }

        // 메서드가 끝날 때(보고서를 연 뒤, 중단·오류 포함) 알림을 지워요.
        using var progress = o.ProgressToast ? ScanningToast.TryShow(store.Log) : null;

        var sigCache = store.LoadSignatureCache(o.Scope);
        var networkDrives = NetworkDrives.Letters;
        var paths = new SystemPaths(Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(e => (string)e.Key, e => LongPath((string?)e.Value ?? string.Empty, networkDrives), StringComparer.OrdinalIgnoreCase));
        var classifier = new PathClassifier(paths) { NetworkDrives = networkDrives };

        // 네트워크 경로(\\server\share, 네트워크 드라이브)는 어떤 경우에도 열지 않아요.
        // ScanContext가 스캐너용 보기에 같은 보호를 씌우고, 서명 캐시도 보호된 보기만 써요.
        var rawFiles = new WinFileSystemView();
        var files = new LocalOnlyFileSystemView(rawFiles, classifier);
        var signatures = new CachingSignatureVerifier(new AuthenticodeVerifier(), files, sigCache, () => DateTimeOffset.UtcNow);
        var self = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in SelfExecutables.For(o.Scope, Environment.ProcessPath, Path.Combine(TaskInstaller.UserInstallDir, TaskInstaller.ExeName), Path.Combine(TaskInstaller.AdminInstallDir, TaskInstaller.ExeName)))
        {
            self.Add(classifier.Normalize(p));
        }

        var userStarted = interactive && o.Force;
        var ctx = new ScanContext
        {
            Registry = new WinRegistryView(),
            Files = rawFiles,
            Signatures = signatures,
            Classifier = classifier,
            Pacer = userStarted ? new Pacer(null, ManualBudget) : new Pacer(detector, Budget, gamesOnly: overdueRun),
            Now = now,
            Tasks = new SchtasksSource(),
            Wmi = new PowerShellWmiSource(),
            SelfPaths = self,
            IsElevated = Environment.IsPrivilegedProcess,
            Scope = o.Scope,

            // 관리자 설치가 있는지 파일·폴더가 있는지만 봐요 (보고서 안내 문장을 고르는 데만 써요).
            AdminScanInstalled = o.Scope == ScanScope.User && TaskInstaller.AdminInstallExists(),
        };

        // 알림이 꺼져 있으면 자동 검사가 새 항목을 찾아도 알려드릴 수 없어요. 설정을 읽기만 해서 보고서에 적어 둬요.
        var notificationsOff = ToastNotifier.IsRegistered() ? Advice.NotificationsOff(ToastNotifier.ReadState()) : null;
        if (notificationsOff is not null)
        {
            ctx.Coverage.Skipped("알림", notificationsOff);
        }

        var sw = Stopwatch.StartNew();
        output.Line(o.Quick
            ? (o.Scope == ScanScope.Admin ? "빠른 관리자 검사 중이에요 (서비스·숨겨진 예약 작업)…" : "빠른 검사 중이에요 (서비스·예약 작업)…")
            : "검사 중이에요. 컴퓨터 사용에 방해되지 않게 천천히 검사해요…");
        var result = ScanEngine.Run(ctx, ScanEngine.AllScanners(), o.Reason, o.Quick, () => DateTimeOffset.UtcNow);
        signatures.Trim();
        store.SaveSignatureCache(o.Scope, sigCache);

        if (result.Aborted)
        {
            // 직접 검사가 멈춰도 미뤄둔 검사는 'Retry'(백그라운드)로 남겨서, 나중에 보고서를 저절로 열지 않아요.
            state.Pending = ScanSchedule.Defer(state.Pending, o.Reason, o.Quick, result.AbortReason ?? "중단됨", now);
            SaveState(store, o.Scope, state, [], now, completedFull: false);
            store.Log($"{o.Scope}/{o.Reason}: 중단 — {result.AbortReason} ({sw.Elapsed.TotalSeconds:0.0}s)");
            output.Line(userStarted && result.AbortReason == Pacer.TimeLimitReason
                ? $"검사가 너무 오래 걸려서 {ManualBudget.TotalMinutes:0}분에서 멈췄어요. 지금까지 확인한 서명은 저장해 뒀으니, 다시 실행하면 더 빨리 끝나요. 자동 검사 작업이 있으면 30분 안에 백그라운드에서 다시 검사해요."
                : $"검사 중에 {result.AbortReason}(이)라 멈췄어요. 나중에 다시 검사해요.");
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

        // 설정 파일이 없으면 기본값으로 만들어 둬요 (직접 고칠 수 있게). 관리자 설치는 사용자 폴더에 미리 만들지 않아서,
        // 사용자 검사가 처음 끝날 때 만들어져요. 관리자 검사는 보호된 관리자 폴더의 설정만 써요.
        store.WriteDefaultConfigIfMissing();
        SaveState(store, o.Scope, state, decision.IgnoreEdits, now, completedFull: !o.Quick);

        var high = result.Findings.Count(f => f.Severity == Severity.High);
        var medium = result.Findings.Count(f => f.Severity == Severity.Medium);
        store.Log($"{o.Scope}/{o.Reason}{(o.Quick ? "/quick" : string.Empty)}{(overdueRun ? "/overdue" : string.Empty)}: 완료 {sw.Elapsed.TotalSeconds:0.0}s, 항목 {result.Findings.Count} (높음 {high}, 보통 {medium}), 알림 {decision.ToNotify.Count}, 서명 캐시 {signatures.Hits}/{signatures.Hits + signatures.Misses}");

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
            // 알림이 꺼져 있으면 Show()는 성공한 것처럼 끝나도 화면에 안 보여요. 그때도 실패처럼 다뤄요.
            var shown = ToastNotifier.TryShow(decision.ToNotify, html, decision.FirstRun, out var error);
            if (!shown || notificationsOff is not null)
            {
                store.Log("알림 실패: " + (error ?? notificationsOff));
                if (interactive)
                {
                    o.Open = true;
                }
            }
            else if (error is not null)
            {
                store.Log("알림: 항목 제목이 든 알림을 띄우지 못해서 개수만 적은 알림으로 보냈어요 — " + error);
            }
        }

        if (o.Open)
        {
            OpenFile(html);
        }

        return ExitCodes.Ok;
    }

    /// <summary>Retry를 실제 검사 종류로 바꿔요. 할 일이 없으면 false.</summary>
    private static bool ResolveRetry(ScanOptions o, ScanState state, DateTimeOffset now)
    {
        if (state.Pending is { } pending)
        {
            // 예전 버전이 남긴 '직접 검사' 미룸도 백그라운드 검사로 해요 (보고서를 저절로 열지 않게).
            o.Reason = ScanSchedule.BackgroundReason(pending.Reason);
            o.Quick = pending.Quick;
            return true;
        }

        if (state.LastFullScanUtc is null || now - state.LastFullScanUtc > (o.Scope == ScanScope.Admin ? AdminInterval : UserSafetyNet))
        {
            o.Reason = ScanReason.Daily;
            o.Quick = false;
            return true;
        }

        return false;
    }

    /// <summary>로그온·하루 한 번 전체 검사를 방금(2시간 안) 전체 검사를 끝냈다는 이유로 건너뛰면 true (기록을 남겨요).</summary>
    private static bool SkippedAsRecent(ScanOptions o, ScanState state, DateTimeOffset now, DataStore store, Output output)
    {
        if (!ScanSchedule.SkipBecauseRecent(o.Reason, o.Quick, o.Force, state, now))
        {
            return false;
        }

        var minutes = (now - state.LastFullScanUtc!.Value).TotalMinutes;
        store.Log($"{o.Scope}/{o.Reason}: 건너뜀 — {minutes:0}분 전에 전체 검사를 끝냈어요");
        output.Line($"{minutes:0}분 전에 전체 검사를 끝내서 이번 검사는 건너뛰어요.");
        return true;
    }

    /// <summary>
    /// 다른 검사가 잠금을 잡고 있어서 하지 못한 자동 검사를 미뤄둔 검사로 남겨요. 짧은 기록 잠금 안에서 디스크의 기록에 바로 더하고,
    /// 지금 검사 중인 쪽은 저장할 때 자기가 시작한 뒤에 들어온 요청을 지우지 않아요 (<see cref="ScanSchedule.MergeOnSave"/>).
    /// </summary>
    private static void RecordWhileOtherScanRuns(ScanOptions o, DataStore store)
    {
        var label = $"{o.Scope}/{o.Reason}{(o.Quick ? "/quick" : string.Empty)}";
        using (StateLock.Acquire(store.StatePath(o.Scope), store.Log))
        {
            var read = store.TryLoadState(o.Scope, out var disk);
            if (read != StateRead.Ok)
            {
                // 읽지 못한 기록을 빈 기록으로 덮어쓰면 베이스라인이 사라져요. 남기지 못한 것만 기록해요.
                store.Log($"{label}: 다른 검사가 실행 중인데, 기록을 읽지 못해서({read}) 미뤄둔 검사로 남기지 못했어요");
                return;
            }

            disk.Pending = ScanSchedule.Defer(disk.Pending, o.Reason, o.Quick, "다른 검사가 실행 중", DateTimeOffset.UtcNow);
            store.SaveState(o.Scope, disk);
        }

        store.Log($"{label}: 미룸 — 다른 검사가 실행 중이라 미뤄둔 검사로 남겨요 (Retry가 해요)");
    }

    /// <summary>게임 때문에 하루 넘게 검사를 못 했다고 한 번만 알려요 (미뤄둔 검사 하나에 한 번). 사용자 범위에서만 띄워요.</summary>
    private static void WarnOverdue(ScanOptions o, PendingScan pending, DataStore store, DateTimeOffset now)
    {
        pending.OverdueNoticeUtc = now;
        if (o.Scope != ScanScope.User || o.NoToast)
        {
            return;
        }

        var hours = (int)(now - pending.SinceUtc).TotalHours;
        var shown = ToastNotifier.TryShowOverdue(hours, out var error);
        store.Log(shown ? $"밀린 검사 알림을 보냈어요 ({hours}시간째)" : "밀린 검사 알림 실패: " + error);
    }

    /// <summary>
    /// 검사 기록을 저장해요. 숨김 목록은 사용자가 ignore·unignore로 바꾸는 것이라, 짧은 기록 잠금 안에서 디스크의 최신 목록을
    /// 다시 읽어 그대로 쓰고, 검사가 한 변경(예전 ID 옮기기, 숨길 때 상태 기록)만 그 위에 다시 적용해요.
    /// 그래서 검사하는 동안 숨긴 항목이 검사가 끝나며 다시 나타나지 않아요.
    /// 미뤄둔 검사도 같아요: 이 검사가 시작된 뒤 다른 검사가 남긴 요청은 지우지 않고 합쳐요.
    /// </summary>
    private static void SaveState(DataStore store, ScanScope scope, ScanState state, IReadOnlyList<IgnoreEdit> edits, DateTimeOffset scanStart, bool completedFull)
    {
        using var stateLock = StateLock.Acquire(store.StatePath(scope), store.Log);
        var read = store.TryLoadState(scope, out var disk);
        if (read == StateRead.Ok)
        {
            IgnoreList.KeepLatest(state, disk, edits);
            var merged = ScanSchedule.MergeOnSave(state.Pending, disk.Pending, scanStart, completedFull);
            if (!ReferenceEquals(merged, state.Pending))
            {
                store.Log($"{scope}: 검사하는 동안 들어온 검사 요청을 미뤄둔 검사로 남겨요 ({merged?.Reason}{(merged?.Quick == true ? "/quick" : string.Empty)})");
            }

            state.Pending = merged;
        }
        else
        {
            store.Log($"{scope}: 저장 직전에 기록을 다시 읽지 못했어요 ({read}). 검사를 시작할 때 읽은 숨김 목록으로 저장해요.");
        }

        store.SaveState(scope, state);
    }

    /// <summary>
    /// 환경 변수 값이 8.3 짧은 이름(예: %TEMP% = C:\Users\RUNNER~1\...)이면 긴 이름으로 바꿔요.
    /// 안 바꾸면 같은 폴더를 다른 곳으로 보고 위치 분류가 틀려져요.
    /// </summary>
    private static unsafe string LongPath(string value, IReadOnlySet<char> networkDrives)
    {
        if (!value.Contains('~') || value.Contains(';') || value.Length < 3 || value[1] != ':' || networkDrives.Contains(char.ToUpperInvariant(value[0])))
        {
            // 네트워크 드라이브는 이름을 바꾸려고 접속하지 않아요.
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
