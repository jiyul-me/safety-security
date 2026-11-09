// 이 파일은 검사기 '자기 데이터 폴더'에만 써요: 상태, 설정, 서명 캐시, 보고서, 로그.
//   일반 권한: %LOCALAPPDATA%\SafetySecurity, 관리자 권한: C:\Program Files\SafetySecurity\data (관리자만 쓸 수 있어요).
// 시스템의 다른 곳은 절대 쓰지 않아요. 그래서 이 파일에서만 금지 API 규칙(RS0030)을 풀어요.
#pragma warning disable RS0030

using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Install;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;
using SafetySecurity.Core.Rules;
using SafetySecurity.Install;

namespace SafetySecurity.Runtime;

/// <summary>기록 파일을 읽은 결과.</summary>
internal enum StateRead
{
    /// <summary>읽었어요 (파일이 없으면 빈 기록).</summary>
    Ok,

    /// <summary>파일은 있는데 지금 읽을 수 없어요 (다른 프로그램이 잡고 있거나 권한이 없어요).</summary>
    Unreadable,

    /// <summary>파일 내용이 깨졌어요.</summary>
    Corrupt,
}

internal sealed class DataStore
{
    public const int KeepReports = 30;
    private const long MaxLogBytes = 1024 * 1024;

    /// <summary>
    /// 데이터 폴더를 정해요. --data-dir이 없으면 일반 권한은 사용자 폴더, 관리자 권한은 보호된 관리자 폴더를 써요.
    /// 관리자 권한 프로세스는 사용자가 쓸 수 있는 %LOCALAPPDATA%\SafetySecurity를 절대 읽거나 쓰지 않아요.
    /// </summary>
    public DataStore(string? overrideDir)
    {
        IsExplicit = !string.IsNullOrWhiteSpace(overrideDir);
        Root = DataRoots.Resolve(overrideDir, Environment.IsPrivilegedProcess, LocalAppData, TaskInstaller.AdminInstallDir);
    }

    /// <summary>사용자 데이터 폴더 (%LOCALAPPDATA%\SafetySecurity). 관리자 권한 프로세스는 쓰지 않아요.</summary>
    public static string UserRoot => DataRoots.User(LocalAppData);

    /// <summary>관리자 데이터 폴더 (C:\Program Files\SafetySecurity\data). Program Files 권한을 물려받아 관리자만 쓸 수 있어요.</summary>
    public static string AdminRoot => DataRoots.Admin(TaskInstaller.AdminInstallDir);

    public string Root { get; }

    /// <summary>--data-dir로 폴더를 직접 정했는지.</summary>
    public bool IsExplicit { get; }

    /// <summary>보호된 관리자 데이터 폴더를 쓰는지.</summary>
    public bool IsAdminRoot => string.Equals(Path.GetFullPath(Root), Path.GetFullPath(AdminRoot), StringComparison.OrdinalIgnoreCase);

    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    public string ReportsDir => Path.Combine(Root, "reports");

    public string LogPath => Path.Combine(Root, "logs", "scan.log");

    public string ConfigPath => Path.Combine(Root, "config.json");

    public string StatePath(ScanScope scope) => Path.Combine(Root, scope == ScanScope.Admin ? "state.admin.json" : "state.json");

    private string SigCachePath(ScanScope scope) => Path.Combine(Root, scope == ScanScope.Admin ? "sigcache.admin.json" : "sigcache.json");

    public ScanConfig LoadConfig() => Load(ConfigPath, SafetyJson.Context.ScanConfig) ?? new ScanConfig();

    public void WriteDefaultConfigIfMissing()
    {
        if (!File.Exists(ConfigPath))
        {
            WriteAtomic(ConfigPath, JsonSerializer.Serialize(new ScanConfig(), SafetyJson.Context.ScanConfig));
        }
    }

    public ScanState LoadState(ScanScope scope) => Load(StatePath(scope), SafetyJson.Context.ScanState) ?? new ScanState();

    /// <summary>
    /// 기록을 읽되, 읽지 못한 이유를 알려줘요. 고쳐서 다시 쓰는 곳(ignore 명령, 검사 저장 직전)은
    /// 읽지 못한 기록을 빈 기록으로 착각해서 베이스라인·숨김 목록을 지우면 안 돼서 이걸 써요.
    /// </summary>
    public StateRead TryLoadState(ScanScope scope, out ScanState state)
    {
        var read = TryLoad(StatePath(scope), SafetyJson.Context.ScanState, out var loaded);
        state = loaded ?? new ScanState();
        return read;
    }

    public void SaveState(ScanScope scope, ScanState state) =>
        WriteAtomic(StatePath(scope), JsonSerializer.Serialize(state, SafetyJson.Context.ScanState));

    public Dictionary<string, CachedSignature> LoadSignatureCache(ScanScope scope) =>
        Load(SigCachePath(scope), SafetyJson.Context.DictionaryStringCachedSignature) ?? [];

    public void SaveSignatureCache(ScanScope scope, Dictionary<string, CachedSignature> cache) =>
        WriteAtomic(SigCachePath(scope), JsonSerializer.Serialize(cache, SafetyJson.Context.DictionaryStringCachedSignature));

    /// <summary>보고서를 HTML과 JSON으로 써요. 돌려주는 값은 HTML 경로.</summary>
    public string WriteReport(ReportDocument doc, string? reportDir, string exeName, bool runDialog)
    {
        var dir = reportDir ?? ReportsDir;
        var stamp = doc.StartedUtc.ToLocalTime().ToString("yyyy-MM-dd_HHmmss", CultureInfo.InvariantCulture);
        var baseName = $"{stamp}_{(doc.Scope == ScanScope.Admin ? "admin" : "user")}";
        var html = Path.Combine(dir, baseName + ".html");
        WriteAtomic(Path.Combine(dir, baseName + ".json"), JsonSerializer.Serialize(doc, SafetyJson.Context.ReportDocument));
        WriteAtomic(html, HtmlReport.Render(doc, exeName, runDialog));
        if (reportDir is null)
        {
            PruneReports(dir);
        }

        return html;
    }

    /// <summary>
    /// 이 범위의 최근 보고서(JSON)를 새것부터 읽어요. 마지막 보고서를 먼저 보고, 그다음 보고서 폴더의 것을 봐요.
    /// ignore 명령이 적은 ID가 정말 보고서에 있던 항목인지 확인하고 제목을 보여줄 때 써요.
    /// 우리 데이터 폴더의 보고서만 읽고, 네트워크 경로는 열지 않아요.
    /// </summary>
    public IEnumerable<ReportDocument> RecentReports(ScanScope scope, string? lastReportPath)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var paths = new List<string>();
        if (lastReportPath is not null && Path.IsPathFullyQualified(lastReportPath) && !Windows.NetworkDrives.IsNetworkPath(lastReportPath))
        {
            paths.Add(Path.ChangeExtension(lastReportPath, ".json"));
        }

        try
        {
            if (Directory.Exists(ReportsDir) && !Windows.NetworkDrives.IsNetworkPath(ReportsDir))
            {
                var suffix = scope == ScanScope.Admin ? "_admin.json" : "_user.json";
                paths.AddRange(new DirectoryInfo(ReportsDir).GetFiles("*" + suffix)
                    .OrderByDescending(f => f.Name, StringComparer.Ordinal)
                    .Take(KeepReports)
                    .Select(f => f.FullName));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // 보고서 폴더를 못 읽으면 마지막 보고서만 봐요.
        }

        foreach (var path in paths)
        {
            if (seen.Add(Path.GetFullPath(path)) && Load(path, SafetyJson.Context.ReportDocument) is { } doc && doc.Scope == scope)
            {
                yield return doc;
            }
        }
    }

    private static void PruneReports(string dir)
    {
        try
        {
            foreach (var ext in new[] { "*.html", "*.json" })
            {
                var old = new DirectoryInfo(dir).GetFiles(ext).OrderByDescending(f => f.Name, StringComparer.Ordinal).Skip(KeepReports);
                foreach (var f in old)
                {
                    f.Delete();
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // 오래된 보고서 정리는 실패해도 괜찮아요.
        }
    }

    /// <summary>
    /// 관리자 검사용 잠금 파일(데이터 폴더 안의 <paramref name="name"/>)을 혼자만 쓰게(공유 없이) 열어요. 다른 프로세스가 열고 있으면 null.
    /// 이름 있는 뮤텍스(Local\…)는 같은 세션의 일반 권한 프로그램도 먼저 만들어 잡아 둘 수 있어서, 악성코드가 관리자 검사를 계속 막을 수
    /// 있어요. 이 파일은 관리자만 쓸 수 있는 데이터 폴더 안에, 관리자·SYSTEM만 열 수 있는 권한(물려받지 않음)으로 만들어서
    /// 일반 권한 프로그램은 열어 둘(가로챌) 수 없어요. 프로세스가 끝나면 Windows가 핸들을 닫아서 잠금도 저절로 풀려요.
    /// 권한은 파일을 새로 만들 때만 정해져요 (이미 있으면 우리가 예전에 같은 권한으로 만든 파일이에요).
    /// </summary>
    public FileStream? TryOpenAdminLock(string name)
    {
        Directory.CreateDirectory(Root);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        try
        {
            return new FileInfo(Path.Combine(Root, name)).Create(FileMode.OpenOrCreate, FileSystemRights.Read | FileSystemRights.Write, FileShare.None, 1, FileOptions.None, security);
        }
        catch (IOException ex) when ((ex.HResult & 0xFFFF) is 32 or 33)
        {
            // ERROR_SHARING_VIOLATION·ERROR_LOCK_VIOLATION: 다른 관리자 검사·명령이 잡고 있어요.
            return null;
        }
    }

    public void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
            var info = new FileInfo(LogPath);
            if (info.Exists && info.Length > MaxLogBytes)
            {
                File.Move(LogPath, LogPath + ".old", overwrite: true);
            }

            File.AppendAllText(LogPath, $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss} [{Environment.ProcessId}] {message}{Environment.NewLine}", Encoding.UTF8);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // 로그를 못 써도 검사는 계속해요.
        }
    }

    public void DeleteAll()
    {
        if (Directory.Exists(Root))
        {
            Directory.Delete(Root, recursive: true);
        }
    }

    private static T? Load<T>(string path, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type)
        where T : class
    {
        TryLoad(path, type, out var value);
        return value;
    }

    private static StateRead TryLoad<T>(string path, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type, out T? value)
        where T : class
    {
        value = null;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                if (!File.Exists(path))
                {
                    return StateRead.Ok;
                }

                // 다른 프로세스가 같은 파일을 바꿔치기(WriteAtomic)하는 중이어도 막지 않게 Delete 공유를 허용해요.
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                value = JsonSerializer.Deserialize(fs, type);
                return StateRead.Ok;
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException)
            {
                return StateRead.Corrupt;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // 다른 검사·명령이 막 파일을 바꾸는 중이면 잠깐 뒤에 다시 읽어요.
                if (attempt >= 3)
                {
                    return StateRead.Unreadable;
                }

                Thread.Sleep(100 * attempt);
            }
        }
    }

    /// <summary>
    /// 임시 파일에 쓴 뒤 바꿔치기해서, 중간에 꺼져도 파일이 깨지지 않게 해요.
    /// 임시 파일 이름에 프로세스 ID를 넣어서, 두 프로세스가 같은 파일을 써도 임시 파일끼리 부딪히지 않아요.
    /// </summary>
    private static void WriteAtomic(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = $"{path}.{Environment.ProcessId.ToString(CultureInfo.InvariantCulture)}.tmp";
        try
        {
            File.WriteAllText(tmp, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    File.Move(tmp, path, overwrite: true);
                    return;
                }
                catch (Exception ex) when (attempt < 3 && ex is IOException or UnauthorizedAccessException)
                {
                    // 다른 프로그램이 잠깐 파일을 열고 있으면(예: 백신 검사) 조금 뒤에 다시 해요.
                    Thread.Sleep(100 * attempt);
                }
            }
        }
        finally
        {
            try
            {
                if (File.Exists(tmp))
                {
                    File.Delete(tmp);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // 남은 임시 파일은 우리 데이터 폴더 안에 있어서 그대로 둬도 괜찮아요.
            }
        }
    }
}
