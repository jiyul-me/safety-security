// 이 파일은 검사기 '자기 데이터 폴더'(%LOCALAPPDATA%\SafetySecurity)에만 써요: 상태, 설정, 서명 캐시, 보고서, 로그.
// 시스템의 다른 곳은 절대 쓰지 않아요. 그래서 이 파일에서만 금지 API 규칙(RS0030)을 풀어요.
#pragma warning disable RS0030

using System.Globalization;
using System.Text;
using System.Text.Json;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Runtime;

internal sealed class DataStore
{
    public const int KeepReports = 30;
    private const long MaxLogBytes = 1024 * 1024;

    public DataStore(string? overrideDir)
    {
        Root = overrideDir ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafetySecurity");
    }

    public string Root { get; }

    public string ReportsDir => Path.Combine(Root, "reports");

    public string LogPath => Path.Combine(Root, "logs", "scan.log");

    public string ConfigPath => Path.Combine(Root, "config.json");

    private string StatePath(ScanScope scope) => Path.Combine(Root, scope == ScanScope.Admin ? "state.admin.json" : "state.json");

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

    public void SaveState(ScanScope scope, ScanState state) =>
        WriteAtomic(StatePath(scope), JsonSerializer.Serialize(state, SafetyJson.Context.ScanState));

    public Dictionary<string, CachedSignature> LoadSignatureCache(ScanScope scope) =>
        Load(SigCachePath(scope), SafetyJson.Context.DictionaryStringCachedSignature) ?? [];

    public void SaveSignatureCache(ScanScope scope, Dictionary<string, CachedSignature> cache) =>
        WriteAtomic(SigCachePath(scope), JsonSerializer.Serialize(cache, SafetyJson.Context.DictionaryStringCachedSignature));

    /// <summary>보고서를 HTML과 JSON으로 써요. 돌려주는 값은 HTML 경로.</summary>
    public string WriteReport(ReportDocument doc, string? reportDir, string exeName)
    {
        var dir = reportDir ?? ReportsDir;
        var stamp = doc.StartedUtc.ToLocalTime().ToString("yyyy-MM-dd_HHmmss", CultureInfo.InvariantCulture);
        var baseName = $"{stamp}_{(doc.Scope == ScanScope.Admin ? "admin" : "user")}";
        var html = Path.Combine(dir, baseName + ".html");
        WriteAtomic(Path.Combine(dir, baseName + ".json"), JsonSerializer.Serialize(doc, SafetyJson.Context.ReportDocument));
        WriteAtomic(html, HtmlReport.Render(doc, exeName));
        if (reportDir is null)
        {
            PruneReports(dir);
        }

        return html;
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
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return JsonSerializer.Deserialize(fs, type);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>임시 파일에 쓴 뒤 바꿔치기해서, 중간에 꺼져도 파일이 깨지지 않게 해요.</summary>
    private static void WriteAtomic(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(tmp, path, overwrite: true);
    }
}
