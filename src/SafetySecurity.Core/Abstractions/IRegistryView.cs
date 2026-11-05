namespace SafetySecurity.Core.Abstractions;

public enum RegHive
{
    CurrentUser,
    LocalMachine,
}

/// <summary>읽기 전용 레지스트리. Windows 구현은 KEY_READ로만 열어요.</summary>
public interface IRegistryView
{
    /// <summary>키를 열어요. 없거나 권한이 없으면 null.</summary>
    IRegistryKeyView? Open(RegHive hive, string path);

    /// <summary>키가 있는데 권한이 없어서 못 연 경우 true. (확인 불가 표시용)</summary>
    bool IsAccessDenied(RegHive hive, string path);
}

public interface IRegistryKeyView : IDisposable
{
    /// <summary>표시용 전체 경로 (예: HKCU\Software\Classes\CLSID\{...}).</summary>
    string FullPath { get; }

    IReadOnlyList<string> GetSubKeyNames();

    IReadOnlyList<string> GetValueNames();

    /// <summary>
    /// 값을 읽어요. REG_SZ/REG_EXPAND_SZ는 string(환경 변수는 펼치지 않음), REG_MULTI_SZ는 string[],
    /// DWORD는 int, QWORD는 long, 나머지는 byte[]. name이 null 또는 ""이면 (기본값).
    /// </summary>
    object? GetValue(string? name);

    /// <summary>키가 마지막으로 수정된 시각 (RegQueryInfoKey).</summary>
    DateTimeOffset? LastWriteTime { get; }

    IRegistryKeyView? OpenSubKey(string name);
}

public static class RegistryExtensions
{
    public static string HiveName(this RegHive hive) => hive == RegHive.CurrentUser ? "HKCU" : "HKLM";

    public static string? GetString(this IRegistryKeyView key, string? name) => key.GetValue(name) switch
    {
        string s => s,
        string[] arr => string.Join(' ', arr),
        null => null,
        var other => other.ToString(),
    };

    public static int? GetInt(this IRegistryKeyView key, string? name) => key.GetValue(name) switch
    {
        int i => i,
        long l => unchecked((int)l),
        string s when int.TryParse(s, out var p) => p,
        _ => null,
    };

    public static string[] GetMultiString(this IRegistryKeyView key, string? name) => key.GetValue(name) switch
    {
        string[] arr => arr,
        string s => [s],
        _ => [],
    };
}
