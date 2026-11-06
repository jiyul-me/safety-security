using System.Text;

namespace SafetySecurity.Core.Rules;

/// <summary>
/// Windows 기본 폴더 위치와 환경 변수. 테스트에서는 가짜 값을 넣을 수 있어요.
/// 경로는 모두 Windows 형식(C:\...)이고 Linux에서도 같은 방식으로 다뤄요.
/// </summary>
public sealed class SystemPaths
{
    private readonly Dictionary<string, string> _env;

    public SystemPaths(IDictionary<string, string> environment)
    {
        _env = new Dictionary<string, string>(environment, StringComparer.OrdinalIgnoreCase);
        SystemRoot = Get("SystemRoot") ?? Get("windir") ?? @"C:\Windows";
        _env.TryAdd("SystemRoot", SystemRoot);
        _env.TryAdd("windir", SystemRoot);
        SystemDrive = Get("SystemDrive") ?? SystemRoot[..2];
        ProgramFiles = Get("ProgramFiles") ?? SystemDrive + @"\Program Files";
        ProgramFilesX86 = Get("ProgramFiles(x86)") ?? SystemDrive + @"\Program Files (x86)";
        ProgramData = Get("ProgramData") ?? SystemDrive + @"\ProgramData";
        UserProfile = Get("USERPROFILE") ?? SystemDrive + @"\Users\user";
        AppData = Get("APPDATA") ?? UserProfile + @"\AppData\Roaming";
        LocalAppData = Get("LOCALAPPDATA") ?? UserProfile + @"\AppData\Local";
        Temp = Get("TEMP") ?? Get("TMP") ?? LocalAppData + @"\Temp";
        Public = Get("PUBLIC") ?? SystemDrive + @"\Users\Public";
    }

    public string SystemRoot { get; }
    public string SystemDrive { get; }
    public string System32 => SystemRoot + @"\System32";
    public string SysWow64 => SystemRoot + @"\SysWOW64";
    public string ProgramFiles { get; }
    public string ProgramFilesX86 { get; }
    public string ProgramData { get; }
    public string UserProfile { get; }
    public string AppData { get; }
    public string LocalAppData { get; }
    public string Temp { get; }
    public string Public { get; }

    public string? Get(string name) => _env.TryGetValue(name, out var v) && !string.IsNullOrEmpty(v) ? v : null;

    /// <summary>%NAME% 형식 환경 변수를 펼쳐요. 모르는 변수는 그대로 둬요.</summary>
    public string Expand(string text)
    {
        if (string.IsNullOrEmpty(text) || !text.Contains('%'))
        {
            return text;
        }

        var sb = new StringBuilder(text.Length + 32);
        var i = 0;
        while (i < text.Length)
        {
            var start = text.IndexOf('%', i);
            if (start < 0)
            {
                sb.Append(text, i, text.Length - i);
                break;
            }

            var end = text.IndexOf('%', start + 1);
            if (end < 0)
            {
                sb.Append(text, i, text.Length - i);
                break;
            }

            sb.Append(text, i, start - i);
            var name = text.Substring(start + 1, end - start - 1);
            if (name.Length > 0 && Get(name) is { } value)
            {
                sb.Append(value);
                i = end + 1;
            }
            else
            {
                // 모르는 변수: '%'를 그대로 두고 다음 '%'부터 다시 찾아요.
                sb.Append('%');
                i = start + 1;
            }
        }

        return sb.ToString();
    }
}
