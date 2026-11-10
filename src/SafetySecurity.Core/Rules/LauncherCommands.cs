using System.Text;
using System.Text.RegularExpressions;
using SafetySecurity.Core.Parsing;

namespace SafetySecurity.Core.Rules;

/// <summary>
/// 다른 프로그램을 대신 실행해 주는 Windows 기본 프로그램(cmd /c, start, conhost, forfiles, pcalua, wmic,
/// explorer, PowerShell)에서 실제로 실행되는 명령과 파일을 꺼내요.
/// 문자열만 다뤄요. 파일을 열지 않고, 어떤 것도 실행하지 않아요.
/// </summary>
public static partial class LauncherCommands
{
    /// <summary>
    /// 열거나 실행하면 코드가 도는 파일 확장자 (인자 속 경로를 볼 때만 써요).
    /// .dll은 넣지 않아요. PowerShell 인자 속 DLL 경로는 데이터일 때가 많고, 리플렉션 로드는 따로 찾아요.
    /// </summary>
    private static readonly string[] RunnableExtensions =
        [".exe", ".com", ".scr", ".pif", ".cpl", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".hta"];

    private static readonly HashSet<string> PowerShells = new(StringComparer.OrdinalIgnoreCase) { "powershell.exe", "pwsh.exe", "powershell_ise.exe" };

    // conhost.exe 옵션 중 다음 토큰을 값으로 쓰는 것
    private static readonly HashSet<string> ConhostValueSwitches = new(StringComparer.OrdinalIgnoreCase)
    {
        "--width", "--height", "--signal", "--server", "--vtmode", "--feature", "--textmeasurement",
    };

    // start 옵션 중 다음 토큰을 값으로 쓰는 것 (/D 폴더, /NODE 번호, /AFFINITY 마스크, /MACHINE 종류)
    private static readonly HashSet<string> StartValueSwitches = new(StringComparer.OrdinalIgnoreCase) { "/d", "/node", "/affinity", "/machine" };

    [GeneratedRegex(@"\$\{env:(?<n>[^}]+)\}|\$env:(?<n>[A-Za-z_][A-Za-z0-9_]*(\(x86\))?)", RegexOptions.IgnoreCase)]
    private static partial Regex PowerShellEnv();

    [GeneratedRegex(@"0x(?<h>[0-9A-Fa-f]{2})")]
    private static partial Regex ForfilesHex();

    /// <summary>
    /// 이 명령이 대신 실행하는 '안쪽 명령줄'들. cmd /c는 &amp;, &amp;&amp;, ||, |로 이어진 명령마다 하나씩 돌려줘요.
    /// 다른 프로그램을 감싸는 실행기가 아니면 빈 목록이에요.
    /// </summary>
    /// <param name="fileExists">따옴표 처리 규칙에 필요해요 (cmd는 따옴표 안이 실제 실행 파일일 때만 따옴표를 남겨요). 없으면 항상 바깥 따옴표를 벗겨요.</param>
    public static IReadOnlyList<string> InnerCommands(ParsedCommand cmd, Func<string, bool>? fileExists = null) => cmd.FileName switch
    {
        "cmd.exe" => CmdCommands(cmd.Arguments, fileExists),
        "conhost.exe" => Single(ConhostCommand(cmd.Arguments)),
        "forfiles.exe" => Single(ForfilesCommand(cmd.Arguments)),
        "pcalua.exe" => Single(PcaluaCommand(cmd.Arguments)),
        "wmic.exe" => Single(WmicCreateCommand(cmd.Arguments)),
        _ => [],
    };

    /// <summary>
    /// 인자로 넘겨서 실행되는 파일 경로 후보 (explorer.exe의 첫 인자, PowerShell 명령 속 경로).
    /// 절대 경로처럼 보이는 것만 돌려줘요. 실제로 볼지는 <see cref="IsRunnableFile"/>과 파일 존재 여부로 다시 걸러야 해요.
    /// </summary>
    public static IReadOnlyList<string> ArgumentPaths(ParsedCommand cmd, SystemPaths paths)
    {
        if (cmd.FileName == "explorer.exe")
        {
            foreach (var t in CommandLine.Tokenize(cmd.Arguments))
            {
                // /e, /n, /select,파일, /root,폴더 는 옵션이에요. /select는 파일을 고르기만 하고 실행하지 않아요.
                if (t.StartsWith('/') || t == ",")
                {
                    continue;
                }

                var p = paths.Expand(t.Trim().Trim(','));
                return IsAbsolutePath(p) ? [p] : [];
            }

            return [];
        }

        if (PowerShells.Contains(cmd.FileName))
        {
            return PowerShellPaths(cmd.Arguments, paths);
        }

        return [];
    }

    /// <summary>드라이브(C:\)나 \로 시작하는 경로인지 (\\server\share, \??\, \SystemRoot\ 포함).</summary>
    public static bool IsAbsolutePath(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        var p = path.Trim().Trim('"');
        return p.StartsWith('\\') || (p.Length >= 3 && char.IsAsciiLetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/'));
    }

    /// <summary>명령줄 첫 토큰(실행 파일 자리)이 절대 경로로 쓰였는지. 'echo', 'start' 같은 이름만 쓴 경우는 false예요.</summary>
    public static bool FirstTokenIsAbsolute(string raw)
    {
        var tokens = CommandLine.Tokenize(raw.Trim());
        return tokens.Count > 0 && IsAbsolutePath(tokens[0]);
    }

    /// <summary>실행하거나 열면 코드가 도는 확장자인지.</summary>
    public static bool IsRunnableFile(string path) =>
        RunnableExtensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase));

    // ---- cmd.exe ---------------------------------------------------------------

    private static IReadOnlyList<string> CmdCommands(string args, Func<string, bool>? fileExists)
    {
        var rest = AfterCmdRunSwitch(args, out var stripQuotes);
        if (rest is null)
        {
            return [];
        }

        rest = rest.Trim();
        rest = StripCmdOuterQuotes(rest, stripQuotes, fileExists);
        var result = new List<string>();
        foreach (var segment in SplitCmdSegments(rest))
        {
            var s = segment.Trim().TrimStart('@').Trim();

            // (a & b) 처럼 괄호로 묶은 명령. 경로 안의 괄호(Program Files (x86))는 짝이 맞아서 그대로 둬요.
            var open = s.Count(c => c == '(');
            var close = s.Count(c => c == ')');
            if (s.StartsWith('(') && (open > close || (open == close && s.EndsWith(')'))))
            {
                s = s[1..].Trim();
                open--;
            }

            if (s.EndsWith(')') && close > open)
            {
                s = s[..^1].Trim();
            }

            s = s.TrimStart('@').Trim();

            if (StripWord(s, "call") is { } called)
            {
                s = called;
            }

            if (StripWord(s, "start") is { } started)
            {
                s = StartCommand(started) ?? string.Empty;
            }

            if (s.Length > 0)
            {
                result.Add(s);
            }
        }

        return result;
    }

    /// <summary>/c, /k, /r 뒤의 문자열. 그 앞의 /q /d /s /v:on 같은 옵션은 건너뛰어요. /c가 없으면 null이에요.</summary>
    private static string? AfterCmdRunSwitch(string args, out bool sSwitch)
    {
        sSwitch = false;
        var i = 0;
        while (true)
        {
            while (i < args.Length && char.IsWhiteSpace(args[i]))
            {
                i++;
            }

            if (i + 1 >= args.Length || args[i] != '/')
            {
                // /c 없이 다른 내용이 오면 cmd가 명령으로 실행하지 않아요.
                return null;
            }

            var letter = char.ToLowerInvariant(args[i + 1]);
            if (letter is 'c' or 'k' or 'r')
            {
                return args[(i + 2)..];
            }

            if (letter == 's')
            {
                sSwitch = true;
            }

            i += 2;
            while (i < args.Length && !char.IsWhiteSpace(args[i]) && args[i] != '/')
            {
                i++;
            }
        }
    }

    /// <summary>
    /// cmd /c의 따옴표 규칙: 따옴표가 정확히 두 개이고 그 안이 실제 실행 파일이면 그대로 두고,
    /// 그렇지 않으면 맨 앞 따옴표와 맨 마지막 따옴표를 지워요 (예: "start "" C:\x.exe" → start "" C:\x.exe).
    /// </summary>
    private static string StripCmdOuterQuotes(string rest, bool sSwitch, Func<string, bool>? fileExists)
    {
        if (!rest.StartsWith('"'))
        {
            return rest;
        }

        var last = rest.LastIndexOf('"');
        if (last <= 0)
        {
            return rest[1..];
        }

        if (!sSwitch && rest.Count(c => c == '"') == 2)
        {
            var inside = rest[1..last];
            if (fileExists is not null && inside.IndexOfAny(['&', '<', '>', '(', ')', '@', '^', '|']) < 0 && inside.Any(char.IsWhiteSpace) && fileExists(inside))
            {
                return rest;
            }
        }

        return rest[1..last] + rest[(last + 1)..];
    }

    /// <summary>따옴표 밖의 &amp;, &amp;&amp;, ||, |에서 나눠요. ^ 이스케이프를 풀고, 2&gt;&amp;1 같은 리디렉션은 나누지 않아요.</summary>
    private static List<string> SplitCmdSegments(string text)
    {
        var segments = new List<string>();
        var sb = new StringBuilder(text.Length);
        var inQuotes = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '"')
            {
                inQuotes = !inQuotes;
                sb.Append(c);
                continue;
            }

            if (!inQuotes && c == '^' && i + 1 < text.Length)
            {
                sb.Append(text[++i]);
                continue;
            }

            if (!inQuotes && (c == '&' || c == '|'))
            {
                var prev = sb.Length > 0 ? sb[^1] : ' ';
                if (c == '&' && (prev == '>' || prev == '<'))
                {
                    sb.Append(c);
                    continue;
                }

                segments.Add(sb.ToString());
                sb.Clear();
                if (i + 1 < text.Length && text[i + 1] == c)
                {
                    i++;
                }

                continue;
            }

            sb.Append(c);
        }

        segments.Add(sb.ToString());
        return segments;
    }

    /// <summary>s가 word로 시작하는 낱말이면(예: "start ...", "start/min ...", "start\"\"") 그 뒤를, 아니면 null을 돌려줘요.</summary>
    private static string? StripWord(string s, string word)
    {
        if (!s.StartsWith(word, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (s.Length == word.Length)
        {
            return string.Empty;
        }

        var next = s[word.Length];
        return char.IsWhiteSpace(next) || next == '"' || next == '/' ? s[word.Length..].Trim() : null;
    }

    /// <summary>start ["제목"] [/b /min /wait /d 폴더 ...] 명령 → 명령. 실행할 것이 없으면 null이에요.</summary>
    private static string? StartCommand(string text)
    {
        var tokens = CommandLine.TokenizeWithSpans(text);
        var titleSeen = false;
        for (var t = 0; t < tokens.Count; t++)
        {
            var token = tokens[t];
            if (!token.StartsQuoted && token.Value.StartsWith('/'))
            {
                if (StartValueSwitches.Contains(token.Value))
                {
                    t++;
                }

                continue;
            }

            if (token.StartsQuoted && !titleSeen)
            {
                // start의 첫 따옴표 인자는 창 제목이에요 (start "C:\a b\x.exe"는 x.exe를 실행하지 않아요).
                titleSeen = true;
                continue;
            }

            return text[token.Start..].Trim();
        }

        return null;
    }

    // ---- 그 밖의 실행기 ------------------------------------------------------------

    private static string? ConhostCommand(string args)
    {
        var tokens = CommandLine.TokenizeWithSpans(args);
        for (var t = 0; t < tokens.Count; t++)
        {
            var v = tokens[t].Value;
            if (v.StartsWith('-'))
            {
                if (ConhostValueSwitches.Contains(v))
                {
                    t++;
                }

                continue;
            }

            if (v.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                // 시스템이 conhost를 띄울 때 붙이는 값 (0xffffffff)
                continue;
            }

            return args[tokens[t].Start..].Trim();
        }

        return null;
    }

    private static string? ForfilesCommand(string args)
    {
        var tokens = CommandLine.Tokenize(args);
        for (var t = 0; t + 1 < tokens.Count; t++)
        {
            if (tokens[t].Equals("/c", StringComparison.OrdinalIgnoreCase) || tokens[t].Equals("-c", StringComparison.OrdinalIgnoreCase))
            {
                // forfiles는 명령 안의 0xHH를 그 문자로 바꿔요 (예: 0x22 → ").
                return ForfilesHex().Replace(tokens[t + 1], m => ((char)Convert.ToInt32(m.Groups["h"].Value, 16)).ToString());
            }
        }

        return null;
    }

    private static string? PcaluaCommand(string args)
    {
        var tokens = CommandLine.Tokenize(args);
        for (var t = 0; t + 1 < tokens.Count; t++)
        {
            if (tokens[t].Equals("-a", StringComparison.OrdinalIgnoreCase) || tokens[t].Equals("/a", StringComparison.OrdinalIgnoreCase))
            {
                return Quote(tokens[t + 1]);
            }
        }

        return null;
    }

    private static string? WmicCreateCommand(string args)
    {
        var tokens = CommandLine.Tokenize(args);
        for (var t = 0; t + 3 < tokens.Count; t++)
        {
            if (tokens[t].Equals("process", StringComparison.OrdinalIgnoreCase)
                && tokens[t + 1].Equals("call", StringComparison.OrdinalIgnoreCase)
                && tokens[t + 2].Equals("create", StringComparison.OrdinalIgnoreCase))
            {
                return tokens[t + 3];
            }
        }

        return null;
    }

    // ---- PowerShell -----------------------------------------------------------

    /// <summary>
    /// PowerShell 명령 속 절대 경로 (Start-Process C:\x.exe, &amp; 'C:\x.exe', . 'C:\x.ps1', -FilePath:C:\x.exe 등).
    /// $env:NAME과 %NAME%을 펼쳐요.
    /// </summary>
    private static List<string> PowerShellPaths(string args, SystemPaths paths)
    {
        var text = string.Join(' ', CommandLine.Tokenize(args));
        var result = new List<string>();
        foreach (var raw in SplitPowerShell(text))
        {
            var t = raw.TrimStart('&');
            if (t.Length > 1 && t[0] == '.' && (t[1] == '\'' || t[1] == '"'))
            {
                t = t[1..];
            }

            if (t.Length > 1 && (t[0] is '-' or '\u2013' or '\u2014' or '\u2015') && t.IndexOf(':') is var colon and > 0)
            {
                // -FilePath:C:\x.exe
                t = t[(colon + 1)..];
            }

            t = t.Trim().Trim('\'', '"').Trim();
            t = PowerShellEnv().Replace(t, m => "%" + m.Groups["n"].Value + "%");
            var p = paths.Expand(t);
            if (IsAbsolutePath(p) && !result.Contains(p, StringComparer.OrdinalIgnoreCase))
            {
                result.Add(p);
            }
        }

        return result;
    }

    /// <summary>PowerShell 문장을 공백과 ; | ( ) { } , &amp;에서 나눠요. '...'와 "..." 안은 나누지 않아요.</summary>
    private static List<string> SplitPowerShell(string text)
    {
        var parts = new List<string>();
        var sb = new StringBuilder();
        char quote = '\0';
        foreach (var c in text)
        {
            if (quote != '\0')
            {
                sb.Append(c);
                if (c == quote)
                {
                    quote = '\0';
                }

                continue;
            }

            if (c is '\'' or '"')
            {
                quote = c;
                sb.Append(c);
                continue;
            }

            if (char.IsWhiteSpace(c) || c is ';' or '|' or '(' or ')' or '{' or '}' or ',' or '&')
            {
                if (sb.Length > 0)
                {
                    parts.Add(sb.ToString());
                    sb.Clear();
                }

                continue;
            }

            sb.Append(c);
        }

        if (sb.Length > 0)
        {
            parts.Add(sb.ToString());
        }

        return parts;
    }

    private static IReadOnlyList<string> Single(string? command) =>
        string.IsNullOrWhiteSpace(command) ? [] : [command.Trim()];

    private static string Quote(string path) => path.StartsWith('"') ? path : "\"" + path + "\"";
}
