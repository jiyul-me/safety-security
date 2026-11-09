using System.Text.RegularExpressions;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;

namespace SafetySecurity.Core.Rules;

/// <summary>
/// 명령줄 패턴 판정 결과. PayloadPath는 실제로 실행되는 DLL·스크립트이고,
/// PayloadIsScript면 확장자와 상관없이 스크립트로 실행돼요 (예: wscript //E:jscript x.log).
/// </summary>
public sealed record HeuristicResult(Severity Severity, IReadOnlyList<string> Reasons, string? PayloadPath, bool PayloadIsScript = false);

/// <summary>
/// 정상 Windows 프로그램(LOLBin)을 악용하는 명령줄 패턴을 찾아요.
/// 예: powershell -enc ..., mshta javascript:..., rundll32 C:\Users\...\x.dll,Start
/// </summary>
public static partial class CommandLineHeuristics
{
    private static readonly HashSet<string> PowerShells = new(StringComparer.OrdinalIgnoreCase) { "powershell.exe", "pwsh.exe", "powershell_ise.exe" };
    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase) { "wscript.exe", "cscript.exe" };

    // 값을 받지 않는 PowerShell 옵션 (앞부분만 써도 돼요: -nop, -noni, -sta). 나머지 옵션(-ExecutionPolicy Bypass 등)은 값을 하나 받아요.
    private static readonly string[] PowerShellFlagSwitches =
        ["noprofile", "nologo", "noexit", "noninteractive", "sta", "mta", "interactive", "login", "help", "noprofileloadtime"];

    [GeneratedRegex(@"\b(iex|invoke-expression|downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr|irm|invoke-restmethod|start-bitstransfer|frombase64string|net\.webclient|reflection\.assembly)\b|-bxor\b", RegexOptions.IgnoreCase)]
    private static partial Regex PowerShellDownloadOrExec();

    [GeneratedRegex(@"https?://|\\\\[^\\\s]+\\", RegexOptions.IgnoreCase)]
    private static partial Regex RemoteReference();

    [GeneratedRegex(@"(javascript|vbscript)\s*:", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptProtocol();

    public static HeuristicResult Analyze(ParsedCommand cmd, PathClassifier classifier)
    {
        var reasons = new List<string>();
        var severity = Severity.Info;
        string? payload = null;
        var payloadIsScript = false;
        var name = cmd.FileName;
        var args = cmd.Arguments;

        void Flag(Severity s, string reason)
        {
            severity = SeverityExtensions.Max(severity, s);
            reasons.Add(reason);
        }

        if (PowerShells.Contains(name))
        {
            var (encoded, hidden) = PowerShellSwitches(args);
            if (encoded)
            {
                Flag(Severity.High, "PowerShell이 인코딩된 명령(-EncodedCommand)을 실행해요. 내용을 숨기는 전형적인 수법이에요.");
            }

            if (PowerShellDownloadOrExec().IsMatch(FoldDashes(args)))
            {
                Flag(Severity.High, "PowerShell이 다운로드·문자열 실행(IEX, DownloadString 등)을 해요.");
            }

            if (hidden)
            {
                Flag(Severity.Medium, "PowerShell 창을 숨겨서(-WindowStyle Hidden) 실행해요.");
            }

            var script = FindScriptArgument(cmd, classifier);
            if (script is not null)
            {
                payload = script;
            }
        }
        else if (name == "mshta.exe")
        {
            Flag(Severity.High, "mshta.exe로 HTA/스크립트를 실행해요. 정상 프로그램은 거의 쓰지 않는 방식이에요.");
        }
        else if (name == "regsvr32.exe")
        {
            if (args.Contains("scrobj", StringComparison.OrdinalIgnoreCase) || RemoteReference().IsMatch(args))
            {
                Flag(Severity.High, "regsvr32로 원격·스크립틀릿을 불러와요 (Squiblydoo 수법).");
            }

            payload = FindDllArgument(args);
        }
        else if (name == "rundll32.exe")
        {
            if (ScriptProtocol().IsMatch(args))
            {
                Flag(Severity.High, "rundll32로 JavaScript/VBScript를 실행해요.");
            }

            if (args.Contains("url.dll", StringComparison.OrdinalIgnoreCase) || args.Contains("ShellExec_RunDLL", StringComparison.OrdinalIgnoreCase))
            {
                Flag(Severity.Medium, "rundll32로 다른 프로그램을 간접 실행해요.");
            }

            payload = FindDllArgument(args);
        }
        else if (ScriptHosts.Contains(name))
        {
            var forced = FindForcedEngineScript(cmd, classifier);
            var script = forced ?? FindScriptArgument(cmd, classifier);
            payload = script;
            if (forced is not null)
            {
                payloadIsScript = true;
                if (!CommandAssessor.IsScript(forced))
                {
                    Flag(Severity.Medium, $"스크립트 엔진을 강제로 지정해서(//E:) 스크립트처럼 보이지 않는 파일({Path.GetFileName(forced.Replace('\\', '/'))})을 스크립트로 실행해요. 스크립트를 숨기는 수법이에요.");
                }
            }

            if (script is not null && PathClassifier.IsUserWritable(classifier.Classify(script)))
            {
                Flag(Severity.Medium, "사용자 폴더에 있는 스크립트(VBS/JS)를 자동 실행해요.");
            }
        }
        else if (name == "cmd.exe")
        {
            if (args.Contains("powershell", StringComparison.OrdinalIgnoreCase) || args.Contains("mshta", StringComparison.OrdinalIgnoreCase))
            {
                Flag(Severity.Medium, "cmd.exe를 거쳐 PowerShell/mshta를 실행해요.");
            }
        }
        else if (name == "certutil.exe" && (args.Contains("urlcache", StringComparison.OrdinalIgnoreCase) || args.Contains("decode", StringComparison.OrdinalIgnoreCase)))
        {
            Flag(Severity.High, "certutil로 파일을 내려받거나 디코딩해요.");
        }
        else if (name == "bitsadmin.exe" && args.Contains("transfer", StringComparison.OrdinalIgnoreCase))
        {
            Flag(Severity.High, "bitsadmin으로 파일을 내려받아요.");
        }

        if (ScriptProtocol().IsMatch(args) && severity < Severity.High)
        {
            Flag(Severity.High, "명령줄에 javascript:/vbscript: 코드가 들어 있어요.");
        }

        if (RemoteReference().IsMatch(args) && severity < Severity.Medium)
        {
            Flag(Severity.Medium, "자동 실행 명령에 인터넷 주소나 네트워크 경로가 들어 있어요.");
        }

        return new HeuristicResult(severity, reasons, payload, payloadIsScript);
    }

    /// <summary>명령 프롬프트·스크립트 실행기 (cmd, PowerShell, wscript/cscript, mshta). 다른 명령을 마음대로 실행할 수 있어요.</summary>
    public static bool IsCommandInterpreter(string path)
    {
        var idx = path.LastIndexOfAny(['\\', '/']);
        var file = (idx >= 0 ? path[(idx + 1)..] : path).Trim('"');
        return file.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) || file.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase)
            || PowerShells.Contains(file) || ScriptHosts.Contains(file);
    }

    /// <summary>
    /// PowerShell은 '-'와 '/' 말고도 en dash(–), em dash(—), horizontal bar(―)를 옵션 기호로 받아요.
    /// </summary>
    public static bool IsSwitchPrefix(char c) => c is '-' or '/' or '\u2013' or '\u2014' or '\u2015';

    private static string FoldDashes(string text) =>
        text.Replace('\u2013', '-').Replace('\u2014', '-').Replace('\u2015', '-');

    /// <summary>
    /// PowerShell처럼 옵션을 하나씩 읽어서 -EncodedCommand와 -WindowStyle Hidden을 찾아요.
    /// 옵션 이름은 앞부분만 써도 되고(-enc, -encodedcom, -w), "-옵션:값" 형식도 받아요.
    /// -Command·-File이나 옵션이 아닌 토큰(명령 시작)이 나오면 그 뒤는 명령 내용이라 더 보지 않아요.
    /// </summary>
    public static (bool Encoded, bool Hidden) PowerShellSwitches(string args)
    {
        var encoded = false;
        var hidden = false;
        var tokens = CommandLine.Tokenize(args);
        for (var i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (t.Length < 2 || !IsSwitchPrefix(t[0]))
            {
                // 옵션이 아니면 여기부터 명령이에요 (powershell Get-Thing -e x 의 -e는 명령의 인자예요).
                break;
            }

            var key = t[1..];
            if (key.Length > 0 && IsSwitchPrefix(key[0]))
            {
                key = key[1..]; // pwsh는 --옵션도 받아요.
            }

            string? inline = null;
            var colon = key.IndexOf(':');
            if (colon >= 0)
            {
                inline = key[(colon + 1)..];
                key = key[..colon];
            }

            key = key.ToLowerInvariant();
            if (key.Length == 0)
            {
                continue;
            }

            if (key == "ec" || "encodedcommand".StartsWith(key, StringComparison.Ordinal))
            {
                encoded = true;
                break;
            }

            if ("command".StartsWith(key, StringComparison.Ordinal) || "file".StartsWith(key, StringComparison.Ordinal))
            {
                break;
            }

            if (PowerShellFlagSwitches.Any(f => f.StartsWith(key, StringComparison.Ordinal)))
            {
                continue;
            }

            // 값을 받는 옵션: "-옵션:값"이 아니면 다음 토큰이 값이에요. 다음 토큰이 옵션이면 값으로 보지 않아요 (-w -enc 를 놓치지 않게).
            var value = inline;
            if (value is null && i + 1 < tokens.Count && !(tokens[i + 1].Length > 0 && IsSwitchPrefix(tokens[i + 1][0])))
            {
                value = tokens[++i];
            }

            if ("windowstyle".StartsWith(key, StringComparison.Ordinal)
                && value is not null && (value == "1" || (value.Length > 0 && "hidden".StartsWith(value, StringComparison.OrdinalIgnoreCase))))
            {
                hidden = true;
            }
        }

        return (encoded, hidden);
    }

    /// <summary>
    /// wscript/cscript에 //E:엔진 옵션이 있으면 확장자와 상관없이 첫 인자(// 로 시작하지 않는 것)가 스크립트예요.
    /// </summary>
    private static string? FindForcedEngineScript(ParsedCommand cmd, PathClassifier classifier)
    {
        var tokens = CommandLine.Tokenize(cmd.Arguments);
        if (!tokens.Any(t => t.StartsWith("//e:", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        var script = tokens.FirstOrDefault(t => !t.StartsWith("//", StringComparison.Ordinal));
        return string.IsNullOrWhiteSpace(script) ? null : classifier.Paths.Expand(script);
    }

    /// <summary>rundll32/regsvr32 인자에서 DLL 경로를 찾아요 ("C:\x\a.dll,Entry" 형식 포함).</summary>
    public static string? FindDllArgument(string args)
    {
        foreach (var token in CommandLine.Tokenize(args))
        {
            if (token.StartsWith('/') || token.StartsWith('-'))
            {
                continue;
            }

            var t = token;
            var comma = t.IndexOf(',');
            if (comma > 0)
            {
                t = t[..comma];
            }

            t = t.Trim().Trim('"');
            if (t.Length > 0)
            {
                return t;
            }
        }

        return null;
    }

    private static string? FindScriptArgument(ParsedCommand cmd, PathClassifier classifier)
    {
        string[] scriptExt = [".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd", ".hta"];
        var tokens = CommandLine.Tokenize(cmd.Arguments);
        for (var i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (scriptExt.Any(e => t.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
            {
                return classifier.Paths.Expand(t);
            }
        }

        return null;
    }
}
