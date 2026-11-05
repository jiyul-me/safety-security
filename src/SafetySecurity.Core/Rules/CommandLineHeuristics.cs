using System.Text.RegularExpressions;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;

namespace SafetySecurity.Core.Rules;

public sealed record HeuristicResult(Severity Severity, IReadOnlyList<string> Reasons, string? PayloadPath);

/// <summary>
/// 정상 Windows 프로그램(LOLBin)을 악용하는 명령줄 패턴을 찾아요.
/// 예: powershell -enc ..., mshta javascript:..., rundll32 C:\Users\...\x.dll,Start
/// </summary>
public static partial class CommandLineHeuristics
{
    private static readonly HashSet<string> PowerShells = new(StringComparer.OrdinalIgnoreCase) { "powershell.exe", "pwsh.exe", "powershell_ise.exe" };
    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase) { "wscript.exe", "cscript.exe" };

    [GeneratedRegex(@"(^|\s)[-/](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)(\s|$)", RegexOptions.IgnoreCase)]
    private static partial Regex EncodedCommand();

    [GeneratedRegex(@"\b(iex|invoke-expression|downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr|irm|invoke-restmethod|start-bitstransfer|frombase64string|net\.webclient|reflection\.assembly|-bxor)\b", RegexOptions.IgnoreCase)]
    private static partial Regex PowerShellDownloadOrExec();

    [GeneratedRegex(@"(^|\s)[-/]w(i|in|ind|indo|indow|indows|indowst|indowsty|indowstyl|indowstyle)?\s+(h|hi|hid|hidd|hidde|hidden|1)\b", RegexOptions.IgnoreCase)]
    private static partial Regex HiddenWindow();

    [GeneratedRegex(@"https?://|\\\\[^\\\s]+\\", RegexOptions.IgnoreCase)]
    private static partial Regex RemoteReference();

    [GeneratedRegex(@"(javascript|vbscript)\s*:", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptProtocol();

    public static HeuristicResult Analyze(ParsedCommand cmd, PathClassifier classifier)
    {
        var reasons = new List<string>();
        var severity = Severity.Info;
        string? payload = null;
        var name = cmd.FileName;
        var args = cmd.Arguments;

        void Flag(Severity s, string reason)
        {
            severity = SeverityExtensions.Max(severity, s);
            reasons.Add(reason);
        }

        if (PowerShells.Contains(name))
        {
            if (EncodedCommand().IsMatch(args))
            {
                Flag(Severity.High, "PowerShell이 인코딩된 명령(-EncodedCommand)을 실행해요. 내용을 숨기는 전형적인 수법이에요.");
            }

            if (PowerShellDownloadOrExec().IsMatch(args))
            {
                Flag(Severity.High, "PowerShell이 다운로드·문자열 실행(IEX, DownloadString 등)을 해요.");
            }

            if (HiddenWindow().IsMatch(args))
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
            var script = FindScriptArgument(cmd, classifier);
            payload = script;
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

        return new HeuristicResult(severity, reasons, payload);
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
