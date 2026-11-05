using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Parsing;

public sealed record ParsedCommand(string Raw, string Executable, string Arguments, bool WasQuoted)
{
    /// <summary>실행 파일 이름만 (소문자, 예: rundll32.exe).</summary>
    public string FileName
    {
        get
        {
            var idx = Executable.LastIndexOfAny(['\\', '/']);
            return (idx >= 0 ? Executable[(idx + 1)..] : Executable).ToLowerInvariant();
        }
    }

    /// <summary>
    /// 따옴표 없이 공백이 들어간 경로 (예: C:\Program Files\A B\x.exe).
    /// Windows가 C:\Program.exe를 먼저 실행하려 해서 권한 상승에 악용될 수 있어요.
    /// </summary>
    public bool IsUnquotedWithSpaces => !WasQuoted && Executable.Contains(' ');
}

/// <summary>Windows 명령줄에서 실행 파일 경로와 인자를 분리해요.</summary>
public static class CommandLine
{
    private static readonly string[] ExecutableExtensions = [".exe", ".com", ".bat", ".cmd"];

    /// <summary>CommandLineToArgvW와 비슷한 규칙으로 토큰을 나눠요.</summary>
    public static List<string> Tokenize(string? text)
    {
        var result = new List<string>();
        if (string.IsNullOrEmpty(text))
        {
            return result;
        }

        var current = new System.Text.StringBuilder();
        var inQuotes = false;
        var hasToken = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '\\')
            {
                // 백슬래시 n개 + 따옴표 규칙
                var start = i;
                while (i < text.Length && text[i] == '\\')
                {
                    i++;
                }

                var count = i - start;
                if (i < text.Length && text[i] == '"')
                {
                    current.Append('\\', count / 2);
                    if (count % 2 == 1)
                    {
                        current.Append('"');
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }

                    hasToken = true;
                }
                else
                {
                    current.Append('\\', count);
                    hasToken = true;
                    i--;
                }

                continue;
            }

            if (c == '"')
            {
                inQuotes = !inQuotes;
                hasToken = true;
                continue;
            }

            if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (hasToken)
                {
                    result.Add(current.ToString());
                    current.Clear();
                    hasToken = false;
                }

                continue;
            }

            current.Append(c);
            hasToken = true;
        }

        if (hasToken)
        {
            result.Add(current.ToString());
        }

        return result;
    }

    /// <summary>
    /// 명령줄에서 실행 파일을 찾아요. 따옴표가 없으면 Windows처럼 공백마다 잘라 보며
    /// 실제로 있는 파일을 찾고, 경로가 없으면 System32와 Windows 폴더에서 찾아요.
    /// </summary>
    public static ParsedCommand? Parse(string? raw, SystemPaths paths, IFileSystemView? files)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var text = paths.Expand(raw.Trim());
        if (text.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            text = text[4..];
        }

        if (text.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            text = paths.SystemRoot + text[11..];
        }

        string exe;
        string args;
        var quoted = false;
        if (text.StartsWith('"'))
        {
            quoted = true;
            var end = text.IndexOf('"', 1);
            if (end < 0)
            {
                exe = text[1..];
                args = string.Empty;
            }
            else
            {
                exe = text[1..end];
                args = text[(end + 1)..].Trim();
            }
        }
        else
        {
            (exe, args) = SplitUnquoted(text, files);
        }

        exe = ResolveExecutable(exe.Trim(), paths, files);
        return new ParsedCommand(raw, exe, args, quoted);
    }

    private static (string Exe, string Args) SplitUnquoted(string text, IFileSystemView? files)
    {
        // "C:\Program Files\App\app.exe -x" → 공백 위치마다 잘라서 존재하는 파일을 찾아요.
        var positions = new List<int>();
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == ' ' || text[i] == '\t')
            {
                positions.Add(i);
            }
        }

        positions.Add(text.Length);
        if (files is not null)
        {
            foreach (var pos in positions)
            {
                var candidate = text[..pos].TrimEnd();
                if (candidate.Length == 0)
                {
                    continue;
                }

                if (files.FileExists(candidate) || (!HasExtension(candidate) && ExecutableExtensions.Any(e => files.FileExists(candidate + e))))
                {
                    return (candidate, text[pos..].Trim());
                }
            }
        }

        // 첫 토큰에 폴더 구분자가 없으면 (예: "certutil -f ...") 그 토큰이 실행 파일이에요.
        var firstToken = text[..positions[0]];
        if (!firstToken.Contains('\\') && !firstToken.Contains('/'))
        {
            return (firstToken, text[positions[0]..].Trim());
        }

        // 못 찾으면, 확장자로 끝나는 첫 지점까지를 실행 파일로 봐요.
        foreach (var pos in positions)
        {
            var candidate = text[..pos].TrimEnd();
            if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                || candidate.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                || candidate.EndsWith(".com", StringComparison.OrdinalIgnoreCase)
                || candidate.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)
                || candidate.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)
                || candidate.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
            {
                return (candidate, text[pos..].Trim());
            }
        }

        var first = positions[0];
        return (text[..first], text[first..].Trim());
    }

    private static bool HasExtension(string path)
    {
        var name = path[(path.LastIndexOf('\\') + 1)..];
        return name.Contains('.');
    }

    /// <summary>경로가 없는 이름(예: rundll32)을 System32 등에서 찾아요.</summary>
    public static string ResolveExecutable(string exe, SystemPaths paths, IFileSystemView? files)
    {
        if (exe.Length == 0)
        {
            return exe;
        }

        var hasDir = exe.Contains('\\') || exe.Contains('/');
        if (!hasDir)
        {
            var name = HasExtension(exe) ? exe : exe + ".exe";
            string[] dirs = [paths.System32, paths.SystemRoot, paths.System32 + @"\WindowsPowerShell\v1.0", paths.System32 + @"\wbem"];
            if (files is not null)
            {
                foreach (var dir in dirs)
                {
                    var full = dir + "\\" + name;
                    if (files.FileExists(full))
                    {
                        return full;
                    }
                }
            }

            // 파일 시스템을 못 보면 System32에 있다고 가정해요.
            return paths.System32 + "\\" + name;
        }

        if (files is not null && !HasExtension(exe) && !files.FileExists(exe))
        {
            foreach (var ext in ExecutableExtensions)
            {
                if (files.FileExists(exe + ext))
                {
                    return exe + ext;
                }
            }
        }

        return exe;
    }
}
