using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Parsing;

namespace SafetySecurity.Core.Rules;

/// <summary>
/// 바로가기(.lnk)의 대상 후보 중 실제로 실행될 것을 골라요. 파일은 존재 여부만 확인하고 열지 않아요.
/// 네트워크 경로는 존재 여부도 확인하지 않아요 (확인만 해도 다른 컴퓨터에 접속해요).
/// </summary>
public static class ShortcutTargets
{
    /// <summary>
    /// 대상 후보: 환경 변수를 펼치고, 상대 경로는 바로가기가 있는 폴더 기준으로 붙이고, 같은 경로는 한 번만 넣어요.
    /// 순서는 Windows가 쓰는 우선순위예요 (<see cref="ShortcutInfo.Candidates"/>).
    /// </summary>
    public static IReadOnlyList<string> Candidates(ScanContext ctx, ShortcutInfo link, string lnkPath)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Add(string path)
        {
            var expanded = ctx.Paths.Expand(path.Trim().Trim('"'));
            if (expanded.Length > 0 && seen.Add(ctx.Classifier.Normalize(expanded)))
            {
                result.Add(expanded);
            }
        }

        foreach (var c in link.Candidates)
        {
            Add(c);
        }

        if (result.Count == 0 && link.RelativePath is { } relative && lnkPath.LastIndexOf('\\') is var slash and > 0)
        {
            Add(CombineRelative(lnkPath[..slash], ctx.Paths.Expand(relative)));
        }

        return result;
    }

    /// <summary>
    /// 실제로 실행될 대상: 우선순위대로 보면서 실제로 있는 파일(또는 열어 보지 않은 네트워크 경로) 중 첫째예요.
    /// 아무것도 없으면 첫 후보예요 (없는 파일이라고 보고돼요).
    /// </summary>
    public static string? Primary(ScanContext ctx, IReadOnlyList<string> candidates)
    {
        foreach (var c in candidates)
        {
            if (ctx.Classifier.IsNetworkPath(c) || ctx.Files.FileExists(c))
            {
                return c;
            }
        }

        return candidates.Count > 0 ? candidates[0] : null;
    }

    /// <summary>
    /// 후보들이 서로 다른 프로그램을 가리키는지 (바로가기 대상 위장). 실제로 있는 파일(또는 네트워크 경로)만 비교하고,
    /// 폴더만 다른 경우(Program Files와 Program Files (x86) 등)는 같은 프로그램으로 봐요.
    /// </summary>
    public static bool IsDisguised(ScanContext ctx, IReadOnlyList<string> candidates) =>
        candidates.Where(c => ctx.Classifier.IsNetworkPath(c) || ctx.Files.FileExists(c))
            .Select(c => FileName(ctx.Classifier.Normalize(c)))
            .Distinct(StringComparer.Ordinal)
            .Count() > 1;

    /// <summary>폴더 + 상대 경로 (.. 과 . 처리). 대소문자는 그대로 둬요.</summary>
    public static string CombineRelative(string folder, string relative)
    {
        if (LauncherCommands.IsAbsolutePath(relative))
        {
            return relative;
        }

        var parts = folder.TrimEnd('\\').Split('\\').ToList();
        foreach (var part in relative.Replace('/', '\\').Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".")
            {
                continue;
            }

            if (part == "..")
            {
                if (parts.Count > 1)
                {
                    parts.RemoveAt(parts.Count - 1);
                }

                continue;
            }

            parts.Add(part);
        }

        return string.Join('\\', parts);
    }

    private static string FileName(string normalized)
    {
        var idx = normalized.LastIndexOf('\\');
        return idx >= 0 ? normalized[(idx + 1)..] : normalized;
    }
}
