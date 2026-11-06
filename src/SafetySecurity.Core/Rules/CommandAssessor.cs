using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;

namespace SafetySecurity.Core.Rules;

public sealed class CommandAssessment
{
    public Severity? Severity { get; set; }

    public string? Target { get; set; }

    public ParsedCommand? Parsed { get; set; }

    public List<string> Reasons { get; } = [];

    public List<KeyValuePair<string, string>> Evidence { get; } = [];

    public bool IsSelf { get; set; }
}

/// <summary>
/// 자동 실행 명령줄 하나를 평가해요: 실행 파일 자체 + LOLBin 악용 패턴 + 실제 페이로드(DLL·스크립트).
/// </summary>
public static class CommandAssessor
{
    private static readonly string[] ScriptExtensions = [".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".hta"];

    public static bool IsScript(string path) =>
        ScriptExtensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase));

    public static CommandAssessment Assess(ScanContext ctx, string raw)
    {
        var result = new CommandAssessment();
        var parsed = CommandLine.Parse(raw, ctx.Paths, ctx.Files);
        result.Parsed = parsed;
        result.Evidence.Add(new("명령줄", raw));
        if (parsed is null)
        {
            return result;
        }

        result.Target = parsed.Executable;
        if (ctx.IsSelf(parsed.Executable))
        {
            result.IsSelf = true;
            return result;
        }

        var heuristic = CommandLineHeuristics.Analyze(parsed, ctx.Classifier);
        if (heuristic.Severity > Model.Severity.Info)
        {
            result.Severity = heuristic.Severity;
            result.Reasons.AddRange(heuristic.Reasons);
        }

        if (IsScript(parsed.Executable))
        {
            AssessScript(ctx, parsed.Executable, result);
        }
        else
        {
            var exe = ExecutableAssessor.Assess(ctx, parsed.Executable);
            result.Target = exe.Path;
            Merge(result, exe.Severity, exe.Reasons);
            result.Evidence.AddRange(exe.Evidence);
        }

        if (heuristic.PayloadPath is { } payload)
        {
            var resolved = CommandLine.ResolveExecutable(ctx.Paths.Expand(payload), ctx.Paths, ctx.Files);
            result.Evidence.Add(new("실제로 실행되는 파일", resolved));
            if (IsScript(resolved))
            {
                AssessScript(ctx, resolved, result);
            }
            else
            {
                var p = ExecutableAssessor.Assess(ctx, resolved);
                Merge(result, p.Severity, p.Reasons.Select(r => "페이로드: " + r));
                foreach (var e in p.Evidence)
                {
                    result.Evidence.Add(new("페이로드 " + e.Key, e.Value));
                }
            }

            result.Target = resolved;
        }

        if (parsed.IsUnquotedWithSpaces && ctx.Files.FileExists(parsed.Executable))
        {
            var firstSpace = parsed.Executable.IndexOf(' ');
            var hijackCandidate = parsed.Executable[..firstSpace] + ".exe";
            if (ctx.Files.FileExists(hijackCandidate))
            {
                Merge(result, Model.Severity.High, [$"따옴표 없는 경로 때문에 '{hijackCandidate}'가 대신 실행될 수 있고, 실제로 그 파일이 있어요."]);
            }
        }

        return result;
    }

    private static void AssessScript(ScanContext ctx, string path, CommandAssessment result)
    {
        var kind = ctx.Classifier.Classify(path);
        var meta = ctx.Files.GetMeta(path);
        result.Evidence.Add(new("스크립트 위치", PathClassifier.ToKorean(kind)));
        if (meta is null)
        {
            Merge(result, Model.Severity.Low, ["등록된 스크립트 파일이 없어요."]);
            return;
        }

        result.Evidence.Add(new("스크립트 수정 시각", ExecutableAssessor.FormatTime(meta.ModifiedUtc)));
        var hash = ctx.Files.Sha256(path, ExecutableAssessor.MaxHashBytes);
        if (hash is not null)
        {
            result.Evidence.Add(new("스크립트 SHA-256", hash));
        }

        switch (kind)
        {
            case PathKind.Temp:
            case PathKind.Public:
            case PathKind.Network:
                Merge(result, Model.Severity.High, [$"스크립트가 {PathClassifier.ToKorean(kind)}에서 자동 실행돼요."]);
                break;
            case PathKind.UserProfile:
            case PathKind.ProgramData:
                Merge(result, Model.Severity.Medium, [$"스크립트가 {PathClassifier.ToKorean(kind)}에서 자동 실행돼요."]);
                break;
        }
    }

    private static void Merge(CommandAssessment result, Severity? severity, IEnumerable<string> reasons)
    {
        if (severity is null)
        {
            return;
        }

        result.Severity = result.Severity is { } current ? SeverityExtensions.Max(current, severity.Value) : severity;
        result.Reasons.AddRange(reasons);
    }
}
