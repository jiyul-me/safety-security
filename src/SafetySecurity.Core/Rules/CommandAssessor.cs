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
/// 자동 실행 명령줄 하나를 평가해요: 실행 파일 자체 + LOLBin 악용 패턴 + 실제 페이로드(DLL·스크립트)
/// + 감싼 명령(cmd /c, start, conhost, explorer, PowerShell Start-Process 등)이 실제로 실행하는 파일.
/// </summary>
public static class CommandAssessor
{
    private static readonly string[] ScriptExtensions = [".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".hta"];

    /// <summary>cmd /c cmd /c ... 처럼 겹겹이 감싼 명령을 몇 겹까지 풀어 볼지.</summary>
    private const int MaxWrapperDepth = 3;

    /// <summary>안쪽 명령의 증거 항목 앞에 붙이는 말.</summary>
    private const string InnerEvidencePrefix = "실제 파일 ";

    public static bool IsScript(string path) =>
        ScriptExtensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase));

    public static CommandAssessment Assess(ScanContext ctx, string raw) => Assess(ctx, raw, 0);

    private static CommandAssessment Assess(ScanContext ctx, string raw, int depth)
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

        // 감싼 명령의 안쪽(cmd /c 뒤 등)에서 경로 없이 이름만 쓴 명령이 Windows 폴더에 없으면 '파일 없음'으로 보지 않아요.
        // echo, set, timeout 같은 cmd 내장 명령이나 PATH의 프로그램까지 '등록된 파일이 없어요'로 보고하게 되니까요.
        var skipFile = depth > 0 && !LauncherCommands.FirstTokenIsAbsolute(ctx.Paths.Expand(raw)) && !ctx.Files.FileExists(parsed.Executable);

        // 명령 자체의 파일(실행 파일·스크립트·페이로드)에서 나온 위험도. 감싼 명령의 결과와 비교해서 대상을 정해요.
        Severity? ownSeverity = null;
        if (!skipFile)
        {
            if (IsScript(parsed.Executable))
            {
                ownSeverity = AssessScript(ctx, parsed.Executable, result);
            }
            else
            {
                var exe = ExecutableAssessor.Assess(ctx, parsed.Executable);
                result.Target = exe.Path;
                ownSeverity = exe.Severity;
                Merge(result, exe.Severity, exe.Reasons);
                result.Evidence.AddRange(exe.Evidence);
            }
        }

        if (heuristic.PayloadPath is { } payload)
        {
            var resolved = CommandLine.ResolveExecutable(ctx.Paths.Expand(payload), ctx.Paths, ctx.Files);
            result.Evidence.Add(new("실제로 실행되는 파일", resolved));
            if (heuristic.PayloadIsScript || IsScript(resolved))
            {
                ownSeverity = Max(ownSeverity, AssessScript(ctx, resolved, result));
            }
            else
            {
                var p = ExecutableAssessor.Assess(ctx, resolved);
                ownSeverity = Max(ownSeverity, p.Severity);
                Merge(result, p.Severity, p.Reasons.Select(r => "페이로드: " + r));
                foreach (var e in p.Evidence)
                {
                    result.Evidence.Add(new("페이로드 " + e.Key, e.Value));
                }
            }

            result.Target = resolved;
        }

        if (depth < MaxWrapperDepth && AssessWrapped(ctx, parsed, heuristic, result, ownSeverity, depth))
        {
            result.IsSelf = true;
            return result;
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

    /// <summary>
    /// 다른 평가 결과(감싼 명령의 안쪽, 바로가기의 다른 대상 후보)를 합쳐요.
    /// 위험도는 더 높은 쪽을 쓰고, 이유 앞에 <paramref name="reasonPrefix"/>를 붙이고, 증거는 "실제 파일 ..."로 덧붙여요.
    /// </summary>
    public static void MergeOther(CommandAssessment result, CommandAssessment other, string reasonPrefix, string evidenceLabel, string evidenceValue)
    {
        Merge(result, other.Severity, other.Reasons.Select(r => reasonPrefix + r));
        result.Evidence.Add(new(evidenceLabel, evidenceValue));
        if (other.Target is not null)
        {
            result.Evidence.Add(new("실제로 실행되는 파일", other.Target));
        }

        foreach (var e in other.Evidence)
        {
            if (e.Key == "명령줄")
            {
                continue;
            }

            var key = e.Key.StartsWith("실제", StringComparison.Ordinal) || e.Key == evidenceLabel ? e.Key : InnerEvidencePrefix + e.Key;
            result.Evidence.Add(new(key, e.Value));
        }
    }

    /// <summary>
    /// 다른 프로그램을 대신 실행하는 명령(cmd /c, start, conhost, explorer, PowerShell Start-Process 등)이면
    /// 실제로 실행되는 명령·파일도 평가해서 가장 위험한 결과를 합쳐요.
    /// 감싸는 프로그램(cmd.exe 등)만으로는 위험도를 올리지 않아요. cmd /c start ""로 프로그램을 띄우는 정상 프로그램도 많아요.
    /// </summary>
    /// <returns>안쪽 명령이 모두 검사기 자신이라 결과에서 빼야 하면 true.</returns>
    private static bool AssessWrapped(ScanContext ctx, ParsedCommand parsed, HeuristicResult heuristic, CommandAssessment result, Severity? ownSeverity, int depth)
    {
        var inner = new List<(string Raw, CommandAssessment A)>();
        var commands = LauncherCommands.InnerCommands(parsed, ctx.Files.FileExists);
        var selfCount = 0;
        foreach (var command in commands)
        {
            ctx.Pacer.Step();
            var a = Assess(ctx, command, depth + 1);
            if (a.IsSelf)
            {
                selfCount++;
            }
            else if (Counts(ctx, a))
            {
                inner.Add((command, a));
            }
        }

        var payload = heuristic.PayloadPath is { } pp ? ctx.Classifier.Normalize(pp) : null;
        var self = ctx.Classifier.Normalize(parsed.Executable);
        var argumentPaths = LauncherCommands.ArgumentPaths(parsed, ctx.Paths);
        foreach (var path in argumentPaths)
        {
            // 인자 속 경로는 실제로 있는 실행 파일·스크립트만 봐요. explorer.exe C:\Users\me\Documents 같은 폴더 열기나
            // 없는 파일 이름은 무시해요. 네트워크 경로는 열지 않고 경로만으로 판단해요.
            var n = ctx.Classifier.Normalize(path);
            if (n == payload || n == self || !LauncherCommands.IsRunnableFile(path)
                || !(ctx.Classifier.IsNetworkPath(path) || ctx.Files.FileExists(path)))
            {
                continue;
            }

            ctx.Pacer.Step();
            var a = Assess(ctx, "\"" + path + "\"", depth + 1);
            if (!a.IsSelf)
            {
                inner.Add((path, a));
            }
        }

        if (commands.Count > 0 && selfCount == commands.Count && inner.Count == 0 && result.Severity is null)
        {
            // cmd /c "검사기.exe ..." 처럼 검사기 자신만 실행하는 등록이에요.
            return true;
        }

        if (inner.Count == 0)
        {
            return false;
        }

        var prefix = parsed.FileName + "를 거쳐 실행: ";
        foreach (var (raw, a) in inner)
        {
            MergeOther(result, a, prefix, "감싼 명령", raw);
        }

        // 대상(Target)은 가장 위험한 안쪽 파일이에요. 예약 작업의 숨김 작업 판정, IFEO의 '서명된 도구' 판정이 이 파일을 봐요.
        // 감싼 프로그램 자체가 문제없고(서명된 cmd.exe 등) 따로 실행하는 페이로드도 없으면, 위험도가 없어도 안쪽 파일을 대상으로 써요.
        var worst = inner.OrderByDescending(x => Rank(x.A.Severity)).First();
        if (Rank(worst.A.Severity) > Rank(ownSeverity) || (ownSeverity is null && heuristic.PayloadPath is null))
        {
            result.Target = worst.A.Target;
        }

        return false;
    }

    /// <summary>안쪽 명령의 결과를 쓸지: 위험도가 있거나, 실제로 있는 파일(또는 열지 않은 네트워크 경로)을 가리킬 때만이요.</summary>
    private static bool Counts(ScanContext ctx, CommandAssessment a) =>
        a.Severity is not null || (a.Target is { } t && (ctx.Files.FileExists(t) || ctx.Classifier.IsNetworkPath(t)));

    private static int Rank(Severity? s) => s is { } v ? (int)v : -1;

    private static Severity? Max(Severity? a, Severity? b) =>
        a is null ? b : b is null ? a : SeverityExtensions.Max(a.Value, b.Value);

    /// <summary>스크립트 파일을 평가해서 결과에 합쳐요. 이 스크립트 때문에 생긴 위험도를 돌려줘요 (없으면 null).</summary>
    private static Severity? AssessScript(ScanContext ctx, string path, CommandAssessment result)
    {
        var kind = ctx.Classifier.Classify(path);
        result.Evidence.Add(new("스크립트 위치", PathClassifier.ToKorean(kind)));
        if (kind == PathKind.Network)
        {
            // 네트워크 경로의 스크립트는 열지 않아요 (열기만 해도 다른 컴퓨터에 접속해요).
            var remote = PathClassifier.IsRemotePath(path);
            if (ctx.Classifier.NetworkLocation(path) is { } host)
            {
                result.Evidence.Add(new("네트워크 위치", host));
            }

            var networkSeverity = remote ? Model.Severity.High : Model.Severity.Medium;
            Merge(result, networkSeverity, [$"스크립트가 {PathClassifier.ToKorean(kind)}에서 자동 실행돼요.", ExecutableAssessor.NotCheckedReason]);
            return networkSeverity;
        }

        var meta = ctx.Files.GetMeta(path);
        if (meta is null)
        {
            Merge(result, Model.Severity.Low, ["등록된 스크립트 파일이 없어요."]);
            return Model.Severity.Low;
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
                return Model.Severity.High;
            case PathKind.UserProfile:
            case PathKind.ProgramData:
                Merge(result, Model.Severity.Medium, [$"스크립트가 {PathClassifier.ToKorean(kind)}에서 자동 실행돼요."]);
                return Model.Severity.Medium;
            default:
                return null;
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
