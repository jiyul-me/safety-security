using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Scanners;

namespace SafetySecurity.Core.Engine;

public sealed class ScanResult
{
    public required DateTimeOffset StartedUtc { get; init; }

    public DateTimeOffset FinishedUtc { get; set; }

    public required ScanScope Scope { get; init; }

    public required ScanReason Reason { get; init; }

    public required bool Quick { get; init; }

    public List<Finding> Findings { get; } = [];

    /// <summary>실제로 끝까지 검사한 분류. 베이스라인은 이 분류만 갱신해요.</summary>
    public List<string> CompletedCategories { get; } = [];

    /// <summary>검사한 분류의 한국어 이름 (일부만 확인한 분류는 "(일부만 확인)"을 붙여요).</summary>
    public List<string> CompletedNames { get; } = [];

    /// <summary>
    /// 검사는 했지만 일부를 읽지 못한 분류 (목록을 못 읽음, 일부 작업 XML이 깨짐, 파일이 너무 큼 등).
    /// 찾은 항목은 베이스라인에 더하지만, 이번에 못 본 예전 항목은 지우지 않아요.
    /// </summary>
    public List<string> PartialCategories { get; } = [];

    public List<string> Coverage { get; } = [];

    public bool Aborted { get; set; }

    public string? AbortReason { get; set; }

    public int IgnoredCount { get; set; }

    /// <summary>사용자가 숨겨서 보고서 본문에서 뺀 항목 (보고서 끝에 목록과 되돌리는 방법을 보여줘요).</summary>
    public List<Finding> IgnoredFindings { get; } = [];
}

public static class ScanEngine
{
    public static IReadOnlyList<IScanner> AllScanners() =>
    [
        new ComHijackScanner(),
        new AutorunScanner(),
        new ServiceScanner(),
        new ScheduledTaskScanner(),
        new HiddenTaskScanner(),
        new BrowserScanner(),
        new DefenderScanner(),
        new HostsScanner(),
        new WmiScanner(),
        new DroppedFileScanner(),
    ];

    /// <summary>
    /// 스캐너를 하나씩 순서대로(단일 스레드) 실행해요. 게임이 시작되면 중간에 멈추고 Aborted=true로 돌려줘요.
    /// 스캐너 하나가 오류를 내도 나머지는 계속해요.
    /// </summary>
    public static ScanResult Run(ScanContext ctx, IEnumerable<IScanner> scanners, ScanReason reason, bool quick, Func<DateTimeOffset> clock)
    {
        var result = new ScanResult { StartedUtc = clock(), Scope = ctx.Scope, Reason = reason, Quick = quick };
        var byId = new Dictionary<string, Finding>();
        foreach (var scanner in scanners)
        {
            if (!scanner.RunsIn(ctx.Scope, quick))
            {
                continue;
            }

            try
            {
                foreach (var f in scanner.Scan(ctx))
                {
                    if (f.Target is not null && ctx.IsSelf(f.Target))
                    {
                        continue;
                    }

                    if (!byId.TryGetValue(f.Id, out var existing) || existing.Severity < f.Severity)
                    {
                        byId[f.Id] = f;
                    }
                }

                if (ctx.Coverage.IncompleteCategories.Contains(scanner.Category))
                {
                    result.PartialCategories.Add(scanner.Category);
                    result.CompletedNames.Add(scanner.DisplayName + " (일부만 확인)");
                }
                else
                {
                    result.CompletedCategories.Add(scanner.Category);
                    result.CompletedNames.Add(scanner.DisplayName);
                }
            }
            catch (ScanAbortedException ex)
            {
                result.Aborted = true;
                result.AbortReason = ex.Reason;
                break;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                ctx.Coverage.Skipped(scanner.DisplayName, $"검사 중 오류가 나서 건너뛰었어요 ({ex.GetType().Name}: {ex.Message})");
            }
        }

        result.Findings.AddRange(byId.Values
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Category, StringComparer.Ordinal)
            .ThenBy(f => f.Location, StringComparer.OrdinalIgnoreCase));
        result.Coverage.AddRange(ctx.Coverage.Notes);
        result.FinishedUtc = clock();
        return result;
    }
}
