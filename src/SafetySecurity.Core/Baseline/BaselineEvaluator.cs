using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Baseline;

public sealed record NotifyDecision(IReadOnlyList<Finding> ToNotify, bool FirstRun);

/// <summary>
/// 지난 검사와 비교해서 새 항목을 표시하고, 알림을 띄울 항목을 골라요.
/// 첫 검사에서는 '높음'만 알리고(이미 감염된 경우를 위해), 그 뒤로는 새로 생긴 항목만 알려요.
/// </summary>
public static class BaselineEvaluator
{
    public static NotifyDecision Apply(ScanResult result, ScanState state, ScanConfig config)
    {
        var firstRun = !state.BaselineInitialized;
        var ignored = result.Findings.Where(f => state.Ignored.Contains(f.Id)).ToList();
        result.IgnoredCount = ignored.Count;
        foreach (var f in ignored)
        {
            result.Findings.Remove(f);
        }

        foreach (var f in result.Findings)
        {
            f.IsNew = !state.Baseline.ContainsKey(f.Id);
        }

        var toNotify = firstRun
            ? result.Findings.Where(f => f.Severity >= Severity.High).ToList()
            : result.Findings.Where(f => f.IsNew && f.Severity >= config.NotifyMinSeverity).ToList();

        // 끝까지 검사한 분류만 갱신해요 (빠른 검사·중단된 검사가 다른 분류의 기록을 지우지 않도록).
        var completed = new HashSet<string>(result.CompletedCategories, StringComparer.Ordinal);
        foreach (var stale in state.Baseline.Where(kv => completed.Contains(kv.Value)).Select(kv => kv.Key).ToList())
        {
            state.Baseline.Remove(stale);
        }

        foreach (var f in result.Findings.Concat(ignored))
        {
            if (completed.Contains(f.Category))
            {
                state.Baseline[f.Id] = f.Category;
            }
        }

        if (!result.Aborted && !result.Quick)
        {
            state.BaselineInitialized = true;
        }

        return new NotifyDecision(toNotify, firstRun);
    }
}
