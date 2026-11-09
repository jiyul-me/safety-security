using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Baseline;

public sealed record NotifyDecision(IReadOnlyList<Finding> ToNotify, bool FirstRun)
{
    /// <summary>검사가 숨김 목록에 한 변경. 저장 직전에 디스크의 최신 숨김 목록 위에 다시 적용해요 (<see cref="IgnoreList.KeepLatest"/>).</summary>
    public IReadOnlyList<IgnoreEdit> IgnoreEdits { get; init; } = [];
}

/// <summary>
/// 지난 검사와 비교해서 새 항목을 표시하고, 알림을 띄울 항목을 골라요.
/// 첫 검사에서는 '높음'만 알리고(이미 감염된 경우를 위해), 그 뒤로는 새로 생긴 항목과
/// 같은 자리(같은 ID)인데 더 위험해졌거나 파일이 바뀐 항목을 알려요.
/// </summary>
public static class BaselineEvaluator
{
    public static NotifyDecision Apply(ScanResult result, ScanState state, ScanConfig config)
    {
        var firstRun = !state.BaselineInitialized;
        var edits = new List<IgnoreEdit>();
        MovePreviousIds(result.Findings, state, edits);

        var fingerprints = new Dictionary<string, Dictionary<string, string>?>(StringComparer.Ordinal);
        foreach (var f in result.Findings)
        {
            f.IsNew = false;
            f.ChangeNote = null;
            f.IgnoreNote = null;
            fingerprints[f.Id] = FindingFingerprint.Of(f);
        }

        var hidden = new List<Finding>();
        foreach (var f in result.Findings)
        {
            if (!state.Ignored.Contains(f.Id))
            {
                continue;
            }

            state.IgnoredDetail.TryGetValue(f.Id, out var entry);
            if (entry?.Severity is not { } accepted)
            {
                // 숨길 때 상태를 모르면(예전 버전에서 숨겼거나, 검사 기록에 없던 ID를 숨겼으면) 지금 상태를 기준으로 기록해요.
                var adopted = new IgnoreEntry
                {
                    Title = entry?.Title ?? f.Title,
                    Category = entry?.Category ?? f.Category,
                    IgnoredUtc = entry?.IgnoredUtc,
                    Severity = f.Severity,
                    Fingerprint = fingerprints[f.Id],
                };
                var edit = IgnoreEdit.Adopt(f.Id, adopted);
                edit.ApplyTo(state);
                edits.Add(edit);
                hidden.Add(f);
                continue;
            }

            var why = Escalation(accepted, f.Severity) ?? FindingFingerprint.Compare(entry.Fingerprint, fingerprints[f.Id]);
            if (why is null)
            {
                hidden.Add(f);
                continue;
            }

            // 숨김은 그대로 두고(다시 숨기면 지금 상태가 새 기준이 돼요) 이번 보고서에는 보여줘요.
            f.IgnoreNote = $"숨긴 항목인데 숨긴 뒤로 달라져서 다시 보여줘요: {why}. 직접 확인해서 괜찮으면 다시 숨기세요 (지금 상태를 새 기준으로 숨겨요).";
        }

        result.IgnoredCount = hidden.Count;
        result.IgnoredFindings.AddRange(hidden);
        foreach (var f in hidden)
        {
            result.Findings.Remove(f);
        }

        foreach (var f in result.Findings)
        {
            if (!state.Baseline.ContainsKey(f.Id))
            {
                f.IsNew = true;
            }
            else if (state.BaselineDetail.TryGetValue(f.Id, out var seen)
                && (Escalation(seen.Severity, f.Severity) ?? FindingFingerprint.Compare(seen.Fingerprint, fingerprints[f.Id])) is { } change)
            {
                // 같은 자리인데 더 위험해졌거나 파일이 바뀌었어요 (예: 없던 파일이 생김, 같은 경로의 파일을 바꿔치기).
                f.IsNew = true;
                f.ChangeNote = change;
            }

            // BaselineDetail이 없으면 예전 버전이 쓴 기록이에요. 업데이트 직후에 알림이 쏟아지지 않게, 알리지 않고 지금 상태를 기록해요.
        }

        // 처음 보는 분류(예: 관리자 범위가 처음 검사한 서비스, 새 버전에 생긴 분류)는 첫 검사처럼 '높음'만 알려요.
        // 그 분류의 기존 항목이 한꺼번에 '새 항목' 알림으로 쏟아지지 않게요.
        var initialized = InitializedCategories(state, result.Scope);
        var toNotify = result.Findings
            .Where(f => firstRun || !initialized.Contains(f.Category)
                ? f.Severity >= Severity.High
                : f.IsNew && f.Severity >= config.NotifyMinSeverity)
            .ToList();

        // 끝까지 검사한 분류만 갱신해요 (빠른 검사·중단된 검사가 다른 분류의 기록을 지우지 않도록).
        // 일부만 확인한 분류는 찾은 항목만 더하고, 이번에 못 본 예전 항목은 지우지 않아요 (읽지 못한 것을 '없어짐'으로 보지 않게).
        var completed = new HashSet<string>(result.CompletedCategories, StringComparer.Ordinal);
        var partial = new HashSet<string>(result.PartialCategories, StringComparer.Ordinal);
        var previous = new Dictionary<string, BaselineEntry>(state.BaselineDetail, StringComparer.Ordinal);
        foreach (var stale in state.Baseline.Where(kv => completed.Contains(kv.Value)).Select(kv => kv.Key).ToList())
        {
            state.Baseline.Remove(stale);
            state.BaselineDetail.Remove(stale);
        }

        foreach (var f in result.Findings.Concat(hidden))
        {
            if (completed.Contains(f.Category) || partial.Contains(f.Category))
            {
                state.Baseline[f.Id] = f.Category;
                previous.TryGetValue(f.Id, out var before);
                state.BaselineDetail[f.Id] = new BaselineEntry
                {
                    Severity = f.Severity,
                    Fingerprint = FindingFingerprint.CarryOver(before?.Fingerprint, fingerprints[f.Id]),
                    Title = f.Title,
                };
            }
        }

        foreach (var orphan in state.BaselineDetail.Keys.Where(k => !state.Baseline.ContainsKey(k)).ToList())
        {
            state.BaselineDetail.Remove(orphan);
        }

        foreach (var orphan in state.IgnoredDetail.Keys.Where(k => !state.Ignored.Contains(k)).ToList())
        {
            state.IgnoredDetail.Remove(orphan);
        }

        if (!result.Aborted)
        {
            initialized.UnionWith(completed);
            state.InitializedCategories = initialized.Known;
            if (!result.Quick)
            {
                state.BaselineInitialized = true;
            }
        }

        state.Version = ScanState.CurrentVersion;
        return new NotifyDecision(toNotify, firstRun) { IgnoreEdits = edits };
    }

    /// <summary>
    /// 베이스라인이 의미 있는 분류. 이 칸이 없던 예전 기록(null)은, 전체 검사를 한 적이 있으면 예전처럼 모든 분류를 끝낸 것으로 보되,
    /// 그 범위의 전체 검사가 하지 않는 분류(예: 관리자 범위의 서비스)만 처음 보는 분류로 봐요.
    /// </summary>
    private static InitializedSet InitializedCategories(ScanState state, ScanScope scope)
    {
        if (state.InitializedCategories is { } known)
        {
            return new InitializedSet(new HashSet<string>(known, StringComparer.Ordinal), null);
        }

        if (!state.BaselineInitialized)
        {
            return new InitializedSet(new HashSet<string>(StringComparer.Ordinal), null);
        }

        var scanners = ScanEngine.AllScanners();
        var inFullScan = scanners.Where(s => s.RunsIn(scope, quick: false)).Select(s => s.Category).ToHashSet(StringComparer.Ordinal);
        var notInFullScan = scanners.Select(s => s.Category).Where(c => !inFullScan.Contains(c)).ToHashSet(StringComparer.Ordinal);
        inFullScan.UnionWith(state.Baseline.Values.Where(c => !notInFullScan.Contains(c)));
        return new InitializedSet(inFullScan, notInFullScan);
    }

    /// <summary>베이스라인이 의미 있는 분류 모음. <paramref name="LegacyExcept"/>가 있으면 예전 기록이라, 거기 없는 분류는 모두 끝낸 것으로 봐요.</summary>
    private sealed record InitializedSet(HashSet<string> Known, HashSet<string>? LegacyExcept)
    {
        public bool Contains(string category) =>
            Known.Contains(category) || (LegacyExcept is not null && !LegacyExcept.Contains(category));

        public void UnionWith(IEnumerable<string> categories) => Known.UnionWith(categories);
    }

    /// <summary>알림·보고서에서 달라진 항목을 새 항목과 구분해서 보여주는 제목.</summary>
    public static string NoticeTitle(Finding f) =>
        f.ChangeNote is not null || f.IgnoreNote is not null ? f.Title + " (달라짐)" : f.Title;

    private static string? Escalation(Severity before, Severity now) =>
        now > before ? $"위험도가 올라갔어요 ({before.ToKorean()} → {now.ToKorean()})" : null;

    /// <summary>
    /// ID 계산 방식이 바뀐 항목(<see cref="Finding.PreviousIds"/>)은 베이스라인과 숨김 목록을 새 ID로 옮겨요.
    /// 그래야 업데이트 뒤 첫 검사에서 같은 항목을 '새 항목'으로 다시 알리거나 숨긴 항목을 다시 보여주지 않아요.
    /// </summary>
    private static void MovePreviousIds(IEnumerable<Finding> findings, ScanState state, List<IgnoreEdit> edits)
    {
        foreach (var f in findings)
        {
            foreach (var old in f.PreviousIds)
            {
                if (old == f.Id)
                {
                    continue;
                }

                if (!state.Baseline.ContainsKey(f.Id) && state.Baseline.Remove(old, out var category))
                {
                    state.Baseline[f.Id] = category;
                    if (state.BaselineDetail.Remove(old, out var detail))
                    {
                        state.BaselineDetail[f.Id] = detail;
                    }
                }

                if (state.Ignored.Contains(old))
                {
                    var edit = IgnoreEdit.Rename(old, f.Id);
                    edit.ApplyTo(state);
                    edits.Add(edit);
                }
            }
        }
    }
}
