using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Baseline;

/// <summary>
/// 검사가 숨김 목록에 한 변경. 숨김 목록은 사용자가 ignore/unignore 명령으로 바꾸는 것이라,
/// 검사는 저장하기 직전에 디스크의 최신 목록을 다시 읽고 이 변경만 그 위에 다시 적용해요 (<see cref="IgnoreList.KeepLatest"/>).
/// </summary>
public sealed record IgnoreEdit(string Id, string? OldId, IgnoreEntry? Entry)
{
    /// <summary>숨길 때 상태를 몰랐던 항목에 지금 상태를 기록해요.</summary>
    public static IgnoreEdit Adopt(string id, IgnoreEntry entry) => new(id, null, entry);

    /// <summary>예전 버전이 쓰던 ID로 숨긴 항목을 새 ID로 옮겨요.</summary>
    public static IgnoreEdit Rename(string oldId, string newId) => new(newId, oldId, null);

    public void ApplyTo(ScanState state)
    {
        if (OldId is not null)
        {
            if (state.Ignored.Remove(OldId))
            {
                state.Ignored.Add(Id);
                if (state.IgnoredDetail.Remove(OldId, out var moved) && !state.IgnoredDetail.ContainsKey(Id))
                {
                    state.IgnoredDetail[Id] = moved;
                }
            }

            return;
        }

        if (Entry is null || !state.Ignored.Contains(Id))
        {
            // 검사하는 사이에 사용자가 다시 보이게(unignore) 했으면 그대로 둬요.
            return;
        }

        state.IgnoredDetail.TryGetValue(Id, out var current);
        if (current?.Severity is not null)
        {
            // 사용자가 그사이 다시 숨겨서 새 기준이 생겼어요.
            return;
        }

        state.IgnoredDetail[Id] = new IgnoreEntry
        {
            Title = current?.Title ?? Entry.Title,
            Category = current?.Category ?? Entry.Category,
            IgnoredUtc = current?.IgnoredUtc ?? Entry.IgnoredUtc,
            Severity = Entry.Severity,
            Fingerprint = Entry.Fingerprint,
        };
    }
}

public enum IdMatch
{
    Found,
    NotFound,
    Ambiguous,
    Invalid,
}

/// <summary>숨김(ignore) 목록을 다루는 규칙. 앱의 ignore·unignore·ignored 명령과 검사가 같이 써요.</summary>
public static class IgnoreList
{
    /// <summary>ID 앞부분만 적을 때 최소 글자 수. 이보다 짧으면 다른 항목과 헷갈리기 쉬워요.</summary>
    public const int MinPrefix = 8;

    /// <summary>보고서 ID 길이 (16진수 16자리).</summary>
    public const int IdLength = 16;

    /// <summary>사용자가 적은 ID를 정리해요 (공백·대소문자). 16진수가 아니면 null.</summary>
    public static string? Normalize(string? input)
    {
        var text = input?.Trim().Trim('"', '\'').ToLowerInvariant();
        if (string.IsNullOrEmpty(text) || text.Length > IdLength || !text.All(char.IsAsciiHexDigit))
        {
            return null;
        }

        return text;
    }

    /// <summary>
    /// 적은 ID(또는 <see cref="MinPrefix"/>자 이상의 앞부분)를 아는 ID 중에서 찾아요.
    /// 오타로 엉뚱한 ID를 저장하지 않도록, 정확히 하나만 맞을 때만 찾았다고 해요.
    /// </summary>
    public static IdMatch Resolve(string? input, IEnumerable<string> known, out string? id)
    {
        id = null;
        var text = Normalize(input);
        if (text is null)
        {
            return IdMatch.Invalid;
        }

        var matches = new HashSet<string>(StringComparer.Ordinal);
        foreach (var k in known)
        {
            var candidate = k.ToLowerInvariant();
            if (candidate == text)
            {
                id = candidate;
                return IdMatch.Found;
            }

            if (text.Length >= MinPrefix && candidate.StartsWith(text, StringComparison.Ordinal))
            {
                matches.Add(candidate);
            }
        }

        if (matches.Count == 1)
        {
            id = matches.First();
            return IdMatch.Found;
        }

        return matches.Count > 1 ? IdMatch.Ambiguous : text.Length < MinPrefix ? IdMatch.Invalid : IdMatch.NotFound;
    }

    /// <summary>
    /// 항목을 숨겨요. 마지막 검사 기록이 있으면 그때의 위험도·지문을 기준으로 삼아서,
    /// 나중에 더 위험해지거나 파일이 바뀌면 다시 보여줘요. 기록이 없으면 다음 검사가 기준을 정해요.
    /// </summary>
    /// <returns>새로 숨겼거나 기준을 새로 정했으면 true, 이미 같은 기준으로 숨겨져 있으면 false.</returns>
    public static bool Add(ScanState state, string id, string? title, string? category, DateTimeOffset now)
    {
        state.BaselineDetail.TryGetValue(id, out var seen);
        var added = state.Ignored.Add(id);
        state.IgnoredDetail.TryGetValue(id, out var existing);
        if (!added && existing is not null
            && (seen is null || (existing.Severity == seen.Severity && FindingFingerprint.Same(existing.Fingerprint, seen.Fingerprint))))
        {
            // 이미 같은 기준으로 숨겨져 있어요.
            return false;
        }

        state.IgnoredDetail[id] = new IgnoreEntry
        {
            Title = seen?.Title ?? title ?? existing?.Title,
            Category = category ?? (state.Baseline.TryGetValue(id, out var c) ? c : existing?.Category),
            IgnoredUtc = now,
            Severity = seen?.Severity,
            Fingerprint = seen?.Fingerprint,
        };
        return true;
    }

    /// <summary>숨김을 풀어요. 목록에 없었으면 false.</summary>
    public static bool Remove(ScanState state, string id)
    {
        var removed = state.Ignored.Remove(id);
        state.IgnoredDetail.Remove(id);
        return removed;
    }

    /// <summary>
    /// 저장 직전에 디스크의 최신 숨김 목록을 가져오고, 검사가 한 변경만 다시 적용해요.
    /// 검사가 몇 분 걸리는 동안 사용자가 ignore/unignore로 바꾼 것을 오래된 목록으로 덮어쓰지 않으려고요.
    /// </summary>
    public static void KeepLatest(ScanState scan, ScanState disk, IEnumerable<IgnoreEdit> edits)
    {
        scan.Ignored = new HashSet<string>(disk.Ignored, StringComparer.Ordinal);
        scan.IgnoredDetail = new Dictionary<string, IgnoreEntry>(disk.IgnoredDetail, StringComparer.Ordinal);
        foreach (var e in edits)
        {
            e.ApplyTo(scan);
        }

        foreach (var orphan in scan.IgnoredDetail.Keys.Where(k => !scan.Ignored.Contains(k)).ToList())
        {
            scan.IgnoredDetail.Remove(orphan);
        }
    }

    /// <summary>숨긴 항목을 보여줄 때의 한 줄 (ID, 위험도, 제목, 숨긴 날).</summary>
    public static string Describe(string id, IgnoreEntry? entry)
    {
        var sev = entry?.Severity is { } s ? $"[{s.ToKorean()}] " : string.Empty;
        var title = entry?.Title ?? "(제목을 몰라요: 예전 버전에서 숨긴 항목)";
        var when = entry?.IgnoredUtc is { } t
            ? " — " + t.ToLocalTime().ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture) + "에 숨김"
            : string.Empty;
        return $"{id}  {sev}{title}{when}";
    }
}
