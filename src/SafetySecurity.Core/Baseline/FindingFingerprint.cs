using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Baseline;

/// <summary>
/// 항목이 가리키는 파일의 '지문': 서명 상태, 서명자, SHA-256. 검사가 이미 모은 증거에서만 만들어서 디스크를 더 읽지 않아요.
/// 같은 위치(같은 ID)인데 파일이 바뀌었는지 알아보는 데 써요. 항목 ID는 그대로라서 숨김(ignore)은 계속 같은 ID로 해요.
/// </summary>
public static class FindingFingerprint
{
    /// <summary>서명을 확인하지 못했을 때(잠긴 파일 등)의 값. 어떤 값과도 같은 것으로 봐요.</summary>
    public const string Unknown = "?";

    private const string SignatureKey = "서명";
    private const string SignerKey = "서명자";
    private const string HashKey = "SHA-256";

    /// <summary>SHA-256은 앞 16자리(64비트)만 기억해요. 바뀌었는지 알기에는 충분하고 기록 파일이 작아져요.</summary>
    private const int HashChars = 16;

    /// <summary>증거에서 지문을 만들어요. 파일 정보가 없는 항목(설정 값, hosts 등)은 null.</summary>
    public static Dictionary<string, string>? Of(Finding finding)
    {
        Dictionary<string, string>? result = null;
        foreach (var (key, value) in finding.Evidence)
        {
            string? part = null;
            if (IsKey(key, HashKey))
            {
                var hex = value.Trim().ToLowerInvariant();
                part = hex.Length > HashChars ? hex[..HashChars] : hex;
            }
            else if (IsKey(key, SignerKey))
            {
                part = value.Trim();
            }
            else if (IsKey(key, SignatureKey))
            {
                part = SignatureToken(value);
            }

            if (part is null)
            {
                continue;
            }

            result ??= new Dictionary<string, string>(StringComparer.Ordinal);
            // 같은 이름의 증거가 여러 개면(감싼 명령 안쪽 파일이 둘 이상 등) 순서대로 이어 붙여요.
            result[key] = result.TryGetValue(key, out var existing) ? existing + "|" + part : part;
        }

        return result;
    }

    /// <summary>
    /// 지문이 달라졌으면 무엇이 달라졌는지 한국어로 돌려줘요. 같으면 null.
    /// 양쪽에 다 있는 값만 비교해요 (해시는 위험도가 보통 이상일 때만 계산해서, 한쪽에만 없는 건 바뀐 게 아니에요).
    /// 예외로 서명 상태가 전에는 없다가 생기면(없던 파일이 생기면) 바뀐 것으로 봐요. 반대로 파일이 없어진 건 실행될 게 없어서 알리지 않아요.
    /// </summary>
    public static string? Compare(IReadOnlyDictionary<string, string>? before, IReadOnlyDictionary<string, string>? now)
    {
        if (now is null || now.Count == 0)
        {
            return null;
        }

        // 전에는 파일 정보가 하나도 없었는데(파일 없음) 이제 서명을 확인했다면 없던 파일이 생긴 거예요.
        // 전에도 다른 정보(해시 등)가 있었다면 서명 확인만 건너뛰었던 것(부하 제한)이라 바뀐 걸로 보지 않아요.
        var wasEmpty = before is null || before.Count == 0;
        string? signature = null, signer = null, hash = null, appeared = null;
        foreach (var (key, value) in now.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var isSignature = IsKey(key, SignatureKey);
            if (before is null || !before.TryGetValue(key, out var old))
            {
                if (isSignature && wasEmpty)
                {
                    appeared ??= "등록된 위치에 없던 파일이 생겼어요";
                }

                continue;
            }

            if (old == value)
            {
                continue;
            }

            if (isSignature)
            {
                // 확인 실패(?)는 어떤 상태와도 같은 것으로 봐요. 잠긴 파일 때문에 다시 알리지 않으려고요.
                if (!old.Contains(Unknown, StringComparison.Ordinal) && !value.Contains(Unknown, StringComparison.Ordinal))
                {
                    signature ??= $"서명 상태가 바뀌었어요 ({TokenKorean(old)} → {TokenKorean(value)})";
                }
            }
            else if (IsKey(key, SignerKey))
            {
                signer ??= $"서명자가 바뀌었어요 ({old} → {value})";
            }
            else
            {
                hash ??= "같은 위치의 파일 내용이 바뀌었어요 (SHA-256이 달라요)";
            }
        }

        return signature ?? signer ?? hash ?? appeared;
    }

    /// <summary>두 지문이 똑같은지 (둘 다 없으면 같아요).</summary>
    public static bool Same(IReadOnlyDictionary<string, string>? a, IReadOnlyDictionary<string, string>? b)
    {
        var ac = a?.Count ?? 0;
        var bc = b?.Count ?? 0;
        if (ac != bc)
        {
            return false;
        }

        return ac == 0 || a!.All(kv => b!.TryGetValue(kv.Key, out var v) && v == kv.Value);
    }

    /// <summary>
    /// 베이스라인에 새 지문을 기억할 때, 이번에 계산하지 않은 해시와 확인하지 못한 서명 상태는 지난 값을 이어서 기억해요.
    /// 파일이 잠깐 잠겨 있거나 위험도가 낮아져 해시를 안 구한 뒤에도, 나중에 파일이 바뀌면 알아챌 수 있어요.
    /// </summary>
    public static Dictionary<string, string>? CarryOver(IReadOnlyDictionary<string, string>? before, Dictionary<string, string>? now)
    {
        if (before is null)
        {
            return now;
        }

        foreach (var (key, value) in before)
        {
            if (IsKey(key, HashKey) && (now is null || !now.ContainsKey(key)))
            {
                now ??= new Dictionary<string, string>(StringComparer.Ordinal);
                now[key] = value;
            }
            else if (IsKey(key, SignatureKey) && value != Unknown && now is not null && now.TryGetValue(key, out var current) && current == Unknown)
            {
                // 이번에 서명을 확인하지 못했으면(잠긴 파일 등) 지난번에 확인한 상태를 이어서 기억해요.
                now[key] = value;
            }
        }

        return now;
    }

    private static bool IsKey(string key, string name) =>
        key == name || key.EndsWith(" " + name, StringComparison.Ordinal);

    private static string SignatureToken(string value)
    {
        if (value == Rules.ExecutableAssessor.PackageSignatureText)
        {
            return "Package";
        }

        return SignatureInfo.TryParseKorean(value, out var status) && status != SignatureStatus.Error
            ? status.ToString()
            : Unknown;
    }

    private static string TokenKorean(string token) =>
        token == "Package" ? "패키지 서명"
        : Enum.TryParse<SignatureStatus>(token, out var s) ? SignatureInfo.StatusKorean(s)
        : token;
}
