namespace SafetySecurity.Core.Model;

public enum SignatureStatus
{
    /// <summary>신뢰할 수 있는 서명이 있음 (파일에 직접 또는 Windows 카탈로그).</summary>
    Valid,

    /// <summary>서명이 없음.</summary>
    Unsigned,

    /// <summary>서명은 있지만 신뢰할 수 없는 인증서 (자체 서명, 체인 오류, 만료 등).</summary>
    Untrusted,

    /// <summary>서명이 손상되었거나(파일 변조) 폐기·명시적 불신 인증서.</summary>
    Invalid,

    /// <summary>파일이 없음.</summary>
    NotFound,

    /// <summary>확인 중 오류 (권한 부족, 잠긴 파일 등).</summary>
    Error,
}

public sealed record SignatureInfo(SignatureStatus Status, string? Signer = null, bool IsCatalog = false, string? Detail = null)
{
    public bool IsTrusted => Status == SignatureStatus.Valid;

    public string ToKorean()
    {
        var text = StatusKorean(Status, IsCatalog);
        if (!string.IsNullOrEmpty(Detail))
        {
            text += $" ({Detail})";
        }

        return text;
    }

    /// <summary>서명 상태만 한국어로 (자세한 이유 없이). 보고서의 '서명' 증거는 이 말로 시작해요.</summary>
    public static string StatusKorean(SignatureStatus status, bool isCatalog = false) => status switch
    {
        SignatureStatus.Valid => isCatalog ? "유효 (Windows 카탈로그 서명)" : "유효",
        SignatureStatus.Unsigned => "서명 없음",
        SignatureStatus.Untrusted => "신뢰할 수 없는 서명",
        SignatureStatus.Invalid => "손상되었거나 폐기된 서명",
        SignatureStatus.NotFound => "파일 없음",
        _ => "확인 실패",
    };

    /// <summary>
    /// <see cref="ToKorean"/>로 만든 글에서 서명 상태를 다시 읽어요 (뒤에 붙은 자세한 이유는 무시해요).
    /// 베이스라인 지문이 "폐기 여부는 확인 안 함" 같은 덧붙임 때문에 바뀌지 않게 하려고 써요.
    /// </summary>
    public static bool TryParseKorean(string? text, out SignatureStatus status)
    {
        status = SignatureStatus.Error;
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        foreach (var candidate in Enum.GetValues<SignatureStatus>())
        {
            var label = StatusKorean(candidate);
            if (text == label || text.StartsWith(label + " (", StringComparison.Ordinal))
            {
                status = candidate;
                return true;
            }
        }

        return false;
    }
}
