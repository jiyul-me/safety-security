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
        var text = Status switch
        {
            SignatureStatus.Valid => IsCatalog ? "유효 (Windows 카탈로그 서명)" : "유효",
            SignatureStatus.Unsigned => "서명 없음",
            SignatureStatus.Untrusted => "신뢰할 수 없는 서명",
            SignatureStatus.Invalid => "손상되었거나 폐기된 서명",
            SignatureStatus.NotFound => "파일 없음",
            _ => "확인 실패",
        };
        if (!string.IsNullOrEmpty(Detail))
        {
            text += $" ({Detail})";
        }

        return text;
    }
}
