using System.Security.Cryptography;
using System.Text;

namespace SafetySecurity.Core.Model;

/// <summary>
/// 검사에서 나온 의심 항목 하나. 프로그램은 이걸 보고만 하고 절대 고치지 않아요.
/// </summary>
public sealed class Finding
{
    /// <summary>규칙 ID (예: COM-001).</summary>
    public required string RuleId { get; init; }

    /// <summary>분류 (예: ComHijack, Autorun). 베이스라인을 분류별로 갱신할 때도 써요.</summary>
    public required string Category { get; init; }

    public required Severity Severity { get; init; }

    /// <summary>사람이 읽는 한 줄 제목.</summary>
    public required string Title { get; init; }

    /// <summary>발견 위치 (레지스트리 경로, 파일 경로, 작업 이름 등).</summary>
    public required string Location { get; init; }

    /// <summary>실제로 실행되거나 로드되는 대상 (DLL, EXE, 명령줄). 없을 수도 있어요.</summary>
    public string? Target { get; init; }

    /// <summary>왜 의심스러운지.</summary>
    public IReadOnlyList<string> Reasons { get; init; } = [];

    /// <summary>증거 (서명 상태, 해시, 시각 등). 키 순서를 유지해요.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Evidence { get; init; } = [];

    /// <summary>사용자가 직접 확인하는 방법.</summary>
    public string? Advice { get; init; }

    /// <summary>이전 검사에 없던 새 항목인지 (BaselineEvaluator가 채워요).</summary>
    public bool IsNew { get; set; }

    private string? _id;

    /// <summary>
    /// 같은 항목이면 검사할 때마다 같은 값이 나오는 짧은 ID. 베이스라인 비교와 ignore 명령에 써요.
    /// 위치나 대상이 바뀌면 ID도 바뀌어서 '바뀐 항목'이 새 항목으로 잡혀요.
    /// </summary>
    public string Id => _id ??= ComputeId(Category, Location, Target);

    public static string ComputeId(string category, string location, string? target)
    {
        var text = $"{category}\n{location.ToLowerInvariant()}\n{target?.ToLowerInvariant()}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexStringLower(hash.AsSpan(0, 8));
    }
}
