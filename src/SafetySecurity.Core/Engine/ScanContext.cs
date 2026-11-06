using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Engine;

/// <summary>스캐너들이 함께 쓰는 읽기 전용 도구 모음.</summary>
public sealed class ScanContext
{
    public required IRegistryView Registry { get; init; }

    public required IFileSystemView Files { get; init; }

    public required ISignatureVerifier Signatures { get; init; }

    public required PathClassifier Classifier { get; init; }

    public IScanPacer Pacer { get; init; } = NoPacer.Instance;

    public DateTimeOffset Now { get; init; } = DateTimeOffset.UtcNow;

    public ITaskSource? Tasks { get; init; }

    public IWmiSource? Wmi { get; init; }

    /// <summary>검사기 자신의 파일 경로 (정규화됨). 자기 자신은 결과에서 빼요.</summary>
    public IReadOnlySet<string> SelfPaths { get; init; } = new HashSet<string>();

    /// <summary>검사기 자신의 예약 작업 이름 접두사.</summary>
    public IReadOnlyList<string> SelfTaskPrefixes { get; init; } = [@"\SafetySecurity\", @"\SafetySecurity-"];

    public bool IsElevated { get; init; }

    public ScanScope Scope { get; init; } = ScanScope.User;

    public CoverageLog Coverage { get; } = new();

    public SystemPaths Paths => Classifier.Paths;

    public bool IsSelf(string? path) => path is not null && SelfPaths.Contains(Classifier.Normalize(path));
}

/// <summary>권한 부족 등으로 확인하지 못한 항목 기록. 보고서에 그대로 보여줘요.</summary>
public sealed class CoverageLog
{
    private readonly List<string> _notes = [];

    public IReadOnlyList<string> Notes => _notes;

    public void Skipped(string what, string why)
    {
        var note = $"{what}: {why}";
        if (!_notes.Contains(note))
        {
            _notes.Add(note);
        }
    }
}
