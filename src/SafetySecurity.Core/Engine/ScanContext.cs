using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Engine;

/// <summary>스캐너들이 함께 쓰는 읽기 전용 도구 모음.</summary>
public sealed class ScanContext
{
    public required IRegistryView Registry { get; init; }

    private readonly IFileSystemView _files = null!;
    private readonly ISignatureVerifier _signatures = null!;
    private IFileSystemView? _localFiles;
    private ISignatureVerifier? _localSignatures;

    /// <summary>
    /// 파일 시스템 (읽기 전용). 넣은 보기에 항상 <see cref="LocalOnlyFileSystemView"/>를 씌워서,
    /// 어떤 스캐너도 네트워크 경로를 열지 못하게 해요.
    /// </summary>
    public required IFileSystemView Files
    {
        get => _localFiles ??= new LocalOnlyFileSystemView(_files, Classifier, folder => Coverage.Skipped("네트워크 폴더 " + folder, "네트워크에 접속하지 않으려고 열지 않았어요."));
        init => _files = value;
    }

    /// <summary>서명 확인. 네트워크 경로는 확인하지 않아요 (<see cref="LocalOnlySignatureVerifier"/>).</summary>
    public required ISignatureVerifier Signatures
    {
        get => _localSignatures ??= _signatures as LocalOnlySignatureVerifier ?? new LocalOnlySignatureVerifier(_signatures, Classifier);
        init => _signatures = value;
    }

    public required PathClassifier Classifier { get; init; }

    public IScanPacer Pacer { get; init; } = NoPacer.Instance;

    public DateTimeOffset Now { get; init; } = DateTimeOffset.UtcNow;

    public ITaskSource? Tasks { get; init; }

    public IWmiSource? Wmi { get; init; }

    /// <summary>
    /// 검사기 자신의 파일 경로 (정규화됨). 자기 자신은 결과에서 빼요. 어떤 경로를 넣는지는 <see cref="Install.SelfExecutables"/>가 정해요.
    /// 예약 작업은 이름이 아니라 이 경로와 인자로 우리 작업인지 확인해요.
    /// </summary>
    public IReadOnlySet<string> SelfPaths { get; init; } = new HashSet<string>();

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
