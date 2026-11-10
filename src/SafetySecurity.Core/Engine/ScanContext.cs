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

    /// <summary>
    /// 관리자 설치(관리자 검사 작업)가 있는지. 사용자 검사에서 관리자만 읽을 수 있는 항목을 못 봤을 때
    /// "관리자 검사에서 확인해요"와 "설치할 때 '관리자 권한으로'를 고르면 확인해요" 가운데 맞는 안내를 고르려고 써요.
    /// </summary>
    public bool AdminScanInstalled { get; init; }

    public CoverageLog Coverage { get; } = new();

    public SystemPaths Paths => Classifier.Paths;

    public bool IsSelf(string? path) => path is not null && SelfPaths.Contains(Classifier.Normalize(path));
}

/// <summary>권한 부족 등으로 확인하지 못한 항목 기록. 보고서에 그대로 보여줘요.</summary>
public sealed class CoverageLog
{
    private readonly List<string> _notes = [];
    private readonly HashSet<string> _incomplete = new(StringComparer.Ordinal);

    public IReadOnlyList<string> Notes => _notes;

    /// <summary>끝까지 확인하지 못한 분류 (<see cref="Incomplete"/>).</summary>
    public IReadOnlySet<string> IncompleteCategories => _incomplete;

    /// <summary>
    /// 분류 하나를 끝까지 확인하지 못했어요 (목록을 읽지 못했거나 일부가 깨졌어요). 보고서의 '확인하지 못한 것'에 적고,
    /// 그 분류는 '깨끗함(검사 완료)'으로 치지 않아요. 그래서 베이스라인에서 그 분류의 예전 항목을 지우지 않고,
    /// 다음에 제대로 읽혔을 때 같은 항목을 '새 항목'으로 다시 알리지 않아요.
    /// </summary>
    public void Incomplete(string category, string what, string why)
    {
        Skipped(what, why);
        _incomplete.Add(category);
    }

    public void Skipped(string what, string why)
    {
        var note = $"{what}: {why}";
        if (!_notes.Contains(note))
        {
            _notes.Add(note);
        }
    }
}
