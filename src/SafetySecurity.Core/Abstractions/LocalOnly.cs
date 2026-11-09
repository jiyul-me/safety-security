using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Abstractions;

/// <summary>
/// 네트워크 경로(\\server\share, \\?\UNC\, WebDAV, 네트워크 드라이브)는 아예 건드리지 않는 파일 시스템 보기예요.
/// 파일 정보를 읽기만 해도 SMB·WebDAV로 다른 컴퓨터에 접속하고(Windows 로그인 정보까지 보내요),
/// 응답이 없으면 검사가 몇십 초씩 멈춰요. 그래서 이런 경로는 '없음'으로 답하고 안쪽 보기를 부르지 않아요.
/// <see cref="Engine.ScanContext"/>가 모든 스캐너에 이 보기를 씌워요.
/// </summary>
public sealed class LocalOnlyFileSystemView(IFileSystemView inner, PathClassifier classifier, Action<string>? skippedFolder = null) : IFileSystemView
{
    public IFileSystemView Inner => inner;

    public bool FileExists(string path) => !classifier.IsNetworkPath(path) && inner.FileExists(path);

    public bool DirectoryExists(string path) => !SkipFolder(path) && inner.DirectoryExists(path);

    public FileMeta? GetMeta(string path) => classifier.IsNetworkPath(path) ? null : inner.GetMeta(path);

    public IReadOnlyList<string> GetFiles(string directory) => SkipFolder(directory) ? [] : inner.GetFiles(directory);

    public IReadOnlyList<string> GetDirectories(string directory) => SkipFolder(directory) ? [] : inner.GetDirectories(directory);

    public byte[]? ReadPrefix(string path, int maxBytes) => classifier.IsNetworkPath(path) ? null : inner.ReadPrefix(path, maxBytes);

    public byte[]? ReadAll(string path, long maxBytes) => classifier.IsNetworkPath(path) ? null : inner.ReadAll(path, maxBytes);

    public string? Sha256(string path, long maxBytes) => classifier.IsNetworkPath(path) ? null : inner.Sha256(path, maxBytes);

    private bool SkipFolder(string path)
    {
        if (!classifier.IsNetworkPath(path))
        {
            return false;
        }

        skippedFolder?.Invoke(path);
        return true;
    }
}

/// <summary>네트워크 경로의 서명은 확인하지 않아요 (파일을 열면 네트워크에 접속해요).</summary>
public sealed class LocalOnlySignatureVerifier(ISignatureVerifier inner, PathClassifier classifier) : ISignatureVerifier
{
    public const string NetworkDetail = "네트워크 경로라 열지 않았어요";

    public ISignatureVerifier Inner => inner;

    public SignatureInfo Verify(string path) =>
        classifier.IsNetworkPath(path) ? new SignatureInfo(SignatureStatus.Error, Detail: NetworkDetail) : inner.Verify(path);
}
