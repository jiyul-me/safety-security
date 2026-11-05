namespace SafetySecurity.Core.Abstractions;

public sealed record FileMeta(long Length, DateTimeOffset CreatedUtc, DateTimeOffset ModifiedUtc, FileAttributes Attributes);

/// <summary>읽기 전용 파일 시스템.</summary>
public interface IFileSystemView
{
    bool FileExists(string path);

    bool DirectoryExists(string path);

    FileMeta? GetMeta(string path);

    /// <summary>폴더 바로 아래 파일들 (하위 폴더 미포함). 권한 없으면 빈 목록.</summary>
    IReadOnlyList<string> GetFiles(string directory);

    /// <summary>폴더 바로 아래 폴더들. 권한 없으면 빈 목록.</summary>
    IReadOnlyList<string> GetDirectories(string directory);

    /// <summary>앞부분 최대 maxBytes만 읽어요. 실패하면 null.</summary>
    byte[]? ReadPrefix(string path, int maxBytes);

    /// <summary>전체를 읽어요. maxBytes보다 크면 null.</summary>
    byte[]? ReadAll(string path, long maxBytes);

    /// <summary>SHA-256 (소문자 hex). maxBytes보다 크면 null.</summary>
    string? Sha256(string path, long maxBytes);
}
