using System.Security.Cryptography;
using SafetySecurity.Core.Abstractions;

namespace SafetySecurity.Windows;

/// <summary>읽기 전용 파일 시스템. 모든 파일을 FileAccess.Read로, 다른 프로그램이 쓰는 중이어도 방해하지 않게 열어요.</summary>
internal sealed class WinFileSystemView : IFileSystemView
{
    private static FileStreamOptions ReadOptions(FileOptions options = FileOptions.None) => new()
    {
        Mode = FileMode.Open,
        Access = FileAccess.Read,
        Share = FileShare.ReadWrite | FileShare.Delete,
        Options = options,
        BufferSize = 0,
    };

    public bool FileExists(string path)
    {
        try
        {
            return File.Exists(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    public bool DirectoryExists(string path)
    {
        try
        {
            return Directory.Exists(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    public FileMeta? GetMeta(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return null;
            }

            return new FileMeta(info.Length, new DateTimeOffset(info.CreationTimeUtc, TimeSpan.Zero), new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero), info.Attributes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    public IReadOnlyList<string> GetFiles(string directory)
    {
        try
        {
            return Directory.Exists(directory)
                ? Directory.EnumerateFiles(directory, "*", new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint, RecurseSubdirectories = false }).ToList()
                : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return [];
        }
    }

    public IReadOnlyList<string> GetDirectories(string directory)
    {
        try
        {
            return Directory.Exists(directory)
                ? Directory.EnumerateDirectories(directory, "*", new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint, RecurseSubdirectories = false }).ToList()
                : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return [];
        }
    }

    public byte[]? ReadPrefix(string path, int maxBytes)
    {
        try
        {
            using var fs = new FileStream(path, ReadOptions());
            var buffer = new byte[(int)Math.Min(maxBytes, fs.Length)];
            fs.ReadExactly(buffer);
            return buffer;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    public byte[]? ReadAll(string path, long maxBytes)
    {
        try
        {
            using var fs = new FileStream(path, ReadOptions());
            if (fs.Length > maxBytes)
            {
                return null;
            }

            var buffer = new byte[fs.Length];
            fs.ReadExactly(buffer);
            return buffer;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    public string? Sha256(string path, long maxBytes)
    {
        try
        {
            using var fs = new FileStream(path, ReadOptions(FileOptions.SequentialScan));
            if (fs.Length > maxBytes)
            {
                return null;
            }

            return Convert.ToHexStringLower(SHA256.HashData(fs));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }
}
