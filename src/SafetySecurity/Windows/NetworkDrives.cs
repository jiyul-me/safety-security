using SafetySecurity.Core.Rules;

namespace SafetySecurity.Windows;

/// <summary>
/// 네트워크 드라이브(예: Z: → \\nas\share)를 찾아요. 검사기는 이 드라이브의 파일을 열지 않아요.
/// GetLogicalDrives와 QueryDosDevice는 Windows 안의 드라이브 연결 정보만 읽어서 네트워크에 접속하지 않아요.
/// </summary>
internal static class NetworkDrives
{
    private static readonly Lazy<IReadOnlySet<char>> CachedLetters = new(Find);
    private static readonly Lazy<PathClassifier> Guard = new(() =>
        new PathClassifier(new SystemPaths(new Dictionary<string, string>())) { NetworkDrives = CachedLetters.Value });

    /// <summary>네트워크 드라이브 문자 (대문자). 프로세스마다 한 번만 확인해요.</summary>
    public static IReadOnlySet<char> Letters => CachedLetters.Value;

    /// <summary>원격 경로(\\server\share, \\?\UNC\ 등)이거나 네트워크 드라이브의 경로인지.</summary>
    public static bool IsNetworkPath(string? path) => Guard.Value.IsNetworkPath(path);

    private static unsafe IReadOnlySet<char> Find()
    {
        var letters = new HashSet<char>();
        const int Size = 1024;
        var buffer = stackalloc char[Size];
        string[] drives;
        try
        {
            drives = Environment.GetLogicalDrives();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return letters;
        }

        foreach (var drive in drives)
        {
            if (drive.Length < 2 || drive[1] != ':' || !char.IsAsciiLetter(drive[0]))
            {
                continue;
            }

            buffer[0] = '\0';
            var len = Native.NativeMethods.QueryDosDevice(drive[..2], buffer, Size);
            if (len is > 0 and < Size && PathClassifier.IsNetworkDeviceTarget(new string(buffer)))
            {
                letters.Add(char.ToUpperInvariant(drive[0]));
            }
        }

        return letters;
    }
}
