using System.Text;

namespace SafetySecurity.Core.Rules;

/// <summary>경로가 어떤 종류의 위치인지.</summary>
public enum PathKind
{
    /// <summary>C:\Windows (단, 사용자가 쓸 수 있는 하위 폴더는 제외).</summary>
    Windows,

    /// <summary>Program Files, Program Files (x86).</summary>
    ProgramFiles,

    /// <summary>
    /// Windows 앱 패키지 폴더 (Program Files\WindowsApps, Windows\SystemApps).
    /// Microsoft Store·MSIX 앱이 설치되는 곳이에요. 파일마다 서명하지 않고 패키지 전체를 서명하고,
    /// Windows(TrustedInstaller)만 쓸 수 있게 보호돼요.
    /// </summary>
    PackagedApp,

    /// <summary>ProgramData. 일반 사용자도 새 파일·폴더를 만들 수 있어요.</summary>
    ProgramData,

    /// <summary>사용자 프로필 (AppData, 바탕화면, 다운로드 등).</summary>
    UserProfile,

    /// <summary>임시 폴더 (%TEMP%, C:\Windows\Temp 등 누구나 쓸 수 있는 곳).</summary>
    Temp,

    /// <summary>C:\Users\Public.</summary>
    Public,

    /// <summary>네트워크 경로 (\\server\share).</summary>
    Network,

    /// <summary>그 밖의 위치 (다른 드라이브 등).</summary>
    Other,
}

public sealed class PathClassifier(SystemPaths paths)
{
    public SystemPaths Paths { get; } = paths;

    /// <summary>
    /// 네트워크 드라이브로 연결된 드라이브 문자 (대문자, 예: 'Z'). Windows 쪽에서 QueryDosDevice로 채워요.
    /// 이 드라이브의 파일도 네트워크 경로로 보고 열지 않아요.
    /// </summary>
    public IReadOnlySet<char> NetworkDrives { get; init; } = new HashSet<char>();

    // 네트워크 리디렉터 장치 (드라이브 문자가 이쪽으로 연결돼 있으면 네트워크 드라이브예요).
    private static readonly string[] NetworkRedirectors =
        [@"\Device\LanmanRedirector", @"\Device\Mup", @"\Device\WebDavRedirector", @"\Device\WinDfs", @"\Device\RdpDr", @"\??\UNC\"];

    // C:\Windows 안이지만 일반 사용자가 쓸 수 있는 폴더 (LOLBAS에서 자주 쓰여요).
    private static readonly string[] WritableWindowsSubdirs =
    [
        @"temp",
        @"tasks",
        @"tracing",
        @"system32\spool\drivers\color",
        @"system32\tasks",
        @"system32\microsoft\crypto\rsa\machinekeys",
        @"syswow64\tasks",
        @"registration\crmlog",
    ];

    /// <summary>
    /// 경로를 비교하기 좋게 정리해요: 따옴표 제거, 환경 변수 펼치기, \\?\ 제거,
    /// / → \, 중복 \ 정리, . 과 .. 처리, 소문자, 끝의 \ 제거.
    /// </summary>
    public string Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var p = Paths.Expand(path.Trim().Trim('"').Trim());
        p = p.Replace('/', '\\');
        if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            p = @"\\" + p[8..];
        }
        else if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            p = p[4..];
        }

        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            p = Paths.SystemRoot + p[11..];
        }

        var isUnc = p.StartsWith(@"\\", StringComparison.Ordinal);
        var parts = p.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        var stack = new List<string>(parts.Length);
        foreach (var part in parts)
        {
            if (part == ".")
            {
                continue;
            }

            if (part == "..")
            {
                if (stack.Count > 1)
                {
                    stack.RemoveAt(stack.Count - 1);
                }

                continue;
            }

            stack.Add(part);
        }

        var sb = new StringBuilder(p.Length);
        if (isUnc)
        {
            sb.Append(@"\\");
        }

        sb.AppendJoin('\\', stack);
        return sb.ToString().ToLowerInvariant();
    }

    /// <summary>child가 parent 폴더 안에 있거나 같은지.</summary>
    public bool IsUnder(string normalizedChild, string parent)
    {
        var np = Normalize(parent);
        if (np.Length == 0)
        {
            return false;
        }

        return normalizedChild.Equals(np, StringComparison.Ordinal)
            || normalizedChild.StartsWith(np + "\\", StringComparison.Ordinal);
    }

    public PathKind Classify(string? path)
    {
        if (IsNetworkPath(path))
        {
            return PathKind.Network;
        }

        var n = Normalize(path);
        if (n.Length == 0)
        {
            return PathKind.Other;
        }

        if (n.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return PathKind.Network;
        }

        // 순서가 중요해요: Temp는 보통 사용자 프로필 안에 있으니 먼저 확인해요.
        if (IsUnder(n, Paths.Temp))
        {
            return PathKind.Temp;
        }

        if (IsUnder(n, Paths.Public))
        {
            return PathKind.Public;
        }

        if (IsUnder(n, Paths.ProgramFiles + @"\WindowsApps") || IsUnder(n, Paths.SystemRoot + @"\SystemApps"))
        {
            return PathKind.PackagedApp;
        }

        if (IsUnder(n, Paths.SystemRoot))
        {
            var root = Normalize(Paths.SystemRoot);
            var rel = n.Length > root.Length ? n[(root.Length + 1)..] : string.Empty;
            foreach (var sub in WritableWindowsSubdirs)
            {
                if (rel.Equals(sub, StringComparison.Ordinal) || rel.StartsWith(sub + "\\", StringComparison.Ordinal))
                {
                    return PathKind.Temp;
                }
            }

            return PathKind.Windows;
        }

        if (IsUnder(n, Paths.ProgramFiles) || IsUnder(n, Paths.ProgramFilesX86))
        {
            return PathKind.ProgramFiles;
        }

        if (IsUnder(n, Paths.ProgramData))
        {
            return PathKind.ProgramData;
        }

        if (IsUnder(n, Paths.UserProfile) || IsUnder(n, Paths.AppData) || IsUnder(n, Paths.LocalAppData))
        {
            return PathKind.UserProfile;
        }

        // 다른 사용자의 프로필 (C:\Users\누군가\...)
        if (IsUnder(n, Paths.SystemDrive + @"\Users"))
        {
            return PathKind.UserProfile;
        }

        return PathKind.Other;
    }

    /// <summary>
    /// 네트워크(다른 컴퓨터)를 거치는 경로인지: \\server\share, \\?\UNC\, \\?\GLOBALROOT\, WebDAV(\\host@SSL\...),
    /// 그리고 네트워크 드라이브(<see cref="NetworkDrives"/>). 이런 경로는 열거나 정보를 읽기만 해도 네트워크에 접속해서,
    /// 검사기는 파일을 전혀 건드리지 않고 경로만 보고 판단해요.
    /// </summary>
    public bool IsNetworkPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var p = Paths.Expand(path.Trim().Trim('"').Trim());
        if (IsRemotePath(p))
        {
            return true;
        }

        return NetworkDrives.Count > 0 && DriveLetter(p) is { } d && NetworkDrives.Contains(d);
    }

    /// <summary>
    /// 문자열만 보고 원격 경로인지 판단해요 (환경 변수는 펼치지 않아요).
    /// \\?\ · \\.\ · \??\ 뒤에는 로컬 드라이브(C:\)나 볼륨(Volume{...})만 허용하고, 나머지(UNC, GLOBALROOT, 파이프·장치)는 모두 원격으로 봐요.
    /// </summary>
    public static bool IsRemotePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var p = path.Trim().Trim('"').Trim().Replace('/', '\\');
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\\.\", StringComparison.Ordinal) || p.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            var rest = p[4..];
            return !(IsDriveRooted(rest) || rest.StartsWith("Volume{", StringComparison.OrdinalIgnoreCase));
        }

        return p.StartsWith(@"\\", StringComparison.Ordinal);
    }

    /// <summary>
    /// 드라이브 문자의 연결 대상(QueryDosDevice 결과)이 네트워크인지.
    /// 예: \Device\LanmanRedirector\;Z:000...\server\share, \Device\Mup\..., \??\UNC\server\share (subst).
    /// 로컬 디스크(\Device\HarddiskVolume3)나 로컬 폴더 subst(\??\C:\foo)는 네트워크가 아니에요.
    /// </summary>
    public static bool IsNetworkDeviceTarget(string? target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return false;
        }

        return NetworkRedirectors.Any(r => target.StartsWith(r, StringComparison.OrdinalIgnoreCase))
            || target.Contains(@"\;", StringComparison.Ordinal); // 네트워크 리디렉터의 드라이브 연결 표시 (\;Z:)
    }

    /// <summary>네트워크 경로의 컴퓨터 이름 (\\server\share → server, Z:\ → Z:). 모르면 null.</summary>
    public string? NetworkLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var p = Paths.Expand(path.Trim().Trim('"').Trim()).Replace('/', '\\');
        foreach (var prefix in new[] { @"\\?\UNC\", @"\\.\UNC\", @"\??\UNC\" })
        {
            if (p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                p = @"\\" + p[prefix.Length..];
                break;
            }
        }

        if (p.StartsWith(@"\\", StringComparison.Ordinal) && !p.StartsWith(@"\\?\", StringComparison.Ordinal) && !p.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            var host = p[2..].Split('\\', 2)[0];
            return host.Length > 0 ? host : null;
        }

        return DriveLetter(p) is { } d && NetworkDrives.Contains(d) ? d + ":" : null;
    }

    private static bool IsDriveRooted(string p) => p.Length >= 2 && p[1] == ':' && char.IsAsciiLetter(p[0]);

    /// <summary>C:\x, \\?\C:\x, \??\C:\x의 드라이브 문자 (대문자). 없으면 null.</summary>
    private static char? DriveLetter(string p)
    {
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\\.\", StringComparison.Ordinal) || p.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            p = p[4..];
        }

        return IsDriveRooted(p) ? char.ToUpperInvariant(p[0]) : null;
    }

    /// <summary>일반 사용자 권한의 악성코드가 파일을 놓을 수 있는 위치인지.</summary>
    public static bool IsUserWritable(PathKind kind) =>
        kind is PathKind.UserProfile or PathKind.Temp or PathKind.Public or PathKind.ProgramData;

    /// <summary>
    /// 패키지 폴더 이름 (예: Microsoft.Paint_11.2609.401.0_x64__8wekyb3d8bbwe).
    /// 끝의 '__' 뒤가 게시자 ID예요 (8wekyb3d8bbwe = Microsoft). 패키지 폴더가 아니면 null.
    /// </summary>
    public string? PackageFolderName(string? path)
    {
        var n = Normalize(path);
        foreach (var root in new[] { Normalize(Paths.ProgramFiles + @"\WindowsApps"), Normalize(Paths.SystemRoot + @"\SystemApps") })
        {
            if (n.StartsWith(root + "\\", StringComparison.Ordinal))
            {
                var rest = n[(root.Length + 1)..];
                var slash = rest.IndexOf('\\');
                return slash > 0 ? rest[..slash] : rest;
            }
        }

        return null;
    }

    public static string ToKorean(PathKind kind) => kind switch
    {
        PathKind.Windows => "Windows 시스템 폴더",
        PathKind.ProgramFiles => "Program Files",
        PathKind.PackagedApp => "Windows 앱 패키지 (시스템이 보호하는 Store 앱 설치 폴더)",
        PathKind.ProgramData => "ProgramData (사용자도 쓸 수 있음)",
        PathKind.UserProfile => "사용자 폴더 (사용자 쓰기 가능)",
        PathKind.Temp => "임시 폴더 (누구나 쓰기 가능)",
        PathKind.Public => "공용 폴더 (누구나 쓰기 가능)",
        PathKind.Network => "네트워크 경로",
        _ => "기타 위치",
    };
}
