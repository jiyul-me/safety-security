using System.Text;

namespace SafetySecurity.Core.Rules;

/// <summary>경로가 어떤 종류의 위치인지.</summary>
public enum PathKind
{
    /// <summary>C:\Windows (단, 사용자가 쓸 수 있는 하위 폴더는 제외).</summary>
    Windows,

    /// <summary>Program Files, Program Files (x86).</summary>
    ProgramFiles,

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

    /// <summary>일반 사용자 권한의 악성코드가 파일을 놓을 수 있는 위치인지.</summary>
    public static bool IsUserWritable(PathKind kind) =>
        kind is PathKind.UserProfile or PathKind.Temp or PathKind.Public or PathKind.ProgramData;

    public static string ToKorean(PathKind kind) => kind switch
    {
        PathKind.Windows => "Windows 시스템 폴더",
        PathKind.ProgramFiles => "Program Files",
        PathKind.ProgramData => "ProgramData (사용자도 쓸 수 있음)",
        PathKind.UserProfile => "사용자 폴더 (사용자 쓰기 가능)",
        PathKind.Temp => "임시 폴더 (누구나 쓰기 가능)",
        PathKind.Public => "공용 폴더 (누구나 쓰기 가능)",
        PathKind.Network => "네트워크 경로",
        _ => "기타 위치",
    };
}
