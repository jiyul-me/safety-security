using System.Text.RegularExpressions;

namespace SafetySecurity.Core.Tests;

/// <summary>
/// 뱅가드·안티치트와 충돌하지 않고, 읽기 전용·오프라인이라는 약속을 소스 코드 수준에서 확인해요.
/// BannedApiAnalyzers가 .NET API를 막고, 이 테스트는 직접 선언한 Win32 함수(P/Invoke)를 막아요.
/// </summary>
public class ForbiddenApiTests
{
    private static readonly string[] ForbiddenNativeNames =
    [
        // 다른 프로세스 접근·주입·후킹
        "OpenProcess", "NtOpenProcess", "ZwOpenProcess", "OpenThread", "NtOpenThread", "ReadProcessMemory", "WriteProcessMemory",
        "NtReadVirtualMemory", "NtWriteVirtualMemory", "VirtualAllocEx", "VirtualProtectEx", "CreateRemoteThread", "CreateRemoteThreadEx",
        "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread", "SetWindowsHookEx", "SetWindowsHookExW",
        "SetWinEventHook", "DebugActiveProcess", "SetThreadContext", "MiniDumpWriteDump", "DuplicateHandle", "NtDuplicateObject",
        "SuspendThread", "NtSuspendProcess", "TerminateProcess", "EnumProcessModules", "EnumProcessModulesEx",
        // 드라이버
        "NtLoadDriver", "ZwLoadDriver", "CreateService", "CreateServiceW", "DeviceIoControl",
        // 네트워크
        "WSAStartup", "InternetOpen", "InternetOpenW", "WinHttpOpen", "URLDownloadToFile", "URLDownloadToFileW", "HttpSendRequest",
        // 시스템 수정
        "RegSetValueEx", "RegSetValueExW", "RegCreateKeyEx", "RegCreateKeyExW", "RegDeleteKey", "RegDeleteKeyW", "RegDeleteValue",
        "RegDeleteValueW", "RegDeleteTree", "RegDeleteTreeW", "DeleteFile", "DeleteFileW", "MoveFileEx", "MoveFileExW",
    ];

    private static readonly string[] ForbiddenLibraries = ["ws2_32", "wininet", "winhttp", "urlmon", "ntoskrnl", "fltlib", "dbghelp"];

    private static string SrcDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src", "SafetySecurity")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "src");
    }

    private static IEnumerable<(string File, string Text)> Sources() =>
        Directory.EnumerateFiles(SrcDir(), "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Select(f => (f, File.ReadAllText(f)));

    [Fact]
    public void NoForbiddenNativeImports()
    {
        var importRegex = new Regex(@"\[(LibraryImport|DllImport)\(\s*""(?<lib>[^""]+)""(?<rest>[^\]]*)\]\s*(\[[^\]]*\]\s*)*(public|internal|private)?\s*(static\s+)?(extern\s+)?(partial\s+)?[\w<>\[\]\*,\s]+?\s(?<name>\w+)\s*\(", RegexOptions.Singleline);
        var violations = new List<string>();
        foreach (var (file, text) in Sources())
        {
            foreach (Match m in importRegex.Matches(text))
            {
                var lib = m.Groups["lib"].Value.ToLowerInvariant().Replace(".dll", string.Empty, StringComparison.Ordinal);
                var entry = Regex.Match(m.Groups["rest"].Value, @"EntryPoint\s*=\s*""(?<e>\w+)""").Groups["e"].Value;
                var name = entry.Length > 0 ? entry : m.Groups["name"].Value;
                if (ForbiddenLibraries.Contains(lib))
                {
                    violations.Add($"{Path.GetFileName(file)}: {lib}");
                }

                if (ForbiddenNativeNames.Any(f => name.Equals(f, StringComparison.Ordinal) || name.Equals(f + "W", StringComparison.Ordinal) || name.Equals(f + "A", StringComparison.Ordinal)))
                {
                    violations.Add($"{Path.GetFileName(file)}: {name}");
                }
            }
        }

        Assert.Empty(violations);
    }

    [Fact]
    public void FindsNativeImportsAtAll()
    {
        // 위 정규식이 실제로 선언을 잡는지 확인 (정규식이 망가지면 위 테스트가 거짓으로 통과해요).
        var count = Sources().Sum(s => Regex.Matches(s.Text, @"\[LibraryImport\(").Count);
        Assert.True(count >= 10, $"LibraryImport 선언이 {count}개밖에 안 보여요.");
    }

    [Fact]
    public void WriteExceptionsAreLimitedToKnownFiles()
    {
        // RS0030(금지 API) 경고를 끄는 파일은 이 목록뿐이어야 해요.
        string[] allowed = ["DataStore.cs", "TaskInstaller.cs", "ChildProcess.cs"];
        var files = Sources().Where(s => s.Text.Contains("RS0030", StringComparison.Ordinal)).Select(s => Path.GetFileName(s.File)).ToList();
        Assert.All(files, f => Assert.Contains(f, allowed));
    }
}
