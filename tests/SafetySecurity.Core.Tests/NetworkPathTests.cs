using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;
using SafetySecurity.Core.Scanners;

namespace SafetySecurity.Core.Tests;

/// <summary>
/// 네트워크 경로(\\server\share, WebDAV, 네트워크 드라이브)는 열지도, 정보를 읽지도, 서명을 확인하지도 않아요.
/// 열기만 해도 SMB·WebDAV로 다른 컴퓨터에 접속해서 "인터넷·네트워크를 쓰지 않는다"는 약속을 깨요.
/// </summary>
public class NetworkPathTests
{
    private const string Run = @"Software\Microsoft\Windows\CurrentVersion\Run";

    [Theory]
    [InlineData(@"\\203.0.113.5\s\a.exe")]
    [InlineData(@"""\\203.0.113.5\s\a.exe""")]
    [InlineData(@"\\?\UNC\host\share\a.exe")]
    [InlineData(@"\\.\UNC\host\share\a.dll")]
    [InlineData(@"\??\UNC\host\share\a.exe")]
    [InlineData(@"\\?\GLOBALROOT\Device\Mup\host\share\a.exe")]
    [InlineData(@"\\host@SSL\DavWWWRoot\a.exe")]
    [InlineData(@"\\host@SSL@443\DavWWWRoot\a.ps1")]
    [InlineData(@"//host/share/a.exe")]
    [InlineData(@"\\.\pipe\something")]
    public void RemotePathsAreRecognized(string path) => Assert.True(PathClassifier.IsRemotePath(path));

    [Theory]
    [InlineData(@"C:\Windows\System32\a.dll")]
    [InlineData(@"\\?\C:\Windows\System32\a.dll")]
    [InlineData(@"\??\C:\Windows\System32\a.dll")]
    [InlineData(@"\\.\C:\a.exe")]
    [InlineData(@"\\?\Volume{12345678-1234-1234-1234-123456789abc}\a.exe")]
    [InlineData(@"rundll32.exe")]
    [InlineData(@"D:\share\a.exe")]
    [InlineData(@"C:\Users\jiyul\a\\b.exe")]
    [InlineData("")]
    [InlineData(null)]
    public void LocalPathsAreNotRemote(string? path) => Assert.False(PathClassifier.IsRemotePath(path));

    [Theory]
    [InlineData(@"\\?\UNC\host\share\a.exe")]
    [InlineData(@"\\?\GLOBALROOT\Device\Mup\host\share\a.exe")]
    [InlineData(@"\\host@SSL\DavWWWRoot\a.exe")]
    [InlineData(@"\??\UNC\host\share\a.exe")]
    public void ClassifiesDevicePrefixedRemotePathsAsNetwork(string path) =>
        Assert.Equal(PathKind.Network, new PathClassifier(TestEnv.Paths).Classify(path));

    [Fact]
    public void MappedNetworkDriveIsNetworkOnlyWhenKnown()
    {
        var plain = new PathClassifier(TestEnv.Paths);
        var mapped = new PathClassifier(TestEnv.Paths) { NetworkDrives = new HashSet<char> { 'Z' } };
        Assert.Equal(PathKind.Other, plain.Classify(@"Z:\tools\app.exe"));
        Assert.Equal(PathKind.Network, mapped.Classify(@"Z:\tools\app.exe"));
        Assert.Equal(PathKind.Network, mapped.Classify(@"z:\tools\app.exe"));
        Assert.Equal(PathKind.Network, mapped.Classify(@"\\?\Z:\tools\app.exe"));
        Assert.Equal(PathKind.Other, mapped.Classify(@"D:\Games\game.exe"));
        Assert.Equal(PathKind.Windows, mapped.Classify(@"C:\Windows\System32\a.dll"));
        Assert.Equal("Z:", mapped.NetworkLocation(@"Z:\tools\app.exe"));
    }

    [Theory]
    [InlineData(@"\Device\LanmanRedirector\;Z:00000000000a1b2c\nas\share", true)]
    [InlineData(@"\Device\Mup\nas\share", true)]
    [InlineData(@"\Device\WebDavRedirector\;Y:000\host@SSL\DavWWWRoot", true)]
    [InlineData(@"\??\UNC\nas\share", true)]
    [InlineData(@"\Device\VBoxMiniRdr\;E:\vboxsvr\shared", true)]
    [InlineData(@"\Device\HarddiskVolume3", false)]
    [InlineData(@"\Device\CdRom0", false)]
    [InlineData(@"\??\C:\work", false)]
    [InlineData("", false)]
    public void RecognizesNetworkDriveTargets(string target, bool expected) =>
        Assert.Equal(expected, PathClassifier.IsNetworkDeviceTarget(target));

    [Theory]
    [InlineData(@"\\203.0.113.5\s\a.exe", "203.0.113.5")]
    [InlineData(@"\\?\UNC\host\share\a.exe", "host")]
    [InlineData(@"\\host@SSL\DavWWWRoot\a.exe", "host@SSL")]
    [InlineData(@"C:\Windows\a.exe", null)]
    public void NamesTheNetworkLocation(string path, string? expected) =>
        Assert.Equal(expected, new PathClassifier(TestEnv.Paths).NetworkLocation(path));

    [Fact]
    public void LocalOnlyViewNeverCallsInnerForRemotePaths()
    {
        var inner = new RemoteTrapFiles(new FakeFileSystem().Add(@"C:\a\b.exe"));
        var skipped = new List<string>();
        var view = new LocalOnlyFileSystemView(inner, new PathClassifier(TestEnv.Paths), skipped.Add);
        const string unc = @"\\203.0.113.5\s\a.exe";
        Assert.False(view.FileExists(unc));
        Assert.False(view.DirectoryExists(@"\\203.0.113.5\s"));
        Assert.Null(view.GetMeta(unc));
        Assert.Empty(view.GetFiles(@"\\203.0.113.5\s"));
        Assert.Empty(view.GetDirectories(@"\\?\UNC\h\s"));
        Assert.Null(view.ReadPrefix(unc, 10));
        Assert.Null(view.ReadAll(unc, 10));
        Assert.Null(view.Sha256(unc, 10));
        Assert.Equal(3, skipped.Count);

        // 로컬 경로는 그대로 안쪽 보기에 물어봐요.
        Assert.True(view.FileExists(@"C:\a\b.exe"));
        Assert.NotNull(view.GetMeta(@"\\?\C:\a\b.exe") ?? view.GetMeta(@"C:\a\b.exe"));
        Assert.True(inner.LocalCalls > 0);
    }

    [Fact]
    public void ScanContextAlwaysGuardsFilesAndSignatures()
    {
        var ctx = new TestEnv().Context();
        Assert.IsType<LocalOnlyFileSystemView>(ctx.Files);
        Assert.IsType<LocalOnlySignatureVerifier>(ctx.Signatures);
        Assert.Same(ctx.Files, ctx.Files);
        var sig = ctx.Signatures.Verify(@"\\host\share\a.exe");
        Assert.Equal(SignatureStatus.Error, sig.Status);
        Assert.Equal(LocalOnlySignatureVerifier.NetworkDetail, sig.Detail);
    }

    [Theory]
    [InlineData(@"""\\203.0.113.5\s\a.exe"" /silent", "203.0.113.5")]
    [InlineData(@"\\203.0.113.5\s\my app\a.exe -x", "203.0.113.5")]
    [InlineData(@"\\?\UNC\host\share\a.exe", "host")]
    [InlineData(@"\\?\GLOBALROOT\Device\Mup\host\share\a.exe", null)]
    [InlineData(@"\\host@SSL\DavWWWRoot\a.exe", "host@SSL")]
    [InlineData(@"powershell.exe -NoProfile -File \\host\share\a.ps1", "host")]
    [InlineData(@"rundll32.exe \\host\share\a.dll,Start", "host")]
    public void RunKeyToNetworkPathIsHighWithoutTouchingIt(string command, string? host)
    {
        var env = new TestEnv();
        env.Files.Add(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        env.Signatures.Signed(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        env.Files.Add(@"C:\Windows\System32\rundll32.exe");
        env.Signatures.Signed(@"C:\Windows\System32\rundll32.exe");
        env.Registry.Set(RegHive.CurrentUser, Run, "Net", command);
        var files = new RemoteTrapFiles(env.Files);
        var signatures = new RemoteTrapSignatures(env.Signatures);

        var f = Assert.Single(new AutorunScanner().Scan(env.Context(files: files, signatures: signatures)));

        Assert.Equal(Severity.High, f.Severity);
        Assert.Contains(f.Reasons, r => r.Contains("네트워크", StringComparison.Ordinal));
        Assert.Contains(f.Reasons, r => r.EndsWith(ExecutableAssessor.NotCheckedReason, StringComparison.Ordinal));
        if (host is not null)
        {
            Assert.Contains(f.Evidence, e => e.Key.EndsWith("네트워크 위치", StringComparison.Ordinal) && e.Value == host);
        }

        Assert.DoesNotContain(f.Evidence, e => e.Key.EndsWith("SHA-256", StringComparison.Ordinal));
        Assert.Equal(0, files.RemoteCalls);
        Assert.Equal(0, signatures.RemoteCalls);
    }

    [Fact]
    public void MappedNetworkDriveRunEntryIsMediumWithoutTouchingIt()
    {
        var env = new TestEnv();
        env.Files.Add(@"Z:\tools\app.exe");
        env.Registry.Set(RegHive.CurrentUser, Run, "Nas", @"Z:\tools\app.exe");
        var files = new RemoteTrapFiles(env.Files, trapDrive: 'Z');
        var signatures = new RemoteTrapSignatures(env.Signatures, trapDrive: 'Z');

        var f = Assert.Single(new AutorunScanner().Scan(env.Context(files: files, signatures: signatures, networkDrives: new HashSet<char> { 'Z' })));

        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Contains(f.Evidence, e => e.Key == "네트워크 위치" && e.Value == "Z:");
        Assert.Equal(0, files.RemoteCalls);
        Assert.Equal(0, signatures.RemoteCalls);
    }

    [Fact]
    public void LocalDriveWithSameLetterIsStillCheckedWhenNotMapped()
    {
        // 네트워크 드라이브가 아니면 평소처럼 파일과 서명을 확인해요 (오탐 방지).
        var env = new TestEnv();
        env.Files.Add(@"Z:\tools\app.exe");
        env.Signatures.Signed(@"Z:\tools\app.exe", "Some Vendor");
        env.Registry.Set(RegHive.CurrentUser, Run, "Tool", @"Z:\tools\app.exe");
        Assert.Empty(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(1, env.Signatures.Calls);
    }

    [Fact]
    public void LongLocalPathPrefixIsStillChecked()
    {
        var env = new TestEnv();
        // \\?\C:\ 형식은 로컬 경로라 평소처럼 파일을 확인해요 (가짜 파일 시스템에는 그 이름 그대로 넣어요).
        const string exe = @"\\?\C:\Users\jiyul\AppData\Roaming\x\evil.exe";
        env.Files.Add(exe);
        env.Registry.Set(RegHive.CurrentUser, Run, "Long", exe);
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Contains(f.Evidence, e => e.Key == "서명");
    }

    [Fact]
    public void ComServerOnNetworkShareIsHighWithoutTouchingIt()
    {
        const string clsid = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}";
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, $@"Software\Classes\CLSID\{clsid}", null, "ShellWindows");
        env.Registry.Set(RegHive.LocalMachine, $@"Software\Classes\CLSID\{clsid}\InprocServer32", null, @"%SystemRoot%\System32\shdocvw.dll");
        env.Files.Add(@"C:\Windows\System32\shdocvw.dll");
        env.Signatures.Signed(@"C:\Windows\System32\shdocvw.dll");
        env.Registry.Set(RegHive.CurrentUser, $@"Software\Classes\CLSID\{clsid}\InprocServer32", null, @"\\203.0.113.5\s\a.dll");
        var files = new RemoteTrapFiles(env.Files);
        var signatures = new RemoteTrapSignatures(env.Signatures);

        var f = Assert.Single(new ComHijackScanner().Scan(env.Context(files: files, signatures: signatures)));

        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(0, files.RemoteCalls);
        Assert.Equal(0, signatures.RemoteCalls);
    }

    [Fact]
    public void ScheduledTaskOnNetworkShareIsHighWithoutTouchingIt()
    {
        var env = new TestEnv
        {
            TasksXml = """
<?xml version="1.0" encoding="UTF-16"?>
<Tasks>
<!-- \Updater -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions Context="Author"><Exec><Command>\\203.0.113.5\s\upd.exe</Command><Arguments>/q</Arguments></Exec></Actions>
</Task>
</Tasks>
""",
        };
        var files = new RemoteTrapFiles(env.Files);
        var signatures = new RemoteTrapSignatures(env.Signatures);

        var f = Assert.Single(new ScheduledTaskScanner().Scan(env.Context(files: files, signatures: signatures)));

        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(0, files.RemoteCalls);
    }

    [Fact]
    public void RedirectedStartupFolderOnNetworkIsSkippedAndNoted()
    {
        var env = new Dictionary<string, string>
        {
            ["SystemRoot"] = @"C:\Windows",
            ["ProgramData"] = @"C:\ProgramData",
            ["USERPROFILE"] = @"C:\Users\jiyul",
            ["APPDATA"] = @"\\fileserver\profiles\jiyul\AppData\Roaming",
        };
        var classifier = new PathClassifier(new SystemPaths(env));
        var files = new RemoteTrapFiles(new FakeFileSystem());
        var ctx = new ScanContext
        {
            Registry = new FakeRegistry(),
            Files = files,
            Signatures = new FakeSignatures(),
            Classifier = classifier,
            Now = TestEnv.Now,
        };

        Assert.Empty(new AutorunScanner().Scan(ctx));
        Assert.Equal(0, files.RemoteCalls);
        Assert.Contains(ctx.Coverage.Notes, n => n.Contains(@"\\fileserver\profiles", StringComparison.Ordinal));
    }

    /// <summary>원격 경로로 불리면 기록하고 예외를 던지는 가짜 파일 시스템.</summary>
    private sealed class RemoteTrapFiles(IFileSystemView inner, char? trapDrive = null) : IFileSystemView
    {
        public int RemoteCalls { get; private set; }

        public int LocalCalls { get; private set; }

        public bool FileExists(string path) => Guard(path) && inner.FileExists(path);

        public bool DirectoryExists(string path) => Guard(path) && inner.DirectoryExists(path);

        public FileMeta? GetMeta(string path) => Guard(path) ? inner.GetMeta(path) : null;

        public IReadOnlyList<string> GetFiles(string directory) => Guard(directory) ? inner.GetFiles(directory) : [];

        public IReadOnlyList<string> GetDirectories(string directory) => Guard(directory) ? inner.GetDirectories(directory) : [];

        public byte[]? ReadPrefix(string path, int maxBytes) => Guard(path) ? inner.ReadPrefix(path, maxBytes) : null;

        public byte[]? ReadAll(string path, long maxBytes) => Guard(path) ? inner.ReadAll(path, maxBytes) : null;

        public string? Sha256(string path, long maxBytes) => Guard(path) ? inner.Sha256(path, maxBytes) : null;

        private bool Guard(string path)
        {
            if (PathClassifier.IsRemotePath(path) || (trapDrive is { } d && path.Length >= 2 && char.ToUpperInvariant(path[0]) == d && path[1] == ':'))
            {
                RemoteCalls++;
                throw new InvalidOperationException("네트워크 경로를 열면 안 돼요: " + path);
            }

            LocalCalls++;
            return true;
        }
    }

    private sealed class RemoteTrapSignatures(ISignatureVerifier inner, char? trapDrive = null) : ISignatureVerifier
    {
        public int RemoteCalls { get; private set; }

        public SignatureInfo Verify(string path)
        {
            if (PathClassifier.IsRemotePath(path) || (trapDrive is { } d && path.Length >= 2 && char.ToUpperInvariant(path[0]) == d && path[1] == ':'))
            {
                RemoteCalls++;
                throw new InvalidOperationException("네트워크 경로의 서명을 확인하면 안 돼요: " + path);
            }

            return inner.Verify(path);
        }
    }
}
