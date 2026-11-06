using System.Text;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Scanners;

namespace SafetySecurity.Core.Tests;

public class AutorunTests
{
    private const string Run = @"Software\Microsoft\Windows\CurrentVersion\Run";

    [Fact]
    public void EncodedPowerShellInRunKeyIsHigh()
    {
        var env = new TestEnv();
        env.Files.Add(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        env.Signatures.Signed(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        env.Registry.Set(RegHive.CurrentUser, Run, "Updater", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AA==");
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater", f.Location);
    }

    [Fact]
    public void SignedProgramIsIgnored()
    {
        var env = new TestEnv();
        const string steam = @"C:\Program Files (x86)\Steam\steam.exe";
        env.Files.Add(steam);
        env.Signatures.Signed(steam, "Valve Corp.");
        env.Registry.Set(RegHive.CurrentUser, Run, "Steam", $"\"{steam}\" -silent");
        Assert.Empty(new AutorunScanner().Scan(env.Context()));
    }

    [Fact]
    public void UnsignedInAppDataIsMedium_AndRecentIsHigh()
    {
        var env = new TestEnv();
        const string old = @"C:\Users\jiyul\AppData\Roaming\Tool\tool.exe";
        const string fresh = @"C:\Users\jiyul\AppData\Roaming\svc\svchost.exe";
        env.Files.Add(old);
        env.Files.Add(fresh, created: TestEnv.Now.AddDays(-2));
        env.Registry.Set(RegHive.CurrentUser, Run, "Tool", old);
        env.Registry.Set(RegHive.CurrentUser, Run, "WindowsHost", fresh);
        var findings = new AutorunScanner().Scan(env.Context()).ToDictionary(f => f.Target!);
        Assert.Equal(Severity.Medium, findings[old].Severity);
        Assert.Equal(Severity.High, findings[fresh].Severity);
    }

    [Fact]
    public void RundllPayloadIsAssessed()
    {
        var env = new TestEnv();
        env.Files.Add(@"C:\Windows\System32\rundll32.exe");
        env.Signatures.Signed(@"C:\Windows\System32\rundll32.exe");
        const string dll = @"C:\Users\Public\lib.dll";
        env.Files.Add(dll);
        env.Registry.Set(RegHive.CurrentUser, Run, "x", $"rundll32.exe {dll},DllMain");
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal(dll, f.Target);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void WinlogonTampering()
    {
        var env = new TestEnv();
        const string path = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
        env.Registry.Set(RegHive.LocalMachine, path, "Shell", "explorer.exe");
        env.Registry.Set(RegHive.LocalMachine, path, "Userinit", @"C:\Windows\system32\userinit.exe,");
        Assert.Empty(new AutorunScanner().Scan(env.Context()));

        env.Registry.Set(RegHive.LocalMachine, path, "Userinit", @"C:\Windows\system32\userinit.exe, C:\Users\Public\x.exe");
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal("RUN-003", f.RuleId);
    }

    [Fact]
    public void IfeoDebuggerAndLogonScript()
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger", @"C:\Windows\System32\cmd.exe");
        env.Registry.Set(RegHive.CurrentUser, "Environment", "UserInitMprLogonScript", @"C:\Users\jiyul\a.bat");
        var findings = new AutorunScanner().Scan(env.Context()).ToList();
        Assert.Contains(findings, f => f.RuleId == "RUN-006" && f.Severity == Severity.High);
        Assert.Contains(findings, f => f.RuleId == "RUN-008");
    }

    [Fact]
    public void StartupFolderShortcutIsResolved()
    {
        var env = new TestEnv();
        const string target = @"C:\Users\jiyul\AppData\Local\Temp\run.exe";
        env.Files.Add(target);
        env.Files.Add(@"C:\Users\jiyul\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Update.lnk", LnkBuilder.Build(target, "-q"));
        var f = Assert.Single(new AutorunScanner().Scan(env.Context()));
        Assert.Equal("RUN-002", f.RuleId);
        Assert.Equal(target, f.Target);
        Assert.Equal(Severity.High, f.Severity);
    }
}

public class ServiceTests
{
    private const string Services = @"SYSTEM\CurrentControlSet\Services";

    [Fact]
    public void SvchostServiceDllInUserFolderIsHigh()
    {
        var env = new TestEnv();
        env.Files.Add(@"C:\Windows\system32\svchost.exe");
        env.Signatures.Signed(@"C:\Windows\system32\svchost.exe");
        const string dll = @"C:\ProgramData\Cache\svc.dll";
        env.Files.Add(dll);
        env.Registry.Set(RegHive.LocalMachine, Services + @"\EvilSvc", "Type", 0x20);
        env.Registry.Set(RegHive.LocalMachine, Services + @"\EvilSvc", "Start", 2);
        env.Registry.Set(RegHive.LocalMachine, Services + @"\EvilSvc", "ImagePath", @"%SystemRoot%\system32\svchost.exe -k netsvcs");
        env.Registry.Set(RegHive.LocalMachine, Services + @"\EvilSvc\Parameters", "ServiceDll", dll);
        var f = Assert.Single(new ServiceScanner().Scan(env.Context()));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(dll, f.Target);
    }

    [Fact]
    public void DriverInUserFolderIsHigh_SystemDriverIgnored()
    {
        var env = new TestEnv();
        env.Files.Add(@"C:\Windows\System32\drivers\good.sys");
        env.Signatures.Signed(@"C:\Windows\System32\drivers\good.sys");
        env.Registry.Set(RegHive.LocalMachine, Services + @"\good", "Type", 1);
        env.Registry.Set(RegHive.LocalMachine, Services + @"\good", "ImagePath", @"\SystemRoot\System32\drivers\good.sys");
        const string bad = @"C:\Users\jiyul\AppData\Local\Temp\kd.sys";
        env.Files.Add(bad);
        env.Signatures.Signed(bad, "Leaked Cert Ltd");
        env.Registry.Set(RegHive.LocalMachine, Services + @"\kd", "Type", 1);
        env.Registry.Set(RegHive.LocalMachine, Services + @"\kd", "Start", 3);
        env.Registry.Set(RegHive.LocalMachine, Services + @"\kd", "ImagePath", @"\??\" + bad);
        var f = Assert.Single(new ServiceScanner().Scan(env.Context()));
        Assert.Equal("SVC-002", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void UnquotedServicePathIsLow()
    {
        var env = new TestEnv();
        const string exe = @"C:\Program Files\Some Vendor\agent.exe";
        env.Files.Add(exe);
        env.Signatures.Signed(exe, "Vendor");
        env.Registry.Set(RegHive.LocalMachine, Services + @"\Agent", "Type", 0x10);
        env.Registry.Set(RegHive.LocalMachine, Services + @"\Agent", "Start", 2);
        env.Registry.Set(RegHive.LocalMachine, Services + @"\Agent", "ImagePath", exe);
        var f = Assert.Single(new ServiceScanner().Scan(env.Context()));
        Assert.Equal(Severity.Low, f.Severity);
    }
}

public class TaskTests
{
    private const string Xml = """
<?xml version="1.0" encoding="UTF-16"?>
<Tasks>
<!-- \Microsoft\Windows\Defrag\ScheduledDefrag -->
<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Microsoft</Author></RegistrationInfo>
  <Settings><Hidden>false</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>%windir%\system32\defrag.exe</Command><Arguments>-c -h -o</Arguments></Exec></Actions>
</Task>
<!-- \OneDriveUpdater -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Hidden>true</Hidden></Settings>
  <Triggers><LogonTrigger /></Triggers>
  <Actions Context="Author"><Exec><Command>C:\Users\jiyul\AppData\Roaming\odu\odu.exe</Command></Exec></Actions>
</Task>
<!-- \SafetySecurity\Daily -->
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions Context="Author"><Exec><Command>C:\Users\Public\x.exe</Command></Exec></Actions>
</Task>
<!-- \Microsoft\Windows\Shell\Thing -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions Context="Author"><ComHandler><ClassId>{AAAA}</ClassId></ComHandler></Actions>
</Task>
</Tasks>
""";

    [Fact]
    public void ParsesTaskNamesAndActions()
    {
        var tasks = TaskXmlParser.Parse(Xml);
        Assert.Equal(4, tasks.Count);
        Assert.Equal(@"\Microsoft\Windows\Defrag\ScheduledDefrag", tasks[0].Name);
        Assert.True(tasks[1].Hidden);
        Assert.Equal("ComHandler", tasks[3].Actions[0].Kind);
        Assert.Equal("{AAAA}", tasks[3].Actions[0].ClassId);
    }

    [Fact]
    public void FlagsHiddenTaskInUserFolder_SkipsSelf()
    {
        var env = new TestEnv { TasksXml = Xml };
        env.Files.Add(@"C:\Windows\system32\defrag.exe");
        env.Signatures.Signed(@"C:\Windows\system32\defrag.exe");
        env.Files.Add(@"C:\Users\jiyul\AppData\Roaming\odu\odu.exe");
        var f = Assert.Single(new ScheduledTaskScanner().Scan(env.Context()));
        Assert.Equal(@"작업 스케줄러\OneDriveUpdater", f.Location);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void HiddenTaskCacheEntryWithoutSd()
    {
        var env = new TestEnv();
        const string tree = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
        env.Registry.Set(RegHive.LocalMachine, tree + @"\Microsoft\Windows\Good", "Id", "{1}");
        env.Registry.Set(RegHive.LocalMachine, tree + @"\Microsoft\Windows\Good", "SD", new byte[] { 1 });
        env.Registry.Set(RegHive.LocalMachine, tree + @"\Updater", "Id", "{2}");
        var f = Assert.Single(new HiddenTaskScanner().Scan(env.Context(ScanScope.Admin)));
        Assert.Contains("Updater", f.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingTaskSourceIsReportedAsCoverage()
    {
        var env = new TestEnv { TasksXml = null };
        var ctx = env.Context();
        Assert.Empty(new ScheduledTaskScanner().Scan(ctx));
        Assert.NotEmpty(ctx.Coverage.Notes);
    }
}

public class MiscScannerTests
{
    [Fact]
    public void HostsFile()
    {
        var text = """
# Copyright (c) Microsoft
127.0.0.1       localhost
0.0.0.0 ads.example.com
0.0.0.0 update.microsoft.com
0.0.0.0 www.virustotal.com
203.0.113.5 auth.riotgames.com
192.168.0.10 nas.local
198.51.100.7 myserver.test # dev
""";
        var findings = HostsScanner.Analyze(text, @"C:\Windows\System32\drivers\etc\hosts");
        Assert.Equal(3, findings.Count(f => f.Severity == Severity.High));
        Assert.Single(findings, f => f.Severity == Severity.Low);
        Assert.DoesNotContain(findings, f => f.Target!.Contains("ads.example.com", StringComparison.Ordinal));
    }

    [Fact]
    public void WmiConsumers()
    {
        var json = """[{"Class":"CommandLine","Name":"Updater","Command":"powershell -enc AAA","Path":null}]""";
        var f = Assert.Single(WmiScanner.Analyze(json));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Empty(WmiScanner.Analyze(""));
        Assert.Single(WmiScanner.Analyze("""{"Class":"ActiveScript","Name":"x","Command":"WScript.Echo 1"}"""));
    }

    [Fact]
    public void DefenderPolicyAndExclusions()
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 1);
        env.Registry.Set(RegHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", @"C:\Users\jiyul\AppData\Roaming", 0);
        env.Registry.Set(RegHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions", "exe", 0);
        env.Registry.Deny(RegHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes");

        var userCtx = env.Context();
        var user = new DefenderScanner().Scan(userCtx).ToList();
        Assert.Single(user);
        Assert.Contains(userCtx.Coverage.Notes, n => n.Contains("관리자", StringComparison.Ordinal));

        var adminCtx = env.Context(ScanScope.Admin, elevated: true);
        var admin = new DefenderScanner().Scan(adminCtx).ToList();
        Assert.Equal(2, admin.Count);
        Assert.All(admin, f => Assert.Equal(Severity.High, f.Severity));
        Assert.Contains(adminCtx.Coverage.Notes, n => n.Contains("Processes", StringComparison.Ordinal));
    }

    [Fact]
    public void BrowserForcedExtensionsAndShortcuts()
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, @"Software\Policies\Google\Chrome\ExtensionInstallForcelist", "1", "abcdefghijklmnopabcdefghijklmnop;https://evil.example/update.xml");
        env.Registry.Set(RegHive.CurrentUser, @"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist", "1", "ponmlkjihgfedcbaponmlkjihgfedcba;https://edge.microsoft.com/extensionwebstorebase/v1/crx");
        env.Files.Add(@"C:\Users\jiyul\Desktop\Chrome.lnk", LnkBuilder.Build(@"C:\Program Files\Google\Chrome\Application\chrome.exe", @"--load-extension=C:\Users\jiyul\AppData\Local\ext"));
        var findings = new BrowserScanner().Scan(env.Context()).ToList();
        Assert.Contains(findings, f => f.RuleId == "WEB-001" && f.Severity == Severity.High);
        Assert.Contains(findings, f => f.RuleId == "WEB-001" && f.Severity == Severity.Medium);
        Assert.Contains(findings, f => f.RuleId == "WEB-006" && f.Severity == Severity.High);
    }

    [Fact]
    public void DroppedFiles()
    {
        var env = new TestEnv();
        var recent = TestEnv.Now.AddDays(-1);
        env.Files.Add(@"C:\Users\jiyul\AppData\Roaming\x7f\host.exe", TestEnv.FakePe(), recent);
        env.Files.Add(@"C:\Users\jiyul\AppData\Roaming\invoice.pdf.exe", TestEnv.FakePe(), recent);
        env.Files.Add(@"C:\ProgramData\photo.jpg", TestEnv.FakePe(), recent);
        env.Files.Add(@"C:\Users\jiyul\AppData\Roaming\old.exe", TestEnv.FakePe(), TestEnv.Now.AddDays(-60));
        env.Files.Add(@"C:\Users\jiyul\AppData\Roaming\signed\app.exe", TestEnv.FakePe(), recent);
        env.Signatures.Signed(@"C:\Users\jiyul\AppData\Roaming\signed\app.exe", "Vendor");
        env.Files.Add(@"C:\Users\jiyul\AppData\Roaming\notes.txt", Encoding.UTF8.GetBytes(new string('a', 200)), recent);
        env.Files.Add(@"C:\Users\jiyul\AppData\Roaming\a\b\deep.exe", TestEnv.FakePe(), recent);
        env.Files.Add(@"C:\Users\jiyul\AppData\Local\Temp\setup.exe1234", TestEnv.FakePe(), recent);

        var findings = new DroppedFileScanner().Scan(env.Context()).ToDictionary(f => f.Location);
        Assert.Equal(4, findings.Count);
        Assert.Equal(Severity.Low, findings[@"C:\Users\jiyul\AppData\Local\Temp\setup.exe1234"].Severity);
        Assert.Equal(Severity.Medium, findings[@"C:\Users\jiyul\AppData\Roaming\x7f\host.exe"].Severity);
        Assert.Equal(Severity.High, findings[@"C:\Users\jiyul\AppData\Roaming\invoice.pdf.exe"].Severity);
        Assert.Equal(Severity.High, findings[@"C:\ProgramData\photo.jpg"].Severity);
    }

    [Theory]
    [InlineData("report.pdf.exe", true)]
    [InlineData("photo.jpg.scr", true)]
    [InlineData("setup.exe", false)]
    [InlineData("my.app.exe", false)]
    public void DoubleExtension(string name, bool expected) => Assert.Equal(expected, DroppedFileScanner.HasDoubleExtension(name));
}

public class LnkParserTests
{
    [Fact]
    public void ParsesTargetAndArguments()
    {
        var info = LnkParser.Parse(LnkBuilder.Build(@"C:\Program Files\App\app.exe", "--flag 한글"))!;
        Assert.Equal(@"C:\Program Files\App\app.exe", info.TargetPath);
        Assert.Equal("--flag 한글", info.Arguments);
    }

    [Fact]
    public void RejectsGarbage()
    {
        Assert.Null(LnkParser.Parse(new byte[10]));
        Assert.Null(LnkParser.Parse(Encoding.ASCII.GetBytes(new string('x', 200))));
        var truncated = LnkBuilder.Build(@"C:\a.exe", "x")[..90];
        Assert.Null(LnkParser.Parse(truncated));
    }
}

/// <summary>테스트용 최소 .lnk 생성기 (LinkInfo + 유니코드 인자).</summary>
internal static class LnkBuilder
{
    public static byte[] Build(string target, string? args)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        uint flags = 0x2 | 0x80 | (args is null ? 0u : 0x20u);
        w.Write(0x4C);
        w.Write(new byte[] { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
        w.Write(flags);
        w.Write(new byte[0x4C - 0x18]);

        var ansi = Encoding.Latin1.GetBytes(target + "\0");
        const int headerSize = 0x1C;
        var localBaseOffset = headerSize;
        var suffixOffset = localBaseOffset + ansi.Length;
        var size = suffixOffset + 1;
        w.Write(size);
        w.Write(headerSize);
        w.Write(1);
        w.Write(0);
        w.Write(localBaseOffset);
        w.Write(0);
        w.Write(suffixOffset);
        w.Write(ansi);
        w.Write((byte)0);

        if (args is not null)
        {
            w.Write((ushort)args.Length);
            w.Write(Encoding.Unicode.GetBytes(args));
        }

        w.Write(0);
        return ms.ToArray();
    }
}
