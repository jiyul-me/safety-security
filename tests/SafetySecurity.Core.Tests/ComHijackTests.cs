using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Scanners;

namespace SafetySecurity.Core.Tests;

public class ComHijackTests
{
    private const string Clsid = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}";
    private const string SystemDll = @"C:\Windows\System32\shdocvw.dll";

    private static TestEnv WithSystemClass()
    {
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, $@"Software\Classes\CLSID\{Clsid}", null, "ShellWindows");
        env.Registry.Set(RegHive.LocalMachine, $@"Software\Classes\CLSID\{Clsid}\InprocServer32", null, @"%SystemRoot%\System32\shdocvw.dll");
        env.Files.Add(SystemDll);
        env.Signatures.Signed(SystemDll);
        return env;
    }

    [Fact]
    public void DetectsLauncherStyleHijack_UnsignedDllShadowsSystemClass()
    {
        // 니케 런처 사건과 같은 형태: HKCU에 같은 CLSID를 만들어 사용자 폴더의 서명 없는 DLL을 가리킴
        var env = WithSystemClass();
        const string evil = @"C:\Users\jiyul\AppData\Roaming\Microsoft\Crypto\mscorsvc.dll";
        env.Registry.Set(RegHive.CurrentUser, $@"Software\Classes\CLSID\{Clsid}\InprocServer32", null, evil);
        env.Registry.Set(RegHive.CurrentUser, $@"Software\Classes\CLSID\{Clsid}\InprocServer32", "ThreadingModel", "Apartment");
        env.Files.Add(evil, TestEnv.FakePe(dll: true));

        var findings = new ComHijackScanner().Scan(env.Context()).ToList();

        var f = Assert.Single(findings);
        Assert.Equal("COM-001", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(evil, f.Target);
        Assert.Contains(f.Evidence, e => e.Key == "HKLM 원래 값");
        Assert.Contains(f.Evidence, e => e.Key == "SHA-256");
        Assert.Contains(@"HKCU\Software\Classes\CLSID", f.Location, StringComparison.Ordinal);
    }

    [Fact]
    public void ShadowWithSignedDllInUserFolderIsMedium()
    {
        var env = WithSystemClass();
        const string dll = @"C:\Users\jiyul\AppData\Local\Vendor\ext.dll";
        env.Registry.Set(RegHive.CurrentUser, $@"Software\Classes\CLSID\{Clsid}\InprocServer32", null, dll);
        env.Files.Add(dll);
        env.Signatures.Signed(dll, "Vendor Inc.");

        var f = Assert.Single(new ComHijackScanner().Scan(env.Context()));
        Assert.Equal(Severity.Medium, f.Severity);
    }

    [Fact]
    public void SamePathAsHklmIsIgnored()
    {
        var env = WithSystemClass();
        env.Registry.Set(RegHive.CurrentUser, $@"Software\Classes\CLSID\{Clsid}\InprocServer32", null, @"C:\WINDOWS\system32\SHDOCVW.dll");
        Assert.Empty(new ComHijackScanner().Scan(env.Context()));
    }

    [Fact]
    public void UserOnlySignedClassIsIgnored()
    {
        // OneDrive, Teams처럼 사용자 단위로 설치된 정상 COM 서버
        var env = new TestEnv();
        const string dll = @"C:\Users\jiyul\AppData\Local\Microsoft\OneDrive\25.1\FileSyncShell64.dll";
        env.Registry.Set(RegHive.CurrentUser, @"Software\Classes\CLSID\{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}\InprocServer32", null, dll);
        env.Files.Add(dll);
        env.Signatures.Signed(dll, "Microsoft Corporation");
        Assert.Empty(new ComHijackScanner().Scan(env.Context()));
    }

    [Fact]
    public void UserOnlyUnsignedInTempIsHigh()
    {
        var env = new TestEnv();
        const string dll = @"C:\Users\jiyul\AppData\Local\Temp\x.dll";
        env.Registry.Set(RegHive.CurrentUser, @"Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32", null, dll);
        env.Files.Add(dll);
        var f = Assert.Single(new ComHijackScanner().Scan(env.Context()));
        Assert.Equal("COM-002", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void RecentKeyBumpsSeverity()
    {
        var env = new TestEnv();
        const string dll = @"C:\Users\jiyul\AppData\Roaming\x.dll";
        var key = @"Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}";
        env.Registry.Set(RegHive.CurrentUser, key + @"\InprocServer32", null, dll);
        env.Registry.Key(RegHive.CurrentUser, key, TestEnv.Now.AddDays(-1));
        env.Files.Add(dll);
        var f = Assert.Single(new ComHijackScanner().Scan(env.Context()));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Contains(f.Reasons, r => r.Contains("최근 7일", StringComparison.Ordinal));
    }

    [Fact]
    public void DetectsScriptletAndTreatAs()
    {
        var env = WithSystemClass();
        env.Registry.Set(RegHive.CurrentUser, $@"Software\Classes\CLSID\{Clsid}\ScriptletURL", null, "http://evil/x.sct");
        env.Registry.Set(RegHive.CurrentUser, $@"Software\Classes\CLSID\{Clsid}\TreatAs", null, "{00000000-0000-0000-0000-000000000001}");
        var findings = new ComHijackScanner().Scan(env.Context()).ToList();
        Assert.Contains(findings, f => f.RuleId == "COM-003" && f.Severity == Severity.High);
        Assert.Contains(findings, f => f.RuleId == "COM-004" && f.Severity == Severity.High);
    }

    [Fact]
    public void ChecksWow64View()
    {
        var env = new TestEnv();
        const string dll = @"C:\Users\Public\x.dll";
        env.Registry.Set(RegHive.LocalMachine, @"Software\Classes\Wow6432Node\CLSID\{A}\InprocServer32", null, @"C:\Windows\SysWOW64\a.dll");
        env.Registry.Set(RegHive.CurrentUser, @"Software\Classes\Wow6432Node\CLSID\{A}\InprocServer32", null, dll);
        env.Files.Add(dll);
        var f = Assert.Single(new ComHijackScanner().Scan(env.Context()));
        Assert.Contains("32비트", f.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalServerCommandLineIsParsed()
    {
        var env = WithSystemClass();
        const string exe = @"C:\Users\jiyul\AppData\Roaming\upd\svc.exe";
        env.Registry.Set(RegHive.LocalMachine, $@"Software\Classes\CLSID\{Clsid}\LocalServer32", null, @"C:\Windows\System32\real.exe");
        env.Registry.Set(RegHive.CurrentUser, $@"Software\Classes\CLSID\{Clsid}\LocalServer32", null, $"\"{exe}\" -Embedding");
        env.Files.Add(exe);
        var f = Assert.Single(new ComHijackScanner().Scan(env.Context()));
        Assert.Equal(exe, f.Target);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void SelfIsExcluded()
    {
        var env = new TestEnv();
        const string dll = @"C:\Users\jiyul\AppData\Local\Temp\x.dll";
        env.Registry.Set(RegHive.CurrentUser, @"Software\Classes\CLSID\{B}\InprocServer32", null, dll);
        env.Files.Add(dll);
        Assert.Empty(new ComHijackScanner().Scan(env.Context(self: [dll])));
    }
}
