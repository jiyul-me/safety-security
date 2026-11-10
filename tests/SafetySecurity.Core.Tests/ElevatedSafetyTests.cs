using SafetySecurity.Core.Install;

namespace SafetySecurity.Core.Tests;

/// <summary>관리자 권한 프로세스가 사용자가 바꿀 수 있는 것(폴더·환경 변수)을 쓰지 않는지 확인해요.</summary>
public class ElevatedSafetyTests
{
    private const string Local = @"C:\Users\jiyul\AppData\Local";
    private const string AdminDir = @"C:\Program Files\SafetySecurity";

    [Fact]
    public void NonElevatedUsesTheUserFolder() =>
        Assert.Equal(@"C:\Users\jiyul\AppData\Local\SafetySecurity", DataRoots.Resolve(null, elevated: false, Local, AdminDir));

    [Fact]
    public void ElevatedNeverUsesTheUserFolder()
    {
        var root = DataRoots.Resolve(null, elevated: true, Local, AdminDir);
        Assert.Equal(@"C:\Program Files\SafetySecurity\data", root);
        Assert.DoesNotContain(Local, root, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExplicitDataDirWins(bool elevated) =>
        Assert.Equal(@"D:\test\data", DataRoots.Resolve(@"D:\test\data", elevated, Local, AdminDir));

    [Fact]
    public void BlankDataDirFallsBackToDefault() =>
        Assert.Equal(@"C:\Program Files\SafetySecurity\data", DataRoots.Resolve("  ", elevated: true, Local, AdminDir));

    [Fact]
    public void AdminRootIgnoresTrailingSlash() =>
        Assert.Equal(@"C:\Program Files\SafetySecurity\data", DataRoots.Admin(AdminDir + @"\"));

    [Theory]
    [InlineData(null, false, true)]
    [InlineData(null, true, false)]
    [InlineData(@"D:\test", false, false)]
    [InlineData(@"D:\test", true, false)]
    public void ChangingAdminStateNeedsElevationOnlyForTheProtectedFolder(string? explicitDir, bool elevated, bool expected) =>
        Assert.Equal(expected, DataRoots.NeedsElevationToChangeAdminState(explicitDir, elevated));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ChildEnvironmentHasOnlyKnownGoodValues(bool elevated)
    {
        var env = ChildEnvironment.Build(@"C:\Windows\system32", elevated, @"C:\Users\jiyul\AppData\Local\Temp\", "AMD64");

        Assert.All(env.Keys, k => Assert.Contains(k, ChildEnvironment.AllowedNames));
        Assert.Equal(@"C:\Windows", env["SystemRoot"]);
        Assert.Equal(@"C:\Windows", env["windir"]);
        Assert.Equal("C:", env["SystemDrive"]);
        Assert.Equal(@"C:\Windows\system32\cmd.exe", env["ComSpec"]);
        Assert.All(env["PATH"].Split(';'), p => Assert.StartsWith(@"C:\Windows", p, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(@"C:\Windows\system32\WindowsPowerShell\v1.0\Modules", env["PSModulePath"]);
        Assert.DoesNotContain(env.Keys, k => k.StartsWith("COR_", StringComparison.OrdinalIgnoreCase) || k.StartsWith("COMPlus_", StringComparison.OrdinalIgnoreCase) || k.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(env.Keys, k => k is "USERPROFILE" or "APPDATA" or "LOCALAPPDATA" or "HOMEPATH");
        Assert.Equal(env["TEMP"], env["TMP"]);
    }

    [Fact]
    public void ElevatedChildTempIsNotTheUserTemp()
    {
        var env = ChildEnvironment.Build(@"C:\Windows\System32", elevated: true, @"C:\Users\jiyul\AppData\Local\Temp", "AMD64");
        Assert.Equal(@"C:\Windows\Temp", env["TEMP"]);
    }

    [Fact]
    public void NonElevatedChildKeepsItsOwnTemp()
    {
        var env = ChildEnvironment.Build(@"C:\Windows\System32", elevated: false, @"C:\Users\jiyul\AppData\Local\Temp\", "AMD64");
        Assert.Equal(@"C:\Users\jiyul\AppData\Local\Temp", env["TEMP"]);
    }

    [Fact]
    public void ChildEnvironmentFollowsTheRealSystemFolder()
    {
        // 환경 변수(windir)가 아니라 GetSystemDirectory 값에서 위치를 구해요.
        var env = ChildEnvironment.Build(@"D:\WIN\System32\", elevated: true, null, "ARM64");
        Assert.Equal(@"D:\WIN", env["SystemRoot"]);
        Assert.Equal("D:", env["SystemDrive"]);
        Assert.Equal(@"D:\WIN\Temp", env["TEMP"]);
        Assert.Equal("ARM64", env["PROCESSOR_ARCHITECTURE"]);
    }
}
