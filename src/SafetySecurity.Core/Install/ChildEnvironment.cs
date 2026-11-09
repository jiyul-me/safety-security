namespace SafetySecurity.Core.Install;

/// <summary>
/// 검사기가 띄우는 Windows 기본 도구(schtasks.exe, powershell.exe)에 줄 환경 변수예요.
/// 사용자 환경 변수(HKCU\Environment, PSModulePath, COR_*/COMPlus_*/DOTNET_* 등)는 사용자 권한 프로그램도 바꿀 수 있어서,
/// 관리자 권한 검사에서 그대로 물려주면 관리자 권한 PowerShell이 사용자가 고른 모듈·설정을 불러올 수 있어요.
/// 그래서 물려받지 않고, 시스템 폴더 위치만으로 필요한 최소한을 새로 만들어요.
/// </summary>
public static class ChildEnvironment
{
    /// <summary>자식 프로세스에 넘기는 변수 이름 전부 (이 밖의 변수는 절대 넘기지 않아요).</summary>
    public static readonly IReadOnlyList<string> AllowedNames =
        ["SystemRoot", "windir", "SystemDrive", "ComSpec", "PATHEXT", "PATH", "TEMP", "TMP", "PROCESSOR_ARCHITECTURE", "PSModulePath"];

    /// <summary>
    /// 최소 환경을 만들어요.
    /// </summary>
    /// <param name="systemDirectory">System32 폴더 (GetSystemDirectory 값, 환경 변수가 아니에요).</param>
    /// <param name="elevated">관리자 권한이면 TEMP를 사용자 폴더가 아닌 Windows\Temp로 해요.</param>
    /// <param name="userTemp">관리자 권한이 아닐 때 쓸 사용자 임시 폴더.</param>
    /// <param name="processorArchitecture">AMD64, ARM64, x86 중 하나.</param>
    public static Dictionary<string, string> Build(string systemDirectory, bool elevated, string? userTemp, string processorArchitecture)
    {
        var system = systemDirectory.TrimEnd('\\');
        var slash = system.LastIndexOf('\\');
        var windows = slash > 0 ? system[..slash] : @"C:\Windows";
        var drive = windows.Length >= 2 && windows[1] == ':' ? windows[..2] : "C:";
        var temp = elevated || string.IsNullOrWhiteSpace(userTemp) ? windows + @"\Temp" : userTemp.TrimEnd('\\');
        var powershell = system + @"\WindowsPowerShell\v1.0";
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = windows,
            ["windir"] = windows,
            ["SystemDrive"] = drive,
            ["ComSpec"] = system + @"\cmd.exe",
            ["PATHEXT"] = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
            ["PATH"] = string.Join(';', system, windows, system + @"\Wbem", powershell),

            // Windows PowerShell 5.1은 이 값이 있으면 사용자 문서 폴더의 모듈 경로를 더하지 않아요.
            // (관리자만 쓸 수 있는 Program Files 모듈 폴더만 스스로 더해요.)
            ["PSModulePath"] = powershell + @"\Modules",
            ["TEMP"] = temp,
            ["TMP"] = temp,
            ["PROCESSOR_ARCHITECTURE"] = processorArchitecture,
        };
    }
}
