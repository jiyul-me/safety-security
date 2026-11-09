using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Install;

namespace SafetySecurity.Windows;

/// <summary>
/// Windows 기본 도구(schtasks.exe, powershell.exe)를 '조회'용으로만 실행해요.
/// 창을 띄우지 않고, 가장 낮은 우선순위로 돌리고, 시간이 지나면 우리가 띄운 프로세스만 종료해요.
/// - 실행 파일은 항상 System32의 전체 경로로 실행해요.
/// - 환경 변수는 물려주지 않고 최소한만 새로 만들어요 (<see cref="ChildEnvironment"/>).
///   사용자가 바꿀 수 있는 PSModulePath·COMPlus_* 같은 값이 관리자 권한 PowerShell에 들어가지 않게 해요.
/// - 시간 초과 때는 우리 자식 프로세스 하나만 그 핸들로 종료해요 (Kill()). 프로세스 트리 종료(Kill(true))는
///   모든 프로세스(게임·안티치트 포함)를 OpenProcess로 열어 보기 때문에 절대 쓰지 않아요 (BannedSymbols.txt).
/// </summary>
internal static class ChildProcess
{
    public static (int ExitCode, byte[] Stdout, string Stderr)? Run(string exe, IEnumerable<string> args, TimeSpan timeout)
    {
        if (!Path.IsPathFullyQualified(exe))
        {
            // 이름만으로 실행하면 PATH·현재 폴더에서 다른 파일을 찾을 수 있어요.
            return null;
        }

        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = false,
            WorkingDirectory = Environment.SystemDirectory,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        psi.Environment.Clear();
        foreach (var (name, value) in MinimalEnvironment())
        {
            psi.Environment[name] = value;
        }

        try
        {
            using var p = Process.Start(psi);
            if (p is null)
            {
                return null;
            }

            try
            {
                p.PriorityClass = ProcessPriorityClass.Idle;
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // 이미 끝났으면 무시
            }

            using var ms = new MemoryStream();
            using var err = new MemoryStream();
            var copy = p.StandardOutput.BaseStream.CopyToAsync(ms);
            var copyErr = p.StandardError.BaseStream.CopyToAsync(err);
            if (!p.WaitForExit(timeout))
            {
                KillOwnChild(p);
                return null;
            }

            copy.Wait(TimeSpan.FromSeconds(5));
            copyErr.Wait(TimeSpan.FromSeconds(5));
            return (p.ExitCode, ms.ToArray(), SchtasksSource.Decode(err.ToArray()));
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// 자식 프로세스에 줄 최소 환경. 위치는 환경 변수가 아니라 GetSystemDirectory(Environment.SystemDirectory)에서 구해요
    /// (사용자 환경 변수로 windir·SystemRoot를 바꿀 수 있어서요).
    /// </summary>
    internal static Dictionary<string, string> MinimalEnvironment()
    {
        var arch = RuntimeInformation.OSArchitecture switch
        {
            Architecture.Arm64 => "ARM64",
            Architecture.X86 => "x86",
            _ => "AMD64",
        };
        var elevated = Environment.IsPrivilegedProcess;
        return ChildEnvironment.Build(Environment.SystemDirectory, elevated, elevated ? null : Path.GetTempPath(), arch);
    }

    /// <summary>
    /// 우리가 띄운 자식 프로세스만 종료해요. Process.Start가 받은 핸들로 TerminateProcess를 부를 뿐,
    /// 다른 프로세스를 찾거나 열지 않아요. schtasks.exe와 powershell.exe(Get-CimInstance)는 자식 프로세스를 띄우지 않아서
    /// 트리 종료가 필요 없어요 (WMI는 WmiPrvSE 서비스에서 돌아요).
    /// </summary>
    private static void KillOwnChild(Process p)
    {
        try
        {
            p.Kill();
            p.WaitForExit(TimeSpan.FromSeconds(5));
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // 그사이 이미 끝났으면 괜찮아요.
        }
    }
}

/// <summary>예약 작업 목록: schtasks /query /xml ONE (읽기 전용 조회).</summary>
internal sealed class SchtasksSource : ITaskSource
{
    public string? GetTasksXml(out string? error)
    {
        var exe = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        var r = ChildProcess.Run(exe, ["/query", "/xml", "ONE"], TimeSpan.FromSeconds(90));
        if (r is not { } result)
        {
            error = "schtasks.exe를 실행하지 못했거나 시간이 초과됐어요.";
            return null;
        }

        if (result.ExitCode != 0)
        {
            error = $"schtasks.exe 오류 (종료 코드 {result.ExitCode}): {FirstLine(result.Stderr)}";
            return null;
        }

        error = null;
        var text = Decode(result.Stdout);
        var start = text.IndexOf('<');
        return start >= 0 ? text[start..] : text;
    }

    internal static string Decode(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        }

        if (bytes.Length >= 4 && bytes[1] == 0 && bytes[3] == 0)
        {
            return Encoding.Unicode.GetString(bytes);
        }

        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        }

        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var oem = Encoding.GetEncoding((int)Native.NativeMethods.GetOEMCP());
            return oem.GetString(bytes);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            return Encoding.UTF8.GetString(bytes);
        }
    }

    internal static string FirstLine(string s) => s.Split('\n', 2)[0].Trim();
}

/// <summary>
/// WMI 영구 구독: PowerShell의 Get-CimInstance로 조회만 해요.
/// 프로필을 읽지 않고(-NoProfile), 최소 환경(PSModulePath = System32 PowerShell 모듈 폴더)에서
/// 모듈 이름까지 붙여(CimCmdlets\Get-CimInstance) 실행해서, 사용자 폴더의 모듈이 끼어들 수 없어요.
/// </summary>
internal sealed class PowerShellWmiSource : IWmiSource
{
    private const string Script =
        "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;" +
        "$r=@();" +
        "$r+=@(CimCmdlets\\Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object { [pscustomobject]@{Class='CommandLine';Name=$_.Name;Command=$_.CommandLineTemplate;Path=$_.ExecutablePath} });" +
        "$r+=@(CimCmdlets\\Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { [pscustomobject]@{Class='ActiveScript';Name=$_.Name;Command=$_.ScriptText;Path=$_.ScriptFileName} });" +
        "Microsoft.PowerShell.Utility\\ConvertTo-Json -InputObject @($r) -Compress -Depth 3";

    public string? GetConsumersJson(out string? error)
    {
        var exe = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var r = ChildProcess.Run(exe, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", Script], TimeSpan.FromSeconds(90));
        if (r is not { } result)
        {
            error = "PowerShell을 실행하지 못했거나 시간이 초과됐어요.";
            return null;
        }

        if (result.ExitCode != 0)
        {
            error = result.Stderr.Contains("denied", StringComparison.OrdinalIgnoreCase) || result.Stderr.Contains("거부", StringComparison.Ordinal)
                ? "권한이 없어요 (관리자 작업에서 확인해요)."
                : "조회 실패: " + SchtasksSource.FirstLine(result.Stderr);
            return null;
        }

        error = null;
        return Encoding.UTF8.GetString(result.Stdout).Trim('\uFEFF', ' ', '\r', '\n');
    }
}
