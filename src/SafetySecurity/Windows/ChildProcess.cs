using System.Diagnostics;
using System.Text;
using SafetySecurity.Core.Abstractions;

namespace SafetySecurity.Windows;

/// <summary>
/// Windows 기본 도구(schtasks.exe, powershell.exe)를 '조회'용으로만 실행해요.
/// 창을 띄우지 않고, 가장 낮은 우선순위로 돌리고, 시간이 지나면 우리가 띄운 프로세스만 종료해요.
/// </summary>
internal static class ChildProcess
{
    public static (int ExitCode, byte[] Stdout, string Stderr)? Run(string exe, IEnumerable<string> args, TimeSpan timeout)
    {
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
                p.Kill(entireProcessTree: true);
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

/// <summary>WMI 영구 구독: PowerShell의 Get-CimInstance로 조회만 해요.</summary>
internal sealed class PowerShellWmiSource : IWmiSource
{
    private const string Script =
        "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;" +
        "$r=@();" +
        "$r+=@(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object { [pscustomobject]@{Class='CommandLine';Name=$_.Name;Command=$_.CommandLineTemplate;Path=$_.ExecutablePath} });" +
        "$r+=@(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { [pscustomobject]@{Class='ActiveScript';Name=$_.Name;Command=$_.ScriptText;Path=$_.ScriptFileName} });" +
        "ConvertTo-Json -InputObject @($r) -Compress -Depth 3";

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
