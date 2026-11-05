// 설치·제거는 사용자가 직접 실행하는 명령이에요 (검사 중에는 절대 실행되지 않아요).
// 자기 exe 복사, 자기 예약 작업 등록/삭제, 알림 등록(AppUserModelId)만 하므로 이 파일에서만 RS0030을 풀어요.
#pragma warning disable RS0030

using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using SafetySecurity.Core.Install;
using SafetySecurity.Notify;
using SafetySecurity.Runtime;
using SafetySecurity.Windows;

namespace SafetySecurity.Install;

internal static class TaskInstaller
{
    public const string ExeName = "SafetySecurity.exe";
    private const string FallbackPrefix = @"\SafetySecurity-";
    private static readonly string[] AllTaskNames = ["Logon", "Daily", "ServiceInstalled", "Retry", "Admin", "ServiceInstalledAdmin"];

    public static string UserInstallDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "SafetySecurity");

    public static string AdminInstallDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SafetySecurity");

    public static int Install(bool admin, DataStore store, Output output)
    {
        var elevated = Environment.IsPrivilegedProcess;
        if (admin && !elevated)
        {
            output.Line("관리자 설치는 관리자 권한이 필요해요. UAC 창에서 '예'를 눌러 주세요.");
            return Relaunch("install --admin");
        }

        var source = Environment.ProcessPath ?? throw new InvalidOperationException("실행 파일 경로를 알 수 없어요.");
        var dir = admin ? AdminInstallDir : UserInstallDir;
        var target = Path.Combine(dir, ExeName);
        Directory.CreateDirectory(dir);
        if (!string.Equals(Path.GetFullPath(source), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
        {
            File.Copy(source, target, overwrite: true);
        }

        output.Line($"설치 위치: {target}");
        store.WriteDefaultConfigIfMissing();
        RegisterToastIdentity();

        var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value ?? throw new InvalidOperationException("사용자 SID를 알 수 없어요.");
        var userName = identity.Name;
        var now = DateTime.Now;

        var failures = 0;
        var serviceTaskOk = true;
        foreach (var spec in TaskXmlBuilder.BuildUserTasks(target, sid, userName, now))
        {
            var ok = CreateTask(spec, store, output);
            if (!ok)
            {
                failures++;
                if (spec.Name == "ServiceInstalled")
                {
                    serviceTaskOk = false;
                }
            }
        }

        if (admin)
        {
            failures += CreateTask(TaskXmlBuilder.BuildAdminTask(target, sid, userName, now), store, output) ? 0 : 1;
            if (!serviceTaskOk && CreateTask(TaskXmlBuilder.BuildAdminServiceTask(target, sid), store, output))
            {
                failures--;
            }
        }

        output.Line(string.Empty);
        if (failures == 0)
        {
            output.Line("설치 완료! 평소엔 꺼져 있고, 로그온·하루 한 번·서비스 설치 때만 잠깐 검사해요.");
            output.Line("지금 바로 검사하려면: " + target + " scan");
        }
        else
        {
            output.Line($"작업 {failures}개를 등록하지 못했어요. 위 메시지를 확인해 주세요.");
        }

        if (!admin)
        {
            output.Line("팁: 관리자 설치(install --admin)를 하면 Defender 제외 목록·숨겨진 작업·WMI 구독도 확인하고, 검사기 파일도 악성코드가 바꾸기 어려운 Program Files에 둬요.");
        }

        return failures == 0 ? 0 : 1;
    }

    public static int Uninstall(bool purge, DataStore store, Output output)
    {
        var deleted = 0;
        var denied = 0;
        foreach (var name in AllTaskNames)
        {
            foreach (var full in new[] { TaskXmlBuilder.Folder + name, FallbackPrefix + name })
            {
                if (!TaskExists(full))
                {
                    continue;
                }

                var r = Schtasks(["/delete", "/tn", full, "/f"]);
                if (r?.ExitCode == 0)
                {
                    deleted++;
                    output.Line("작업 삭제: " + full);
                }
                else
                {
                    denied++;
                    output.Line("작업 삭제 실패 (관리자 작업이면 관리자 권한이 필요해요): " + full);
                }
            }
        }

        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\AppUserModelId\" + ToastNotifier.AppUserModelId, throwOnMissingSubKey: false);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            output.Line("알림 등록 정보를 지우지 못했어요: " + ex.Message);
        }

        if (purge)
        {
            store.DeleteAll();
            output.Line("검사 기록·보고서 폴더를 지웠어요: " + store.Root);
        }

        output.Line($"작업 {deleted}개를 지웠어요.");
        output.Line("실행 파일은 실행 중이라 스스로 지울 수 없어요. 아래 폴더를 직접 지워 주세요:");
        output.Line("  " + UserInstallDir);
        output.Line("  " + AdminInstallDir + " (관리자 설치를 했다면)");
        return denied == 0 ? 0 : 1;
    }

    public static List<string> ListInstalledTasks() =>
        [.. AllTaskNames.SelectMany(n => new[] { TaskXmlBuilder.Folder + n, FallbackPrefix + n }).Where(TaskExists)];

    private static bool CreateTask(TaskSpec spec, DataStore store, Output output)
    {
        var xmlPath = Path.Combine(store.Root, "task-" + spec.Name + ".xml");
        Directory.CreateDirectory(store.Root);
        try
        {
            File.WriteAllText(xmlPath, spec.Xml, Encoding.Unicode);
            foreach (var name in new[] { TaskXmlBuilder.Folder + spec.Name, FallbackPrefix + spec.Name })
            {
                var r = Schtasks(["/create", "/tn", name, "/xml", xmlPath, "/f"]);
                if (r?.ExitCode == 0)
                {
                    output.Line("작업 등록: " + name);
                    return true;
                }

                output.Line($"작업 등록 실패 ({name}): {SchtasksSource.FirstLine(r?.Stderr ?? "실행 실패")}");
            }

            return false;
        }
        finally
        {
            try
            {
                File.Delete(xmlPath);
            }
            catch (IOException)
            {
            }
        }
    }

    private static bool TaskExists(string name) => Schtasks(["/query", "/tn", name])?.ExitCode == 0;

    private static (int ExitCode, byte[] Stdout, string Stderr)? Schtasks(string[] args)
    {
        var r = ChildProcess.Run(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), args, TimeSpan.FromSeconds(30));
        if (r is { } x)
        {
            // schtasks 오류 메시지는 콘솔 코드 페이지(한국어 Windows는 CP949)로 나와요.
            return (x.ExitCode, x.Stdout, x.Stderr.Length > 0 ? x.Stderr : SchtasksSource.Decode(x.Stdout));
        }

        return null;
    }

    private static void RegisterToastIdentity()
    {
        using var key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\AppUserModelId\" + ToastNotifier.AppUserModelId);
        key.SetValue("DisplayName", "SafetySecurity");
        key.SetValue("ShowInSettings", 1, RegistryValueKind.DWord);
    }

    private static int Relaunch(string arguments)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, arguments) { UseShellExecute = true, Verb = "runas" });
            p?.WaitForExit();
            return p?.ExitCode ?? 1;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return 1;
        }
    }
}
