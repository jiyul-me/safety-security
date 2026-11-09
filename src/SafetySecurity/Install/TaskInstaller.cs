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

    /// <summary>관리자 설치(Program Files의 exe나 보호된 데이터 폴더)가 있는지.</summary>
    public static bool AdminInstallExists() =>
        File.Exists(Path.Combine(AdminInstallDir, ExeName)) || Directory.Exists(DataStore.AdminRoot);

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
            if (store.IsAdminRoot)
            {
                // 관리자 권한으로는 사용자가 쓸 수 있는 폴더를 지우지 않아요 (링크를 심어 다른 파일을 지우게 할 수 있어서요).
                output.Line(@"내 계정의 검사 기록 폴더(%LOCALAPPDATA%\SafetySecurity)는 관리자 권한으로 지우지 않아요. 필요하면 관리자 권한 없이 'uninstall --purge'를 실행하거나 직접 지워 주세요.");
            }
        }

        output.Line($"작업 {deleted}개를 지웠어요.");
        if (InstalledBySetup())
        {
            // 설치 프로그램(Setup)으로 설치했으면 Windows 앱 목록에서 제거해야 파일·바로가기까지 지워져요.
            output.Line("설치 프로그램으로 설치했다면 설정 → 앱 → 설치된 앱에서 SafetySecurity를 제거하세요. 파일과 바로가기까지 지워져요.");
        }
        else
        {
            output.Line("실행 파일은 실행 중이라 스스로 지울 수 없어요. 아래 폴더를 직접 지워 주세요:");
            output.Line("  " + UserInstallDir);
            output.Line("  " + AdminInstallDir + " (관리자 설치를 했다면)");
        }

        return denied == 0 ? 0 : 1;
    }

    public static List<string> ListInstalledTasks() =>
        [.. AllTaskNames.SelectMany(n => new[] { TaskXmlBuilder.Folder + n, FallbackPrefix + n }).Where(TaskExists)];

    private static bool CreateTask(TaskSpec spec, DataStore store, Output output)
    {
        // 임시 XML은 데이터 폴더에 둬요. 관리자 권한이면 데이터 폴더가 관리자만 쓸 수 있는 Program Files\SafetySecurity\data라서,
        // 사용자 권한 프로그램이 schtasks가 읽기 전에 XML을 바꿔치기할 수 없어요.
        // 이름을 매번 새로 짓고 CreateNew로 만들어서, 미리 놓아 둔 파일이나 링크를 따라가지 않아요.
        var xmlPath = Path.Combine(store.Root, $"task-{spec.Name}-{Guid.NewGuid():N}.xml");
        Directory.CreateDirectory(store.Root);
        try
        {
            using (var fs = new FileStream(xmlPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(Encoding.Unicode.GetPreamble());
                fs.Write(Encoding.Unicode.GetBytes(spec.Xml));
            }

            foreach (var name in new[] { TaskXmlBuilder.Folder + spec.Name, FallbackPrefix + spec.Name })
            {
                var r = Schtasks(["/create", "/tn", name, "/xml", xmlPath, "/f"]);
                if (r?.ExitCode == 0)
                {
                    output.Line("작업 등록: " + name);
                    return true;
                }

                var reason = SchtasksSource.FirstLine(r?.Stderr ?? "실행 실패");
                output.Line($"작업 등록 실패 ({name}): {reason}");

                // 설치 프로그램은 --quiet로 실행해서 화면에 안 보이니, 원인을 로그에도 남겨요.
                store.Log($"install: 작업 등록 실패 ({name}): {reason}");
            }

            return false;
        }
        finally
        {
            try
            {
                File.Delete(xmlPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // 임시 XML을 못 지워도 설치에는 영향이 없어요 (자기 데이터 폴더 안의 파일이에요).
            }
        }
    }

    /// <summary>Inno Setup 설치 프로그램은 exe 옆에 제거 프로그램(unins000.exe)을 둬요.</summary>
    private static bool InstalledBySetup() =>
        Environment.ProcessPath is { } exe && File.Exists(Path.Combine(Path.GetDirectoryName(exe) ?? string.Empty, "unins000.exe"));

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

    /// <summary>
    /// 이 exe를 관리자 권한으로 다시 실행하고 끝날 때까지 기다려요 (UAC 창이 떠요). 취소하면 1을 돌려줘요.
    /// 인자는 프로그램이 만든 고정된 값만 넘겨요.
    /// </summary>
    public static int Relaunch(string arguments)
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
