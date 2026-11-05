using SafetySecurity.Core.Baseline;
using static SafetySecurity.Native.NativeMethods;

namespace SafetySecurity.Runtime;

/// <summary>
/// 게임 중인지 확인해요. 다른 프로세스를 열지 않고(OpenProcess 없음) 아래 정보만 읽어요:
/// - Windows 알림 상태 (전체 화면 D3D, 발표 모드 등)
/// - 맨 앞 창이 화면 전체를 덮는지 (창 크기와 스타일만)
/// - 실행 중인 프로세스 이름 (Toolhelp 스냅샷: 핸들 없이 이름 목록만)
/// - 시스템 전체 CPU 사용률
/// </summary>
internal sealed unsafe class GameDetector(ScanConfig config)
{
    private readonly HashSet<string> _games = new(config.GameProcesses, StringComparer.OrdinalIgnoreCase);

    /// <summary>바쁘면 이유 문자열, 아니면 null.</summary>
    public string? Check(bool includeCpu)
    {
        if (config.DeferOnFullscreen)
        {
            if (SHQueryUserNotificationState(out var state) == 0)
            {
                switch (state)
                {
                    case QUNS_RUNNING_D3D_FULL_SCREEN:
                        return "전체 화면 게임(D3D)이 실행 중";
                    case QUNS_BUSY:
                        return "전체 화면 앱이 실행 중";
                    case QUNS_PRESENTATION_MODE:
                        return "발표 모드";
                }
            }

            if (IsForegroundFullscreen())
            {
                return "전체 화면 창이 맨 앞에 있음";
            }
        }

        var game = FindGameProcess();
        if (game is not null)
        {
            return $"게임 프로세스 실행 중 ({game})";
        }

        if (includeCpu && config.CpuBusyPercent is > 0 and < 100)
        {
            var cpu = MeasureCpuPercent(TimeSpan.FromMilliseconds(700));
            if (cpu > config.CpuBusyPercent)
            {
                return $"CPU 사용률이 높음 ({cpu:0}%)";
            }
        }

        return null;
    }

    private static bool IsForegroundFullscreen()
    {
        var hwnd = GetForegroundWindow();
        if (hwnd == IntPtr.Zero || hwnd == GetShellWindow() || hwnd == GetDesktopWindow())
        {
            return false;
        }

        var cls = stackalloc char[64];
        var len = GetClassName(hwnd, cls, 64);
        var className = len > 0 ? new string(cls, 0, len) : string.Empty;
        if (className is "Progman" or "WorkerW" or "Shell_TrayWnd" or "Shell_SecondaryTrayWnd")
        {
            return false;
        }

        if (!GetWindowRect(hwnd, out var rect))
        {
            return false;
        }

        var monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        var info = new MONITORINFO { cbSize = (uint)sizeof(MONITORINFO) };
        if (monitor == IntPtr.Zero || !GetMonitorInfo(monitor, ref info))
        {
            return false;
        }

        var m = info.rcMonitor;
        var covers = rect.Left <= m.Left && rect.Top <= m.Top && rect.Right >= m.Right && rect.Bottom >= m.Bottom;
        if (!covers)
        {
            return false;
        }

        // 최대화된 일반 창(제목 표시줄 있음)은 제외하고, 테두리 없는 전체 화면만 게임으로 봐요.
        var style = (long)GetWindowLongPtr(hwnd, GWL_STYLE);
        return (style & WS_CAPTION) != WS_CAPTION;
    }

    private string? FindGameProcess()
    {
        if (_games.Count == 0)
        {
            return null;
        }

        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
        {
            return null;
        }

        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)sizeof(PROCESSENTRY32W) };
            if (!Process32First(snapshot, ref entry))
            {
                return null;
            }

            do
            {
                var name = new string(entry.szExeFile);
                if (_games.Contains(name))
                {
                    return name;
                }
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return null;
    }

    private static double MeasureCpuPercent(TimeSpan window)
    {
        if (!GetSystemTimes(out var idle1, out var kernel1, out var user1))
        {
            return 0;
        }

        Thread.Sleep(window);
        if (!GetSystemTimes(out var idle2, out var kernel2, out var user2))
        {
            return 0;
        }

        var idle = idle2 - idle1;
        var total = (kernel2 - kernel1) + (user2 - user1); // kernel 시간에 idle이 포함돼 있어요.
        return total <= 0 ? 0 : Math.Clamp(100.0 * (total - idle) / total, 0, 100);
    }
}
