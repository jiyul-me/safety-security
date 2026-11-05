using System.Reflection;
using SafetySecurity.Core.Model;
using SafetySecurity.Install;
using SafetySecurity.Runtime;

namespace SafetySecurity;

internal static class Program
{
    public static string Version { get; } =
        typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    private const string Help = """
SafetySecurity — 읽기 전용 Windows 보안 검사기

사용법:
  SafetySecurity.exe                      지금 검사하고 보고서 열기 (더블클릭과 같아요)
  SafetySecurity.exe install [--admin]    작업 스케줄러에 등록 (--admin: 관리자 검사도 추가)
  SafetySecurity.exe uninstall [--purge]  작업 삭제 (--purge: 검사 기록·보고서도 삭제)
  SafetySecurity.exe scan [옵션]          검사
      --reason manual|logon|daily|service|retry
      --quick              서비스·예약 작업만 빠르게
      --scope user|admin   관리자 범위 (관리자 권한 필요)
      --force              게임 중이어도 검사
      --no-toast           알림 끄기
      --open               끝나면 보고서 열기
      --report-dir <폴더>  보고서 저장 위치
  SafetySecurity.exe status               마지막 검사, 미뤄둔 검사, 등록된 작업
  SafetySecurity.exe report               마지막 보고서 열기
  SafetySecurity.exe ignore <ID>          항목을 무시 목록에 추가 (보고서에 ID가 있어요)
  SafetySecurity.exe unignore <ID>        무시 목록에서 빼기
  SafetySecurity.exe verify <파일>        파일 하나의 디지털 서명 확인
  SafetySecurity.exe test-notify          알림이 뜨는지 시험
  SafetySecurity.exe version

공통 옵션:  --data-dir <폴더>  상태·보고서 폴더 (기본: %LOCALAPPDATA%\SafetySecurity)

이 프로그램은 아무것도 지우거나 고치지 않고, 인터넷을 쓰지 않아요.
""";

    [STAThread]
    public static int Main(string[] args)
    {
        var output = new Output();
        var list = args.ToList();
        var dataDir = TakeValue(list, "--data-dir");
        var store = new DataStore(dataDir);
        var command = list.Count > 0 && !list[0].StartsWith('-') ? list[0].ToLowerInvariant() : "manual";
        if (list.Count > 0 && command == list[0].ToLowerInvariant())
        {
            list.RemoveAt(0);
        }

        try
        {
            switch (command)
            {
                case "manual":
                {
                    var code = ScanCommand.Run(new ScanOptions { Reason = ScanReason.Manual, Force = true, Open = true, NoToast = true }, store, output);
                    return code;
                }

                case "scan":
                {
                    var o = ParseScan(list);
                    output.Quiet = o.Reason != ScanReason.Manual && !output.HasConsole;
                    return ScanCommand.Run(o, store, output);
                }

                case "install":
                {
                    var code = TaskInstaller.Install(list.Contains("--admin"), store, output);
                    output.ShowIfNoConsole("SafetySecurity 설치");
                    return code;
                }

                case "uninstall":
                {
                    var code = TaskInstaller.Uninstall(list.Contains("--purge"), store, output);
                    output.ShowIfNoConsole("SafetySecurity 제거");
                    return code;
                }

                case "status":
                    Status(store, output);
                    output.ShowIfNoConsole("SafetySecurity 상태");
                    return 0;

                case "report":
                {
                    var state = store.LoadState(ScanScope.User);
                    if (state.LastReportPath is { } path && File.Exists(path))
                    {
                        ScanCommand.OpenFile(path);
                        return 0;
                    }

                    output.Line("아직 보고서가 없어요. 먼저 검사해 주세요.");
                    output.ShowIfNoConsole("SafetySecurity");
                    return 1;
                }

                case "ignore":
                case "unignore":
                {
                    var scope = TakeValue(list, "--scope") == "admin" ? ScanScope.Admin : ScanScope.User;
                    var id = list.FirstOrDefault(a => !a.StartsWith('-'));
                    if (id is null)
                    {
                        output.Line("ID를 적어 주세요. 예: SafetySecurity.exe ignore 1a2b3c4d5e6f7a8b");
                        return 1;
                    }

                    var state = store.LoadState(scope);
                    var changed = command == "ignore" ? state.Ignored.Add(id.ToLowerInvariant()) : state.Ignored.Remove(id.ToLowerInvariant());
                    store.SaveState(scope, state);
                    output.Line(changed ? (command == "ignore" ? $"{id}: 다음 검사부터 숨겨요." : $"{id}: 다시 보여요.") : "이미 그 상태예요.");
                    output.ShowIfNoConsole("SafetySecurity");
                    return 0;
                }

                case "verify":
                {
                    // 파일 하나의 서명을 확인해요 (테스트·직접 확인용).
                    var path = list.FirstOrDefault(a => !a.StartsWith('-'));
                    if (path is null)
                    {
                        output.Line("파일 경로를 적어 주세요.");
                        return 1;
                    }

                    var info = new Windows.AuthenticodeVerifier().Verify(Path.GetFullPath(path));
                    output.Line($"{info.Status}|{info.Signer}|{(info.IsCatalog ? "catalog" : "embedded")}|{info.Detail}");
                    output.Line(info.ToKorean() + (info.Signer is null ? string.Empty : " — " + info.Signer));
                    output.ShowIfNoConsole("SafetySecurity 서명 확인");
                    return info.Status == SignatureStatus.Valid ? 0 : 5;
                }

                case "test-notify":
                {
                    // 알림이 제대로 뜨는지 확인 (설치 후 한 번 해 보세요).
                    var sample = new Finding
                    {
                        RuleId = "TEST",
                        Category = "Test",
                        Severity = Severity.Medium,
                        Title = "알림 테스트예요 (실제 문제 아님)",
                        Location = "test",
                    };
                    var ok = Notify.ToastNotifier.TryShow([sample], store.Root, firstRun: false, out var error);
                    output.Line(ok ? "알림을 보냈어요. 화면 오른쪽 아래를 확인하세요." : "알림 실패: " + error);
                    output.ShowIfNoConsole("SafetySecurity 알림 테스트");
                    return ok ? 0 : 6;
                }

                case "version":
                case "--version":
                    output.Line("SafetySecurity " + Version);
                    output.ShowIfNoConsole("SafetySecurity");
                    return 0;

                case "help":
                case "--help":
                case "-h":
                case "/?":
                    output.Line(Help);
                    output.ShowIfNoConsole("SafetySecurity 도움말");
                    return 0;

                default:
                    output.Line($"알 수 없는 명령: {command}");
                    output.Line(Help);
                    output.ShowIfNoConsole("SafetySecurity");
                    return 1;
            }
        }
        catch (Exception ex)
        {
            store.Log($"오류: {ex}");
            output.Line("오류가 났어요: " + ex.Message);
            output.ShowIfNoConsole("SafetySecurity 오류");
            return ExitCodes.Error;
        }
    }

    private static ScanOptions ParseScan(List<string> args)
    {
        var o = new ScanOptions
        {
            Quick = args.Contains("--quick"),
            Force = args.Contains("--force"),
            NoToast = args.Contains("--no-toast"),
            Open = args.Contains("--open"),
            ReportDir = TakeValue(args, "--report-dir"),
        };
        o.Reason = (TakeValue(args, "--reason") ?? "manual").ToLowerInvariant() switch
        {
            "logon" => ScanReason.Logon,
            "daily" => ScanReason.Daily,
            "service" => ScanReason.Service,
            "retry" => ScanReason.Retry,
            _ => ScanReason.Manual,
        };
        o.Scope = TakeValue(args, "--scope")?.ToLowerInvariant() == "admin" ? ScanScope.Admin : ScanScope.User;
        return o;
    }

    private static string? TakeValue(List<string> args, string name)
    {
        var i = args.FindIndex(a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (i < 0 || i + 1 >= args.Count)
        {
            return null;
        }

        var v = args[i + 1];
        args.RemoveRange(i, 2);
        return v;
    }

    private static void Status(DataStore store, Output output)
    {
        output.Line($"SafetySecurity {Version}");
        output.Line("데이터 폴더: " + store.Root);
        foreach (var scope in new[] { ScanScope.User, ScanScope.Admin })
        {
            var s = store.LoadState(scope);
            if (s.LastScanUtc is null && s.Pending is null)
            {
                continue;
            }

            output.Line($"[{(scope == ScanScope.Admin ? "관리자" : "사용자")} 검사]");
            output.Line("  마지막 검사: " + (s.LastScanUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture) ?? "없음"));
            output.Line("  마지막 전체 검사: " + (s.LastFullScanUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture) ?? "없음"));
            if (s.Pending is { } p)
            {
                output.Line($"  미뤄둔 검사: {p.Reason}{(p.Quick ? " (빠른 검사)" : string.Empty)} — {p.DeferredBecause} ({p.Attempts}번 미룸)");
            }

            output.Line($"  무시 목록: {s.Ignored.Count}개, 베이스라인: {s.Baseline.Count}개");
            if (s.LastReportPath is not null)
            {
                output.Line("  마지막 보고서: " + s.LastReportPath);
            }
        }

        var tasks = TaskInstaller.ListInstalledTasks();
        output.Line(tasks.Count == 0 ? "등록된 작업: 없음 (install로 등록하세요)" : "등록된 작업: " + string.Join(", ", tasks));
    }
}
