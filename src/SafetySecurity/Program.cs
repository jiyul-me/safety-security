using System.Reflection;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Install;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;
using SafetySecurity.Install;
using SafetySecurity.Notify;
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
  SafetySecurity.exe ignore <ID>          보고서의 항목 숨기기 (ID는 보고서에 있어요. 앞 8자리 이상만 적어도 돼요)
      --scope admin        관리자 검사 항목 (적지 않으면 두 검사 기록에서 찾아요. 관리자 권한을 요청해요)
  SafetySecurity.exe unignore <ID>        숨긴 항목을 다시 보이게 하기
  SafetySecurity.exe ignored              숨긴 항목 목록 (ID, 제목, 숨긴 날)
  SafetySecurity.exe verify <파일>        파일 하나의 디지털 서명 확인
  SafetySecurity.exe test-notify          알림이 뜨는지 시험
  SafetySecurity.exe version              버전 (--version도 돼요)
  SafetySecurity.exe help                 이 도움말 (--help, -h, /?도 돼요)

공통 옵션:  --data-dir <폴더>  상태·보고서 폴더 (기본: %LOCALAPPDATA%\SafetySecurity,
                              관리자 권한이면 C:\Program Files\SafetySecurity\data)
            --quiet           메시지를 보여주지 않고 종료 코드만 돌려줘요 (설치 프로그램용)

이 프로그램은 아무것도 지우거나 고치지 않고, 인터넷을 쓰지 않아요.
""";

    [STAThread]
    public static int Main(string[] args)
    {
        var output = new Output();
        var list = args.ToList();
        output.Quiet = list.RemoveAll(a => a.Equals("--quiet", StringComparison.OrdinalIgnoreCase)) > 0;
        var dataDir = TakeValue(list, "--data-dir");
        var store = new DataStore(dataDir);
        // 인자가 하나도 없을 때만(더블클릭·시작 메뉴·바탕화면) 바로 검사해요. 첫 인자는 항상 명령으로 봐서,
        // --help·--version은 도움말·버전을 보여주고, 모르는 옵션(오타 등)은 검사를 시작하지 않고 도움말을 보여줘요.
        var command = list.Count > 0 ? list[0].ToLowerInvariant() : "manual";
        if (list.Count > 0)
        {
            list.RemoveAt(0);
        }

        if (!output.HasConsole && !output.Quiet && command is not ("manual" or "scan"))
        {
            // Win+R·바로가기처럼 콘솔 없이 실행한 명령은 결과가 메시지 창으로만 보여서, 실행됐는지 기록해 둬요.
            store.Log($"명령: {command} (결과는 메시지 창으로 보여줘요)");
        }

        try
        {
            switch (command)
            {
                case "manual":
                {
                    // 더블클릭·시작 메뉴: 지금 검사하고 보고서 열기. 검사하는 동안 알림으로 진행 중임을 보여줘요.
                    var options = new ScanOptions { Reason = ScanReason.Manual, Force = true, Open = true, NoToast = true, ProgressToast = !output.HasConsole };
                    var code = ScanCommand.Run(options, store, output);
                    if (code != ExitCodes.Ok)
                    {
                        // 보고서가 열리지 않는 모든 경우(이미 검사 중, 너무 오래 걸려 멈춤, 오류)에 이유를 보여줘요.
                        output.ShowIfNoConsole("SafetySecurity");
                    }

                    return code;
                }

                case "scan":
                {
                    var o = ParseScan(list);
                    output.Quiet |= o.Reason != ScanReason.Manual && !output.HasConsole;
                    if (o.Reason == ScanReason.Manual && !output.HasConsole && !output.Quiet)
                    {
                        // Win+R·바로가기로 'scan'을 실행했어요. 더블클릭처럼 검사 중 알림을 띄우고, 끝나면 보고서를 열어요.
                        o.ProgressToast = !o.NoToast;
                        o.Open = true;
                    }

                    var code = ScanCommand.Run(o, store, output);
                    if (code != ExitCodes.Ok)
                    {
                        // 미룸·이미 검사 중·멈춤·오류도 콘솔 없이 실행했으면 메시지 창으로 알려요 (작업 스케줄러 검사는 --quiet처럼 조용해요).
                        output.ShowIfNoConsole("SafetySecurity");
                    }

                    return code;
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
                    // 관리자 권한이면 데이터 폴더가 관리자 폴더라서, 사용자 범위 보고서가 없으면 관리자 검사 보고서를 열어요.
                    var state = store.LoadState(ScanScope.User);
                    if (state.LastReportPath is null && store.IsAdminRoot)
                    {
                        state = store.LoadState(ScanScope.Admin);
                    }

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
                    var code = ChangeIgnore(command, list, dataDir, store, output, out var showResult);
                    if (showResult)
                    {
                        output.ShowIfNoConsole("SafetySecurity");
                    }

                    return code;
                }

                case "ignored":
                    ListIgnored(store, output);
                    output.ShowIfNoConsole("SafetySecurity 숨긴 항목");
                    return 0;

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
                    if (ok && Notify.ToastNotifier.IsRegistered() && Advice.NotificationsOff(Notify.ToastNotifier.ReadState()) is { } off)
                    {
                        // 알림이 꺼져 있으면 Windows가 조용히 버려서 화면에 안 보여요.
                        output.Line("다만 알림이 보이지 않을 거예요. " + off);
                    }
                    output.ShowIfNoConsole("SafetySecurity 알림 테스트");
                    return ok ? 0 : 6;
                }

                case "version":
                case "--version":
                case "-v":
                    output.Line("SafetySecurity " + Version);
                    output.ShowIfNoConsole("SafetySecurity");
                    return 0;

                case "help":
                case "--help":
                case "-h":
                case "-?":
                case "/?":
                case "/h":
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

    /// <summary>관리자 검사 기록이 있는 저장소 (status와 같은 규칙: 일반 권한에서도 읽기만 해요).</summary>
    private static DataStore AdminStore(DataStore store) =>
        store.IsExplicit || store.IsAdminRoot ? store : new DataStore(DataStore.AdminRoot);

    /// <summary>ignore·unignore가 찾은 항목.</summary>
    private sealed record IgnoreTarget(ScanScope Scope, string Id, string? Title, Severity? Severity, string? Category);

    /// <summary>
    /// 숨기기·되돌리기. 적은 ID가 정말 최근 검사 기록이나 보고서에 있는 항목인지 먼저 확인하고(오타를 조용히 저장하지 않아요),
    /// 어떤 항목인지 제목을 보여줘요. --scope를 적지 않으면 사용자 검사 기록, 그다음 관리자 검사 기록에서 찾아요.
    /// </summary>
    private static int ChangeIgnore(string command, List<string> list, string? dataDir, DataStore store, Output output, out bool showResult)
    {
        showResult = true;
        var scopeArg = TakeValue(list, "--scope")?.ToLowerInvariant();
        var input = list.FirstOrDefault(a => !a.StartsWith('-'));
        if (input is null)
        {
            output.Line($"ID를 적어 주세요. 예: SafetySecurity.exe {command} 1a2b3c4d5e6f7a8b");
            return 1;
        }

        var adminStore = AdminStore(store);
        ScanScope[] scopes = scopeArg switch
        {
            "admin" => [ScanScope.Admin],
            "user" => [ScanScope.User],
            _ => [ScanScope.User, ScanScope.Admin],
        };

        IgnoreTarget? target = null;
        var match = IdMatch.NotFound;
        foreach (var scope in scopes)
        {
            var s = scope == ScanScope.Admin ? adminStore : store;
            match = command == "ignore" ? FindToIgnore(input, scope, s, out target) : FindToUnignore(input, scope, s, out target);
            if (match != IdMatch.NotFound)
            {
                break;
            }
        }

        switch (match)
        {
            case IdMatch.Invalid:
                output.Line($"'{input}'은(는) ID 형식이 아니에요. 보고서에 적힌 16자리 ID(예: 1a2b3c4d5e6f7a8b)를 그대로 적어 주세요. 앞 {IgnoreList.MinPrefix}자리 이상만 적어도 돼요.");
                return 1;
            case IdMatch.Ambiguous:
                output.Line($"'{input}'(으)로 시작하는 항목이 여러 개예요. 보고서의 ID를 16자리 모두 적어 주세요. 아무것도 바꾸지 않았어요.");
                return 1;
            case IdMatch.NotFound:
                output.Line(command == "ignore"
                    ? $"'{input}': 최근 검사 기록과 보고서에서 이 ID를 찾지 못해서 아무것도 바꾸지 않았어요. 보고서에 적힌 ID를 그대로 적었는지 확인해 주세요."
                    : $"'{input}': 숨긴 항목 목록에 없어요. 숨긴 항목은 'SafetySecurity.exe ignored'로 볼 수 있어요.");
                return 1;
        }

        var t = target!;
        var label = Label(t);
        if (command == "ignore" && !output.Confirm(
                $"이 항목을 숨길까요?\n\n{label}\nID: {t.Id}\n\n숨겨도 파일·설정은 그대로예요 (SafetySecurity는 아무것도 지우거나 고치지 않아요). 보고서와 알림에서만 빠지고, 숨긴 뒤로 더 위험해지거나 같은 위치의 파일이 바뀌면 다시 보여줘요.",
                "SafetySecurity 항목 숨기기"))
        {
            store.Log($"ignore {t.Id}: 사용자가 취소했어요");
            showResult = false;
            return 1;
        }

        if (t.Scope == ScanScope.Admin && DataRoots.NeedsElevationToChangeAdminState(dataDir, Environment.IsPrivilegedProcess))
        {
            return ChangeAdminIgnore(command, t.Id, label, output);
        }

        var target2 = t.Scope == ScanScope.Admin ? adminStore : store;
        using (StateLock.Acquire(target2.StatePath(t.Scope), target2.Log))
        {
            // 검사가 저장하는 순간과 겹치지 않게, 잠금 안에서 최신 기록을 다시 읽고 바로 써요.
            if (target2.TryLoadState(t.Scope, out var state) == StateRead.Unreadable)
            {
                output.Line("검사 기록 파일을 지금 읽을 수 없어서 아무것도 바꾸지 않았어요. 잠시 뒤에 다시 해 주세요.");
                return 1;
            }

            var wasIgnored = state.Ignored.Contains(t.Id);
            var changed = command == "ignore"
                ? IgnoreList.Add(state, t.Id, t.Title, t.Category, DateTimeOffset.UtcNow)
                : IgnoreList.Remove(state, t.Id);
            if (changed)
            {
                target2.SaveState(t.Scope, state);
            }

            var where = t.Scope == ScanScope.Admin ? "관리자 검사" : "검사";
            var undo = $"SafetySecurity.exe unignore {t.Id}{(t.Scope == ScanScope.Admin ? " --scope admin" : string.Empty)}";
            output.Line(command switch
            {
                "ignore" when !changed => $"이미 숨긴 항목이에요: {label}",
                "ignore" when wasIgnored => $"다시 숨겼어요: {label}\n지금 상태를 새 기준으로 다음 {where}부터 숨겨요. 되돌리려면: {undo}",
                "ignore" => $"숨겼어요: {label}\n다음 {where}부터 보고서와 알림에서 빠져요. 숨긴 뒤로 더 위험해지거나 파일이 바뀌면 다시 보여줘요. 되돌리려면: {undo}",
                _ => $"다시 보여요: {label}\n다음 {where}부터 보고서에 나와요.",
            });
            return 0;
        }
    }

    private static string Label(IgnoreTarget t)
    {
        var sev = t.Severity is { } s ? $"[{s.ToKorean()}] " : string.Empty;
        var cat = t.Category is { } c ? $" ({Core.Reporting.HtmlReport.CategoryKorean(c)})" : string.Empty;
        return $"{sev}{t.Title ?? "(제목 없음)"}{cat}";
    }

    /// <summary>숨길 항목을 이 범위의 검사 기록에서 찾고, 없으면 최근 보고서에서 찾아요.</summary>
    private static IdMatch FindToIgnore(string input, ScanScope scope, DataStore s, out IgnoreTarget? target)
    {
        target = null;
        var state = s.LoadState(scope);
        var match = IgnoreList.Resolve(input, state.Baseline.Keys.Concat(state.Ignored), out var id);
        if (match == IdMatch.Found)
        {
            state.BaselineDetail.TryGetValue(id!, out var seen);
            state.IgnoredDetail.TryGetValue(id!, out var hidden);
            var title = seen?.Title ?? hidden?.Title;
            var severity = seen?.Severity ?? hidden?.Severity;
            var category = state.Baseline.TryGetValue(id!, out var c) ? c : hidden?.Category;
            if (title is null && s.RecentReports(scope, state.LastReportPath).SelectMany(d => d.Findings).FirstOrDefault(f => f.Id == id) is { } rf)
            {
                // 예전 버전이 쓴 기록에는 제목이 없어서 보고서에서 가져와요.
                title = rf.Title;
                severity ??= rf.Severity;
            }

            target = new IgnoreTarget(scope, id!, title, severity, category);
            return match;
        }

        if (match != IdMatch.NotFound)
        {
            return match;
        }

        // 지금은 없어진 항목도 예전 보고서에 있었다면 숨길 수 있어요 (다시 생겨도 보이지 않게).
        foreach (var doc in s.RecentReports(scope, state.LastReportPath))
        {
            var m = IgnoreList.Resolve(input, doc.Findings.Select(f => f.Id), out var rid);
            if (m == IdMatch.Found)
            {
                var f = doc.Findings.First(x => x.Id == rid);
                target = new IgnoreTarget(scope, rid!, f.Title, f.Severity, f.Category);
                return m;
            }

            if (m != IdMatch.NotFound)
            {
                return m;
            }
        }

        return IdMatch.NotFound;
    }

    /// <summary>되돌릴 항목을 이 범위의 숨김 목록에서 찾아요.</summary>
    private static IdMatch FindToUnignore(string input, ScanScope scope, DataStore s, out IgnoreTarget? target)
    {
        target = null;
        var state = s.LoadState(scope);
        var match = IgnoreList.Resolve(input, state.Ignored, out var id);
        if (match == IdMatch.Found)
        {
            state.IgnoredDetail.TryGetValue(id!, out var hidden);
            state.BaselineDetail.TryGetValue(id!, out var seen);
            target = new IgnoreTarget(scope, id!, hidden?.Title ?? seen?.Title, hidden?.Severity ?? seen?.Severity, hidden?.Category);
        }

        return match;
    }

    /// <summary>숨긴 항목 목록. 일반 권한에서도 관리자 검사 기록을 읽기만 해서 보여줘요.</summary>
    private static void ListIgnored(DataStore store, Output output)
    {
        var adminStore = AdminStore(store);
        var any = false;
        foreach (var scope in new[] { ScanScope.User, ScanScope.Admin })
        {
            var s = (scope == ScanScope.Admin ? adminStore : store).LoadState(scope);
            if (s.Ignored.Count == 0)
            {
                continue;
            }

            any = true;
            output.Line($"[{(scope == ScanScope.Admin ? "관리자" : "사용자")} 검사에서 숨긴 항목 {s.Ignored.Count}개]");
            foreach (var id in s.Ignored.OrderByDescending(i => s.IgnoredDetail.GetValueOrDefault(i)?.IgnoredUtc ?? DateTimeOffset.MinValue).ThenBy(i => i, StringComparer.Ordinal))
            {
                output.Line("  " + IgnoreList.Describe(id, s.IgnoredDetail.GetValueOrDefault(id)));
            }

            output.Line($"  다시 보이게 하려면: SafetySecurity.exe unignore <ID>{(scope == ScanScope.Admin ? " --scope admin" : string.Empty)}");
        }

        if (!any)
        {
            output.Line("숨긴 항목이 없어요. 보고서의 항목을 숨기려면: SafetySecurity.exe ignore <ID>");
        }
    }

    /// <summary>
    /// 관리자 검사의 무시 목록은 관리자만 쓸 수 있는 폴더에 있어서, 관리자 권한으로 다시 실행해서 바꿔요 (install --admin과 같은 방식).
    /// </summary>
    private static int ChangeAdminIgnore(string command, string id, string label, Output output)
    {
        if (!TaskInstaller.AdminInstallExists())
        {
            output.Line("관리자 설치가 없어서 관리자 검사 무시 목록도 없어요. 설치할 때 '관리자 권한으로'를 고르면 관리자 검사가 생겨요.");
            return 1;
        }

        // 다시 실행할 때 넘기는 인자는 우리가 만든 값만 써요. ID는 보고서의 16진수 ID 형식만 받아요.
        if (IgnoreList.Normalize(id) != id)
        {
            output.Line("ID 형식이 아니에요. 보고서에 적힌 ID(예: 1a2b3c4d5e6f7a8b)를 그대로 적어 주세요.");
            return 1;
        }

        output.Line("관리자 검사의 무시 목록은 관리자 권한으로만 바꿀 수 있어요. UAC 창에서 '예'를 눌러 주세요.");
        var code = TaskInstaller.Relaunch($"{command} {id.ToLowerInvariant()} --scope admin --quiet");
        output.Line(code == 0
            ? (command == "ignore" ? $"숨겼어요: {label}\n다음 관리자 검사부터 숨겨요. 되돌리려면: SafetySecurity.exe unignore {id} --scope admin" : $"다시 보여요: {label}\n관리자 검사에서 다시 보여요.")
            : "바꾸지 못했어요 (권한 요청을 취소했거나 오류가 났어요).");
        return code == 0 ? 0 : 1;
    }

    private static void Status(DataStore store, Output output)
    {
        output.Line($"SafetySecurity {Version}");
        output.Line("데이터 폴더: " + store.Root);

        // 관리자 검사 기록은 보호된 관리자 폴더에 있어요. 일반 권한에서도 읽기만 해서 보여줘요.
        var adminStore = store.IsExplicit || store.IsAdminRoot ? store : new DataStore(DataStore.AdminRoot);
        if (!ReferenceEquals(adminStore, store) && Directory.Exists(adminStore.Root))
        {
            output.Line("관리자 검사 데이터 폴더: " + adminStore.Root);
        }

        foreach (var scope in new[] { ScanScope.User, ScanScope.Admin })
        {
            var s = (scope == ScanScope.Admin ? adminStore : store).LoadState(scope);
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
                if (ScanSchedule.OverdueText(p, DateTimeOffset.UtcNow) is { } overdue)
                {
                    output.Line("  " + overdue);
                }
            }

            output.Line($"  숨긴 항목: {s.Ignored.Count}개 (목록: ignored), 베이스라인: {s.Baseline.Count}개");
            if (s.LastReportPath is not null)
            {
                output.Line("  마지막 보고서: " + s.LastReportPath);
            }
        }

        var tasks = TaskInstaller.ListInstalledTasks();
        output.Line(tasks.Count == 0 ? "등록된 작업: 없음 (install로 등록하세요)" : "등록된 작업: " + string.Join(", ", tasks));

        // 알림 설정은 읽기만 해요. 꺼져 있으면 자동 검사가 찾은 항목을 알려드릴 수 없어요.
        if (ToastNotifier.IsRegistered())
        {
            var state = ToastNotifier.ReadState();
            output.Line(state switch
            {
                NotificationState.Enabled => "알림: 켜져 있어요",
                NotificationState.Unknown => "알림: 설정을 읽지 못했어요",
                _ => "알림: " + (Advice.NotificationsOff(state) ?? "꺼져 있어요"),
            });
        }
    }
}
