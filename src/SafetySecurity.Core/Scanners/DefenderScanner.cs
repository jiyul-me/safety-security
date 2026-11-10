using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>
/// Microsoft Defender를 끄는 정책과 제외 목록.
/// 정책 키는 일반 사용자도 읽을 수 있고, 로컬 제외 목록은 관리자만 읽을 수 있어요.
/// </summary>
public sealed class DefenderScanner : IScanner
{
    public const string CategoryName = "Defender";

    private static readonly string[] DangerousExtensions = ["exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "scr", "com", "hta", "msi", "lnk", "sys"];

    public string Category => CategoryName;

    public string DisplayName => "Microsoft Defender 설정";

    public bool RunsIn(ScanScope scope, bool quick) => !quick;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var findings = new List<Finding>();
        if (ctx.Scope == ScanScope.User)
        {
            ScanPolicies(ctx, findings);
            ScanExclusions(ctx, findings, @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions", "정책");
            if (!ctx.IsElevated)
            {
                ctx.Coverage.Skipped("Defender 로컬 제외 목록", LocalExclusionsNote(ctx.AdminScanInstalled));
            }
        }

        if (ctx.Scope == ScanScope.Admin || ctx.IsElevated)
        {
            ScanExclusions(ctx, findings, @"SOFTWARE\Microsoft\Windows Defender\Exclusions", "로컬");
        }

        return findings;
    }

    /// <summary>
    /// 사용자 검사가 로컬 제외 목록을 못 읽었을 때의 안내. 관리자 설치가 있으면 관리자 검사가 이미 확인하고,
    /// 없으면 설치 방식을 고르는 화면에서 '관리자 권한으로'를 고르면 확인한다고 알려요 (명령을 직접 치라고 하지 않아요).
    /// </summary>
    public static string LocalExclusionsNote(bool adminScanInstalled) => adminScanInstalled
        ? "관리자만 읽을 수 있어요. 관리자 검사(하루 한 번)에서 확인해요. 관리자 검사 보고서를 보세요."
        : "관리자만 읽을 수 있어요. 설치할 때 '관리자 권한으로'를 고르면 확인해요.";

    private static void ScanPolicies(ScanContext ctx, List<Finding> findings)
    {
        (string Path, string Value, string Meaning)[] checks =
        [
            (@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "Defender 자체를 끄는 정책"),
            (@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus", "Defender 바이러스 검사를 끄는 정책"),
            (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", "실시간 보호를 끄는 정책"),
            (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", "행위 감시를 끄는 정책"),
            (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", "파일 접근 검사를 끄는 정책"),
            (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableIOAVProtection", "다운로드 파일 검사를 끄는 정책"),
            (@"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "DisableBlockAtFirstSeen", "처음 보는 파일 차단을 끄는 정책"),
        ];

        foreach (var (path, value, meaning) in checks)
        {
            ctx.Pacer.Step();
            using var key = ctx.Registry.Open(RegHive.LocalMachine, path);
            if (key?.GetInt(value) != 1)
            {
                continue;
            }

            findings.Add(new Finding
            {
                RuleId = "DEF-001",
                Category = CategoryName,
                Severity = Severity.High,
                Title = $"Defender를 약하게 만드는 정책: {value}",
                Location = key.FullPath + "\\" + value,
                Target = "1",
                Reasons = [$"{meaning}이 켜져 있어요. 다른 백신을 쓰지 않는데 이 값이 있다면 악성코드가 넣었을 가능성이 높아요."],
                Evidence = [new(value, "1")],
                Advice = Advice.Defender,
            });
        }
    }

    private static void ScanExclusions(ScanContext ctx, List<Finding> findings, string basePath, string origin)
    {
        foreach (var kind in new[] { "Paths", "Processes", "Extensions" })
        {
            ctx.Pacer.Step();
            var path = basePath + "\\" + kind;
            using var key = ctx.Registry.Open(RegHive.LocalMachine, path);
            if (key is null)
            {
                if (ctx.Registry.IsAccessDenied(RegHive.LocalMachine, path))
                {
                    ctx.Coverage.Skipped($"Defender {origin} 제외 목록({kind})", "읽을 권한이 없어요.");
                }

                continue;
            }

            foreach (var item in key.GetValueNames())
            {
                if (string.IsNullOrWhiteSpace(item))
                {
                    continue;
                }

                var (severity, reason) = Assess(ctx, kind, item);
                findings.Add(new Finding
                {
                    RuleId = "DEF-002",
                    Category = CategoryName,
                    Severity = severity,
                    Title = $"Defender {origin} 제외 항목 ({KindKorean(kind)}): {item}",
                    Location = key.FullPath + "\\" + item,
                    Target = item,
                    Reasons = [reason],
                    Evidence = [new("종류", KindKorean(kind)), new("값", item)],
                    Advice = Advice.Defender,
                });
            }
        }
    }

    private static string KindKorean(string kind) => kind switch
    {
        "Paths" => "경로",
        "Processes" => "프로세스",
        _ => "확장자",
    };

    private static (Severity, string) Assess(ScanContext ctx, string kind, string item)
    {
        if (kind == "Extensions")
        {
            var ext = item.TrimStart('*', '.').ToLowerInvariant();
            return DangerousExtensions.Contains(ext)
                ? (Severity.High, $".{ext} 파일 전체가 검사에서 빠져요. 악성코드가 자기 자신을 숨기려고 넣는 설정이에요.")
                : (Severity.Medium, $".{ext} 파일이 검사에서 빠져요.");
        }

        var n = ctx.Classifier.Normalize(item.TrimEnd('*'));
        if (n.Length <= 3 || n == ctx.Classifier.Normalize(ctx.Paths.UserProfile) || n == ctx.Classifier.Normalize(ctx.Paths.AppData)
            || n == ctx.Classifier.Normalize(ctx.Paths.LocalAppData) || n == ctx.Classifier.Normalize(ctx.Paths.Temp)
            || n == ctx.Classifier.Normalize(ctx.Paths.ProgramData) || n == ctx.Classifier.Normalize(ctx.Paths.SystemRoot))
        {
            return (Severity.High, "드라이브 전체나 주요 폴더 전체가 검사에서 빠져요.");
        }

        var pathKind = ctx.Classifier.Classify(item);
        if (PathClassifier.IsUserWritable(pathKind))
        {
            return (Severity.High, $"{PathClassifier.ToKorean(pathKind)} 안의 경로가 검사에서 빠져요. 악성코드가 자주 쓰는 설정이에요.");
        }

        return (Severity.Medium, "이 경로·프로세스가 검사에서 빠져요. 직접 추가한 것인지 확인하세요.");
    }
}
