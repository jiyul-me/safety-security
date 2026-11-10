using System.Net;
using System.Text;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>hosts 파일에서 보안·업데이트·주요 사이트를 막거나 다른 곳으로 보내는 줄을 찾아요.</summary>
public sealed class HostsScanner : IScanner
{
    public const string CategoryName = "Hosts";

    // 이 도메인(또는 하위 도메인)을 hosts로 바꾸는 건 거의 항상 악성이에요.
    private static readonly string[] SensitiveDomains =
    [
        "microsoft.com", "windowsupdate.com", "windows.com", "live.com", "office.com", "msftconnecttest.com",
        "google.com", "googleapis.com", "gstatic.com", "youtube.com", "gmail.com",
        "virustotal.com", "malwarebytes.com", "kaspersky.com", "avast.com", "avg.com", "eset.com", "norton.com", "bitdefender.com",
        "mcafee.com", "sophos.com", "ahnlab.com", "estsecurity.com", "alyac.co.kr", "trendmicro.com",
        "riotgames.com", "leagueoflegends.com", "playvalorant.com", "steampowered.com", "steamcommunity.com",
        "epicgames.com", "blizzard.com", "battle.net", "nexon.com", "ncsoft.com", "netmarble.com", "hoyoverse.com",
        "naver.com", "daum.net", "kakao.com", "github.com", "discord.com", "paypal.com", "toss.im",
        "shiftup.co.kr", "nikke-kr.com", "level-infinite.com", "proximabeta.com",
    ];

    // 위 도메인 가운데 하위 주소가 아주 많은 큰 포털·서비스. 여기서는 텔레메트리·광고 주소를 막은 줄을 '참고'로 낮춰요.
    // 보안 프로그램·업데이트·게임·결제 도메인은 하위 주소를 막아도 계속 '높음'이에요.
    private static readonly HashSet<string> PortalDomains = new(StringComparer.Ordinal)
    {
        "microsoft.com", "windows.com", "live.com", "office.com",
        "google.com", "googleapis.com", "gstatic.com", "youtube.com",
        "naver.com", "daum.net", "kakao.com",
    };

    // 이런 말이 들어간 주소는 업데이트·로그인·보안 기능이라, 텔레메트리처럼 보여도 낮추지 않아요.
    private static readonly string[] ProtectedWords =
    [
        "update", "upgrade", "download", "delivery", "login", "logon", "signin", "signup", "account", "auth", "passport", "secur",
        "defender", "smartscreen", "spynet", "wdcp", "definition", "safebrowsing", "connecttest", "ncsi", "activation", "licens",
        "ocsp", "crl", "pki", "cert",
    ];

    // 막아도 보안에는 영향이 없는 텔레메트리(사용 정보 전송)·광고 주소. Windows 최적화·광고 차단 목록이 흔히 넣어요.
    private static readonly string[] TrackingSuffixes = ["data.microsoft.com", "telemetry.microsoft.com", "aria.microsoft.com"];

    private static readonly string[] TrackingLabelPrefixes =
    [
        "telemetry", "vortex", "watson", "settings-win", "settings-sandbox", "adservice", "pagead", "adserver", "adsense", "adssettings",
        "doubleclick", "analytics", "tracking", "beacon", "stats", "metrics",
    ];

    private static readonly HashSet<string> TrackingLabels = new(StringComparer.Ordinal) { "ad", "ads", "sqm", "oca", "telecommand" };

    public string Category => CategoryName;

    public string DisplayName => "hosts 파일";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.User && !quick;

    /// <summary>한 번에 읽는 크기. 광고 차단 목록을 넣은 큰 hosts 파일도 보통 이보다 작아요.</summary>
    public const int MaxBytes = 4 * 1024 * 1024;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var path = ctx.Paths.System32 + @"\drivers\etc\hosts";
        var bytes = ctx.Files.ReadAll(path, MaxBytes);
        if (bytes is not null)
        {
            return Analyze(Encoding.UTF8.GetString(bytes), path);
        }

        if (!ctx.Files.FileExists(path))
        {
            // hosts 파일이 없으면 바뀐 주소도 없어요 (끝까지 확인한 거예요).
            return [];
        }

        // 너무 크면 앞부분만 확인해요. 읽은 만큼은 검사하되, 뒤쪽에 나쁜 줄이 있을 수 있어서 '일부만 확인'으로 남겨요.
        // (파일을 일부러 크게 부풀려 검사를 피하는 경우도 있어요.)
        var prefix = ctx.Files.ReadPrefix(path, MaxBytes);
        if (prefix is null)
        {
            ctx.Coverage.Incomplete(CategoryName, "hosts 파일", "파일을 읽지 못했어요 (잠겨 있거나 권한이 없어요).");
            return [];
        }

        var text = Encoding.UTF8.GetString(prefix);
        if (prefix.Length < MaxBytes)
        {
            // 앞부분 읽기가 파일 끝까지 읽었어요 (처음 읽을 때만 잠깐 잠겨 있었어요). 끝까지 확인한 거예요.
            return Analyze(text, path);
        }

        var lastLine = text.LastIndexOf('\n');
        if (lastLine >= 0)
        {
            // 잘린 마지막 줄은 버려요 (반쪽 주소를 잘못 읽지 않게).
            text = text[..lastLine];
        }

        ctx.Coverage.Incomplete(CategoryName, "hosts 파일", $"파일이 {MaxBytes / (1024 * 1024)}MB보다 커서 앞부분만 확인했어요. 메모장으로 열어 뒤쪽에 낯선 줄이 있는지 확인해 보세요.");
        return Analyze(text, path);
    }

    public static List<Finding> Analyze(string content, string path)
    {
        var findings = new List<Finding>();
        // 같은 줄(같은 IP·주소)이 여러 번 있어도 항목은 하나예요. 예전 버전이 쓰던 '줄 번호가 들어간 ID'는 모두 기억해요.
        var byTarget = new Dictionary<string, (Finding Finding, List<string> PreviousIds)>(StringComparer.OrdinalIgnoreCase);
        var lineNo = 0;
        foreach (var rawLine in content.Split('\n'))
        {
            lineNo++;
            var line = rawLine;
            var hash = line.IndexOf('#');
            if (hash >= 0)
            {
                line = line[..hash];
            }

            var parts = line.Split([' ', '\t', '\r'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                continue;
            }

            var ip = parts[0];
            var isBlock = ip is "0.0.0.0" or "127.0.0.1" or "::1" or "::" or "0:0:0:0:0:0:0:0";
            var isLoopbackish = isBlock || ip.StartsWith("127.", StringComparison.Ordinal);
            foreach (var host in parts.Skip(1))
            {
                var h = host.Trim().TrimEnd('.').ToLowerInvariant();
                if (h is "localhost" or "localhost.localdomain" or "local" or "broadcasthost" || h.Length == 0)
                {
                    continue;
                }

                var target = $"{ip} {h}";
                if (byTarget.TryGetValue(target, out var seen))
                {
                    seen.PreviousIds.Add(LegacyId(path, lineNo, target));
                    continue;
                }

                var sensitive = SensitiveDomains.FirstOrDefault(d => h == d || h.EndsWith("." + d, StringComparison.Ordinal));
                Severity severity;
                string reason;
                if (sensitive is not null && isLoopbackish && IsTrackingBlock(h, sensitive))
                {
                    // 텔레메트리·광고 주소를 0.0.0.0/127.0.0.1로 막은 줄. Windows 최적화 도구나 광고 차단 목록이 넣는 흔한 항목이에요.
                    severity = Severity.Info;
                    reason = $"'{h}'를 막아요. 텔레메트리(사용 정보 전송)·광고 주소라서 Windows 최적화 도구나 광고 차단 목록이 흔히 넣는 항목이에요. 보안 기능(업데이트·로그인·백신)과는 관계없어서 위험할 가능성은 낮아요.";
                }
                else if (sensitive is not null)
                {
                    severity = Severity.High;
                    reason = isLoopbackish
                        ? $"'{h}'를 막아요. 악성코드가 보안 프로그램·업데이트·주요 사이트 접속을 막을 때 쓰는 방법이에요."
                        : $"'{h}'를 다른 IP({ip})로 보내요. 가짜 사이트(피싱)로 유도하는 수법일 수 있어요.";
                }
                else if (!isLoopbackish && IPAddress.TryParse(ip, out var addr) && !IsPrivate(addr))
                {
                    severity = Severity.Low;
                    reason = $"'{h}'를 외부 IP({ip})로 고정해요.";
                }
                else
                {
                    // 광고 차단(0.0.0.0) 목록이나 개발용 사설 IP 항목은 흔해서 넘어가요.
                    continue;
                }

                // 위치에는 줄 번호를 넣지 않아요. 위에 줄이 늘거나 줄어도(Docker·VPN 도구가 줄을 더하는 등) ID가 그대로라서,
                // 숨긴 항목이 다시 나타나거나 같은 항목을 '새 항목'으로 다시 알리지 않아요. 줄 번호는 증거에만 적어요.
                var previous = new List<string> { LegacyId(path, lineNo, target) };
                var finding = new Finding
                {
                    RuleId = "HOST-001",
                    Category = CategoryName,
                    Severity = severity,
                    Title = $"hosts 파일이 {h}를 바꿔요",
                    Location = path,
                    Target = target,
                    Reasons = [reason],
                    Evidence = [new("줄 번호", lineNo.ToString(System.Globalization.CultureInfo.InvariantCulture)), new("내용", rawLine.Trim())],
                    Advice = Advice.Hosts,
                    PreviousIds = previous,
                };
                byTarget[target] = (finding, previous);
                findings.Add(finding);
            }
        }

        return findings;
    }

    /// <summary>예전 버전(위치에 줄 번호를 넣던 때)의 ID. 업데이트 뒤 베이스라인·숨김 목록을 새 ID로 옮길 때 써요.</summary>
    private static string LegacyId(string path, int lineNo, string target) =>
        Finding.ComputeId(CategoryName, $"{path}:{lineNo}", target);

    /// <summary>
    /// 큰 포털 도메인의 텔레메트리·광고 주소를 막은 줄인지. 도메인 자체(예: google.com, www.google.com)와
    /// 업데이트·로그인·보안 주소는 절대 낮추지 않아요. 확실한 텔레메트리·광고 주소만 골라요.
    /// </summary>
    private static bool IsTrackingBlock(string host, string domain)
    {
        if (!PortalDomains.Contains(domain) || host == domain || host == "www." + domain)
        {
            return false;
        }

        if (ProtectedWords.Any(w => host.Contains(w, StringComparison.Ordinal)))
        {
            return false;
        }

        if (TrackingSuffixes.Any(t => host == t || host.EndsWith("." + t, StringComparison.Ordinal)))
        {
            return true;
        }

        var labels = host[..^(domain.Length + 1)].Split('.');
        return labels.Any(l => TrackingLabels.Contains(l)
            || (l.Length > 2 && l.StartsWith("ad", StringComparison.Ordinal) && l[2..].All(char.IsAsciiDigit))
            || (l.Length > 3 && l.StartsWith("ads", StringComparison.Ordinal) && l[3..].All(char.IsAsciiDigit))
            || TrackingLabelPrefixes.Any(p => l.StartsWith(p, StringComparison.Ordinal)));
    }

    private static bool IsPrivate(IPAddress addr)
    {
        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
        }

        return addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal || addr.IsIPv6UniqueLocal;
    }
}
