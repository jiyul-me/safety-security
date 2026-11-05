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

    public string Category => CategoryName;

    public string DisplayName => "hosts 파일";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.User && !quick;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var path = ctx.Paths.System32 + @"\drivers\etc\hosts";
        var bytes = ctx.Files.ReadAll(path, 4 * 1024 * 1024);
        if (bytes is null)
        {
            return [];
        }

        return Analyze(Encoding.UTF8.GetString(bytes), path);
    }

    public static List<Finding> Analyze(string content, string path)
    {
        var findings = new List<Finding>();
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

                var sensitive = SensitiveDomains.FirstOrDefault(d => h == d || h.EndsWith("." + d, StringComparison.Ordinal));
                Severity severity;
                string reason;
                if (sensitive is not null)
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

                findings.Add(new Finding
                {
                    RuleId = "HOST-001",
                    Category = CategoryName,
                    Severity = severity,
                    Title = $"hosts 파일이 {h}를 바꿔요",
                    Location = $"{path}:{lineNo}",
                    Target = $"{ip} {h}",
                    Reasons = [reason],
                    Evidence = [new("줄 번호", lineNo.ToString(System.Globalization.CultureInfo.InvariantCulture)), new("내용", rawLine.Trim())],
                    Advice = Advice.Hosts,
                });
            }
        }

        return findings;
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
