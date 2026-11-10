using System.Text.Json;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>
/// 브라우저 정책(강제 설치 확장 프로그램, 프록시), 시스템 프록시,
/// --load-extension 같은 인자가 붙은 브라우저 바로가기.
/// </summary>
public sealed class BrowserScanner : IScanner
{
    public const string CategoryName = "Browser";

    private static readonly (string Name, string PolicyPath, string StoreUpdateHost)[] Browsers =
    [
        ("Chrome", @"Software\Policies\Google\Chrome", "clients2.google.com"),
        ("Edge", @"Software\Policies\Microsoft\Edge", "edge.microsoft.com"),
        ("Brave", @"Software\Policies\BraveSoftware\Brave", "clients2.google.com"),
        ("Whale", @"Software\Policies\Naver\Whale", "store.whale.naver.com"),
    ];

    private static readonly HashSet<string> BrowserExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "msedge.exe", "brave.exe", "whale.exe", "firefox.exe", "opera.exe", "vivaldi.exe",
    };

    public string Category => CategoryName;

    public string DisplayName => "브라우저 정책·바로가기·프록시";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.User && !quick;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var findings = new List<Finding>();
        foreach (var hive in new[] { RegHive.LocalMachine, RegHive.CurrentUser })
        {
            foreach (var (name, policyPath, storeHost) in Browsers)
            {
                ctx.Pacer.Step();
                ScanPolicies(ctx, findings, hive, name, policyPath, storeHost);
            }
        }

        ScanSystemProxy(ctx, findings);
        ScanShortcuts(ctx, findings);
        return findings;
    }

    private static void ScanPolicies(ScanContext ctx, List<Finding> findings, RegHive hive, string browser, string policyPath, string storeHost)
    {
        using (var forced = ctx.Registry.Open(hive, policyPath + @"\ExtensionInstallForcelist"))
        {
            if (forced is not null)
            {
                foreach (var valueName in forced.GetValueNames())
                {
                    var value = forced.GetString(valueName);
                    if (string.IsNullOrWhiteSpace(value))
                    {
                        continue;
                    }

                    var parts = value.Split(';', 2);
                    var id = parts[0].Trim();
                    var updateUrl = parts.Length > 1 ? parts[1].Trim() : string.Empty;
                    var offStore = IsOffStore(updateUrl, storeHost);
                    findings.Add(new Finding
                    {
                        RuleId = "WEB-001",
                        Category = CategoryName,
                        Severity = offStore ? Severity.High : Severity.Medium,
                        Title = $"{browser}에 확장 프로그램이 정책으로 강제 설치돼요",
                        Location = forced.FullPath + "\\" + valueName,
                        Target = value,
                        Reasons = offStore
                            ? ["정책으로 강제 설치되는 확장 프로그램이고, 공식 웹 스토어가 아닌 곳에서 업데이트돼요. 사용자가 지울 수 없어요."]
                            : ["정책으로 강제 설치되는 확장 프로그램이에요. 사용자가 지울 수 없어서 악성 확장 프로그램이 자주 쓰는 방식이에요."],
                        Evidence = [new("확장 프로그램 ID", id), new("업데이트 주소", updateUrl.Length > 0 ? updateUrl : "(없음)")],
                        Advice = Advice.Browser,
                    });
                }
            }
        }

        using var policy = ctx.Registry.Open(hive, policyPath);
        if (policy is null)
        {
            return;
        }

        foreach (var proxyValue in new[] { "ProxyServer", "ProxyPacUrl", "ProxySettings" })
        {
            var v = policy.GetString(proxyValue);
            if (string.IsNullOrWhiteSpace(v))
            {
                continue;
            }

            findings.Add(new Finding
            {
                RuleId = "WEB-002",
                Category = CategoryName,
                Severity = Severity.Medium,
                Title = $"{browser} 프록시가 정책으로 고정돼 있어요",
                Location = policy.FullPath + "\\" + proxyValue,
                Target = v,
                Reasons = ["브라우저 트래픽이 정책으로 지정된 프록시를 거쳐요. 회사·학교 PC가 아니라면 트래픽을 가로채려는 설정일 수 있어요."],
                Evidence = [new(proxyValue, v)],
                Advice = Advice.Browser,
            });
        }

        ScanExtensionSettings(ctx, findings, policy, browser, storeHost);
    }

    /// <summary>
    /// ExtensionSettings 정책: 정책 키의 JSON 문자열 값(공식 형식)과, 확장 프로그램 ID마다 하위 키를 둔 형식을 모두 읽어요.
    /// installation_mode가 force_installed·normal_installed인 항목만 보고해요. blocked·allowed 같은 제한은 정상적인 관리 설정이에요.
    /// </summary>
    private static void ScanExtensionSettings(ScanContext ctx, List<Finding> findings, IRegistryKeyView policy, string browser, string storeHost)
    {
        var location = policy.FullPath + @"\ExtensionSettings";
        var json = policy.GetString("ExtensionSettings");
        if (!string.IsNullOrWhiteSpace(json))
        {
            var entries = ParseExtensionSettings(json);
            if (entries is null)
            {
                // JSON 형식이 깨졌어요. 브라우저가 무시할 수도 있지만, 설치 설정이 들어 있으면 알려요.
                if (json.Contains("force_installed", StringComparison.OrdinalIgnoreCase) || json.Contains("normal_installed", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(ExtensionSettingsFinding(browser, location, "(JSON 형식 오류)", "force_installed", null, storeHost,
                        "ExtensionSettings 정책 값의 JSON 형식이 올바르지 않지만 확장 프로그램 설치 설정(force_installed/normal_installed)이 들어 있어요."));
                }
            }
            else
            {
                foreach (var (id, mode, updateUrl) in entries)
                {
                    if (IsInstallMode(mode))
                    {
                        findings.Add(ExtensionSettingsFinding(browser, location, id, mode!, updateUrl, storeHost, null));
                    }
                }
            }
        }

        using var settings = policy.OpenSubKey("ExtensionSettings");
        if (settings is null)
        {
            return;
        }

        foreach (var id in settings.GetSubKeyNames())
        {
            ctx.Pacer.Step();
            using var sub = settings.OpenSubKey(id);
            var mode = sub?.GetString("installation_mode")?.Trim();
            if (sub is null || !IsInstallMode(mode))
            {
                continue;
            }

            findings.Add(ExtensionSettingsFinding(browser, sub.FullPath, id, mode!, sub.GetString("update_url")?.Trim(), storeHost, null));
        }
    }

    /// <summary>ExtensionSettings JSON에서 (ID, installation_mode, update_url)을 꺼내요. JSON이 아니면 null이에요.</summary>
    public static List<(string Id, string? Mode, string? UpdateUrl)>? ParseExtensionSettings(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var result = new List<(string, string?, string?)>();
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                result.Add((property.Name, Str(property.Value, "installation_mode"), Str(property.Value, "update_url")));
            }

            return result;
        }
        catch (JsonException)
        {
            return null;
        }

        static string? Str(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()?.Trim() : null;
    }

    private static bool IsInstallMode(string? mode) =>
        string.Equals(mode, "force_installed", StringComparison.OrdinalIgnoreCase) || string.Equals(mode, "normal_installed", StringComparison.OrdinalIgnoreCase);

    private static Finding ExtensionSettingsFinding(string browser, string location, string id, string mode, string? updateUrl, string storeHost, string? reason)
    {
        var offStore = IsOffStore(updateUrl, storeHost);
        var forced = mode.Equals("force_installed", StringComparison.OrdinalIgnoreCase);
        var reasons = new List<string>
        {
            reason ?? (forced
                ? "ExtensionSettings 정책으로 확장 프로그램을 강제 설치해요 (force_installed). 사용자가 지울 수 없어서 악성 확장 프로그램이 자주 쓰는 방식이에요."
                : "ExtensionSettings 정책으로 확장 프로그램을 자동 설치해요 (normal_installed)."),
        };
        if (offStore)
        {
            reasons.Add("공식 웹 스토어가 아닌 곳에서 설치·업데이트돼요.");
        }

        var ids = string.Join(", ", id.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return new Finding
        {
            RuleId = "WEB-003",
            Category = CategoryName,
            Severity = offStore ? Severity.High : Severity.Medium,
            Title = $"{browser} ExtensionSettings 정책으로 확장 프로그램을 설치해요",
            Location = location,
            Target = ids,
            Reasons = reasons,
            Evidence = [new("확장 프로그램 ID", ids), new("installation_mode", mode), new("업데이트 주소", string.IsNullOrEmpty(updateUrl) ? "(없음)" : updateUrl)],
            Advice = Advice.Browser,
        };
    }

    /// <summary>
    /// 업데이트 주소가 공식 웹 스토어가 아닌지. 주소의 호스트 이름이 스토어 호스트와 정확히 같아야 해요
    /// (https://evil.example/clients2.google.com/... 이나 clients2.google.com.evil.example 은 스토어가 아니에요).
    /// 주소가 없으면 스토어에서 받아요. 주소 형식이 아니면 스토어가 아닌 것으로 봐요.
    /// </summary>
    public static bool IsOffStore(string? updateUrl, string storeHost)
    {
        if (string.IsNullOrWhiteSpace(updateUrl))
        {
            return false;
        }

        var url = updateUrl.Trim();
        if (!url.Contains("://", StringComparison.Ordinal))
        {
            // 'clients2.google.com/service/update2/crx'처럼 https://를 빼고 쓴 주소
            url = "https://" + url;
        }

        return !Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Host, storeHost, StringComparison.OrdinalIgnoreCase);
    }

    private static void ScanSystemProxy(ScanContext ctx, List<Finding> findings)
    {
        using var key = ctx.Registry.Open(RegHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
        if (key is null)
        {
            return;
        }

        var pac = key.GetString("AutoConfigURL")?.Trim();
        if (!string.IsNullOrEmpty(pac))
        {
            var local = IsLocal(pac);
            findings.Add(new Finding
            {
                RuleId = "WEB-004",
                Category = CategoryName,
                Severity = local ? Severity.Low : Severity.Medium,
                Title = "시스템 프록시 자동 구성(PAC) 주소가 설정돼 있어요",
                Location = key.FullPath + "\\AutoConfigURL",
                Target = pac,
                Reasons = [local ? "PAC 파일이 이 PC 안에 있어요 (VPN·보안 프로그램일 수 있어요)." : "외부 PAC 주소로 모든 웹 트래픽 경로를 정해요. 트래픽 가로채기에 쓰일 수 있어요."],
                Evidence = [new("AutoConfigURL", pac)],
                Advice = Advice.Browser,
            });
        }

        var enabled = key.GetInt("ProxyEnable") == 1;
        var server = key.GetString("ProxyServer")?.Trim();
        if (enabled && !string.IsNullOrEmpty(server))
        {
            var local = IsLocal(server);
            findings.Add(new Finding
            {
                RuleId = "WEB-005",
                Category = CategoryName,
                Severity = local ? Severity.Low : Severity.Medium,
                Title = "시스템 프록시가 켜져 있어요",
                Location = key.FullPath + "\\ProxyServer",
                Target = server,
                Reasons = [local ? "이 PC 안의 프록시(127.0.0.1 등)를 써요. 개발 도구·VPN·광고 차단기일 수 있지만 악성코드도 써요." : "외부 프록시 서버로 웹 트래픽이 지나가요."],
                Evidence = [new("ProxyServer", server)],
                Advice = Advice.Browser,
            });
        }
    }

    private static bool IsLocal(string address)
    {
        var a = address.ToLowerInvariant();
        return a.Contains("127.0.0.1", StringComparison.Ordinal) || a.Contains("localhost", StringComparison.Ordinal) || a.StartsWith("file:", StringComparison.Ordinal) || a.Contains("[::1]", StringComparison.Ordinal);
    }

    private static void ScanShortcuts(ScanContext ctx, List<Finding> findings)
    {
        var folders = new List<string>
        {
            ctx.Paths.UserProfile + @"\Desktop",
            ctx.Paths.Public + @"\Desktop",
            ctx.Paths.AppData + @"\Microsoft\Windows\Start Menu\Programs",
            ctx.Paths.ProgramData + @"\Microsoft\Windows\Start Menu\Programs",
            ctx.Paths.AppData + @"\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar",
            ctx.Paths.AppData + @"\Microsoft\Internet Explorer\Quick Launch",
        };

        var unresolved = 0;
        foreach (var folder in folders)
        {
            foreach (var file in ctx.Files.GetFiles(folder))
            {
                if (!file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                ctx.Pacer.Step();
                var bytes = ctx.Files.ReadPrefix(file, LnkParser.MaxReadBytes);
                var link = bytes is null ? null : LnkParser.Parse(bytes);
                if (link?.Arguments is null)
                {
                    continue;
                }

                var target = ShortcutTargets.Primary(ctx, ShortcutTargets.Candidates(ctx, link, file));
                if (target is null)
                {
                    if (!link.IsAdvertised)
                    {
                        unresolved++;
                    }

                    continue;
                }

                var exe = Path.GetFileName(target.Replace('\\', '/'));
                if (!BrowserExecutables.Contains(exe))
                {
                    continue;
                }

                var args = link.Arguments;
                var reasons = new List<string>();
                var severity = Severity.Info;
                if (args.Contains("--load-extension", StringComparison.OrdinalIgnoreCase))
                {
                    severity = Severity.High;
                    reasons.Add("브라우저 바로가기에 --load-extension이 붙어 있어요. 몰래 확장 프로그램을 불러오는 수법이에요.");
                }

                if (args.Contains("--remote-debugging", StringComparison.OrdinalIgnoreCase) || args.Contains("--disable-web-security", StringComparison.OrdinalIgnoreCase))
                {
                    severity = Severity.High;
                    reasons.Add("원격 디버깅·보안 끄기 옵션이 붙어 있어요. 쿠키·세션 탈취에 쓰일 수 있어요.");
                }

                if (System.Text.RegularExpressions.Regex.IsMatch(args, @"(^|\s)""?https?://", System.Text.RegularExpressions.RegexOptions.IgnoreCase) && severity < Severity.Medium)
                {
                    severity = Severity.Medium;
                    reasons.Add("바로가기가 특정 웹 주소를 강제로 열어요 (시작 페이지 변경형 애드웨어 수법).");
                }

                if (severity == Severity.Info)
                {
                    continue;
                }

                findings.Add(new Finding
                {
                    RuleId = "WEB-006",
                    Category = CategoryName,
                    Severity = severity,
                    Title = $"브라우저 바로가기에 이상한 인자가 있어요: {Path.GetFileName(file.Replace('\\', '/'))}",
                    Location = file,
                    Target = target + " " + args,
                    Reasons = reasons,
                    Evidence = [new("바로가기 대상", target), new("인자", args)],
                    Advice = "바로가기를 오른쪽 클릭 → 속성 → '대상' 칸에서 .exe 뒤에 붙은 내용을 확인하세요. 의심되면 바로가기를 지우고 새로 만드세요. " + Advice.Browser,
                });
            }
        }

        if (unresolved > 0)
        {
            ctx.Coverage.Skipped("브라우저 바로가기", $"인자가 붙은 바로가기 {unresolved}개는 대상을 해석하지 못해서 브라우저 인자를 확인하지 못했어요.");
        }
    }
}
