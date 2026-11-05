using System.Text.Json;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>WMI 영구 이벤트 구독 (CommandLineEventConsumer, ActiveScriptEventConsumer). root\subscription은 보통 관리자만 읽을 수 있어서 관리자 작업에서 확인해요.</summary>
public sealed class WmiScanner : IScanner
{
    public const string CategoryName = "Wmi";

    public string Category => CategoryName;

    public string DisplayName => "WMI 영구 이벤트 구독";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.Admin && !quick;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        if (ctx.Wmi is null)
        {
            return [];
        }

        ctx.Pacer.Step(20);
        var json = ctx.Wmi.GetConsumersJson(out var error);
        if (json is null)
        {
            ctx.Coverage.Skipped("WMI 구독", error ?? "확인하지 못했어요.");
            return [];
        }

        return Analyze(json);
    }

    public static List<Finding> Analyze(string json)
    {
        var findings = new List<Finding>();
        if (string.IsNullOrWhiteSpace(json))
        {
            return findings;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return findings;
        }

        using (doc)
        {
            var items = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToList() : [doc.RootElement];
            foreach (var item in items)
            {
                if (item.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var cls = Str(item, "Class") ?? "?";
                var name = Str(item, "Name") ?? "(이름 없음)";
                var command = Str(item, "Command");
                var path = Str(item, "Path");
                var evidence = new List<KeyValuePair<string, string>> { new("종류", cls + "EventConsumer"), new("이름", name) };
                if (command is not null)
                {
                    evidence.Add(new(cls == "ActiveScript" ? "스크립트" : "명령줄", command.Length > 500 ? command[..500] + "…" : command));
                }

                if (path is not null)
                {
                    evidence.Add(new("파일", path));
                }

                findings.Add(new Finding
                {
                    RuleId = "WMI-001",
                    Category = CategoryName,
                    Severity = Severity.High,
                    Title = $"WMI 영구 구독이 명령을 실행해요: {name}",
                    Location = $@"root\subscription\{cls}EventConsumer.Name=""{name}""",
                    Target = path ?? command,
                    Reasons = ["WMI 이벤트가 생길 때마다 명령이나 스크립트가 실행돼요. 파일 없이 숨어 있는 악성코드가 자주 쓰는 지속성 수법이에요 (T1546.003)."],
                    Evidence = evidence,
                    Advice = Advice.Wmi,
                });
            }
        }

        return findings;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()) ? v.GetString() : null;
}
