using System.Text.Json.Serialization;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Reporting;

public sealed class ReportDocument
{
    public string Tool { get; set; } = "SafetySecurity";

    public string Version { get; set; } = "0.0.0";

    public string? Computer { get; set; }

    public DateTimeOffset StartedUtc { get; set; }

    public DateTimeOffset FinishedUtc { get; set; }

    public ScanScope Scope { get; set; }

    public ScanReason Reason { get; set; }

    public bool Quick { get; set; }

    public bool Aborted { get; set; }

    public string? AbortReason { get; set; }

    public bool FirstRun { get; set; }

    public int IgnoredCount { get; set; }

    public List<string> Completed { get; set; } = [];

    public List<string> Coverage { get; set; } = [];

    public List<ReportFinding> Findings { get; set; } = [];

    public static ReportDocument From(ScanResult result, NotifyDecision decision, string version, string? computer) => new()
    {
        Version = version,
        Computer = computer,
        StartedUtc = result.StartedUtc,
        FinishedUtc = result.FinishedUtc,
        Scope = result.Scope,
        Reason = result.Reason,
        Quick = result.Quick,
        Aborted = result.Aborted,
        AbortReason = result.AbortReason,
        FirstRun = decision.FirstRun,
        IgnoredCount = result.IgnoredCount,
        Completed = [.. result.CompletedNames],
        Coverage = [.. result.Coverage],
        Findings = [.. result.Findings.Select(ReportFinding.From)],
    };
}

public sealed class ReportFinding
{
    public string Id { get; set; } = string.Empty;

    public string RuleId { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public Severity Severity { get; set; }

    public bool IsNew { get; set; }

    public string Title { get; set; } = string.Empty;

    public string Location { get; set; } = string.Empty;

    public string? Target { get; set; }

    public List<string> Reasons { get; set; } = [];

    public List<EvidenceItem> Evidence { get; set; } = [];

    public string? Advice { get; set; }

    public static ReportFinding From(Finding f) => new()
    {
        Id = f.Id,
        RuleId = f.RuleId,
        Category = f.Category,
        Severity = f.Severity,
        IsNew = f.IsNew,
        Title = f.Title,
        Location = f.Location,
        Target = f.Target,
        Reasons = [.. f.Reasons],
        Evidence = [.. f.Evidence.Select(e => new EvidenceItem { Key = e.Key, Value = e.Value })],
        Advice = f.Advice,
    };
}

public sealed class EvidenceItem
{
    public string Key { get; set; } = string.Empty;

    public string Value { get; set; } = string.Empty;
}

[JsonSourceGenerationOptions(WriteIndented = true, UseStringEnumConverter = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ReportDocument))]
[JsonSerializable(typeof(ScanState))]
[JsonSerializable(typeof(ScanConfig))]
[JsonSerializable(typeof(Dictionary<string, CachedSignature>))]
public sealed partial class SafetyJsonContext : JsonSerializerContext;
