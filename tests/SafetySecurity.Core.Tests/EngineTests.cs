using System.Xml.Linq;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Install;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Tests;

public class EngineTests
{
    private static Finding F(string cat, string loc, Severity s) => new()
    {
        RuleId = "T-1",
        Category = cat,
        Severity = s,
        Title = "t",
        Location = loc,
    };

    private static ScanResult Result(bool quick, params Finding[] findings)
    {
        var r = new ScanResult { StartedUtc = TestEnv.Now, Scope = ScanScope.User, Reason = ScanReason.Daily, Quick = quick };
        r.Findings.AddRange(findings);
        r.CompletedCategories.AddRange(findings.Select(f => f.Category).Distinct());
        return r;
    }

    [Fact]
    public void FirstRunNotifiesOnlyHigh_ThenOnlyNew()
    {
        var state = new ScanState();
        var config = new ScanConfig();
        var d1 = BaselineEvaluator.Apply(Result(false, F("A", "1", Severity.High), F("A", "2", Severity.Medium)), state, config);
        Assert.True(d1.FirstRun);
        Assert.Single(d1.ToNotify);
        Assert.True(state.BaselineInitialized);

        var r2 = Result(false, F("A", "1", Severity.High), F("A", "2", Severity.Medium), F("A", "3", Severity.Medium), F("A", "4", Severity.Low));
        var d2 = BaselineEvaluator.Apply(r2, state, config);
        Assert.False(d2.FirstRun);
        var n = Assert.Single(d2.ToNotify);
        Assert.Equal("3", n.Location);
        Assert.Equal(2, r2.Findings.Count(f => f.IsNew));
    }

    [Fact]
    public void IgnoredFindingsAreHidden()
    {
        var state = new ScanState { BaselineInitialized = true };
        var f = F("A", "1", Severity.High);
        state.Ignored.Add(f.Id);
        var r = Result(false, f);
        var d = BaselineEvaluator.Apply(r, state, new ScanConfig());
        Assert.Empty(r.Findings);
        Assert.Equal(1, r.IgnoredCount);
        Assert.Empty(d.ToNotify);
    }

    [Fact]
    public void QuickScanOnlyUpdatesItsCategories()
    {
        var state = new ScanState { BaselineInitialized = true };
        state.Baseline[F("ComHijack", "x", Severity.High).Id] = "ComHijack";
        BaselineEvaluator.Apply(Result(true, F("Service", "s", Severity.Medium)), state, new ScanConfig());
        Assert.Equal(2, state.Baseline.Count);
    }

    [Fact]
    public void IdIsStableAndCaseInsensitive()
    {
        Assert.Equal(Finding.ComputeId("A", @"HKCU\X", @"C:\a.dll"), Finding.ComputeId("A", @"hkcu\x", @"c:\A.DLL"));
        Assert.NotEqual(Finding.ComputeId("A", @"HKCU\X", @"C:\a.dll"), Finding.ComputeId("A", @"HKCU\X", @"C:\b.dll"));
    }

    [Fact]
    public void EngineStopsOnAbortAndSurvivesErrors()
    {
        var env = new TestEnv();
        var ctx = env.Context();
        var result = ScanEngine.Run(ctx, [new Throwing(), new Aborting(), new Throwing()], ScanReason.Manual, false, () => TestEnv.Now);
        Assert.True(result.Aborted);
        Assert.Single(result.Coverage);
    }

    [Fact]
    public void FullEngineRunOnEmptyMachineFindsNothing()
    {
        var env = new TestEnv { TasksXml = "<Tasks/>" };
        var result = ScanEngine.Run(env.Context(), ScanEngine.AllScanners(), ScanReason.Manual, false, () => TestEnv.Now);
        Assert.Empty(result.Findings);
        Assert.False(result.Aborted);
        Assert.Contains("ComHijack", result.CompletedCategories);
    }

    [Fact]
    public void SignatureCacheAvoidsRepeatChecks()
    {
        var env = new TestEnv();
        env.Files.Add(@"C:\a.dll");
        var cache = new Dictionary<string, CachedSignature>();
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, cache, () => TestEnv.Now);
        v.Verify(@"C:\a.dll");
        v.Verify(@"C:\a.dll");
        Assert.Equal(1, env.Signatures.Calls);
        Assert.Equal(1, v.Hits);
    }

    private sealed class Throwing : IScanner
    {
        public string Category => "T";
        public string DisplayName => "T";
        public bool RunsIn(ScanScope scope, bool quick) => true;
        public IEnumerable<Finding> Scan(ScanContext ctx) => throw new InvalidOperationException("boom");
    }

    private sealed class Aborting : IScanner
    {
        public string Category => "A";
        public string DisplayName => "A";
        public bool RunsIn(ScanScope scope, bool quick) => true;
        public IEnumerable<Finding> Scan(ScanContext ctx) => throw new ScanAbortedException("게임 시작");
    }
}

public class ReportTests
{
    [Fact]
    public void HtmlEncodesHostileStrings()
    {
        var doc = new ReportDocument
        {
            Findings =
            [
                new ReportFinding
                {
                    Id = "x",
                    Title = "<script>alert(1)</script>",
                    Location = "HKCU\\\"><img src=x onerror=alert(1)>",
                    Target = "invoice\u202Efdp.exe",
                    Severity = Severity.High,
                    Reasons = ["a&b"],
                    Evidence = [new EvidenceItem { Key = "k", Value = "\u0001" }],
                },
            ],
        };
        var html = HtmlReport.Render(doc);
        Assert.DoesNotContain("<script>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<img", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("[U+202E]", html, StringComparison.Ordinal);
        Assert.Contains("\\x01", html, StringComparison.Ordinal);
        Assert.Contains("default-src 'none'", html, StringComparison.Ordinal);
    }

    [Fact]
    public void JsonRoundTripsWithKorean()
    {
        var state = new ScanState { Pending = new PendingScan { Reason = ScanReason.Daily, DeferredBecause = "게임 중" } };
        state.Baseline["a"] = "ComHijack";
        var json = System.Text.Json.JsonSerializer.Serialize(state, SafetyJson.Context.ScanState);
        Assert.Contains("게임 중", json, StringComparison.Ordinal);
        Assert.Contains("\"Daily\"", json, StringComparison.Ordinal);
        var back = System.Text.Json.JsonSerializer.Deserialize(json, SafetyJson.Context.ScanState)!;
        Assert.Equal(ScanReason.Daily, back.Pending!.Reason);
        Assert.Equal("ComHijack", back.Baseline["a"]);
    }
}

public class TaskXmlBuilderTests
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    [Fact]
    public void BuildsFourLowPriorityUserTasks()
    {
        var tasks = TaskXmlBuilder.BuildUserTasks(@"C:\Users\jiyul\AppData\Local\Programs\SafetySecurity\SafetySecurity.exe", "S-1-5-21-1-2-3-1001", @"PC\jiyul", new DateTime(2026, 11, 5, 10, 0, 0));
        Assert.Equal(["Logon", "Daily", "ServiceInstalled", "Retry"], tasks.Select(t => t.Name));
        foreach (var t in tasks)
        {
            Assert.StartsWith("<?xml version=\"1.0\" encoding=\"utf-16\"?>", t.Xml, StringComparison.OrdinalIgnoreCase);
            var doc = XDocument.Parse(t.Xml);
            var settings = doc.Root!.Element(Ns + "Settings")!;
            Assert.Equal("7", settings.Element(Ns + "Priority")!.Value);
            Assert.Equal("PT15M", settings.Element(Ns + "ExecutionTimeLimit")!.Value);
            Assert.Equal("IgnoreNew", settings.Element(Ns + "MultipleInstancesPolicy")!.Value);
            Assert.Equal("LeastPrivilege", doc.Descendants(Ns + "RunLevel").Single().Value);
            Assert.StartsWith("\"C:\\", doc.Descendants(Ns + "Command").Single().Value, StringComparison.Ordinal);
        }

        var service = XDocument.Parse(tasks[2].Xml);
        var subscription = service.Descendants(Ns + "Subscription").Single().Value;
        Assert.Contains("EventID=7045", subscription, StringComparison.Ordinal);
        Assert.Contains("--quick", service.Descendants(Ns + "Arguments").Single().Value, StringComparison.Ordinal);
        Assert.Contains("<Interval>PT30M</Interval>", tasks[3].Xml, StringComparison.Ordinal);
    }

    [Fact]
    public void AdminTaskIsElevated()
    {
        var t = TaskXmlBuilder.BuildAdminTask(@"C:\Program Files\SafetySecurity\SafetySecurity.exe", "S-1-5-21-1", @"PC\u", DateTime.Now);
        var doc = XDocument.Parse(t.Xml);
        Assert.Equal("HighestAvailable", doc.Descendants(Ns + "RunLevel").Single().Value);
        Assert.Contains("--scope admin", doc.Descendants(Ns + "Arguments").Single().Value, StringComparison.Ordinal);
    }
}
