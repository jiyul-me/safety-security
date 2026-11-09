using System.Text;
using System.Xml.Linq;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Install;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Scanners;

namespace SafetySecurity.Core.Tests;

/// <summary>
/// 끝까지 읽지 못한 분류는 '깨끗함'이 아니라 '일부만 확인'이어야 해요. 그래야 보고서가 정직하고,
/// 베이스라인이 읽지 못한 항목을 '없어짐'으로 지웠다가 다음 검사에서 '새 항목'으로 다시 알리지 않아요.
/// </summary>
public class PartialCoverageTests
{
    private const string Services = @"SYSTEM\CurrentControlSet\Services";
    private const string Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    private static string Task(string name, string command, string description = "") => $"""
<!-- {name} -->
<Task version="1.2" xmlns="{Ns}">
  <RegistrationInfo><Description>{description}</Description></RegistrationInfo>
  <Actions Context="Author"><Exec><Command>{command}</Command></Exec></Actions>
</Task>
""";

    private static string Tasks(params string[] tasks) => "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Tasks>\n" + string.Concat(tasks) + "</Tasks>\n";

    private static TestEnv EnvWithPublicExe()
    {
        var env = new TestEnv();
        env.Files.Add(@"C:\Users\Public\x.exe", TestEnv.FakePe());
        return env;
    }

    [Fact]
    public void ControlCharacterInOneTaskDoesNotHideTheOthers()
    {
        // 예전에는 문서 전체를 한 번에 읽어서, 설명에 &#x1;이 든 작업 하나 때문에 모든 작업이 사라졌어요.
        var env = EnvWithPublicExe();
        env.TasksXml = Tasks(Task(@"\Noise", @"C:\Windows\System32\notepad.exe", "a&#x1;b"), Task(@"\Evil", @"C:\Users\Public\x.exe"));
        var ctx = env.Context();
        var findings = new ScheduledTaskScanner().Scan(ctx).ToList();
        Assert.Contains(findings, f => f.Location == @"작업 스케줄러\Evil" && f.Severity >= Severity.Medium);
        Assert.Empty(ctx.Coverage.IncompleteCategories);
    }

    [Fact]
    public void TaskNameWithDoubleDashIsRead()
    {
        // "--"는 XML 주석 안에 쓸 수 없어서 예전 파서는 출력 전체를 버렸어요.
        var env = EnvWithPublicExe();
        env.TasksXml = Tasks(Task(@"\a--b", @"C:\Users\Public\x.exe"));
        var parsed = TaskXmlParser.ParseAll(env.TasksXml);
        Assert.Equal(@"\a--b", Assert.Single(parsed.Tasks).Name);
        Assert.Empty(parsed.Unreadable);
        Assert.Single(new ScheduledTaskScanner().Scan(env.Context()));
    }

    [Fact]
    public void BrokenTaskIsNamedAndTheCategoryIsPartial()
    {
        var env = EnvWithPublicExe();
        var broken = $"""
<!-- \Broken -->
<Task version="1.2" xmlns="{Ns}">
  <Actions Context="Author"><Exec><Command>C:\Users\Public\y.exe</Exec></Actions>
</Task>
""";
        env.TasksXml = Tasks(broken, Task(@"\Evil", @"C:\Users\Public\x.exe"));
        var parsed = TaskXmlParser.ParseAll(env.TasksXml);
        Assert.Equal([@"\Broken"], parsed.Unreadable);
        Assert.Single(parsed.Tasks);

        var result = ScanEngine.Run(env.Context(), [new ScheduledTaskScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Contains(result.Findings, f => f.Location == @"작업 스케줄러\Evil");
        Assert.DoesNotContain(ScheduledTaskScanner.CategoryName, result.CompletedCategories);
        Assert.Contains(ScheduledTaskScanner.CategoryName, result.PartialCategories);
        Assert.Contains(result.Coverage, c => c.Contains(@"\Broken", StringComparison.Ordinal));
        Assert.Contains(result.CompletedNames, n => n.Contains("일부만", StringComparison.Ordinal));
    }

    [Fact]
    public void TruncatedOutputCountsAsUnreadable()
    {
        var xml = Tasks(Task(@"\Ok", @"C:\Windows\System32\notepad.exe")) + $"<!-- \\Cut -->\n<Task version=\"1.2\" xmlns=\"{Ns}\"><Actions>";
        var parsed = TaskXmlParser.ParseAll(xml);
        Assert.Single(parsed.Tasks);
        Assert.Single(parsed.Unreadable);
    }

    [Fact]
    public void UnclosedTaskThatSwallowsTheNextOneCountsBoth()
    {
        var unclosed = $"""
<!-- \Unclosed -->
<Task version="1.2" xmlns="{Ns}">
  <Actions Context="Author"><Exec><Command>C:\Users\Public\y.exe</Command></Exec></Actions>
""";
        var parsed = TaskXmlParser.ParseAll(Tasks(unclosed, Task(@"\Next", @"C:\Users\Public\x.exe"), Task(@"\Last", @"C:\Windows\System32\notepad.exe")));
        Assert.Equal(2, parsed.Unreadable.Count);
        Assert.Equal(@"\Unclosed", parsed.Unreadable[0]);
        Assert.Equal([@"\Last"], parsed.Tasks.Select(t => t.Name));
    }

    [Fact]
    public void EmptyTaskListIsComplete()
    {
        var env = new TestEnv { TasksXml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Tasks>\n</Tasks>\n" };
        var result = ScanEngine.Run(env.Context(), [new ScheduledTaskScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Contains(ScheduledTaskScanner.CategoryName, result.CompletedCategories);
        Assert.Empty(result.PartialCategories);
        Assert.Empty(result.Coverage);
    }

    [Fact]
    public void UnreadableTaskListIsPartial()
    {
        var env = new TestEnv { TasksXml = null };
        var result = ScanEngine.Run(env.Context(), [new ScheduledTaskScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Contains(ScheduledTaskScanner.CategoryName, result.PartialCategories);
        Assert.DoesNotContain(ScheduledTaskScanner.CategoryName, result.CompletedCategories);
    }

    [Fact]
    public void LargeHostsFileIsScannedFromTheStartAndMarkedPartial()
    {
        var env = new TestEnv();
        const string path = @"C:\Windows\System32\drivers\etc\hosts";
        var sb = new StringBuilder("127.0.0.1 www.virustotal.com\r\n");
        while (sb.Length < HostsScanner.MaxBytes + 300_000)
        {
            sb.Append("0.0.0.0 ad-").Append(sb.Length).Append(".example.net\r\n");
        }

        env.Files.Add(path, Encoding.UTF8.GetBytes(sb.ToString()));
        var result = ScanEngine.Run(env.Context(), [new HostsScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        var f = Assert.Single(result.Findings, x => x.Target is not null && x.Target.Contains("virustotal", StringComparison.Ordinal));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Contains(HostsScanner.CategoryName, result.PartialCategories);
        Assert.Contains(result.Coverage, c => c.StartsWith("hosts 파일", StringComparison.Ordinal));
    }

    [Fact]
    public void NormalOrMissingHostsFileIsComplete()
    {
        var env = new TestEnv();
        var missing = ScanEngine.Run(env.Context(), [new HostsScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Contains(HostsScanner.CategoryName, missing.CompletedCategories);

        env.Files.Add(@"C:\Windows\System32\drivers\etc\hosts", Encoding.UTF8.GetBytes("127.0.0.1 localhost\r\n"));
        var normal = ScanEngine.Run(env.Context(), [new HostsScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Contains(HostsScanner.CategoryName, normal.CompletedCategories);
        Assert.Empty(normal.Coverage);
    }

    [Fact]
    public void UnreadableHostsFileIsPartial()
    {
        var env = new TestEnv();
        const string path = @"C:\Windows\System32\drivers\etc\hosts";
        env.Files.Add(path, Encoding.UTF8.GetBytes("127.0.0.1 www.virustotal.com\r\n"));
        var ctx = env.Context(files: new LockedFiles(env.Files, path));
        var result = ScanEngine.Run(ctx, [new HostsScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Empty(result.Findings);
        Assert.Contains(HostsScanner.CategoryName, result.PartialCategories);
        Assert.Contains(result.Coverage, c => c.Contains("읽지 못했어요", StringComparison.Ordinal));
    }

    [Fact]
    public void UnreadableOrBrokenWmiResultIsPartial()
    {
        var env = new TestEnv { WmiJson = null };
        var denied = ScanEngine.Run(env.Context(ScanScope.Admin, elevated: true), [new WmiScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Contains(WmiScanner.CategoryName, denied.PartialCategories);

        env.WmiJson = "{ not json";
        var broken = ScanEngine.Run(env.Context(ScanScope.Admin, elevated: true), [new WmiScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Contains(WmiScanner.CategoryName, broken.PartialCategories);

        env.WmiJson = "[]";
        var none = ScanEngine.Run(env.Context(ScanScope.Admin, elevated: true), [new WmiScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Contains(WmiScanner.CategoryName, none.CompletedCategories);
    }

    [Fact]
    public void UnreadableServiceListIsPartial()
    {
        var env = new TestEnv();
        var missing = ScanEngine.Run(env.Context(), [new ServiceScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Contains(ServiceScanner.CategoryName, missing.PartialCategories);

        env.Registry.Key(RegHive.LocalMachine, Services);
        var ok = ScanEngine.Run(env.Context(), [new ServiceScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Contains(ServiceScanner.CategoryName, ok.CompletedCategories);
    }

    [Fact]
    public void PartialCategoryKeepsOldBaselineEntriesAndAddsNewOnes()
    {
        var state = new ScanState { BaselineInitialized = true };
        var config = new ScanConfig();
        Finding T(string loc, Severity s = Severity.Medium) => new() { RuleId = "TASK-001", Category = ScheduledTaskScanner.CategoryName, Severity = s, Title = loc, Location = loc };

        // 1) 끝까지 검사: 작업 A, B를 기억해요.
        var full = Result(completed: true, T("A"), T("B"));
        BaselineEvaluator.Apply(full, state, config);
        Assert.Equal(2, state.Baseline.Count);

        // 2) 일부만 읽음: B를 못 읽었어요. B를 지우면 안 되고, 새로 본 C는 더해요.
        var partial = Result(completed: false, T("A"), T("C"));
        var d2 = BaselineEvaluator.Apply(partial, state, config);
        Assert.Equal(3, state.Baseline.Count);
        Assert.Contains(d2.ToNotify, f => f.Location == "C");

        // 3) 다시 제대로 읽음: B는 예전부터 있던 항목이라 '새 항목'으로 알리지 않아요.
        var again = Result(completed: true, T("A"), T("B"), T("C"));
        var d3 = BaselineEvaluator.Apply(again, state, config);
        Assert.Empty(d3.ToNotify);
        Assert.All(again.Findings, f => Assert.False(f.IsNew));
    }

    [Fact]
    public void CompletedCategoryStillDropsStaleEntries()
    {
        var state = new ScanState { BaselineInitialized = true };
        Finding T(string loc) => new() { RuleId = "TASK-001", Category = ScheduledTaskScanner.CategoryName, Severity = Severity.Medium, Title = loc, Location = loc };
        BaselineEvaluator.Apply(Result(true, T("A"), T("B")), state, new ScanConfig());
        BaselineEvaluator.Apply(Result(true, T("A")), state, new ScanConfig());
        Assert.Single(state.Baseline);
    }

    private static ScanResult Result(bool completed, params Finding[] findings)
    {
        var r = new ScanResult { StartedUtc = TestEnv.Now, Scope = ScanScope.User, Reason = ScanReason.Daily, Quick = false };
        r.Findings.AddRange(findings);
        (completed ? r.CompletedCategories : r.PartialCategories).Add(ScheduledTaskScanner.CategoryName);
        return r;
    }

    /// <summary>파일 하나만 잠겨 있는 것처럼 (있기는 한데 읽을 수 없어요).</summary>
    private sealed class LockedFiles(IFileSystemView inner, string locked) : IFileSystemView
    {
        private bool IsLocked(string path) => string.Equals(path, locked, StringComparison.OrdinalIgnoreCase);

        public bool FileExists(string path) => inner.FileExists(path);

        public bool DirectoryExists(string path) => inner.DirectoryExists(path);

        public FileMeta? GetMeta(string path) => inner.GetMeta(path);

        public IReadOnlyList<string> GetFiles(string directory) => inner.GetFiles(directory);

        public IReadOnlyList<string> GetDirectories(string directory) => inner.GetDirectories(directory);

        public byte[]? ReadPrefix(string path, int maxBytes) => IsLocked(path) ? null : inner.ReadPrefix(path, maxBytes);

        public byte[]? ReadAll(string path, long maxBytes) => IsLocked(path) ? null : inner.ReadAll(path, maxBytes);

        public string? Sha256(string path, long maxBytes) => IsLocked(path) ? null : inner.Sha256(path, maxBytes);
    }
}

/// <summary>범위(사용자·관리자)와 빠른 검사마다 어떤 스캐너가 도는지, 그리고 처음 보는 분류의 알림.</summary>
public class ScopeCoverageTests
{
    private const string Services = @"SYSTEM\CurrentControlSet\Services";

    private static TestEnv ReadableEnv()
    {
        var env = new TestEnv { TasksXml = "<Tasks/>", WmiJson = "[]" };
        env.Registry.Key(RegHive.LocalMachine, Services);
        env.Registry.Key(RegHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree");
        return env;
    }

    public static TheoryData<ScanScope, bool, string[]> Expected => new()
    {
        { ScanScope.User, false, ["ComHijack", "Autorun", "Service", "ScheduledTask", "Browser", "Defender", "Hosts", "Discord", "DroppedFile"] },
        { ScanScope.User, true, ["Service", "ScheduledTask"] },
        { ScanScope.Admin, false, ["HiddenTask", "Defender", "Wmi"] },

        // 관리자 설치의 예비 작업(ServiceInstalledAdmin)이 하는 빠른 검사: 새 서비스를 정말 확인해야 해요.
        { ScanScope.Admin, true, ["Service", "HiddenTask"] },
    };

    [Theory]
    [MemberData(nameof(Expected))]
    public void EachScopeRunsTheExpectedScanners(ScanScope scope, bool quick, string[] expected)
    {
        var env = ReadableEnv();
        var result = ScanEngine.Run(env.Context(scope, elevated: scope == ScanScope.Admin), ScanEngine.AllScanners(), ScanReason.Service, quick, () => TestEnv.Now);
        Assert.Equal(expected.Order(StringComparer.Ordinal), result.CompletedCategories.Concat(result.PartialCategories).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void AdminQuickScanFindsANewServiceFromAppData()
    {
        var env = ReadableEnv();
        const string exe = @"C:\Users\jiyul\AppData\Roaming\upd\svc.exe";
        env.Files.Add(exe, TestEnv.FakePe());
        env.Registry.Set(RegHive.LocalMachine, Services + @"\EvilSvc", "Type", 0x10);
        env.Registry.Set(RegHive.LocalMachine, Services + @"\EvilSvc", "Start", 2);
        env.Registry.Set(RegHive.LocalMachine, Services + @"\EvilSvc", "ImagePath", exe);
        var result = ScanEngine.Run(env.Context(ScanScope.Admin, elevated: true), ScanEngine.AllScanners(), ScanReason.Service, true, () => TestEnv.Now);
        Assert.Contains(result.Findings, f => f.Category == ServiceScanner.CategoryName && f.Target == exe && f.Severity >= Severity.Medium);
    }

    [Fact]
    public void AdminServiceTaskRunsTheQuickServiceScanElevated()
    {
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var t = TaskXmlBuilder.BuildAdminServiceTask(@"C:\Program Files\SafetySecurity\SafetySecurity.exe", "S-1-5-21-1");
        var doc = XDocument.Parse(t.Xml);
        var args = doc.Descendants(ns + "Arguments").Single().Value;
        Assert.Equal(OwnTasks.ServiceInstalledAdmin.Arguments, args);
        Assert.Contains("--quick", args, StringComparison.Ordinal);
        Assert.Contains("--reason service", args, StringComparison.Ordinal);
        Assert.Contains("--scope admin", args, StringComparison.Ordinal);
        Assert.Equal("HighestAvailable", doc.Descendants(ns + "RunLevel").Single().Value);
        Assert.Contains("EventID=7045", doc.Descendants(ns + "Subscription").Single().Value, StringComparison.Ordinal);

        // 이 인자로 실행하면 서비스 스캐너가 정말 돌아요.
        Assert.True(new ServiceScanner().RunsIn(ScanScope.Admin, quick: true));
        Assert.False(new ServiceScanner().RunsIn(ScanScope.Admin, quick: false));
    }

    private static Finding Svc(string loc, Severity s) => new()
    {
        RuleId = "SVC-001",
        Category = ServiceScanner.CategoryName,
        Severity = s,
        Title = loc,
        Location = loc,
    };

    private static ScanResult AdminQuick(params Finding[] findings)
    {
        var r = new ScanResult { StartedUtc = TestEnv.Now, Scope = ScanScope.Admin, Reason = ScanReason.Service, Quick = true };
        r.Findings.AddRange(findings);
        r.CompletedCategories.AddRange([ServiceScanner.CategoryName, HiddenTaskScanner.CategoryName]);
        return r;
    }

    [Fact]
    public void FirstAdminServiceScanOnAnOldAdminStateNotifiesOnlyHigh()
    {
        // 관리자 전체 검사는 서비스를 검사하지 않아서, 예전 관리자 기록에는 서비스 항목이 없어요.
        // 예비 작업이 처음 서비스를 검사할 때 기존 서비스가 모두 '새 항목' 알림으로 쏟아지면 안 돼요.
        var state = new ScanState { BaselineInitialized = true };
        state.Baseline["feedc0de12345678"] = HiddenTaskScanner.CategoryName;
        var config = new ScanConfig();
        var d1 = BaselineEvaluator.Apply(AdminQuick(Svc("old-medium", Severity.Medium), Svc("old-high", Severity.High)), state, config);
        Assert.Equal(["old-high"], d1.ToNotify.Select(f => f.Location));
        Assert.Contains(ServiceScanner.CategoryName, state.InitializedCategories!);

        // 그다음부터는 새로 생긴 서비스를 보통 위험도부터 알려요.
        var d2 = BaselineEvaluator.Apply(AdminQuick(Svc("old-medium", Severity.Medium), Svc("old-high", Severity.High), Svc("new-medium", Severity.Medium)), state, config);
        Assert.Equal(["new-medium"], d2.ToNotify.Select(f => f.Location));
    }

    [Fact]
    public void OldUserStateKeepsNotifyingNewMediumItems()
    {
        // 사용자 범위의 예전 기록은 전체 검사가 모든 분류를 이미 끝냈어요. 업데이트 뒤에도 보통 위험도 새 항목을 알려요.
        var state = new ScanState { BaselineInitialized = true };
        var r = new ScanResult { StartedUtc = TestEnv.Now, Scope = ScanScope.User, Reason = ScanReason.Service, Quick = true };
        r.Findings.Add(Svc("new-medium", Severity.Medium));
        r.CompletedCategories.Add(ServiceScanner.CategoryName);
        var d = BaselineEvaluator.Apply(r, state, new ScanConfig());
        Assert.Single(d.ToNotify);
    }

    [Fact]
    public void CategoryFirstSeenAfterInitializationNotifiesOnlyHigh()
    {
        var state = new ScanState { BaselineInitialized = true, InitializedCategories = ["Autorun"] };
        var r = new ScanResult { StartedUtc = TestEnv.Now, Scope = ScanScope.User, Reason = ScanReason.Daily, Quick = false };
        r.Findings.Add(Svc("medium", Severity.Medium));
        r.Findings.Add(new Finding { RuleId = "RUN-001", Category = "Autorun", Severity = Severity.Medium, Title = "run", Location = "run" });
        r.CompletedCategories.AddRange([ServiceScanner.CategoryName, "Autorun"]);
        var d = BaselineEvaluator.Apply(r, state, new ScanConfig());
        Assert.Equal(["run"], d.ToNotify.Select(f => f.Location));
        Assert.Contains(ServiceScanner.CategoryName, state.InitializedCategories!);
    }

    [Fact]
    public void PartialCategoryIsNotMarkedInitialized()
    {
        var state = new ScanState { BaselineInitialized = true, InitializedCategories = [] };
        var r = new ScanResult { StartedUtc = TestEnv.Now, Scope = ScanScope.User, Reason = ScanReason.Daily, Quick = false };
        r.PartialCategories.Add(ScheduledTaskScanner.CategoryName);
        BaselineEvaluator.Apply(r, state, new ScanConfig());
        Assert.DoesNotContain(ScheduledTaskScanner.CategoryName, state.InitializedCategories!);
    }

    [Fact]
    public void DefenderNoteDoesNotTellInstallerUsersToTypeACommand()
    {
        var env = new TestEnv();
        var ctx = env.Context();
        new DefenderScanner().Scan(ctx).ToList();
        var note = Assert.Single(ctx.Coverage.Notes, n => n.StartsWith("Defender 로컬", StringComparison.Ordinal));
        Assert.DoesNotContain("install --admin", note, StringComparison.Ordinal);
        Assert.Contains("설치할 때 '관리자 권한으로'를 고르면 확인해요", note, StringComparison.Ordinal);

        var withAdmin = new ScanContext
        {
            Registry = env.Registry,
            Files = env.Files,
            Signatures = env.Signatures,
            Classifier = new Rules.PathClassifier(TestEnv.Paths),
            Now = TestEnv.Now,
            AdminScanInstalled = true,
        };
        new DefenderScanner().Scan(withAdmin).ToList();
        var adminNote = Assert.Single(withAdmin.Coverage.Notes, n => n.StartsWith("Defender 로컬", StringComparison.Ordinal));
        Assert.Contains("관리자 검사", adminNote, StringComparison.Ordinal);
        Assert.DoesNotContain("install --admin", adminNote, StringComparison.Ordinal);

        // 관리자 권한이면 직접 읽어서 안내가 없어요.
        var elevated = env.Context(elevated: true);
        new DefenderScanner().Scan(elevated).ToList();
        Assert.DoesNotContain(elevated.Coverage.Notes, n => n.StartsWith("Defender 로컬 제외 목록:", StringComparison.Ordinal));
    }
}
