using System.Text;
using System.Xml.Linq;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Install;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Rules;
using SafetySecurity.Core.Scanners;

namespace SafetySecurity.Core.Tests;

/// <summary>검사기 자신을 지키는 검사: 우리 작업은 이름이 아니라 동작으로 확인하고, 이름을 흉내 낸 작업과 꺼진 작업을 알려요.</summary>
public class OwnTaskTests
{
    private const string UserExe = @"C:\Users\jiyul\AppData\Local\Programs\SafetySecurity\SafetySecurity.exe";
    private const string AdminExe = @"C:\Program Files\SafetySecurity\SafetySecurity.exe";
    private const string Sid = "S-1-5-21-1-2-3-1001";
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
    private static readonly DateTime Now = new(2026, 11, 5, 10, 0, 0);

    /// <summary>schtasks /query /xml ONE 출력처럼 작업마다 이름 주석을 붙여 하나로 묶어요.</summary>
    private static string Query(params (string Name, string Xml)[] tasks)
    {
        var sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Tasks>\n");
        foreach (var (name, xml) in tasks)
        {
            sb.Append("<!-- ").Append(name).Append(" -->\n").Append(xml).Append('\n');
        }

        return sb.Append("</Tasks>\n").ToString();
    }

    private static string SimpleTask(string command, string? arguments = null, bool enabled = true, string extraActions = "") => $"""
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Enabled>{(enabled ? "true" : "false")}</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>{command}</Command>{(arguments is null ? string.Empty : $"<Arguments>{arguments}</Arguments>")}</Exec>{extraActions}</Actions>
</Task>
""";

    private static string Disable(string taskXml)
    {
        var doc = XDocument.Parse(taskXml);
        doc.Root!.Element(Ns + "Settings")!.Element(Ns + "Enabled")!.Value = "false";
        return doc.ToString();
    }

    private static TestEnv Env(string xml)
    {
        var env = new TestEnv { TasksXml = xml };
        env.Files.Add(UserExe, TestEnv.FakePe());
        env.Files.Add(AdminExe, TestEnv.FakePe());
        return env;
    }

    private static List<Finding> Scan(TestEnv env, params string[] self) =>
        [.. new ScheduledTaskScanner().Scan(env.Context(self: self.Length == 0 ? [UserExe, AdminExe] : self))];

    public static TheoryData<string> Prefixes => new() { OwnTasks.Folder, OwnTasks.FallbackPrefix };

    [Theory]
    [MemberData(nameof(Prefixes))]
    public void RealTasksFromTaskXmlBuilderAreNotReported(string prefix)
    {
        // 설치가 만드는 작업 그대로(사용자 작업 4개 + 관리자 작업 2개, 폴더 이름과 루트 예비 이름 모두)는 아무것도 보고하지 않아요.
        var tasks = TaskXmlBuilder.BuildUserTasks(UserExe, Sid, @"PC\jiyul", Now)
            .Select(t => (prefix + t.Name, t.Xml))
            .Append((prefix + OwnTasks.Admin.Name, TaskXmlBuilder.BuildAdminTask(AdminExe, Sid, @"PC\jiyul", Now).Xml))
            .Append((prefix + OwnTasks.ServiceInstalledAdmin.Name, TaskXmlBuilder.BuildAdminServiceTask(AdminExe, Sid).Xml))
            .ToArray();
        var xml = Query(tasks);

        // 작업 6개를 모두 읽었는지 먼저 확인해요 (못 읽으면 결과가 비어서 테스트가 거짓으로 통과해요).
        var parsed = TaskXmlParser.Parse(xml);
        Assert.Equal(tasks.Select(t => t.Item1), parsed.Select(t => t.Name));
        Assert.All(parsed, t => Assert.True(t.Enabled));
        Assert.Empty(Scan(Env(xml)));
    }

    [Fact]
    public void RealTaskWithDifferentNameCaseIsNotReported()
    {
        // Windows 작업 이름은 대소문자를 구분하지 않아요.
        var logon = TaskXmlBuilder.BuildUserTasks(UserExe, Sid, @"PC\jiyul", Now)[0];
        Assert.Empty(Scan(Env(Query((@"\safetysecurity\LOGON", logon.Xml)))));
    }

    [Fact]
    public void RealTaskRunningTheProcessPathCopyIsNotReported()
    {
        // 지금 실행 중인 exe(SelfPaths에 들어 있는 다른 위치)를 가리키는 우리 작업도 우리 작업이에요.
        const string portable = @"D:\Tools\SafetySecurity\SafetySecurity.exe";
        var daily = TaskXmlBuilder.BuildUserTasks(portable, Sid, @"PC\jiyul", Now)[1];
        Assert.Empty(Scan(Env(Query((@"\SafetySecurity\Daily", daily.Xml))), portable));
    }

    [Fact]
    public void DisabledOwnTaskIsMedium()
    {
        var daily = TaskXmlBuilder.BuildUserTasks(UserExe, Sid, @"PC\jiyul", Now)[1];
        var f = Assert.Single(Scan(Env(Query((@"\SafetySecurity\Daily", Disable(daily.Xml))))));
        Assert.Equal("TASK-004", f.RuleId);
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Equal(ScheduledTaskScanner.CategoryName, f.Category);
        Assert.Equal(@"작업 스케줄러\SafetySecurity\Daily", f.Location);
        Assert.Null(f.Target);
        Assert.Contains(f.Reasons, r => r.Contains(OwnTasks.Daily.Purpose, StringComparison.Ordinal));
        Assert.Contains("/enable", f.Advice, StringComparison.Ordinal);
    }

    [Fact]
    public void DisabledOwnAdminFallbackTaskIsMedium()
    {
        var admin = TaskXmlBuilder.BuildAdminTask(AdminExe, Sid, @"PC\jiyul", Now);
        var f = Assert.Single(Scan(Env(Query((@"\SafetySecurity-Admin", Disable(admin.Xml))))));
        Assert.Equal("TASK-004", f.RuleId);
        Assert.Equal(Severity.Medium, f.Severity);
    }

    [Fact]
    public void DisabledOwnTaskSurvivesTheEngineSelfFilter()
    {
        // 엔진은 대상이 검사기 자신인 항목을 빼요. TASK-004는 대상을 비워서 빠지지 않아야 해요.
        var retry = TaskXmlBuilder.BuildUserTasks(UserExe, Sid, @"PC\jiyul", Now)[3];
        var env = Env(Query((@"\SafetySecurity\Retry", Disable(retry.Xml))));
        var result = ScanEngine.Run(env.Context(self: [UserExe, AdminExe]), [new ScheduledTaskScanner()], ScanReason.Manual, false, () => TestEnv.Now);
        Assert.Equal("TASK-004", Assert.Single(result.Findings).RuleId);
    }

    [Fact]
    public void LookAlikeFallbackNameRunningEncodedPowerShellIsHigh()
    {
        // 사용자 권한 악성코드: schtasks /create /tn "\SafetySecurity-Updater" /tr "powershell -nop -w hidden -enc ..."
        const string ps = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        var env = Env(Query((@"\SafetySecurity-Updater", SimpleTask(ps, "-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AA=="))));
        env.Files.Add(ps);
        env.Signatures.Signed(ps);
        var f = Assert.Single(Scan(env));
        Assert.Equal("TASK-003", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(@"작업 스케줄러\SafetySecurity-Updater", f.Location);
        Assert.Contains("위장", f.Title, StringComparison.Ordinal);
        Assert.Contains(f.Reasons, r => r.Contains("흉내", StringComparison.Ordinal));
        Assert.Contains(f.Reasons, r => r.Contains("EncodedCommand", StringComparison.OrdinalIgnoreCase) || r.Contains("인코딩", StringComparison.Ordinal));
    }

    [Fact]
    public void SameActionUnderAnOrdinaryNameIsStillTask001()
    {
        // 같은 동작을 우리 이름이 아닌 작업에 넣으면 평소처럼 TASK-001로 판정해요 (위장 규칙은 우리 이름에만 적용).
        const string ps = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        var env = Env(Query((@"\SafetySecurityHelper", SimpleTask(ps, "-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AA=="))));
        env.Files.Add(ps);
        env.Signatures.Signed(ps);
        var f = Assert.Single(Scan(env));
        Assert.Equal("TASK-001", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void OwnTaskNameRepointedToAnotherProgramIsHigh()
    {
        const string evil = @"C:\Users\Public\x.exe";
        var env = Env(Query((@"\SafetySecurity\Daily", SimpleTask(evil, "scan --reason daily"))));
        env.Files.Add(evil, TestEnv.FakePe());
        var f = Assert.Single(Scan(env));
        Assert.Equal("TASK-003", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(evil, f.Target);
        Assert.Contains("바뀌었어요", f.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void SignedProgramUnderOurNameIsStillHigh()
    {
        // 서명된 Windows 프로그램이라도 우리 이름을 쓰면 위장이에요 (TASK-001이었다면 보고하지 않았을 동작).
        const string whoami = @"C:\Windows\System32\whoami.exe";
        var env = Env(Query((@"\SafetySecurity\Logon", SimpleTask(whoami))));
        env.Files.Add(whoami);
        env.Signatures.Signed(whoami);
        var f = Assert.Single(Scan(env));
        Assert.Equal("TASK-003", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void OwnExeWithOtherArgumentsIsHighAndNotDroppedAsSelf()
    {
        // 검사기 자신을 실행해도 인자가 다르면(예: 작업을 지우는 uninstall) 우리 작업이 아니에요.
        var env = Env(Query((@"\SafetySecurity\Daily", SimpleTask("\"" + UserExe + "\"", "uninstall --purge"))));
        var result = ScanEngine.Run(env.Context(self: [UserExe, AdminExe]), [new ScheduledTaskScanner()], ScanReason.Manual, false, () => TestEnv.Now);
        var f = Assert.Single(result.Findings);
        Assert.Equal("TASK-003", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal("\"" + UserExe + "\" uninstall --purge", f.Target);
        Assert.Contains(f.Reasons, r => r.Contains("uninstall --purge", StringComparison.Ordinal) && r.Contains(OwnTasks.Daily.Arguments, StringComparison.Ordinal));
    }

    [Fact]
    public void TamperedOwnTaskIsANewItemEvenIfItWasDisabledBefore()
    {
        // 꺼져 있던 우리 작업(TASK-004)이 다른 인자로 바뀌면(TASK-003) ID가 달라서 새 항목으로 알려요.
        var daily = TaskXmlBuilder.BuildUserTasks(UserExe, Sid, @"PC\jiyul", Now)[1];
        var disabled = Assert.Single(Scan(Env(Query((@"\SafetySecurity\Daily", Disable(daily.Xml))))));
        var tampered = Assert.Single(Scan(Env(Query((@"\SafetySecurity\Daily", SimpleTask("\"" + UserExe + "\"", "uninstall", enabled: false))))));
        Assert.Equal("TASK-004", disabled.RuleId);
        Assert.Equal("TASK-003", tampered.RuleId);
        Assert.NotEqual(disabled.Id, tampered.Id);
    }

    [Fact]
    public void OwnExeWithoutArgumentsUnderAnUnknownNameIsStillReported()
    {
        // 인자 없이 검사기만 실행하면 명령줄이 검사기 경로뿐이라 대상으로 쓰지 않아요 (엔진이 '자기 자신'으로 빼지 않게).
        var env = Env(Query((@"\SafetySecurity\Updater", SimpleTask("\"" + UserExe + "\""))));
        var result = ScanEngine.Run(env.Context(self: [UserExe, AdminExe]), [new ScheduledTaskScanner()], ScanReason.Manual, false, () => TestEnv.Now);
        var f = Assert.Single(result.Findings);
        Assert.Equal("TASK-003", f.RuleId);
        Assert.Null(f.Target);
    }

    [Fact]
    public void OwnExeWithAnotherTasksArgumentsIsReported()
    {
        var env = Env(Query((@"\SafetySecurity\Logon", SimpleTask("\"" + UserExe + "\"", OwnTasks.Daily.Arguments))));
        Assert.Equal("TASK-003", Assert.Single(Scan(env)).RuleId);
    }

    [Fact]
    public void ExtraActionNextToOurOwnIsHigh()
    {
        const string evil = @"C:\Users\jiyul\AppData\Roaming\u\u.exe";
        var extra = $"<Exec><Command>{evil}</Command></Exec>";
        var env = Env(Query((@"\SafetySecurity\Logon", SimpleTask("\"" + UserExe + "\"", OwnTasks.Logon.Arguments, extraActions: extra))));
        env.Files.Add(evil, TestEnv.FakePe());
        var f = Assert.Single(Scan(env));
        Assert.Equal("TASK-003", f.RuleId);
        Assert.Equal(evil, f.Target);
        Assert.Contains(f.Reasons, r => r.Contains("2개", StringComparison.Ordinal));
    }

    [Fact]
    public void ComHandlerUnderOurNameIsHigh()
    {
        const string xml = """
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions Context="Author"><ComHandler><ClassId>{11111111-2222-3333-4444-555555555555}</ClassId></ComHandler></Actions>
</Task>
""";
        var f = Assert.Single(Scan(Env(Query((@"\SafetySecurity\Retry", xml)))));
        Assert.Equal("TASK-003", f.RuleId);
        Assert.Contains(f.Reasons, r => r.Contains("ComHandler", StringComparison.Ordinal));
        Assert.Contains(f.Evidence, e => e.Value == "{11111111-2222-3333-4444-555555555555}");
    }

    [Fact]
    public void UnknownNameRunningOurExeWithOurArgumentsIsReportedForTheNameOnly()
    {
        var env = Env(Query((@"\SafetySecurity\Updater", SimpleTask("\"" + UserExe + "\"", OwnTasks.Logon.Arguments))));
        var f = Assert.Single(Scan(env));
        Assert.Equal("TASK-003", f.RuleId);
        Assert.Contains(f.Reasons, r => r.Contains("흉내", StringComparison.Ordinal));
        Assert.DoesNotContain(f.Reasons, r => r.Contains("쓰지 않는 인자", StringComparison.Ordinal));
    }

    [Fact]
    public void OwnNameInASubfolderIsNotOurs()
    {
        var logon = TaskXmlBuilder.BuildUserTasks(UserExe, Sid, @"PC\jiyul", Now)[0];
        Assert.Equal("TASK-003", Assert.Single(Scan(Env(Query((@"\SafetySecurity\Sub\Logon", logon.Xml))))).RuleId);
    }

    [Fact]
    public void OurTaskXmlPointingAtAnUntrustedCopyIsReported()
    {
        // 이름·인자는 진짜와 같아도, 검사기 자신으로 인정한 위치(SelfPaths)가 아닌 exe를 실행하면 우리 작업이 아니에요.
        const string copy = @"C:\Users\Public\SafetySecurity.exe";
        var logon = TaskXmlBuilder.BuildUserTasks(copy, Sid, @"PC\jiyul", Now)[0];
        var env = Env(Query((@"\SafetySecurity-Logon", logon.Xml)));
        env.Files.Add(copy, TestEnv.FakePe());
        var f = Assert.Single(Scan(env));
        Assert.Equal("TASK-003", f.RuleId);
        Assert.Equal(copy, f.Target);
    }

    [Fact]
    public void DisabledLookAlikeStaysHigh()
    {
        const string evil = @"C:\Users\Public\x.exe";
        var env = Env(Query((@"\SafetySecurity-Daily", SimpleTask(evil, enabled: false))));
        env.Files.Add(evil, TestEnv.FakePe());
        var f = Assert.Single(Scan(env));
        Assert.Equal("TASK-003", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Contains(f.Reasons, r => r.Contains("꺼져 있어요", StringComparison.Ordinal));
    }

    [Fact]
    public void HiddenTaskCacheEntryUnderOurNameIsReported()
    {
        // 우리 작업도 schtasks로 등록해서 항상 SD가 있어요. 우리 이름인데 SD가 없으면 숨은 작업이에요.
        const string tree = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
        var env = new TestEnv();
        env.Registry.Set(RegHive.LocalMachine, tree + @"\SafetySecurity\Logon", "Id", "{1}");
        env.Registry.Set(RegHive.LocalMachine, tree + @"\SafetySecurity\Logon", "SD", new byte[] { 1 });
        env.Registry.Set(RegHive.LocalMachine, tree + @"\SafetySecurity\x", "Id", "{2}");
        env.Registry.Set(RegHive.LocalMachine, tree + @"\SafetySecurity-Update", "Id", "{3}");
        var findings = new HiddenTaskScanner().Scan(env.Context(ScanScope.Admin, elevated: true, self: [UserExe, AdminExe])).ToList();
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("TASK-002", f.RuleId));
        Assert.Contains(findings, f => f.Title.EndsWith(@"\SafetySecurity\x", StringComparison.Ordinal));
        Assert.Contains(findings, f => f.Title.EndsWith(@"\SafetySecurity-Update", StringComparison.Ordinal));
    }
}

public class OwnTasksTests
{
    [Theory]
    [InlineData(@"\SafetySecurity\Logon", "Logon")]
    [InlineData(@"\SafetySecurity-Logon", "Logon")]
    [InlineData(@"\safetysecurity\serviceinstalledadmin", "ServiceInstalledAdmin")]
    [InlineData(@"\SafetySecurity-Admin", "Admin")]
    public void FindsOwnTaskNames(string fullName, string expected)
    {
        Assert.Equal(expected, OwnTasks.Find(fullName)?.Name);
        Assert.True(OwnTasks.HasOwnPrefix(fullName));
    }

    [Theory]
    [InlineData(@"\SafetySecurity\Updater")]
    [InlineData(@"\SafetySecurity\Sub\Logon")]
    [InlineData(@"\SafetySecurity-Logon2")]
    public void UnknownNamesUnderOurPrefixAreNotOwnTasks(string fullName)
    {
        Assert.Null(OwnTasks.Find(fullName));
        Assert.True(OwnTasks.HasOwnPrefix(fullName));
    }

    [Theory]
    [InlineData(@"\Logon")]
    [InlineData(@"\SafetySecurityLogon")]
    [InlineData(@"\SafetySecurity")]
    [InlineData(@"\Microsoft\SafetySecurity\Logon")]
    public void OtherNamesDoNotUseOurPrefix(string fullName)
    {
        Assert.Null(OwnTasks.Find(fullName));
        Assert.False(OwnTasks.HasOwnPrefix(fullName));
    }

    [Fact]
    public void TaskXmlBuilderRegistersExactlyTheKnownArguments()
    {
        // 설치가 만드는 작업 이름·인자와 검사가 확인하는 값이 같아야 우리 작업을 잘못 보고하지 않아요.
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var now = new DateTime(2026, 11, 5, 10, 0, 0);
        var built = TaskXmlBuilder.BuildUserTasks(@"C:\a\SafetySecurity.exe", "S-1", @"PC\u", now)
            .Append(TaskXmlBuilder.BuildAdminTask(@"C:\a\SafetySecurity.exe", "S-1", @"PC\u", now))
            .Append(TaskXmlBuilder.BuildAdminServiceTask(@"C:\a\SafetySecurity.exe", "S-1"))
            .ToList();
        Assert.Equal(OwnTasks.All.Select(t => t.Name), built.Select(t => t.Name));
        foreach (var spec in built)
        {
            var args = XDocument.Parse(spec.Xml).Descendants(ns + "Arguments").Single().Value;
            Assert.Equal(OwnTasks.Find(OwnTasks.Folder + spec.Name)!.Arguments, args);
        }

        Assert.Equal([@"\SafetySecurity\Daily", @"\SafetySecurity-Daily"], OwnTasks.FullNames("Daily"));
    }
}

public class SelfExecutablesTests
{
    private const string Process = @"D:\Downloads\SafetySecurity.exe";
    private const string UserExe = @"C:\Users\jiyul\AppData\Local\Programs\SafetySecurity\SafetySecurity.exe";
    private const string AdminExe = @"C:\Program Files\SafetySecurity\SafetySecurity.exe";

    [Fact]
    public void UserScanTrustsBothInstallsAndTheRunningExe()
    {
        Assert.Equal([Process, AdminExe, UserExe], SelfExecutables.For(ScanScope.User, Process, UserExe, AdminExe));
    }

    [Fact]
    public void AdminScanDoesNotTrustTheUserWritableInstall()
    {
        var self = SelfExecutables.For(ScanScope.Admin, AdminExe, UserExe, AdminExe);
        Assert.Contains(AdminExe, self);
        Assert.DoesNotContain(UserExe, self);
    }

    [Fact]
    public void AdminScanStillTrustsTheRunningImage()
    {
        // 내 계정 설치의 exe로 관리자 검사를 직접 실행하면, 실행 중인 그 exe만은 자기 자신이에요.
        Assert.Contains(UserExe, SelfExecutables.For(ScanScope.Admin, UserExe, UserExe, AdminExe));
    }

    [Fact]
    public void MissingProcessPathIsSkipped()
    {
        Assert.Equal([AdminExe, UserExe], SelfExecutables.For(ScanScope.User, null, UserExe, AdminExe));
    }

    [Theory]
    [InlineData(ScanScope.User, 0)]
    [InlineData(ScanScope.Admin, 1)]
    public void EngineDropsOnlyTrustedSelfTargets(ScanScope scope, int expected)
    {
        // 관리자 검사에서는 사용자 권한 악성코드가 내 계정 설치 위치에 둔 exe를 가리키는 항목이 '검사기 자신'으로 빠지지 않아요.
        var env = new TestEnv();
        var self = SelfExecutables.For(scope, AdminExe, UserExe, AdminExe);
        var result = ScanEngine.Run(env.Context(scope, elevated: scope == ScanScope.Admin, self: self), [new PointsAt(UserExe)], ScanReason.Manual, false, () => TestEnv.Now);
        Assert.Equal(expected, result.Findings.Count);
    }

    private sealed class PointsAt(string target) : IScanner
    {
        public string Category => "Wmi";

        public string DisplayName => "test";

        public bool RunsIn(ScanScope scope, bool quick) => true;

        public IEnumerable<Finding> Scan(ScanContext ctx) =>
        [
            new Finding { RuleId = "WMI-001", Category = Category, Severity = Severity.High, Title = "t", Location = "root/subscription:x", Target = target },
        ];
    }
}

public class NotificationNoteTests
{
    [Theory]
    [InlineData(NotificationState.Enabled)]
    [InlineData(NotificationState.Unknown)]
    public void NoNoteWhenNotificationsAreOnOrUnknown(NotificationState state)
    {
        Assert.Null(Advice.NotificationsOff(state));
    }

    [Theory]
    [InlineData(NotificationState.DisabledForApplication, "SafetySecurity")]
    [InlineData(NotificationState.DisabledByManifest, "SafetySecurity")]
    [InlineData(NotificationState.DisabledForUser, "모두")]
    [InlineData(NotificationState.DisabledByGroupPolicy, "정책")]
    public void NoteExplainsWhyAndHowToFix(NotificationState state, string mentions)
    {
        var note = Advice.NotificationsOff(state);
        Assert.NotNull(note);
        Assert.Contains(mentions, note, StringComparison.Ordinal);
        Assert.Contains("알려드릴 수 없어요", note, StringComparison.Ordinal);
    }
}
