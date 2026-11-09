using System.Text;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Tests;

/// <summary>
/// README에 쓰는 샘플 보고서. 평소에는 렌더링이 깨지지 않는지만 확인하고,
/// 환경 변수 SS_WRITE_SAMPLE=1이 있으면 docs/sample-report.html로 저장해요.
/// </summary>
/// <remarks>
/// 항목을 손으로 쓰지 않고, 가짜 PC(가짜 레지스트리·파일·서명)를 만들어 진짜 스캐너와 베이스라인으로 검사한 결과를 써요.
/// 그래야 규칙이 바뀌어도 샘플이 지금 규칙으로는 나오지 않는 항목·문구를 보여주지 않아요.
/// </remarks>
public class SampleReportTests
{
    private const string Clsid = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}";
    private const string Run = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string Services = @"SYSTEM\CurrentControlSet\Services";

    private static readonly DateTimeOffset Started = new(2026, 11, 6, 9, 12, 0, TimeSpan.Zero);

    // 샘플에 실제 사용자 이름이 보이지 않게 'me'를 써요.
    private static readonly SystemPaths Paths = new(new Dictionary<string, string>
    {
        ["SystemRoot"] = @"C:\Windows",
        ["SystemDrive"] = "C:",
        ["ProgramFiles"] = @"C:\Program Files",
        ["ProgramFiles(x86)"] = @"C:\Program Files (x86)",
        ["ProgramData"] = @"C:\ProgramData",
        ["USERPROFILE"] = @"C:\Users\me",
        ["APPDATA"] = @"C:\Users\me\AppData\Roaming",
        ["LOCALAPPDATA"] = @"C:\Users\me\AppData\Local",
        ["TEMP"] = @"C:\Users\me\AppData\Local\Temp",
        ["PUBLIC"] = @"C:\Users\Public",
        ["ComSpec"] = @"C:\Windows\System32\cmd.exe",
    });

    public static ReportDocument Sample()
    {
        var registry = new FakeRegistry();
        var files = new FakeFileSystem();
        var signatures = new FakeSignatures();
        var recent = Started.AddDays(-2);

        // COM-001: HKCU가 시스템 COM 클래스(ShellWindows)를 덮어써서 사용자 폴더의 서명 없는 DLL을 불러와요 (니케 런처 사건과 같은 형태).
        const string systemDll = @"C:\Windows\System32\shdocvw.dll";
        registry.Set(RegHive.LocalMachine, $@"Software\Classes\CLSID\{Clsid}", null, "ShellWindows");
        registry.Set(RegHive.LocalMachine, $@"Software\Classes\CLSID\{Clsid}\InprocServer32", null, @"%SystemRoot%\System32\shdocvw.dll");
        files.Add(systemDll);
        signatures.Signed(systemDll);
        const string evilDll = @"C:\Users\me\AppData\Roaming\Microsoft\Crypto\mscorsvc.dll";
        registry.Set(RegHive.CurrentUser, $@"Software\Classes\CLSID\{Clsid}\InprocServer32", null, evilDll, recent);
        registry.Set(RegHive.CurrentUser, $@"Software\Classes\CLSID\{Clsid}\InprocServer32", "ThreadingModel", "Apartment");
        registry.Key(RegHive.CurrentUser, $@"Software\Classes\CLSID\{Clsid}", recent);
        files.Add(evilDll, TestEnv.FakePe(dll: true), recent);

        // RUN-001 (숨긴 항목): 직접 확인하고 ignore로 숨긴 서명 없는 개인 도구예요. 보고서 맨 아래 '숨긴 항목'에 보여요.
        const string tool = @"C:\Users\me\AppData\Local\Programs\MyMacro\macro.exe";
        files.Add(tool, TestEnv.FakePe(), Started.AddDays(-90));
        registry.Set(RegHive.CurrentUser, Run, "MyMacro", $"\"{tool}\" --tray", Started.AddDays(-90));

        // RUN-001: 창을 숨긴 PowerShell이 인코딩된 명령을 실행해요.
        const string powershell = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        files.Add(powershell);
        signatures.Signed(powershell);
        registry.Set(RegHive.CurrentUser, Run, "WindowsUpdateHelper", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", recent);

        // FILE-001: 사용자 폴더에 새로 생긴 서명 없는 실행 파일이에요.
        files.Add(@"C:\Users\me\AppData\Roaming\x7f3\svchost.exe", TestEnv.FakePe(), Started.AddDays(-3));

        // SVC-001: 따옴표 없는 공백 경로인데, Windows가 먼저 실행해 볼 D:\는 일반 사용자도 쓸 수 있어요 (Program Files였다면 보고하지 않아요).
        const string service = @"D:\My Games\Launcher Service\svc.exe";
        files.Add(service);
        signatures.Signed(service, "Launcher Vendor Inc.");
        registry.Set(RegHive.LocalMachine, Services + @"\Launcher", "Type", 0x10);
        registry.Set(RegHive.LocalMachine, Services + @"\Launcher", "Start", 2);
        registry.Set(RegHive.LocalMachine, Services + @"\Launcher", "ImagePath", service);
        registry.Key(RegHive.LocalMachine, Services + @"\Launcher", Started.AddDays(-200));

        // 깨끗한 hosts 파일과 빈 예약 작업 목록 (읽지 못했다는 안내가 샘플에 나오지 않게요).
        files.Add(@"C:\Windows\System32\drivers\etc\hosts", Encoding.ASCII.GetBytes("# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# localhost name resolution is handled within DNS itself.\r\n"));

        var classifier = new PathClassifier(Paths) { NetworkDrives = new HashSet<char>() };
        var ctx = new ScanContext
        {
            Registry = registry,
            Files = files,
            Signatures = signatures,
            Classifier = classifier,
            Now = Started,
            Scope = ScanScope.User,
            Tasks = new NoTasks(),
        };
        var ticks = 0;
        var result = ScanEngine.Run(ctx, ScanEngine.AllScanners(), ScanReason.Logon, quick: false, () => ticks++ == 0 ? Started : Started.AddSeconds(4));

        // 지난 검사에서 이미 본 항목(새 실행 파일, 서비스)과 숨긴 항목이 있는 두 번째 이후 검사로 만들어요.
        var state = new ScanState { BaselineInitialized = true, LastFullScanUtc = Started.AddDays(-1) };
        foreach (var seen in result.Findings.Where(f => f.RuleId is "FILE-001" or "SVC-001"))
        {
            state.Baseline[seen.Id] = seen.Category;
        }

        var hidden = result.Findings.Single(f => f.Target == tool);
        state.Ignored.Add(hidden.Id);
        state.IgnoredDetail[hidden.Id] = new IgnoreEntry
        {
            Title = hidden.Title,
            Category = hidden.Category,
            IgnoredUtc = Started.AddDays(-30),
            Severity = hidden.Severity,
            Fingerprint = FindingFingerprint.Of(hidden),
        };

        var decision = BaselineEvaluator.Apply(result, state, new ScanConfig());
        return ReportDocument.From(result, decision, "0.2.0", "MY-PC");
    }

    [Fact]
    public void SampleComesFromTheCurrentRules()
    {
        var doc = Sample();
        Assert.Equal(["COM-001", "FILE-001", "RUN-001", "SVC-001"], doc.Findings.Select(f => f.RuleId).Order(StringComparer.Ordinal));
        Assert.All(doc.Findings.Where(f => f.RuleId is "COM-001" or "RUN-001"), f => Assert.True(f.IsNew));
        Assert.All(doc.Findings.Where(f => f.RuleId is "FILE-001" or "SVC-001"), f => Assert.False(f.IsNew));
        var svc = Assert.Single(doc.Findings, f => f.RuleId == "SVC-001");
        Assert.Equal(Severity.Low, svc.Severity);
        Assert.Contains(svc.Reasons, r => r.Contains(@"'D:\'", StringComparison.Ordinal));
        var ignored = Assert.Single(doc.Ignored);
        Assert.Equal("RUN-001", ignored.RuleId);

        // 가짜 PC가 덜 만들어져서 생기는 '읽지 못했어요'·'일부만 확인' 안내는 샘플에 없어야 해요 (사용자 검사에 원래 있는 Defender 안내만).
        Assert.DoesNotContain(doc.Completed, c => c.Contains("일부만 확인", StringComparison.Ordinal));
        var note = Assert.Single(doc.Coverage);
        Assert.StartsWith("Defender", note, StringComparison.Ordinal);
    }

    [Fact]
    public void SampleRendersAndCanBeWritten()
    {
        // 설치 프로그램으로 설치한 사람이 보는 보고서 (숨기기 안내가 Win+R 방법)
        var html = HtmlReport.Render(Sample(), runDialog: true);
        Assert.Contains("COM-001", html, StringComparison.Ordinal);
        Assert.Contains("<kbd>Win</kbd>", html, StringComparison.Ordinal);
        Assert.Contains("새 항목", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);

        if (Environment.GetEnvironmentVariable("SS_WRITE_SAMPLE") is { Length: > 0 })
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SafetySecurity.slnx")))
            {
                dir = dir.Parent;
            }

            Assert.NotNull(dir);
            File.WriteAllText(Path.Combine(dir!.FullName, "docs", "sample-report.html"), html);
        }
    }

    private sealed class NoTasks : ITaskSource
    {
        public string? GetTasksXml(out string? error)
        {
            error = null;
            return "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Tasks>\n</Tasks>";
        }
    }
}
