using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;
using SafetySecurity.Core.Scanners;

namespace SafetySecurity.Core.Tests;

/// <summary>
/// 베이스라인 지문: 같은 ID(같은 위치)인데 더 위험해졌거나 파일이 바뀌면 다시 알리고, 숨긴 항목도 다시 보여줘요.
/// </summary>
public class BaselineFingerprintTests
{
    private const string Run = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string Tool = @"C:\Users\jiyul\AppData\Roaming\Tool\tool.exe";

    private static Finding F(Severity s, params (string Key, string Value)[] evidence) => new()
    {
        RuleId = "T-1",
        Category = "Autorun",
        Severity = s,
        Title = "자동 실행 등록: Tool",
        Location = @"HKCU\Run\Tool",
        Target = Tool,
        Evidence = [.. evidence.Select(e => new KeyValuePair<string, string>(e.Key, e.Value))],
    };

    private static ScanResult Result(params Finding[] findings)
    {
        var r = new ScanResult { StartedUtc = TestEnv.Now, Scope = ScanScope.User, Reason = ScanReason.Daily, Quick = false };
        r.Findings.AddRange(findings);
        r.CompletedCategories.AddRange(findings.Select(f => f.Category).Append("Autorun").Distinct());
        return r;
    }

    private static ScanState Initialized() => new() { BaselineInitialized = true };

    private static ScanResult ScanAutorun(TestEnv env)
    {
        var ctx = env.Context();
        return ScanEngine.Run(ctx, [new AutorunScanner()], ScanReason.Daily, quick: false, () => TestEnv.Now);
    }

    [Fact]
    public void MissingFileThatAppearsAsFreshUnsignedExeIsNotifiedAgain()
    {
        // 검증된 실패 사례: 없는 파일을 가리키던 Run 값(낮음)에 나중에 서명 없는 새 파일이 생기면(높음) 같은 ID라도 알려야 해요.
        var env = new TestEnv();
        env.Registry.Set(RegHive.CurrentUser, Run, "Tool", Tool);
        var state = new ScanState();
        var config = new ScanConfig();

        var r1 = ScanAutorun(env);
        Assert.Equal(Severity.Low, Assert.Single(r1.Findings).Severity);
        BaselineEvaluator.Apply(r1, state, config);
        var r2 = ScanAutorun(env);
        Assert.Empty(BaselineEvaluator.Apply(r2, state, config).ToNotify);

        env.Files.Add(Tool, created: TestEnv.Now.AddDays(-1));
        var r3 = ScanAutorun(env);
        var d3 = BaselineEvaluator.Apply(r3, state, config);
        var f = Assert.Single(d3.ToNotify);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(r1.Findings[0].Id, f.Id);
        Assert.True(f.IsNew);
        Assert.Contains("위험도가 올라갔어요", f.ChangeNote, StringComparison.Ordinal);
        Assert.Contains("낮음 → 높음", f.ChangeNote, StringComparison.Ordinal);

        // 다음 검사에서 그대로면 다시 알리지 않아요.
        var r4 = ScanAutorun(env);
        Assert.Empty(BaselineEvaluator.Apply(r4, state, config).ToNotify);
        Assert.False(r4.Findings[0].IsNew);
    }

    [Fact]
    public void SwappedUnsignedBinaryAtSameSeverityIsNotified()
    {
        // 수정 시각까지 그대로 둔(timestomp) 바꿔치기: 위험도는 그대로 보통이지만 SHA-256이 달라요.
        var env = new TestEnv();
        env.Files.Add(Tool, [.. TestEnv.FakePe(), 1]);
        env.Registry.Set(RegHive.CurrentUser, Run, "Tool", Tool);
        var state = new ScanState();
        var config = new ScanConfig();
        BaselineEvaluator.Apply(ScanAutorun(env), state, config);
        var same = ScanAutorun(env);
        Assert.Empty(BaselineEvaluator.Apply(same, state, config).ToNotify);
        Assert.Equal(Severity.Medium, same.Findings[0].Severity);

        env.Files.Add(Tool, [.. TestEnv.FakePe(), 2]);
        var swapped = ScanAutorun(env);
        var d = BaselineEvaluator.Apply(swapped, state, config);
        var f = Assert.Single(d.ToNotify);
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Contains("SHA-256", f.ChangeNote, StringComparison.Ordinal);
    }

    [Fact]
    public void IgnoredItemIsShownAgainWhenItsFileIsOverwritten()
    {
        var env = new TestEnv();
        env.Files.Add(Tool, [.. TestEnv.FakePe(), 1]);
        env.Registry.Set(RegHive.CurrentUser, Run, "Tool", Tool);
        var state = new ScanState();
        var config = new ScanConfig();
        var r1 = ScanAutorun(env);
        BaselineEvaluator.Apply(r1, state, config);
        var id = r1.Findings[0].Id;
        Assert.True(IgnoreList.Add(state, id, null, null, TestEnv.Now));
        Assert.Equal(Severity.Medium, state.IgnoredDetail[id].Severity);

        var hidden = ScanAutorun(env);
        BaselineEvaluator.Apply(hidden, state, config);
        Assert.Empty(hidden.Findings);
        Assert.Single(hidden.IgnoredFindings);

        env.Files.Add(Tool, [.. TestEnv.FakePe(), 9]);
        var r3 = ScanAutorun(env);
        var d3 = BaselineEvaluator.Apply(r3, state, config);
        var f = Assert.Single(r3.Findings);
        Assert.NotNull(f.IgnoreNote);
        Assert.Contains("숨긴 뒤로", f.IgnoreNote, StringComparison.Ordinal);
        Assert.Contains("SHA-256", f.IgnoreNote, StringComparison.Ordinal);
        Assert.Single(d3.ToNotify);
        Assert.Contains(id, state.Ignored);

        // 다음 검사: 베이스라인은 새 파일을 알아서 알리지 않지만, 숨길 때와 달라서 계속 보여줘요.
        var r4 = ScanAutorun(env);
        var d4 = BaselineEvaluator.Apply(r4, state, config);
        Assert.Empty(d4.ToNotify);
        Assert.NotNull(Assert.Single(r4.Findings).IgnoreNote);

        // 다시 숨기면 지금 상태가 새 기준이에요.
        Assert.True(IgnoreList.Add(state, id, null, null, TestEnv.Now));
        var r5 = ScanAutorun(env);
        BaselineEvaluator.Apply(r5, state, config);
        Assert.Empty(r5.Findings);
    }

    [Fact]
    public void IgnoredMediumThatBecomesHighIsShownAndNotified()
    {
        var state = Initialized();
        var config = new ScanConfig();
        var medium = F(Severity.Medium, ("서명", "서명 없음"));
        BaselineEvaluator.Apply(Result(medium), state, config);
        IgnoreList.Add(state, medium.Id, null, null, TestEnv.Now);

        var high = F(Severity.High, ("서명", "서명 없음"));
        var r = Result(high);
        var d = BaselineEvaluator.Apply(r, state, config);
        var f = Assert.Single(r.Findings);
        Assert.Contains("보통 → 높음", f.IgnoreNote, StringComparison.Ordinal);
        Assert.Single(d.ToNotify);
    }

    [Fact]
    public void LowerSeverityOrSameFingerprintIsNotNew()
    {
        var state = Initialized();
        var config = new ScanConfig { NotifyMinSeverity = Severity.Low };
        BaselineEvaluator.Apply(Result(F(Severity.High, ("서명", "서명 없음"), ("SHA-256", "aa11"))), state, config);

        var lower = Result(F(Severity.Medium, ("서명", "서명 없음"), ("SHA-256", "aa11")));
        Assert.Empty(BaselineEvaluator.Apply(lower, state, config).ToNotify);
        Assert.False(lower.Findings[0].IsNew);
        Assert.Null(lower.Findings[0].ChangeNote);

        var same = Result(F(Severity.Medium, ("서명", "서명 없음"), ("SHA-256", "aa11")));
        Assert.Empty(BaselineEvaluator.Apply(same, state, config).ToNotify);
    }

    [Fact]
    public void FileThatDisappearsIsNotNotified()
    {
        var state = Initialized();
        var config = new ScanConfig { NotifyMinSeverity = Severity.Low };
        BaselineEvaluator.Apply(Result(F(Severity.Medium, ("서명", "서명 없음"), ("SHA-256", "aa11"))), state, config);
        var gone = Result(F(Severity.Low, ("경로 종류", "사용자 폴더")));
        Assert.Empty(BaselineEvaluator.Apply(gone, state, config).ToNotify);

        // 해시는 이어서 기억해서, 같은 자리에 다른 파일이 다시 생기면 알아요.
        var back = Result(F(Severity.Medium, ("서명", "서명 없음"), ("SHA-256", "bb22")));
        var d = BaselineEvaluator.Apply(back, state, config);
        Assert.Contains("위험도가 올라갔어요", Assert.Single(d.ToNotify).ChangeNote, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingFileThatAppearsAtSameSeverityIsMarkedChanged()
    {
        var state = Initialized();
        var config = new ScanConfig { NotifyMinSeverity = Severity.Low };
        BaselineEvaluator.Apply(Result(F(Severity.Low, ("경로 종류", "Program Files"))), state, config);
        var appeared = Result(F(Severity.Low, ("경로 종류", "Program Files"), ("서명", "서명 없음")));
        var f = Assert.Single(BaselineEvaluator.Apply(appeared, state, config).ToNotify);
        Assert.Contains("없던 파일이 생겼어요", f.ChangeNote, StringComparison.Ordinal);
    }

    [Fact]
    public void SignerOrSignatureChangeIsNotified()
    {
        var state = Initialized();
        var config = new ScanConfig();
        BaselineEvaluator.Apply(Result(F(Severity.Medium, ("서명", "유효"), ("서명자", "Good Corp"))), state, config);
        var r = Result(F(Severity.Medium, ("서명", "유효 (폐기 여부는 확인 안 함)"), ("서명자", "Evil LLC")));
        var f = Assert.Single(BaselineEvaluator.Apply(r, state, config).ToNotify);
        Assert.Contains("Good Corp → Evil LLC", f.ChangeNote, StringComparison.Ordinal);

        var r2 = Result(F(Severity.Medium, ("서명", "신뢰할 수 없는 서명 (만료된 인증서)"), ("서명자", "Evil LLC")));
        var f2 = Assert.Single(BaselineEvaluator.Apply(r2, state, config).ToNotify);
        Assert.Contains("유효 → 신뢰할 수 없는 서명", f2.ChangeNote, StringComparison.Ordinal);
    }

    [Fact]
    public void FlakyChecksDoNotLookLikeChanges()
    {
        var state = Initialized();
        var config = new ScanConfig { NotifyMinSeverity = Severity.Low };
        BaselineEvaluator.Apply(Result(F(Severity.Medium, ("서명", "서명 없음"), ("SHA-256", "aa11"))), state, config);

        // 잠긴 파일: 서명 확인 실패, 해시 없음 → 바뀐 게 아니에요.
        var locked = Result(F(Severity.Medium, ("서명", "확인 실패 (IOException)")));
        Assert.Empty(BaselineEvaluator.Apply(locked, state, config).ToNotify);

        // 지난번에 확인한 서명 상태와 해시를 이어서 기억해요.
        Assert.Equal("Unsigned", state.BaselineDetail[locked.Findings[0].Id].Fingerprint!["서명"]);
        Assert.Equal("aa11", state.BaselineDetail[locked.Findings[0].Id].Fingerprint!["SHA-256"]);
        var again = Result(F(Severity.Medium, ("서명", "서명 없음"), ("SHA-256", "aa11")));
        Assert.Empty(BaselineEvaluator.Apply(again, state, config).ToNotify);

        // "유효"와 "유효 (Windows 카탈로그 서명)"·"유효 (폐기 여부는 확인 안 함)"은 같은 상태예요.
        var s2 = Initialized();
        BaselineEvaluator.Apply(Result(F(Severity.Medium, ("서명", "유효"))), s2, config);
        Assert.Empty(BaselineEvaluator.Apply(Result(F(Severity.Medium, ("서명", "유효 (폐기 여부는 확인 안 함)"))), s2, config).ToNotify);
        Assert.Empty(BaselineEvaluator.Apply(Result(F(Severity.Medium, ("서명", "유효 (Windows 카탈로그 서명)"))), s2, config).ToNotify);
    }

    [Fact]
    public void StateWrittenByVersion1DoesNotNotifyAfterUpgrade()
    {
        // 예전 버전의 state.json: Baseline(ID → 분류)와 Ignored(ID 목록)만 있어요.
        var high = F(Severity.High, ("서명", "서명 없음"));
        var hiddenOne = new Finding { RuleId = "T-2", Category = "Autorun", Severity = Severity.Medium, Title = "숨긴 것", Location = "x" };
        var json = $$"""
{
  "version": 1,
  "baselineInitialized": true,
  "baseline": { "{{high.Id}}": "Autorun", "{{hiddenOne.Id}}": "Autorun" },
  "ignored": [ "{{hiddenOne.Id}}" ],
  "lastReportPath": "C:\\r.html"
}
""";
        var state = System.Text.Json.JsonSerializer.Deserialize(json, SafetyJson.Context.ScanState)!;
        Assert.Empty(state.BaselineDetail);
        Assert.Empty(state.IgnoredDetail);

        var r = Result(high, hiddenOne);
        var d = BaselineEvaluator.Apply(r, state, new ScanConfig());
        Assert.Empty(d.ToNotify);
        Assert.Single(r.Findings);
        Assert.False(r.Findings[0].IsNew);
        Assert.Equal(1, r.IgnoredCount);
        Assert.Equal(Severity.High, state.BaselineDetail[high.Id].Severity);
        Assert.Equal("자동 실행 등록: Tool", state.BaselineDetail[high.Id].Title);
        Assert.Equal(Severity.Medium, state.IgnoredDetail[hiddenOne.Id].Severity);
        Assert.Equal(ScanState.CurrentVersion, state.Version);
        var adopt = Assert.Single(d.IgnoreEdits);
        Assert.Equal(hiddenOne.Id, adopt.Id);

        // 버전 2로 저장해도 예전 칸(baseline, ignored)은 같은 모양이라 예전 버전도 읽을 수 있어요.
        var saved = System.Text.Json.JsonSerializer.Serialize(state, SafetyJson.Context.ScanState);
        using var doc = System.Text.Json.JsonDocument.Parse(saved);
        Assert.Equal("Autorun", doc.RootElement.GetProperty("baseline").GetProperty(high.Id).GetString());
        Assert.Equal(hiddenOne.Id, doc.RootElement.GetProperty("ignored")[0].GetString());
        var back = System.Text.Json.JsonSerializer.Deserialize(saved, SafetyJson.Context.ScanState)!;
        Assert.Equal("Unsigned", back.BaselineDetail[high.Id].Fingerprint!["서명"]);
    }

    [Fact]
    public void FingerprintReadsOnlyFileEvidence()
    {
        var f = F(
            Severity.Medium,
            ("명령줄", "x.exe --a"),
            ("서명", ExecutableAssessorText.Package),
            ("페이로드 서명", "확인 실패 (UnauthorizedAccessException)"),
            ("페이로드 SHA-256", "ABCDEF0123456789ABCDEF0123456789"),
            ("실제 파일 서명자", "Valve Corp."),
            ("크기", "1,024 바이트"),
            ("수정 시각", "2026-01-01 00:00:00"));
        var fp = FindingFingerprint.Of(f)!;
        Assert.Equal("Package", fp["서명"]);
        Assert.Equal(FindingFingerprint.Unknown, fp["페이로드 서명"]);
        Assert.Equal("abcdef0123456789", fp["페이로드 SHA-256"]);
        Assert.Equal("Valve Corp.", fp["실제 파일 서명자"]);
        Assert.Equal(4, fp.Count);
        Assert.Null(FindingFingerprint.Of(F(Severity.High, ("값", "1"))));
    }

    [Theory]
    [InlineData(SignatureStatus.Valid, true, "폐기 여부는 확인 안 함")]
    [InlineData(SignatureStatus.Valid, false, null)]
    [InlineData(SignatureStatus.Unsigned, false, null)]
    [InlineData(SignatureStatus.Untrusted, false, "0x800B0109")]
    [InlineData(SignatureStatus.Invalid, true, "파일이 서명 후 변경됨")]
    [InlineData(SignatureStatus.NotFound, false, null)]
    [InlineData(SignatureStatus.Error, false, "IOException")]
    public void SignatureTextParsesBack(SignatureStatus status, bool catalog, string? detail)
    {
        var text = new SignatureInfo(status, "S", catalog, detail).ToKorean();
        Assert.True(SignatureInfo.TryParseKorean(text, out var parsed));
        Assert.Equal(status, parsed);
    }

    [Fact]
    public void SignatureTextParserRejectsOtherText()
    {
        Assert.False(SignatureInfo.TryParseKorean("유효함", out _));
        Assert.False(SignatureInfo.TryParseKorean(null, out _));
    }

    private static class ExecutableAssessorText
    {
        public const string Package = Rules.ExecutableAssessor.PackageSignatureText;
    }
}

public class IgnoreListTests
{
    private static readonly string[] Known = ["1a2b3c4d5e6f7a8b", "1a2b3c4d00000000", "ffeeddccbbaa9988"];

    [Theory]
    [InlineData("1a2b3c4d5e6f7a8b", IdMatch.Found, "1a2b3c4d5e6f7a8b")]
    [InlineData(" 1A2B3C4D5E6F7A8B ", IdMatch.Found, "1a2b3c4d5e6f7a8b")]
    [InlineData("\"ffeeddccbbaa9988\"", IdMatch.Found, "ffeeddccbbaa9988")]
    [InlineData("1a2b3c4d5e", IdMatch.Found, "1a2b3c4d5e6f7a8b")]
    [InlineData("ffeeddcc", IdMatch.Found, "ffeeddccbbaa9988")]
    [InlineData("1a2b3c4d", IdMatch.Ambiguous, null)]
    [InlineData("1a2b3c4", IdMatch.Invalid, null)]
    [InlineData("1a2b3c4d5e6f7a8c", IdMatch.NotFound, null)]
    [InlineData("1a2b3c4d5e6f7a8b0", IdMatch.Invalid, null)]
    [InlineData("hello-world", IdMatch.Invalid, null)]
    [InlineData("", IdMatch.Invalid, null)]
    public void ResolvesOnlyKnownIds(string input, IdMatch expected, string? id)
    {
        Assert.Equal(expected, IgnoreList.Resolve(input, Known, out var got));
        Assert.Equal(id, got);
    }

    [Fact]
    public void AddRecordsTheLastScanStateAndKnowsWhenNothingChanged()
    {
        var state = new ScanState();
        state.Baseline["1a2b3c4d5e6f7a8b"] = "Autorun";
        state.BaselineDetail["1a2b3c4d5e6f7a8b"] = new BaselineEntry { Severity = Severity.Medium, Title = "도구", Fingerprint = new() { ["서명"] = "Unsigned" } };
        Assert.True(IgnoreList.Add(state, "1a2b3c4d5e6f7a8b", null, null, TestEnv.Now));
        var e = state.IgnoredDetail["1a2b3c4d5e6f7a8b"];
        Assert.Equal("도구", e.Title);
        Assert.Equal("Autorun", e.Category);
        Assert.Equal(Severity.Medium, e.Severity);
        Assert.Equal(TestEnv.Now, e.IgnoredUtc);
        Assert.False(IgnoreList.Add(state, "1a2b3c4d5e6f7a8b", null, null, TestEnv.Now));

        // 기준이 바뀌었으면(숨김이 풀린 항목) 다시 숨길 때 새 기준으로 바꿔요.
        state.BaselineDetail["1a2b3c4d5e6f7a8b"].Severity = Severity.High;
        Assert.True(IgnoreList.Add(state, "1a2b3c4d5e6f7a8b", null, null, TestEnv.Now));
        Assert.Equal(Severity.High, state.IgnoredDetail["1a2b3c4d5e6f7a8b"].Severity);

        Assert.True(IgnoreList.Remove(state, "1a2b3c4d5e6f7a8b"));
        Assert.Empty(state.IgnoredDetail);
        Assert.False(IgnoreList.Remove(state, "1a2b3c4d5e6f7a8b"));
    }

    [Fact]
    public void ItemOnlyInReportIsHiddenAndAdoptedByNextScan()
    {
        var state = new ScanState { BaselineInitialized = true };
        var f = new Finding { RuleId = "T", Category = "Autorun", Severity = Severity.Medium, Title = "t", Location = "l" };
        Assert.True(IgnoreList.Add(state, f.Id, "보고서 제목", "Autorun", TestEnv.Now));
        Assert.Null(state.IgnoredDetail[f.Id].Severity);

        var r = new ScanResult { StartedUtc = TestEnv.Now, Scope = ScanScope.User, Reason = ScanReason.Daily, Quick = false };
        r.Findings.Add(f);
        r.CompletedCategories.Add("Autorun");
        BaselineEvaluator.Apply(r, state, new ScanConfig());
        Assert.Empty(r.Findings);
        Assert.Equal(Severity.Medium, state.IgnoredDetail[f.Id].Severity);
        Assert.Equal("보고서 제목", state.IgnoredDetail[f.Id].Title);
        Assert.Equal(TestEnv.Now, state.IgnoredDetail[f.Id].IgnoredUtc);
    }

    [Fact]
    public void SaveKeepsIgnoreChangesMadeDuringTheScan()
    {
        // 검사 시작 때 읽은 기록: a는 숨김(기준 모름), b는 숨김.
        var scan = new ScanState();
        scan.Ignored.UnionWith(["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "0000000000000000"]);
        var adoptA = IgnoreEdit.Adopt("aaaaaaaaaaaaaaaa", new IgnoreEntry { Severity = Severity.Medium, Title = "a" });
        var adoptB = IgnoreEdit.Adopt("bbbbbbbbbbbbbbbb", new IgnoreEntry { Severity = Severity.Low, Title = "b" });
        var rename = IgnoreEdit.Rename("0000000000000000", "1111111111111111");
        adoptA.ApplyTo(scan);
        adoptB.ApplyTo(scan);
        rename.ApplyTo(scan);

        // 검사하는 사이에 사용자가 b를 되돌리고 c를 숨겼어요.
        var disk = new ScanState();
        disk.Ignored.UnionWith(["aaaaaaaaaaaaaaaa", "cccccccccccccccc", "0000000000000000"]);
        disk.IgnoredDetail["cccccccccccccccc"] = new IgnoreEntry { Title = "c", Severity = Severity.High };

        IgnoreList.KeepLatest(scan, disk, [adoptA, adoptB, rename]);
        Assert.Equal(new[] { "1111111111111111", "aaaaaaaaaaaaaaaa", "cccccccccccccccc" }, scan.Ignored.Order(StringComparer.Ordinal));
        Assert.Equal(Severity.Medium, scan.IgnoredDetail["aaaaaaaaaaaaaaaa"].Severity);
        Assert.Equal("c", scan.IgnoredDetail["cccccccccccccccc"].Title);
        Assert.False(scan.IgnoredDetail.ContainsKey("bbbbbbbbbbbbbbbb"));
    }

    [Fact]
    public void AdoptDoesNotOverwriteANewIgnoreBaseline()
    {
        var state = new ScanState();
        state.Ignored.Add("aaaaaaaaaaaaaaaa");
        state.IgnoredDetail["aaaaaaaaaaaaaaaa"] = new IgnoreEntry { Severity = Severity.High, Title = "new" };
        IgnoreEdit.Adopt("aaaaaaaaaaaaaaaa", new IgnoreEntry { Severity = Severity.Low, Title = "old" }).ApplyTo(state);
        Assert.Equal(Severity.High, state.IgnoredDetail["aaaaaaaaaaaaaaaa"].Severity);
        Assert.Equal("new", state.IgnoredDetail["aaaaaaaaaaaaaaaa"].Title);
    }

    [Fact]
    public void DescribeShowsTitleSeverityAndDate()
    {
        var line = IgnoreList.Describe("1a2b3c4d5e6f7a8b", new IgnoreEntry { Title = "도구", Severity = Severity.Medium, IgnoredUtc = TestEnv.Now });
        Assert.StartsWith("1a2b3c4d5e6f7a8b  [보통] 도구 — ", line, StringComparison.Ordinal);
        Assert.EndsWith("에 숨김", line, StringComparison.Ordinal);
        Assert.Contains("예전 버전", IgnoreList.Describe("1a2b3c4d5e6f7a8b", null), StringComparison.Ordinal);
    }
}

public class ChangeReportTests
{
    [Fact]
    public void ChangedAndReleasedItemsAreLabelledAndHiddenItemsListed()
    {
        var doc = new ReportDocument
        {
            Scope = ScanScope.User,
            Findings =
            [
                new ReportFinding { Id = "1111111111111111", Title = "바뀐 것", Location = "l", Severity = Severity.High, IsNew = true, ChangeNote = "위험도가 올라갔어요 (낮음 → 높음)" },
                new ReportFinding { Id = "2222222222222222", Title = "풀린 것", Location = "l", Severity = Severity.Medium, IgnoreNote = "숨긴 항목인데 숨긴 뒤로 달라져서 다시 보여줘요: x." },
            ],
            IgnoredCount = 1,
            Ignored = [new ReportIgnored { Id = "3333333333333333", Title = "<숨긴 것>", Severity = Severity.Low, Location = "l" }],
        };
        var html = HtmlReport.Render(doc, runDialog: true);
        Assert.Contains("<span class=\"badge new\">달라진 항목</span>", html, StringComparison.Ordinal);
        Assert.Contains("지난 검사와 달라졌어요: 위험도가 올라갔어요 (낮음 → 높음)", html, StringComparison.Ordinal);
        Assert.Contains("숨김 풀림", html, StringComparison.Ordinal);
        Assert.Contains("새·달라진 항목", html, StringComparison.Ordinal);
        Assert.Contains("<h2>숨긴 항목</h2>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;숨긴 것&gt;", html, StringComparison.Ordinal);
        Assert.Contains("<code>safetysecurity unignore 3333333333333333</code>", html, StringComparison.Ordinal);

        var admin = HtmlReport.Render(new ReportDocument { Scope = ScanScope.Admin, Ignored = doc.Ignored, IgnoredCount = 1 });
        Assert.Contains("<code>SafetySecurity.exe unignore 3333333333333333 --scope admin</code>", admin, StringComparison.Ordinal);
    }

    [Fact]
    public void NewItemsKeepTheNewBadge()
    {
        var html = HtmlReport.Render(new ReportDocument { Findings = [new ReportFinding { Id = "1", Title = "t", Location = "l", IsNew = true }] });
        Assert.Contains("<span class=\"badge new\">새 항목</span>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("달라진 항목", html, StringComparison.Ordinal);
        Assert.DoesNotContain("숨김 풀림", html, StringComparison.Ordinal);
    }

    [Fact]
    public void ReportCarriesNotesAndHiddenItems()
    {
        var state = new ScanState { BaselineInitialized = true };
        var hidden = new Finding { RuleId = "T", Category = "A", Severity = Severity.Low, Title = "숨김", Location = "h" };
        state.Ignored.Add(hidden.Id);
        var r = new ScanResult { StartedUtc = TestEnv.Now, Scope = ScanScope.User, Reason = ScanReason.Daily, Quick = false };
        r.Findings.Add(hidden);
        var decision = BaselineEvaluator.Apply(r, state, new ScanConfig());
        var doc = ReportDocument.From(r, decision, "1", null);
        var i = Assert.Single(doc.Ignored);
        Assert.Equal(hidden.Id, i.Id);
        Assert.Equal("숨김", i.Title);
        Assert.Equal(1, doc.IgnoredCount);
    }

    [Fact]
    public void NoticeTitleMarksChangedItems()
    {
        var f = new Finding { RuleId = "T", Category = "A", Severity = Severity.High, Title = "도구", Location = "l" };
        Assert.Equal("도구", BaselineEvaluator.NoticeTitle(f));
        f.ChangeNote = "x";
        Assert.Equal("도구 (달라짐)", BaselineEvaluator.NoticeTitle(f));
    }
}
