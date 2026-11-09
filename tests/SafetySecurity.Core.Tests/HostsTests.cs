using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Scanners;

namespace SafetySecurity.Core.Tests;

/// <summary>hosts 파일: 텔레메트리·광고 차단은 낮추고, 보안·업데이트·로그인 주소는 계속 높음. 줄이 움직여도 ID는 그대로.</summary>
public class HostsTests
{
    private const string Path = @"C:\Windows\System32\drivers\etc\hosts";

    private static Finding One(string line) => Assert.Single(HostsScanner.Analyze(line, Path));

    [Theory]
    [InlineData("0.0.0.0 vortex.data.microsoft.com")]
    [InlineData("0.0.0.0 vortex-win.data.microsoft.com")]
    [InlineData("0.0.0.0 settings-win.data.microsoft.com")]
    [InlineData("0.0.0.0 v10.events.data.microsoft.com")]
    [InlineData("0.0.0.0 watson.telemetry.microsoft.com")]
    [InlineData("127.0.0.1 telemetry.microsoft.com")]
    [InlineData("0.0.0.0 browser.pipe.aria.microsoft.com")]
    [InlineData("0.0.0.0 statsfe2.ws.microsoft.com")]
    [InlineData("0.0.0.0 adservice.google.com")]
    [InlineData("0.0.0.0 pagead2.google.com")]
    [InlineData("0.0.0.0 ads.google.com")]
    [InlineData("0.0.0.0 ad.daum.net")]
    [InlineData(":: ads1.naver.com")]
    public void TelemetryAndAdBlocksAreOnlyInfo(string line)
    {
        var f = One(line);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.DoesNotContain("악성코드", f.Reasons[0], StringComparison.Ordinal);
        Assert.Contains("텔레메트리", f.Reasons[0], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("0.0.0.0 update.microsoft.com")]
    [InlineData("0.0.0.0 fe2.update.microsoft.com")]
    [InlineData("0.0.0.0 statsfe2.update.microsoft.com")]
    [InlineData("0.0.0.0 definitionupdates.microsoft.com")]
    [InlineData("0.0.0.0 wdcp.microsoft.com")]
    [InlineData("0.0.0.0 smartscreen-prod.microsoft.com")]
    [InlineData("0.0.0.0 tlu.dl.delivery.mp.microsoft.com")]
    [InlineData("0.0.0.0 login.live.com")]
    [InlineData("0.0.0.0 accounts.google.com")]
    [InlineData("0.0.0.0 safebrowsing.googleapis.com")]
    [InlineData("0.0.0.0 microsoft.com")]
    [InlineData("0.0.0.0 www.google.com")]
    [InlineData("0.0.0.0 go.microsoft.com")]
    [InlineData("0.0.0.0 www.virustotal.com")]
    [InlineData("0.0.0.0 telemetry.malwarebytes.com")]
    [InlineData("0.0.0.0 ads.riotgames.com")]
    [InlineData("0.0.0.0 download.windowsupdate.com")]
    [InlineData("203.0.113.5 vortex.data.microsoft.com")]
    [InlineData("203.0.113.5 adservice.google.com")]
    [InlineData("203.0.113.5 auth.riotgames.com")]
    public void SecurityUpdateLoginAndRedirectsStayHigh(string line)
    {
        Assert.Equal(Severity.High, One(line).Severity);
    }

    [Fact]
    public void IdDoesNotDependOnLineNumber()
    {
        var before = One("0.0.0.0 update.microsoft.com");
        var after = Assert.Single(HostsScanner.Analyze("# Docker Desktop\n10.0.0.5 host.docker.internal\n\n0.0.0.0 update.microsoft.com\n", Path));
        Assert.Equal(before.Id, after.Id);
        Assert.Equal(Path, after.Location);
        Assert.Equal("4", after.Evidence.First(e => e.Key == "줄 번호").Value);
        Assert.NotEqual(One("0.0.0.0 login.live.com").Id, before.Id);
        Assert.NotEqual(One("127.0.0.1 update.microsoft.com").Id, before.Id);
    }

    [Fact]
    public void DuplicateLinesAreOneFinding()
    {
        var f = Assert.Single(HostsScanner.Analyze("0.0.0.0 update.microsoft.com\n0.0.0.0 UPDATE.microsoft.com.\n", Path));
        Assert.Equal(2, f.PreviousIds.Count);
    }

    [Fact]
    public void OldLineNumberIdsMoveToTheNewIdOnce()
    {
        // 예전 버전은 위치에 줄 번호를 넣었어요 (hosts:3). 업데이트 뒤 첫 검사에서 새로 알리거나 숨김이 풀리면 안 돼요.
        var text = "# a\n# b\n0.0.0.0 update.microsoft.com\n203.0.113.5 auth.riotgames.com\n";
        var oldBlock = Finding.ComputeId(HostsScanner.CategoryName, Path + ":3", "0.0.0.0 update.microsoft.com");
        var oldRedirect = Finding.ComputeId(HostsScanner.CategoryName, Path + ":4", "203.0.113.5 auth.riotgames.com");
        var state = new ScanState { BaselineInitialized = true };
        state.Baseline[oldBlock] = HostsScanner.CategoryName;
        state.Baseline[oldRedirect] = HostsScanner.CategoryName;
        state.Ignored.Add(oldRedirect);

        var r = new ScanResult { StartedUtc = TestEnv.Now, Scope = ScanScope.User, Reason = ScanReason.Daily, Quick = false };
        r.Findings.AddRange(HostsScanner.Analyze(text, Path));
        r.CompletedCategories.Add(HostsScanner.CategoryName);
        var d = BaselineEvaluator.Apply(r, state, new ScanConfig());

        Assert.Empty(d.ToNotify);
        var block = Assert.Single(r.Findings);
        Assert.False(block.IsNew);
        var hidden = Assert.Single(r.IgnoredFindings);
        Assert.Contains(hidden.Id, state.Ignored);
        Assert.DoesNotContain(oldRedirect, state.Ignored);
        Assert.False(state.Baseline.ContainsKey(oldBlock));
        Assert.Equal(2, state.Baseline.Count);
        Assert.Contains(d.IgnoreEdits, e => e.OldId == oldRedirect && e.Id == hidden.Id);
    }
}
