using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Tests;

/// <summary>자동 검사를 언제 하고 언제 미룰지 (<see cref="ScanSchedule"/>).</summary>
public class SchedulingTests
{
    private static readonly DateTimeOffset Now = TestEnv.Now;

    private static PendingScan Pending(TimeSpan age, bool quick = false, DateTimeOffset? requested = null) => new()
    {
        Reason = quick ? ScanReason.Service : ScanReason.Daily,
        Quick = quick,
        SinceUtc = Now - age,
        RequestedUtc = requested ?? Now - age,
        Attempts = 1,
    };

    [Theory]
    [InlineData(ScanReason.Logon)]
    [InlineData(ScanReason.Daily)]
    public void LogonAndDailySkipRightAfterAFullScan(ScanReason reason)
    {
        var state = new ScanState { LastFullScanUtc = Now.AddMinutes(-20) };
        Assert.True(ScanSchedule.SkipBecauseRecent(reason, quick: false, force: false, state, Now));
    }

    [Theory]
    [InlineData(ScanReason.Manual)]
    [InlineData(ScanReason.Service)]
    [InlineData(ScanReason.Retry)]
    public void OtherReasonsAreNeverSkippedForRecency(ScanReason reason)
    {
        var state = new ScanState { LastFullScanUtc = Now.AddMinutes(-5) };
        Assert.False(ScanSchedule.SkipBecauseRecent(reason, quick: false, force: false, state, Now));
    }

    [Fact]
    public void RecencySkipNeedsARecentFullScanAndNothingPending()
    {
        var recent = Now.AddMinutes(-30);
        Assert.False(ScanSchedule.SkipBecauseRecent(ScanReason.Logon, false, false, new ScanState(), Now));
        Assert.False(ScanSchedule.SkipBecauseRecent(ScanReason.Logon, false, false, new ScanState { LastFullScanUtc = Now.AddHours(-3) }, Now));
        Assert.False(ScanSchedule.SkipBecauseRecent(ScanReason.Logon, false, force: true, new ScanState { LastFullScanUtc = recent }, Now));
        Assert.False(ScanSchedule.SkipBecauseRecent(ScanReason.Logon, quick: true, false, new ScanState { LastFullScanUtc = recent }, Now));

        // 미뤄둔 검사가 있으면 로그온 검사가 그걸 해 줘야 해요.
        Assert.False(ScanSchedule.SkipBecauseRecent(ScanReason.Daily, false, false, new ScanState { LastFullScanUtc = recent, Pending = Pending(TimeSpan.FromHours(1)) }, Now));

        // 시계를 뒤로 돌려서 기록이 미래에 있으면 최근으로 보지 않아요.
        Assert.False(ScanSchedule.SkipBecauseRecent(ScanReason.Daily, false, false, new ScanState { LastFullScanUtc = Now.AddHours(5) }, Now));
    }

    [Fact]
    public void DeferringAManualScanLeavesABackgroundRetry()
    {
        var p = ScanSchedule.Defer(null, ScanReason.Manual, quick: false, "시간 제한을 넘음", Now);
        Assert.Equal(ScanReason.Retry, p.Reason);
        Assert.False(p.Quick);
        Assert.Equal(Now, p.SinceUtc);
        Assert.Equal(Now, p.RequestedUtc);
        Assert.Equal(1, p.Attempts);

        // 예전 버전이 남긴 Manual 미룸도 백그라운드 검사로 바꿔요.
        var legacy = new PendingScan { Reason = ScanReason.Manual, SinceUtc = Now.AddHours(-1), Attempts = 2 };
        Assert.Equal(ScanReason.Retry, ScanSchedule.Defer(legacy, ScanReason.Daily, false, "x", Now).Reason);
    }

    [Fact]
    public void DeferMergesAndKeepsTheOldestStartAndOverdueMarks()
    {
        var existing = new PendingScan
        {
            Reason = ScanReason.Service,
            Quick = true,
            SinceUtc = Now.AddHours(-3),
            RequestedUtc = Now.AddHours(-3),
            Attempts = 4,
            OverdueRunUtc = Now.AddHours(-1),
            OverdueNoticeUtc = Now.AddHours(-2),
        };
        var p = ScanSchedule.Defer(existing, ScanReason.Logon, quick: false, "게임 프로세스 실행 중", Now);
        Assert.Equal(ScanReason.Service, p.Reason);
        Assert.False(p.Quick);
        Assert.Equal(existing.SinceUtc, p.SinceUtc);
        Assert.Equal(Now, p.RequestedUtc);
        Assert.Equal(5, p.Attempts);
        Assert.Equal(existing.OverdueRunUtc, p.OverdueRunUtc);
        Assert.Equal(existing.OverdueNoticeUtc, p.OverdueNoticeUtc);
        Assert.True(ScanSchedule.Defer(existing, ScanReason.Service, quick: true, "x", Now).Quick);
    }

    [Fact]
    public void SaveKeepsARequestThatAnotherScanMadeDuringThisScan()
    {
        var start = Now.AddMinutes(-5);
        var serviceRequest = Pending(TimeSpan.FromMinutes(2), quick: true);

        // 전체 검사를 끝냈어도, 그 사이 들어온 새 서비스 검사 요청은 남겨요 (서비스 목록은 이미 지나갔을 수 있어요).
        var kept = ScanSchedule.MergeOnSave(null, serviceRequest, start, completedFull: true);
        Assert.NotNull(kept);
        Assert.True(kept!.Quick);
        Assert.Equal(ScanReason.Service, kept.Reason);

        // 빠른 검사를 끝냈으면 전체 검사 요청도 그대로 남겨요.
        var fullRequest = Pending(TimeSpan.FromMinutes(1));
        var afterQuick = ScanSchedule.MergeOnSave(null, fullRequest, start, completedFull: false);
        Assert.False(afterQuick!.Quick);
    }

    [Fact]
    public void FullScanTurnsAFullRequestMadeDuringItIntoAQuickFollowUp()
    {
        var start = Now.AddMinutes(-5);
        var logonRequest = Pending(TimeSpan.FromMinutes(1));
        var p = ScanSchedule.MergeOnSave(null, logonRequest, start, completedFull: true);
        Assert.NotNull(p);
        Assert.True(p!.Quick);
        Assert.Equal(ScanReason.Retry, p.Reason);
    }

    [Fact]
    public void SaveDoesNotResurrectAPendingThisScanAlreadyDid()
    {
        var start = Now.AddMinutes(-5);
        var old = Pending(TimeSpan.FromHours(2));
        Assert.Null(ScanSchedule.MergeOnSave(null, old, start, completedFull: true));

        // RequestedUtc가 없는 예전 기록도 이 검사가 읽은 것으로 봐요.
        var legacy = new PendingScan { Reason = ScanReason.Daily, SinceUtc = Now.AddMinutes(-1) };
        Assert.Null(ScanSchedule.MergeOnSave(null, legacy, start, completedFull: true));
        Assert.Null(ScanSchedule.MergeOnSave(null, null, start, completedFull: false));
    }

    [Fact]
    public void SaveMergesWhenThisScanWasDeferredToo()
    {
        var start = Now.AddMinutes(-5);
        var mine = ScanSchedule.Defer(Pending(TimeSpan.FromHours(30)), ScanReason.Daily, false, "게임 프로세스 실행 중", start);
        var other = Pending(TimeSpan.FromMinutes(1), quick: true);
        var p = ScanSchedule.MergeOnSave(mine, other, start, completedFull: false);
        Assert.NotNull(p);
        Assert.False(p!.Quick);
        Assert.Equal(mine.SinceUtc, p.SinceUtc);
        Assert.Equal(other.RequestedUtc, p.RequestedUtc);
        Assert.Equal("게임 프로세스 실행 중", p.DeferredBecause);
    }

    [Fact]
    public void NotBusyAlwaysRuns()
    {
        Assert.Equal(DeferAction.Run, ScanSchedule.Decide(null, null, Now));
        Assert.Equal(DeferAction.Run, ScanSchedule.Decide(null, Pending(TimeSpan.FromDays(3)), Now));
    }

    [Theory]
    [InlineData(BusyKind.Cpu)]
    [InlineData(BusyKind.Fullscreen)]
    [InlineData(BusyKind.GameProcess)]
    public void BusyDefersUntilADayHasPassed(BusyKind kind)
    {
        var busy = new BusyReason(kind, "바쁨");
        Assert.Equal(DeferAction.Defer, ScanSchedule.Decide(busy, null, Now));
        Assert.Equal(DeferAction.Defer, ScanSchedule.Decide(busy, Pending(TimeSpan.FromHours(23)), Now));
    }

    [Theory]
    [InlineData(BusyKind.Cpu)]
    [InlineData(BusyKind.Fullscreen)]
    public void CpuOrFullscreenRunsAnywayOnceOverdue_AtMostEverySixHours(BusyKind kind)
    {
        var busy = new BusyReason(kind, "바쁨");
        var pending = Pending(TimeSpan.FromHours(25));
        Assert.Equal(DeferAction.RunOverdue, ScanSchedule.Decide(busy, pending, Now));

        pending.OverdueRunUtc = Now.AddHours(-2);
        Assert.Equal(DeferAction.Defer, ScanSchedule.Decide(busy, pending, Now));

        pending.OverdueRunUtc = Now.AddHours(-7);
        Assert.Equal(DeferAction.RunOverdue, ScanSchedule.Decide(busy, pending, Now));

        // 시계를 바꿔서 마지막 시도가 미래에 있으면 막지 않아요.
        pending.OverdueRunUtc = Now.AddHours(3);
        Assert.Equal(DeferAction.RunOverdue, ScanSchedule.Decide(busy, pending, Now));
    }

    [Fact]
    public void GameProcessNeverRunsEvenWhenOverdue_AndWarnsOnlyOnce()
    {
        var game = new BusyReason(BusyKind.GameProcess, "게임 프로세스 실행 중 (cs2.exe)");
        var pending = Pending(TimeSpan.FromDays(4));
        Assert.Equal(DeferAction.DeferAndWarn, ScanSchedule.Decide(game, pending, Now));

        pending.OverdueNoticeUtc = Now.AddHours(-1);
        Assert.Equal(DeferAction.Defer, ScanSchedule.Decide(game, pending, Now));

        pending.OverdueRunUtc = null;
        pending.OverdueNoticeUtc = Now.AddDays(-3);
        Assert.Equal(DeferAction.Defer, ScanSchedule.Decide(game, pending, Now));
    }

    [Fact]
    public void FullscreenGameThatIsAlsoListedIsTreatedAsGame_NeverRunOverdue()
    {
        // 게임 목록의 게임이 전체 화면으로 실행 중이면(보통 이래요) 게임으로 봐야 해요. 전체 화면으로 보면 밀린 검사가 게임 중에 시작돼요.
        var game = new BusyReason(BusyKind.GameProcess, "게임 프로세스 실행 중 (cs2.exe)");
        var fullscreen = new BusyReason(BusyKind.Fullscreen, "전체 화면 게임(D3D)이 실행 중");
        var cpuCalled = false;
        var busy = ScanSchedule.FirstBusy(() => game, () => fullscreen, () =>
        {
            cpuCalled = true;
            return new BusyReason(BusyKind.Cpu, "CPU");
        });

        Assert.Same(game, busy);
        Assert.False(cpuCalled);

        var pending = Pending(TimeSpan.FromDays(2));
        Assert.Equal(DeferAction.DeferAndWarn, ScanSchedule.Decide(busy, pending, Now));
        pending.OverdueNoticeUtc = Now.AddHours(-1);
        Assert.Equal(DeferAction.Defer, ScanSchedule.Decide(busy, pending, Now));
    }

    [Fact]
    public void FullscreenWithoutListedGameStillRunsOverdue()
    {
        // 게임 목록에 없는 전체 화면 앱(영상 등)만 있으면, 하루 넘게 밀린 검사는 예전처럼 백그라운드로 해요.
        var fullscreen = new BusyReason(BusyKind.Fullscreen, "전체 화면 앱이 실행 중");
        var busy = ScanSchedule.FirstBusy(() => null, () => fullscreen, () => new BusyReason(BusyKind.Cpu, "CPU"));
        Assert.Same(fullscreen, busy);
        Assert.Equal(DeferAction.RunOverdue, ScanSchedule.Decide(busy, Pending(TimeSpan.FromDays(2)), Now));

        Assert.Equal(BusyKind.Cpu, ScanSchedule.FirstBusy(() => null, () => null, () => new BusyReason(BusyKind.Cpu, "CPU"))?.Kind);
        Assert.Null(ScanSchedule.FirstBusy(() => null, () => null, () => null));
    }

    [Fact]
    public void FutureStartIsNotOverdue()
    {
        var pending = Pending(TimeSpan.FromHours(-30));
        Assert.False(ScanSchedule.IsOverdue(pending, Now));
        Assert.Equal(DeferAction.Defer, ScanSchedule.Decide(new BusyReason(BusyKind.Cpu, "CPU"), pending, Now));
    }

    [Fact]
    public void OverdueTextOnlyWhenOverdue()
    {
        Assert.Null(ScanSchedule.OverdueText(null, Now));
        Assert.Null(ScanSchedule.OverdueText(Pending(TimeSpan.FromHours(3)), Now));
        var text = ScanSchedule.OverdueText(Pending(TimeSpan.FromHours(30)), Now);
        Assert.NotNull(text);
        Assert.Contains("30시간", text, StringComparison.Ordinal);
    }

    [Fact]
    public void NewPendingFieldsRoundTripThroughJson()
    {
        var state = new ScanState
        {
            Pending = ScanSchedule.Defer(null, ScanReason.Logon, false, "x", Now),
            InitializedCategories = ["Service"],
        };
        state.Pending.OverdueRunUtc = Now.AddHours(-1);
        state.Pending.OverdueNoticeUtc = Now.AddHours(-2);
        var json = System.Text.Json.JsonSerializer.Serialize(state, Reporting.SafetyJson.Context.ScanState);
        var back = System.Text.Json.JsonSerializer.Deserialize(json, Reporting.SafetyJson.Context.ScanState)!;
        Assert.Equal(Now, back.Pending!.RequestedUtc);
        Assert.Equal(Now.AddHours(-1), back.Pending.OverdueRunUtc);
        Assert.Equal(Now.AddHours(-2), back.Pending.OverdueNoticeUtc);
        Assert.Contains("Service", back.InitializedCategories!);

        // 예전 기록(새 칸 없음)은 null로 읽혀요.
        var old = System.Text.Json.JsonSerializer.Deserialize("""{"version":2,"baselineInitialized":true,"pending":{"reason":"Daily","quick":false,"sinceUtc":"2026-11-05T10:00:00+00:00","attempts":1}}""", Reporting.SafetyJson.Context.ScanState)!;
        Assert.Null(old.InitializedCategories);
        Assert.Null(old.Pending!.RequestedUtc);
    }
}
