using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Baseline;

/// <summary>지금 검사하면 방해가 되는 이유의 종류.</summary>
public enum BusyKind
{
    /// <summary>시스템 전체 CPU 사용률이 높아요.</summary>
    Cpu,

    /// <summary>전체 화면 앱(게임·영상·발표)이 맨 앞에 있어요.</summary>
    Fullscreen,

    /// <summary>설정의 게임 목록에 있는 프로세스가 실행 중이에요.</summary>
    GameProcess,
}

/// <summary>검사를 미루는 이유 (종류와 사용자에게 보여줄 문장).</summary>
public sealed record BusyReason(BusyKind Kind, string Text)
{
    public override string ToString() => Text;
}

/// <summary>바쁠 때 자동 검사를 어떻게 할지.</summary>
public enum DeferAction
{
    /// <summary>바쁘지 않아요. 그대로 검사해요.</summary>
    Run,

    /// <summary>하루 넘게 밀렸어요. 바빠도(CPU·전체 화면) 백그라운드 우선순위로 천천히 검사해요.</summary>
    RunOverdue,

    /// <summary>미뤄요.</summary>
    Defer,

    /// <summary>게임 중이라 계속 미루지만, 하루 넘게 밀렸다고 한 번 알려 드려요.</summary>
    DeferAndWarn,
}

/// <summary>
/// 자동 검사를 언제 하고 언제 미룰지 정하는 규칙이에요 (Windows API 없이 시각과 기록만 봐요).
/// - 로그온·하루 한 번 검사는 방금(2시간 안) 전체 검사를 끝냈으면 건너뛰어요 (같은 검사를 연달아 두 번 하지 않게).
/// - 다른 검사와 겹쳐 못 한 검사는 미뤄둔 검사로 남겨요. 30분마다 깨는 Retry 작업이 해요.
/// - CPU·전체 화면 때문에 하루 넘게 밀리면 백그라운드로 검사해요 (6시간에 한 번까지만 시도해요). 게임 프로세스가 실행 중이면
///   절대 검사하지 않고, 대신 하루 넘게 밀렸다고 한 번만 알려요.
/// </summary>
public static class ScanSchedule
{
    /// <summary>이 시간 안에 전체 검사를 끝냈으면 로그온·하루 한 번 검사를 건너뛰어요.</summary>
    public static readonly TimeSpan RecentFullScan = TimeSpan.FromHours(2);

    /// <summary>미뤄둔 검사가 이만큼 밀리면 '밀린 검사'로 봐요.</summary>
    public static readonly TimeSpan OverdueAfter = TimeSpan.FromHours(24);

    /// <summary>밀린 검사를 바쁠 때 시작하는 간격 (하루 최대 4번).</summary>
    public static readonly TimeSpan OverdueRunEvery = TimeSpan.FromHours(6);

    /// <summary>
    /// 로그온·하루 한 번 전체 검사를 건너뛸지. 방금 전체 검사를 끝냈고 미뤄둔 검사도 없을 때만 건너뛰어요.
    /// 직접 검사·서비스 설치 검사·--force·빠른 검사는 건너뛰지 않아요. 기록 시각이 미래(시계를 바꿈)면 최근으로 보지 않아요.
    /// </summary>
    public static bool SkipBecauseRecent(ScanReason reason, bool quick, bool force, ScanState state, DateTimeOffset now)
    {
        if (force || quick || reason is not (ScanReason.Logon or ScanReason.Daily) || state.Pending is not null || state.LastFullScanUtc is not { } last)
        {
            return false;
        }

        var age = now - last;
        return age >= TimeSpan.Zero && age < RecentFullScan;
    }

    /// <summary>
    /// 백그라운드(Retry 작업)가 대신 할 검사 이유. 직접 검사(Manual)를 미루면 Retry로 바꿔서, 나중에 작업 스케줄러가
    /// 대신 검사할 때 '직접 실행'처럼 보고서를 저절로 열지 않게 해요.
    /// </summary>
    public static ScanReason BackgroundReason(ScanReason reason) => reason == ScanReason.Manual ? ScanReason.Retry : reason;

    /// <summary>검사를 미뤄요. 이미 미뤄둔 검사가 있으면 합쳐요 (전체 검사가 하나라도 있으면 전체 검사).</summary>
    public static PendingScan Defer(PendingScan? existing, ScanReason reason, bool quick, string because, DateTimeOffset now) => new()
    {
        Reason = BackgroundReason(existing?.Reason ?? reason),
        Quick = (existing?.Quick ?? true) && quick,
        SinceUtc = existing?.SinceUtc ?? now,
        DeferredBecause = because,
        Attempts = (existing?.Attempts ?? 0) + 1,
        RequestedUtc = Later(existing?.RequestedUtc, now),
        OverdueRunUtc = existing?.OverdueRunUtc,
        OverdueNoticeUtc = existing?.OverdueNoticeUtc,
    };

    /// <summary>
    /// 검사가 기록을 저장하기 직전에, 디스크의 미뤄둔 검사와 이 검사가 저장하려는 것을 합쳐요.
    /// 이 검사가 시작된 뒤에 다른 검사가 남긴 요청(예: 전체 검사 중에 새 서비스가 설치됨)은 지우지 않아요.
    /// 전체 검사를 끝냈으면 그 사이 요청은 빠른 검사(서비스·예약 작업)로만 남겨요. 전체 검사를 연달아 하지 않으면서도,
    /// 이 검사가 이미 지나간 서비스 목록에 새로 생긴 것을 놓치지 않으려고요.
    /// </summary>
    /// <param name="mine">이 검사가 저장하려는 미뤄둔 검사 (끝까지 검사했으면 보통 null).</param>
    /// <param name="onDisk">저장 직전에 다시 읽은 디스크의 미뤄둔 검사.</param>
    /// <param name="scanStart">이 검사가 시작된 시각.</param>
    /// <param name="completedFull">이 검사가 전체 검사를 끝까지 했는지.</param>
    public static PendingScan? MergeOnSave(PendingScan? mine, PendingScan? onDisk, DateTimeOffset scanStart, bool completedFull)
    {
        if (onDisk?.RequestedUtc is not { } requested || requested <= scanStart)
        {
            return mine;
        }

        if (mine is not null)
        {
            return new PendingScan
            {
                Reason = mine.Reason,
                Quick = mine.Quick && onDisk.Quick,
                SinceUtc = mine.SinceUtc <= onDisk.SinceUtc ? mine.SinceUtc : onDisk.SinceUtc,
                DeferredBecause = mine.DeferredBecause ?? onDisk.DeferredBecause,
                Attempts = Math.Max(mine.Attempts, onDisk.Attempts),
                RequestedUtc = Later(mine.RequestedUtc, requested),
                OverdueRunUtc = Later(mine.OverdueRunUtc, onDisk.OverdueRunUtc),
                OverdueNoticeUtc = Later(mine.OverdueNoticeUtc, onDisk.OverdueNoticeUtc),
            };
        }

        return new PendingScan
        {
            Reason = completedFull && !onDisk.Quick ? ScanReason.Retry : onDisk.Reason,
            Quick = completedFull || onDisk.Quick,
            SinceUtc = onDisk.SinceUtc,
            DeferredBecause = onDisk.DeferredBecause,
            Attempts = onDisk.Attempts,
            RequestedUtc = requested,
            OverdueRunUtc = onDisk.OverdueRunUtc,
            OverdueNoticeUtc = onDisk.OverdueNoticeUtc,
        };
    }

    /// <summary>미뤄둔 검사가 하루 넘게 밀렸는지. 시작 시각이 미래(시계를 바꿈)면 밀리지 않은 것으로 봐요.</summary>
    public static bool IsOverdue(PendingScan? pending, DateTimeOffset now) =>
        pending is not null && now - pending.SinceUtc > OverdueAfter;

    /// <summary>
    /// 지금 바쁜 이유를 하나 골라요. 게임 프로세스를 가장 먼저 봐요: 게임은 보통 전체 화면이라, 전체 화면을 먼저 보면
    /// 게임 중인데도 '전체 화면 앱'으로 잘못 알고 <see cref="Decide"/>가 밀린 검사를 시작해 버려요 (게임 중에는 절대 검사하지 않아요).
    /// 그다음 전체 화면, 마지막으로 CPU(재는 데 시간이 걸려요)를 봐요. 앞에서 이유를 찾으면 뒤는 부르지 않아요.
    /// </summary>
    /// <param name="gameProcess">게임 목록의 프로세스가 실행 중인지.</param>
    /// <param name="fullscreen">전체 화면 앱이 맨 앞에 있는지 (안 볼 때는 null을 돌려줘요).</param>
    /// <param name="cpu">CPU 사용률이 높은지 (안 볼 때는 null을 돌려줘요).</param>
    public static BusyReason? FirstBusy(Func<BusyReason?> gameProcess, Func<BusyReason?> fullscreen, Func<BusyReason?> cpu) =>
        gameProcess() ?? fullscreen() ?? cpu();

    /// <summary>
    /// 바쁠 때 자동 검사를 어떻게 할지 정해요.
    /// 게임 프로세스가 실행 중이면 얼마나 밀렸든 검사하지 않아요 (하루 넘게 밀렸으면 한 번만 알려요).
    /// CPU·전체 화면 때문이면 하루 넘게 밀린 뒤에는 백그라운드로 검사하되, 6시간에 한 번까지만 시도해요.
    /// </summary>
    public static DeferAction Decide(BusyReason? busy, PendingScan? pending, DateTimeOffset now)
    {
        if (busy is null)
        {
            return DeferAction.Run;
        }

        if (!IsOverdue(pending, now))
        {
            return DeferAction.Defer;
        }

        if (busy.Kind == BusyKind.GameProcess)
        {
            return pending!.OverdueNoticeUtc is null ? DeferAction.DeferAndWarn : DeferAction.Defer;
        }

        if (pending!.OverdueRunUtc is { } last && now >= last && now - last < OverdueRunEvery)
        {
            return DeferAction.Defer;
        }

        return DeferAction.RunOverdue;
    }

    /// <summary>status에 보여줄 '밀린 검사' 안내. 밀리지 않았으면 null.</summary>
    public static string? OverdueText(PendingScan? pending, DateTimeOffset now)
    {
        if (!IsOverdue(pending, now))
        {
            return null;
        }

        var hours = (int)(now - pending!.SinceUtc).TotalHours;
        return $"검사가 {hours}시간째 밀려 있어요. 게임을 끈 뒤 바탕화면·시작 메뉴의 SafetySecurity를 눌러 검사해 주세요 (게임 중이 아니면 백그라운드로 천천히 검사해요).";
    }

    private static DateTimeOffset? Later(DateTimeOffset? a, DateTimeOffset? b) =>
        a is null ? b : b is null ? a : a > b ? a : b;
}
