using System.Diagnostics;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Model;
using static SafetySecurity.Native.NativeMethods;

namespace SafetySecurity.Runtime;

internal static class Throttle
{
    /// <summary>
    /// 자기 프로세스만 백그라운드 모드(낮은 CPU·디스크·메모리 우선순위)와 효율 모드(EcoQoS)로 바꿔요.
    /// 다른 프로세스의 우선순위는 건드리지 않아요.
    /// </summary>
    public static void EnterBackgroundMode()
    {
        var self = GetCurrentProcess();
        SetPriorityClass(self, PROCESS_MODE_BACKGROUND_BEGIN);
        var state = new PROCESS_POWER_THROTTLING_STATE
        {
            Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
            StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        };
        unsafe
        {
            SetProcessInformation(self, ProcessPowerThrottling, ref state, (uint)sizeof(PROCESS_POWER_THROTTLING_STATE));
        }
    }
}

/// <summary>
/// 스캐너가 Step()을 부를 때마다 무게를 세서, 일정량마다 잠깐 쉬고 게임 시작 여부를 다시 봐요.
/// 시간 제한(작업 스케줄러 15분 제한보다 짧게)도 여기서 지켜요.
/// </summary>
/// <param name="detector">게임·전체 화면을 볼 감지기. null이면 보지 않아요 (사용자가 직접 시작한 검사).</param>
/// <param name="budget">시간 제한.</param>
/// <param name="gamesOnly">true면 게임 프로세스가 시작될 때만 멈춰요 (하루 넘게 밀린 검사: 전체 화면 앱이 있어도 계속해요).</param>
internal sealed class Pacer(GameDetector? detector, TimeSpan budget, bool gamesOnly = false) : IScanPacer
{
    /// <summary>시간 제한으로 멈췄을 때의 이유 문장.</summary>
    public const string TimeLimitReason = "시간 제한을 넘음";

    private const int SleepEvery = 40;
    private const int SleepMs = 8;
    private const int RecheckEvery = 400;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private long _weight;
    private long _nextSleep = SleepEvery;
    private long _nextCheck = RecheckEvery;

    public void Step(int weight = 1)
    {
        _weight += weight;
        if (_weight >= _nextSleep)
        {
            _nextSleep = _weight + SleepEvery;
            Thread.Sleep(SleepMs);
        }

        if (_weight >= _nextCheck)
        {
            _nextCheck = _weight + RecheckEvery;
            if (_clock.Elapsed > budget)
            {
                throw new ScanAbortedException(TimeLimitReason);
            }

            if (detector?.Check(includeCpu: false, includeFullscreen: !gamesOnly) is { } reason)
            {
                throw new ScanAbortedException(reason.Text);
            }
        }
    }
}

/// <summary>
/// 같은 범위의 검사가 동시에 두 번 돌지 않게 해요.
/// 사용자 검사는 세션 안의 이름 있는 뮤텍스를 써요. 관리자 검사는 일반 권한 프로그램이 이름을 먼저 차지해서 막을 수 없게,
/// 관리자 데이터 폴더 안의 잠금 파일(관리자·SYSTEM만 열 수 있어요)을 써요 (<see cref="DataStore.TryOpenAdminLock"/>).
/// </summary>
internal sealed class ScanLock : IDisposable
{
    private readonly IDisposable _held;

    private ScanLock(IDisposable held) => _held = held;

    public static ScanLock? TryAcquire(ScanScope scope, DataStore store)
    {
        if (scope == ScanScope.Admin && Environment.IsPrivilegedProcess)
        {
            return store.TryOpenAdminLock("scan.admin.lock") is { } file ? new ScanLock(file) : null;
        }

        var mutex = new Mutex(false, @"Local\SafetySecurity.Scan." + scope);
        try
        {
            bool acquired;
            try
            {
                acquired = mutex.WaitOne(0);
            }
            catch (AbandonedMutexException)
            {
                // 이전 검사가 비정상 종료됐어요. 소유권은 이미 우리에게 넘어왔어요.
                acquired = true;
            }

            if (acquired)
            {
                return new ScanLock(new OwnedMutex(mutex));
            }
        }
        catch
        {
            mutex.Dispose();
            throw;
        }

        mutex.Dispose();
        return null;
    }

    public void Dispose() => _held.Dispose();
}

/// <summary>잡은 뮤텍스를 놓고 닫아요.</summary>
internal sealed class OwnedMutex(Mutex mutex) : IDisposable
{
    public void Dispose()
    {
        mutex.ReleaseMutex();
        mutex.Dispose();
    }
}

/// <summary>
/// 기록 파일(state*.json) 하나를 읽고-고치고-쓰는 동안만 잡는 짧은 잠금.
/// 몇 분 걸리는 검사와 ignore·unignore 명령이 서로의 변경을 덮어쓰지 않게 해요. 검사 잠금(<see cref="ScanLock"/>)과 달리
/// 검사 내내 잡지 않아서, 검사 중에도 ignore 명령은 기다리지 않고 바로 끝나요. 우리 프로세스끼리 쓰는 이름 있는 뮤텍스라
/// 다른 프로세스를 열지 않아요.
/// </summary>
internal sealed class StateLock : IDisposable
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);
    private readonly IDisposable? _held;

    private StateLock(IDisposable? held) => _held = held;

    /// <summary>
    /// 잠금을 잡아요. 10초 안에 못 잡거나 잠금을 열 수 없으면 기록만 남기고 잠금 없이 계속해요.
    /// 관리자 권한으로 관리자 기록을 쓸 때는 일반 권한 프로그램이 가로챌 수 없는 잠금 파일을 써요 (<see cref="ScanLock"/>와 같아요).
    /// </summary>
    public static StateLock Acquire(DataStore store, ScanScope scope)
    {
        var statePath = store.StatePath(scope);
        Action<string> log = store.Log;
        if (scope == ScanScope.Admin && Environment.IsPrivilegedProcess)
        {
            return AcquireFile(store, log);
        }

        // 파일 경로마다 다른 이름: 사용자 폴더와 관리자 폴더의 기록은 서로 다른 잠금을 써요.
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Path.GetFullPath(statePath).ToLowerInvariant()));
        var name = @"Local\SafetySecurity.State." + Convert.ToHexStringLower(hash.AsSpan(0, 8));
        Mutex mutex;
        try
        {
            mutex = new Mutex(false, name);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or WaitHandleCannotBeOpenedException or IOException)
        {
            log($"기록 잠금을 열지 못해서 잠금 없이 계속해요 ({ex.GetType().Name})");
            return new StateLock(null);
        }

        try
        {
            bool acquired;
            try
            {
                acquired = mutex.WaitOne(Wait);
            }
            catch (AbandonedMutexException)
            {
                // 다른 프로세스가 기록을 쓰다가 비정상 종료됐어요. 소유권은 이미 우리에게 넘어왔어요.
                acquired = true;
            }

            if (acquired)
            {
                return new StateLock(new OwnedMutex(mutex));
            }
        }
        catch
        {
            mutex.Dispose();
            throw;
        }

        mutex.Dispose();
        log("기록 잠금을 10초 안에 얻지 못해서 잠금 없이 계속해요.");
        return new StateLock(null);
    }

    public void Dispose() => _held?.Dispose();

    private static StateLock AcquireFile(DataStore store, Action<string> log)
    {
        var clock = Stopwatch.StartNew();
        try
        {
            while (true)
            {
                if (store.TryOpenAdminLock("state.admin.lock") is { } file)
                {
                    return new StateLock(file);
                }

                if (clock.Elapsed >= Wait)
                {
                    break;
                }

                Thread.Sleep(100);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            log($"기록 잠금을 열지 못해서 잠금 없이 계속해요 ({ex.GetType().Name})");
            return new StateLock(null);
        }

        log("기록 잠금을 10초 안에 얻지 못해서 잠금 없이 계속해요.");
        return new StateLock(null);
    }
}
