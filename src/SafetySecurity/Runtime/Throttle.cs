using System.Diagnostics;
using SafetySecurity.Core.Abstractions;
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
internal sealed class Pacer(GameDetector? detector, TimeSpan budget) : IScanPacer
{
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
                throw new ScanAbortedException("시간 제한을 넘음");
            }

            if (detector?.Check(includeCpu: false) is { } reason)
            {
                throw new ScanAbortedException(reason);
            }
        }
    }
}

/// <summary>같은 범위의 검사가 동시에 두 번 돌지 않게 해요.</summary>
internal sealed class ScanLock : IDisposable
{
    private readonly Mutex _mutex;

    private ScanLock(Mutex mutex) => _mutex = mutex;

    public static ScanLock? TryAcquire(string scope)
    {
        var mutex = new Mutex(false, @"Local\SafetySecurity.Scan." + scope);
        try
        {
            if (mutex.WaitOne(0))
            {
                return new ScanLock(mutex);
            }
        }
        catch (AbandonedMutexException)
        {
            return new ScanLock(mutex);
        }

        mutex.Dispose();
        return null;
    }

    public void Dispose()
    {
        _mutex.ReleaseMutex();
        _mutex.Dispose();
    }
}
