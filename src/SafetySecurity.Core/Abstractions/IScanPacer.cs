namespace SafetySecurity.Core.Abstractions;

/// <summary>
/// 검사 속도 조절. 스캐너는 항목 하나를 볼 때마다 Step()을 불러요.
/// 구현은 가끔 잠깐 쉬고, 게임이 시작되면 ScanAbortedException을 던져요.
/// </summary>
public interface IScanPacer
{
    void Step(int weight = 1);
}

public sealed class ScanAbortedException(string reason) : Exception(reason)
{
    public string Reason { get; } = reason;
}

public sealed class NoPacer : IScanPacer
{
    public static readonly NoPacer Instance = new();

    public void Step(int weight = 1)
    {
    }
}
