using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Baseline;

/// <summary>%LOCALAPPDATA%\SafetySecurity\state*.json에 저장되는 상태.</summary>
public sealed class ScanState
{
    public int Version { get; set; } = 1;

    public DateTimeOffset? LastFullScanUtc { get; set; }

    public DateTimeOffset? LastScanUtc { get; set; }

    /// <summary>게임 중이라 미뤄둔 검사. 없으면 null.</summary>
    public PendingScan? Pending { get; set; }

    public bool BaselineInitialized { get; set; }

    /// <summary>지난 검사에서 본 항목 ID → 분류.</summary>
    public Dictionary<string, string> Baseline { get; set; } = [];

    /// <summary>사용자가 ignore 명령으로 허용한 항목 ID.</summary>
    public HashSet<string> Ignored { get; set; } = [];

    public string? LastReportPath { get; set; }
}

public sealed class PendingScan
{
    public ScanReason Reason { get; set; }

    public bool Quick { get; set; }

    public DateTimeOffset SinceUtc { get; set; }

    public string? DeferredBecause { get; set; }

    public int Attempts { get; set; }
}

/// <summary>사용자 설정 (config.json, 없으면 기본값).</summary>
public sealed class ScanConfig
{
    /// <summary>이 이름의 프로세스가 실행 중이면 게임 중으로 보고 검사를 미뤄요.</summary>
    public List<string> GameProcesses { get; set; } =
    [
        "VALORANT-Win64-Shipping.exe", "League of Legends.exe", "TslGame.exe", "cs2.exe", "FortniteClient-Win64-Shipping.exe",
        "r5apex.exe", "r5apex_dx12.exe", "Overwatch.exe", "GenshinImpact.exe", "StarRail.exe", "ZenlessZoneZero.exe",
        "eldenring.exe", "MapleStory.exe", "LostArk.exe", "BlueArchive.exe", "nikke.exe", "Diablo IV.exe", "destiny2.exe",
        "RainbowSix.exe", "GTA5.exe", "Cyberpunk2077.exe", "Palworld-Win64-Shipping.exe", "dota2.exe", "Wow.exe", "FC26.exe",
    ];

    /// <summary>이 위험도 이상인 '새' 항목만 알림을 띄워요.</summary>
    public Severity NotifyMinSeverity { get; set; } = Severity.Medium;

    /// <summary>시스템 CPU 사용률이 이 값(%)을 넘으면 검사를 미뤄요.</summary>
    public int CpuBusyPercent { get; set; } = 60;

    /// <summary>전체 화면 앱(게임, 영상, 발표)이 떠 있으면 미룰지.</summary>
    public bool DeferOnFullscreen { get; set; } = true;
}
