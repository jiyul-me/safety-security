using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Baseline;

/// <summary>%LOCALAPPDATA%\SafetySecurity\state*.json에 저장되는 상태.</summary>
/// <remarks>
/// 버전 2는 버전 1의 칸(Baseline, Ignored)을 그대로 두고 자세한 기록(BaselineDetail, IgnoredDetail)만 더했어요.
/// 그래서 예전 버전도 이 파일을 그대로 읽을 수 있고, 예전 파일은 다음 검사가 자세한 기록을 채워요.
/// </remarks>
public sealed class ScanState
{
    public const int CurrentVersion = 2;

    public int Version { get; set; } = CurrentVersion;

    public DateTimeOffset? LastFullScanUtc { get; set; }

    public DateTimeOffset? LastScanUtc { get; set; }

    /// <summary>게임 중이라 미뤄둔 검사. 없으면 null.</summary>
    public PendingScan? Pending { get; set; }

    public bool BaselineInitialized { get; set; }

    /// <summary>지난 검사에서 본 항목 ID → 분류.</summary>
    public Dictionary<string, string> Baseline { get; set; } = [];

    /// <summary>
    /// 지난 검사에서 본 항목 ID → 그때의 위험도·지문·제목 (버전 2). 위험도가 올라가거나 같은 위치의 파일이 바뀌면 다시 알리려고 기억해요.
    /// 항목이 Baseline에는 있는데 여기 없으면 예전 버전이 쓴 기록이라, 알리지 않고 지금 상태를 기록해요.
    /// </summary>
    public Dictionary<string, BaselineEntry> BaselineDetail { get; set; } = [];

    /// <summary>사용자가 ignore 명령으로 허용한 항목 ID.</summary>
    public HashSet<string> Ignored { get; set; } = [];

    /// <summary>
    /// 숨긴 항목 ID → 숨길 때의 제목·시각·위험도·지문 (버전 2). 숨긴 뒤로 더 위험해지거나 파일이 바뀌면 다시 보여줘요.
    /// </summary>
    public Dictionary<string, IgnoreEntry> IgnoredDetail { get; set; } = [];

    public string? LastReportPath { get; set; }
}

/// <summary>베이스라인에 기억하는 항목 하나의 상태.</summary>
public sealed class BaselineEntry
{
    public Severity Severity { get; set; }

    /// <summary>서명 상태·서명자·SHA-256 같은 파일 지문 (<see cref="FindingFingerprint"/>). 파일 정보가 없는 항목은 null.</summary>
    public Dictionary<string, string>? Fingerprint { get; set; }

    /// <summary>ignore 명령이 숨길 항목을 보여줄 때 쓰는 제목.</summary>
    public string? Title { get; set; }
}

/// <summary>숨긴 항목 하나. 숨길 때 본 상태와 지금 상태가 같을 때만 숨겨요.</summary>
public sealed class IgnoreEntry
{
    public string? Title { get; set; }

    public string? Category { get; set; }

    /// <summary>숨긴 시각. 예전 버전에서 숨긴 항목은 모르니까 null이에요.</summary>
    public DateTimeOffset? IgnoredUtc { get; set; }

    /// <summary>숨길 때의 위험도. null이면 아직 검사로 확인하지 않았어요 (다음 검사가 지금 상태를 기록해요).</summary>
    public Severity? Severity { get; set; }

    /// <summary>숨길 때의 파일 지문. <see cref="Severity"/>가 있을 때만 의미가 있어요 (null = 파일 정보 없는 항목).</summary>
    public Dictionary<string, string>? Fingerprint { get; set; }
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
