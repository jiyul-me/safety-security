namespace SafetySecurity.Core.Install;

/// <summary>SafetySecurity가 등록하는 예약 작업 하나 (이름, 검사기에 넘기는 인자, 보고서에 쓰는 설명).</summary>
/// <param name="Name">작업 이름 (폴더나 접두사 없이, 예: Logon).</param>
/// <param name="Arguments">작업이 SafetySecurity.exe에 넘기는 인자. 이 값과 똑같아야 우리 작업으로 봐요.</param>
/// <param name="Purpose">이 작업이 하는 검사 (보고서 문장에 들어가요, "…검사"로 끝나요).</param>
public sealed record OwnTaskSpec(string Name, string Arguments, string Purpose);

/// <summary>
/// SafetySecurity 자신의 예약 작업 목록이에요. 설치(TaskXmlBuilder·TaskInstaller)와 검사(ScheduledTaskScanner)가 같은 값을 써요.
/// 검사할 때는 이름만 믿지 않고, 이름·실행 파일·인자가 모두 맞아야 우리 작업으로 봐요.
/// </summary>
public static class OwnTasks
{
    /// <summary>작업 스케줄러의 우리 폴더예요.</summary>
    public const string Folder = @"\SafetySecurity\";

    /// <summary>일반 사용자가 폴더를 만들 수 없을 때 루트에 쓰는 이름 앞부분이에요 (예: \SafetySecurity-Logon).</summary>
    public const string FallbackPrefix = @"\SafetySecurity-";

    public static readonly OwnTaskSpec Logon = new("Logon", "scan --reason logon", "로그온할 때 하는 자동 검사");

    public static readonly OwnTaskSpec Daily = new("Daily", "scan --reason daily", "하루 한 번 하는 자동 검사");

    public static readonly OwnTaskSpec ServiceInstalled = new("ServiceInstalled", "scan --reason service --quick", "새 서비스가 설치될 때 하는 빠른 검사");

    public static readonly OwnTaskSpec Retry = new("Retry", "scan --reason retry", "게임 때문에 미뤄 둔 검사");

    public static readonly OwnTaskSpec Admin = new("Admin", "scan --scope admin --reason retry", "관리자 범위 자동 검사(Defender 제외 목록·숨겨진 작업·WMI 구독)");

    public static readonly OwnTaskSpec ServiceInstalledAdmin = new("ServiceInstalledAdmin", "scan --scope admin --reason service --quick", "새 서비스가 설치될 때 하는 관리자 범위 빠른 검사");

    /// <summary>등록할 수 있는 작업 전부 (사용자 작업 4개 + 관리자 설치 때의 작업 2개).</summary>
    public static IReadOnlyList<OwnTaskSpec> All { get; } = [Logon, Daily, ServiceInstalled, Retry, Admin, ServiceInstalledAdmin];

    /// <summary>작업 하나가 가질 수 있는 전체 이름 두 가지 (폴더 안, 루트의 예비 이름).</summary>
    public static IReadOnlyList<string> FullNames(string name) => [Folder + name, FallbackPrefix + name];

    /// <summary>우리 폴더나 예비 이름 앞부분을 쓰는 작업인지 (이름이 우리 작업 이름과 맞는지와는 상관없어요).</summary>
    public static bool HasOwnPrefix(string fullName) =>
        fullName.StartsWith(Folder, StringComparison.OrdinalIgnoreCase)
        || fullName.StartsWith(FallbackPrefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>전체 이름(\SafetySecurity\Logon, \SafetySecurity-Logon)이 우리 작업 이름이면 그 작업을 돌려줘요. 아니면 null.</summary>
    public static OwnTaskSpec? Find(string fullName)
    {
        string rest;
        if (fullName.StartsWith(Folder, StringComparison.OrdinalIgnoreCase))
        {
            rest = fullName[Folder.Length..];
        }
        else if (fullName.StartsWith(FallbackPrefix, StringComparison.OrdinalIgnoreCase))
        {
            rest = fullName[FallbackPrefix.Length..];
        }
        else
        {
            return null;
        }

        // 작업 이름은 Windows에서 대소문자를 구분하지 않아요. 하위 폴더(\SafetySecurity\x\Logon)는 우리 작업이 아니에요.
        return All.FirstOrDefault(t => string.Equals(t.Name, rest, StringComparison.OrdinalIgnoreCase));
    }
}
