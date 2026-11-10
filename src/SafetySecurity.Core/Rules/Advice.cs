using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Rules;

/// <summary>보고서에 붙이는 '직접 확인하는 법'. 프로그램은 아무것도 자동으로 고치지 않아요.</summary>
public static class Advice
{
    private const string Common =
        "SHA-256 값을 VirusTotal 웹사이트(virustotal.com)에 직접 붙여 넣어 검색해 보세요. 이 프로그램은 파일을 어디에도 올리지 않아요. "
        + "지우기 전에는 반드시 백업하고, 먼저 Windows 보안 → 바이러스 및 위협 방지 → 검사 옵션 → 'Microsoft Defender 오프라인 검사'를 해 보세요.";

    public static string ComHijack(string keyPath) =>
        $"1) 대상 DLL의 서명자와 위치가 설치한 프로그램과 맞는지 확인하세요. 2) {Common} "
        + $"3) 악성이 확실하면 백업: reg export \"{keyPath}\" backup.reg  → 삭제: reg delete \"{keyPath}\" /f. "
        + "HKCU 쪽 키만 지우면 원래(HKLM) 등록으로 돌아가요. 4) Sysinternals Autoruns의 'Everything' 탭에서도 같은 항목을 볼 수 있어요.";

    public static string RegistryAutorun(string keyPath, string valueName) =>
        $"1) 이 이름의 프로그램을 직접 설치했는지 확인하세요. 2) {Common} "
        + $"3) 악성이 확실하면 백업: reg export \"{keyPath}\" backup.reg  → 삭제: reg delete \"{keyPath}\" /v \"{valueName}\" /f. "
        + "작업 관리자 → 시작프로그램 탭에서 '사용 안 함'으로 먼저 꺼 둘 수도 있어요.";

    public static string StartupFile =>
        $"1) 시작프로그램 폴더(실행 창에 shell:startup)를 열어 이 파일을 직접 설치했는지 확인하세요. 2) {Common} 3) 의심되면 파일을 다른 폴더로 옮겨 두고 재부팅해서 확인하세요.";

    public static string Service(string name) =>
        $"1) services.msc에서 '{name}' 서비스의 설명과 실행 파일을 확인하세요. 2) {Common} "
        + $"3) 의심되면 관리자 명령 프롬프트에서 sc config \"{name}\" start= disabled 로 먼저 꺼 두세요(삭제는 확인 후에).";

    public static string Task(string name) =>
        $"1) 작업 스케줄러(taskschd.msc)에서 '{name}' 작업의 동작 탭을 확인하세요. 2) {Common} "
        + $"3) 의심되면 schtasks /change /tn \"{name}\" /disable 로 먼저 꺼 두세요.";

    /// <summary>SafetySecurity 이름을 흉내 낸 작업 (TASK-003).</summary>
    public static string ImpersonatingTask(string name) =>
        "SafetySecurity의 진짜 작업은 SafetySecurity.exe를 'scan …' 인자로 실행하는 동작 하나만 있어요. 그 밖의 작업은 SafetySecurity가 만든 게 아니에요. "
        + $"1) 작업 스케줄러(taskschd.msc)에서 '{name}' 작업의 동작 탭을 확인하세요. 2) {Common} "
        + $"3) 의심되면 schtasks /change /tn \"{name}\" /disable 로 먼저 꺼 두세요. "
        + "4) SafetySecurity 설치 프로그램을 다시 실행하면 진짜 작업을 다시 등록해요 (zip으로 설치했다면 SafetySecurity.exe install).";

    /// <summary>꺼져 있는 우리 작업 (TASK-004). 프로그램이 직접 켜지 않아요.</summary>
    public static string DisabledOwnTask(string name) =>
        $"1) 직접 끈 적이 있는지 떠올려 보세요. 2) 다시 켜려면 작업 스케줄러(taskschd.msc) → SafetySecurity에서 '{name}' 작업을 오른쪽 클릭해 '사용'을 누르거나, "
        + $"명령 프롬프트에서 schtasks /change /tn \"{name}\" /enable 을 실행하세요 (Admin 작업은 관리자 권한이 필요해요). "
        + "SafetySecurity 설치 프로그램을 다시 실행해도 다시 켜져요. 3) 직접 끈 적이 없다면 다른 프로그램이 검사를 막으려고 껐을 수 있어요. 다른 항목도 함께 확인해 보세요.";

    /// <summary>
    /// Windows 알림 설정이 꺼져 있을 때 보고서의 '확인하지 못한 것'에 넣을 안내예요. 켜져 있거나 알 수 없으면 null이에요.
    /// </summary>
    public static string? NotificationsOff(NotificationState state) => state switch
    {
        NotificationState.DisabledForApplication or NotificationState.DisabledByManifest =>
            "Windows 설정에서 SafetySecurity 알림이 꺼져 있어서, 자동 검사가 새 항목을 찾아도 알려드릴 수 없어요. 설정 → 시스템 → 알림에서 SafetySecurity를 켜 주세요.",
        NotificationState.DisabledForUser =>
            "Windows 알림이 모두 꺼져 있어서, 자동 검사가 새 항목을 찾아도 알려드릴 수 없어요. 설정 → 시스템 → 알림에서 '알림'을 켜 주세요.",
        NotificationState.DisabledByGroupPolicy =>
            "회사·학교 정책으로 알림이 꺼져 있어서, 자동 검사가 새 항목을 찾아도 알려드릴 수 없어요. 가끔 시작 메뉴의 SafetySecurity로 직접 검사해서 보고서를 확인해 주세요.",
        _ => null,
    };

    public static string Browser =>
        "1) 브라우저 주소창에 chrome://policy 또는 edge://policy를 열어 정책이 어디서 왔는지 확인하세요. 회사·학교 PC가 아니라면 강제 설치 확장 프로그램은 대부분 악성이에요. "
        + "2) chrome://extensions에서 확장 프로그램을 확인하세요. 3) 정책 키를 지우기 전에 reg export로 백업하세요.";

    public static string DroppedFile =>
        $"1) 최근에 이 파일을 직접 받거나 설치했는지 떠올려 보세요. 2) {Common} 3) 의심되면 파일을 지우지 말고 Defender로 그 파일만 검사(오른쪽 클릭 → Microsoft Defender로 검사)해 보세요.";

    public static string Hosts =>
        "1) 메모장을 관리자 권한으로 열어 C:\\Windows\\System32\\drivers\\etc\\hosts를 확인하세요. "
        + "2) 보안 프로그램·Windows 업데이트·게임 사이트를 막거나 다른 IP로 보내는 줄은 악성코드가 넣은 경우가 많아요. 3) 고치기 전에 파일을 복사해 백업하세요.";

    /// <summary>디스코드 시작 파일이 변조됐을 때 (DISC-001). <paramref name="folder"/>는 그 디스코드의 %LOCALAPPDATA% 폴더예요.</summary>
    public static string Discord(string folder) =>
        "1) 디스코드를 완전히 끄세요 (작업 표시줄 오른쪽 아래 디스코드 아이콘을 오른쪽 클릭 → 'Discord 종료'). "
        + "2) 이런 악성코드는 보통 다른 곳에도 숨어 있어요. 먼저 Windows 보안 → 바이러스 및 위협 방지 → 검사 옵션 → 'Microsoft Defender 오프라인 검사'를 하고, 이 보고서의 다른 항목도 확인하세요. "
        + $"3) 디스코드 폴더({folder})를 지우고 discord.com에서 받은 설치 파일로 다시 설치하세요. 이 프로그램은 파일을 고치거나 지우지 않아요. "
        + "4) 휴대폰 등 다른 기기에서 디스코드 비밀번호를 바꾸고 2단계 인증을 켜세요. 비밀번호를 바꾸면 훔쳐 간 토큰을 더 이상 쓸 수 없어요. "
        + "사용자 설정 → 기기에서 다른 기기도 모두 로그아웃시키세요. "
        + "5) 같은 비밀번호를 쓰는 게임·메일 계정도 비밀번호를 바꾸세요. 이런 악성코드는 브라우저에 저장된 비밀번호도 함께 훔쳐 가는 경우가 많아요.";

    /// <summary>BetterDiscord가 바꾼 시작 파일 (DISC-002).</summary>
    public static string DiscordMod(string folder) =>
        "BetterDiscord를 직접 설치했다면 괜찮아요. 이 항목을 숨겨 두면 다음부터 알리지 않아요 (디스코드를 업데이트하면 폴더 이름이 바뀌어서 다시 보일 수 있어요). "
        + "직접 설치한 적이 없다면 변조(DISC-001)로 보고 이렇게 하세요: " + Discord(folder);

    public static string Defender =>
        "1) Windows 보안 → 바이러스 및 위협 방지 → 설정 관리 → 제외 항목에서 직접 추가한 것인지 확인하세요. "
        + "2) 기억에 없는 제외는 악성코드가 Defender를 피하려고 넣은 경우가 많아요. 확인 후 제거하세요.";

    public static string Wmi =>
        "1) 관리자 PowerShell에서 Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer 로 내용을 확인하세요. "
        + "2) WMI 영구 구독은 정상 프로그램이 거의 쓰지 않는 지속성 수법이에요. 3) 제거는 전문가 도움을 받는 것을 권장해요.";
}
