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

    public static string Browser =>
        "1) 브라우저 주소창에 chrome://policy 또는 edge://policy를 열어 정책이 어디서 왔는지 확인하세요. 회사·학교 PC가 아니라면 강제 설치 확장 프로그램은 대부분 악성이에요. "
        + "2) chrome://extensions에서 확장 프로그램을 확인하세요. 3) 정책 키를 지우기 전에 reg export로 백업하세요.";

    public static string DroppedFile =>
        $"1) 최근에 이 파일을 직접 받거나 설치했는지 떠올려 보세요. 2) {Common} 3) 의심되면 파일을 지우지 말고 Defender로 그 파일만 검사(오른쪽 클릭 → Microsoft Defender로 검사)해 보세요.";

    public static string Hosts =>
        "1) 메모장을 관리자 권한으로 열어 C:\\Windows\\System32\\drivers\\etc\\hosts를 확인하세요. "
        + "2) 보안 프로그램·Windows 업데이트·게임 사이트를 막거나 다른 IP로 보내는 줄은 악성코드가 넣은 경우가 많아요. 3) 고치기 전에 파일을 복사해 백업하세요.";

    public static string Defender =>
        "1) Windows 보안 → 바이러스 및 위협 방지 → 설정 관리 → 제외 항목에서 직접 추가한 것인지 확인하세요. "
        + "2) 기억에 없는 제외는 악성코드가 Defender를 피하려고 넣은 경우가 많아요. 확인 후 제거하세요.";

    public static string Wmi =>
        "1) 관리자 PowerShell에서 Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer 로 내용을 확인하세요. "
        + "2) WMI 영구 구독은 정상 프로그램이 거의 쓰지 않는 지속성 수법이에요. 3) 제거는 전문가 도움을 받는 것을 권장해요.";
}
