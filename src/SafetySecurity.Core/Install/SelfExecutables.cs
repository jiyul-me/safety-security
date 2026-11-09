using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Install;

/// <summary>
/// 검사 결과에서 '검사기 자신'으로 보고 뺄 실행 파일 경로를 정해요 (<see cref="Engine.ScanContext.SelfPaths"/>).
/// 여기에 들어간 경로를 실행하는 항목은 보고하지 않으니, 악성코드가 바꿔치기할 수 있는 경로는 꼭 필요할 때만 넣어요.
/// </summary>
public static class SelfExecutables
{
    /// <param name="scope">검사 범위.</param>
    /// <param name="processPath">지금 실행 중인 exe (Environment.ProcessPath). 항상 자기 자신이에요.</param>
    /// <param name="userInstallExe">내 계정 설치 위치의 exe (%LOCALAPPDATA%\Programs\SafetySecurity\SafetySecurity.exe). 일반 사용자도 바꿀 수 있어요.</param>
    /// <param name="adminInstallExe">관리자 설치 위치의 exe (Program Files\SafetySecurity\SafetySecurity.exe). 관리자만 바꿀 수 있어요.</param>
    public static IReadOnlyList<string> For(ScanScope scope, string? processPath, string userInstallExe, string adminInstallExe)
    {
        var result = new List<string>(3);
        if (!string.IsNullOrWhiteSpace(processPath))
        {
            result.Add(processPath);
        }

        result.Add(adminInstallExe);

        // 관리자 검사에서는 사용자가 쓸 수 있는 내 계정 설치 위치를 믿지 않아요. 사용자 권한 악성코드가 그 자리에 exe를 두고
        // WMI 구독이나 Defender 제외에 걸어도 '검사기 자신'으로 빠지면 안 되니까요. 관리자 검사가 보는 항목(Defender, 숨겨진 작업,
        // WMI 구독)에는 SafetySecurity가 등록하는 것이 없어서, 빼도 우리 항목이 잘못 보고되지 않아요.
        // 사용자 검사는 내 계정 설치의 예약 작업을 알아봐야 해서 그대로 믿어요 (사용자 검사가 보는 곳은 원래 그 사용자가 바꿀 수 있어요).
        if (scope == ScanScope.User)
        {
            result.Add(userInstallExe);
        }

        return result;
    }
}
