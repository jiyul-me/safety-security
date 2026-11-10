namespace SafetySecurity.Core.Install;

/// <summary>
/// 검사기 데이터 폴더(상태·설정·서명 캐시·보고서·로그) 위치를 정해요.
/// - 일반 권한: %LOCALAPPDATA%\SafetySecurity (사용자 폴더)
/// - 관리자 권한: C:\Program Files\SafetySecurity\data (Program Files의 권한을 물려받아 관리자만 쓸 수 있어요)
/// 관리자 권한 프로세스가 사용자가 쓸 수 있는 폴더를 읽고 쓰면, 사용자 권한 악성코드가 관리자 검사의 설정·기록을 바꾸거나
/// 링크(정션)를 심어 관리자 권한으로 다른 곳의 파일을 지우게 할 수 있어요. 그래서 관리자 권한이면 사용자 폴더를 아예 쓰지 않아요.
/// </summary>
public static class DataRoots
{
    public const string FolderName = "SafetySecurity";

    /// <summary>사용자 데이터 폴더 (%LOCALAPPDATA%\SafetySecurity).</summary>
    public static string User(string localAppData) => Join(localAppData, FolderName);

    /// <summary>관리자 데이터 폴더 (관리자 설치 폴더 안의 data).</summary>
    public static string Admin(string adminInstallDir) => Join(adminInstallDir, "data");

    /// <summary>이 프로세스가 쓸 데이터 폴더. --data-dir로 직접 정했으면 그 폴더를 써요.</summary>
    public static string Resolve(string? explicitDir, bool elevated, string localAppData, string adminInstallDir) =>
        !string.IsNullOrWhiteSpace(explicitDir) ? explicitDir : elevated ? Admin(adminInstallDir) : User(localAppData);

    /// <summary>
    /// 관리자 검사의 상태(무시 목록 등)를 바꾸려면 관리자 권한으로 다시 실행해야 하는지.
    /// 보호된 폴더는 관리자만 쓸 수 있어요. --data-dir로 직접 정한 폴더는 그대로 써요 (시험용).
    /// </summary>
    public static bool NeedsElevationToChangeAdminState(string? explicitDir, bool elevated) =>
        string.IsNullOrWhiteSpace(explicitDir) && !elevated;

    private static string Join(string dir, string name) => dir.TrimEnd('\\', '/') + @"\" + name;
}
