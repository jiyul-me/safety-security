namespace SafetySecurity.Core.Model;

/// <summary>어떤 권한/범위로 검사하는지.</summary>
public enum ScanScope
{
    /// <summary>일반 사용자 권한 작업이 하는 검사.</summary>
    User,

    /// <summary>관리자 작업이 하는 검사 (관리자만 읽을 수 있는 항목).</summary>
    Admin,
}

/// <summary>검사가 시작된 이유.</summary>
public enum ScanReason
{
    Manual,
    Logon,
    Daily,
    Service,
    Retry,
}
