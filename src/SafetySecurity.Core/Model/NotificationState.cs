namespace SafetySecurity.Core.Model;

/// <summary>
/// Windows가 알려주는 이 앱의 알림 설정 (Windows.UI.Notifications.NotificationSetting과 같은 뜻이에요).
/// 방해 금지 모드(집중 지원)는 Windows가 알려주지 않아서 여기에 없어요.
/// </summary>
public enum NotificationState
{
    /// <summary>읽지 못했어요 (설치하지 않았거나 Windows가 답하지 않았어요).</summary>
    Unknown = 0,

    Enabled,

    /// <summary>설정 → 시스템 → 알림에서 이 앱만 껐어요.</summary>
    DisabledForApplication,

    /// <summary>모든 앱의 알림을 껐어요.</summary>
    DisabledForUser,

    /// <summary>회사·학교 그룹 정책으로 꺼져 있어요.</summary>
    DisabledByGroupPolicy,

    DisabledByManifest,
}
