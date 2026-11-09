using System.Globalization;
using System.Security;
using SafetySecurity.Core.Baseline;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace SafetySecurity.Notify;

/// <summary>
/// Windows 토스트 알림. 누르면 HTML 보고서가 기본 브라우저로 열려요 (protocol 활성화, file:// 주소).
/// 알림은 Windows가 보여주니까 우리 프로세스는 바로 끝나도 돼요.
/// </summary>
internal static class ToastNotifier
{
    public const string AppUserModelId = "SafetySecurity.Scanner";
    private const string ProgressTag = "scan";
    private const string ProgressGroup = "progress";

    /// <summary>
    /// 찾은 항목을 알려요. 항목 제목에 든 글자 때문에 알림을 만들지 못하면(남이 지은 이름이라 무엇이든 들어 있을 수 있어요)
    /// 제목 없이 개수만 적은 알림으로 한 번 더 시도해요. 그때 <paramref name="error"/>에는 처음 실패한 이유가 들어 있어요.
    /// </summary>
    public static bool TryShow(IReadOnlyList<Finding> findings, string reportPath, bool firstRun, out string? error)
    {
        var high = findings.Count(f => f.Severity == Severity.High);
        var medium = findings.Count(f => f.Severity == Severity.Medium);
        var title = high > 0
            ? $"위험도 높은 항목 {high}개를 찾았어요"
            : $"새로 확인할 항목 {findings.Count}개가 있어요";

        // 지난 검사에도 있던 항목이 더 위험해졌거나 파일이 바뀐 것이면 제목 뒤에 "(달라짐)"을 붙여요.
        // 제목은 레지스트리 값 이름처럼 남이 지은 글자라서, 제어 문자·XML에 못 넣는 글자·방향 바꾸기 문자를 먼저 바꿔요.
        var detail = string.Join(", ", findings.Take(2).Select(f => DisplayText.ForNotification(BaselineEvaluator.NoticeTitle(f), 120)));
        if (findings.Count > 2)
        {
            detail += $" 외 {findings.Count - 2}개";
        }

        var summary = $"높음 {high} · 보통 {medium}{(firstRun ? " · 첫 검사" : string.Empty)} — 눌러서 보고서 보기";
        string uri;
        try
        {
            uri = new Uri(reportPath).AbsoluteUri;
        }
        catch (UriFormatException ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }

        if (TryShowReport(title, DisplayText.ForNotification(detail, 180), summary, uri, out error))
        {
            return true;
        }

        // 항목 제목 없이 개수와 고정된 문장만으로 다시 시도해요. 처음 실패한 이유는 기록에 남기려고 그대로 돌려줘요.
        var first = error;
        if (TryShowReport(title, null, summary, uri, out var second))
        {
            error = first;
            return true;
        }

        error = first + " / 간단한 알림도 실패: " + second;
        return false;
    }

    private static bool TryShowReport(string title, string? detail, string summary, string uri, out string? error)
    {
        try
        {
            var detailLine = detail is null ? string.Empty : $"\n      <text>{SecurityElement.Escape(detail)}</text>";
            var xml = string.Create(CultureInfo.InvariantCulture, $"""
<toast activationType="protocol" launch="{SecurityElement.Escape(uri)}" scenario="reminder">
  <visual>
    <binding template="ToastGeneric">
      <text>{SecurityElement.Escape(DisplayText.ForNotification("SafetySecurity: " + title, 200))}</text>{detailLine}
      <text>{SecurityElement.Escape(DisplayText.ForNotification(summary, 200))}</text>
    </binding>
  </visual>
  <actions>
    <action content="보고서 열기" activationType="protocol" arguments="{SecurityElement.Escape(uri)}" />
    <action content="닫기" activationType="system" arguments="dismiss" />
  </actions>
</toast>
""");
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var toast = new ToastNotification(doc) { ExpirationTime = DateTimeOffset.Now.AddDays(3) };
            // 설정에서 이 앱 알림이 꺼져 있으면 Show()는 성공한 것처럼 끝나지만 Windows가 조용히 버려요.
            // 그 경우는 검사 쪽(ScanCommand)이 ReadState()로 따로 확인해서 보고서·로그에 적어요.
            ToastNotificationManager.CreateToastNotifier(AppUserModelId).Show(toast);
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// 게임 때문에 하루 넘게 자동 검사를 못 했다고 알려요 (미뤄둔 검사 하나에 한 번만). 게임 중이면 Windows가 알림 센터로 조용히 보내요.
    /// 누르는 동작은 없어요 (게임 중에 브라우저나 창을 열지 않아요).
    /// </summary>
    public static bool TryShowOverdue(int hours, out string? error)
    {
        try
        {
            var xml = string.Create(CultureInfo.InvariantCulture, $"""
<toast duration="long">
  <visual>
    <binding template="ToastGeneric">
      <text>SafetySecurity: {hours}시간째 검사를 못 했어요</text>
      <text>게임이 계속 실행 중이라 자동 검사를 미뤘어요. 게임을 끝낸 뒤 바탕화면·시작 메뉴의 SafetySecurity를 눌러 검사해 주세요.</text>
    </binding>
  </visual>
  <audio silent="true" />
</toast>
""");
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var toast = new ToastNotification(doc) { ExpirationTime = DateTimeOffset.Now.AddDays(1) };
            ToastNotificationManager.CreateToastNotifier(AppUserModelId).Show(toast);
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    /// <summary>알림 등록(install이 만든 AppUserModelId 키)이 있는지 읽기만 해서 확인해요.</summary>
    public static bool IsRegistered()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\AppUserModelId\" + AppUserModelId);
            return key is not null;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    /// <summary>
    /// Windows 설정의 이 앱 알림 상태를 읽기만 해요 (권한이 필요 없어요). 알림 등록(install)이 없거나 읽지 못하면 Unknown이에요.
    /// 방해 금지 모드(집중 지원)는 Windows가 알려주지 않아서 알 수 없어요.
    /// </summary>
    public static NotificationState ReadState()
    {
        try
        {
            return Map(ToastNotificationManager.CreateToastNotifier(AppUserModelId));
        }
        catch (Exception)
        {
            // 알림 플랫폼이 없거나(서버 코어 등) 등록 정보가 없으면 알 수 없다고 봐요.
            return NotificationState.Unknown;
        }
    }

    private static NotificationState Map(global::Windows.UI.Notifications.ToastNotifier notifier)
    {
        try
        {
            return notifier.Setting switch
            {
                NotificationSetting.Enabled => NotificationState.Enabled,
                NotificationSetting.DisabledForApplication => NotificationState.DisabledForApplication,
                NotificationSetting.DisabledForUser => NotificationState.DisabledForUser,
                NotificationSetting.DisabledByGroupPolicy => NotificationState.DisabledByGroupPolicy,
                NotificationSetting.DisabledByManifest => NotificationState.DisabledByManifest,
                _ => NotificationState.Unknown,
            };
        }
        catch (Exception)
        {
            return NotificationState.Unknown;
        }
    }

    /// <summary>"검사하고 있어요" 알림. 검사가 끝나면 <see cref="ClearScanning"/>으로 알림 센터에서도 지워요.</summary>
    public static bool TryShowScanning(out string? problem)
    {
        try
        {
            const string xml = """
<toast duration="short">
  <visual>
    <binding template="ToastGeneric">
      <text>SafetySecurity: 검사하고 있어요</text>
      <text>끝나면 보고서가 열려요. 보통 1분 안에 끝나요.</text>
    </binding>
  </visual>
  <audio silent="true" />
</toast>
""";
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var toast = new ToastNotification(doc)
            {
                Tag = ProgressTag,
                Group = ProgressGroup,
                // 직접 검사의 시간 제한(30분)보다 조금 길게 둬요. 검사가 끝나면 바로 지워요.
                ExpirationTime = DateTimeOffset.Now.AddMinutes(35),
            };
            var notifier = ToastNotificationManager.CreateToastNotifier(AppUserModelId);
            notifier.Show(toast);

            // 설정에서 이 앱 알림이 꺼져 있으면 Windows가 조용히 버려요. 원인을 알 수 있게 알려줘요.
            // (방해 금지 모드는 Windows가 알려주지 않아서 여기서 알 수 없어요.)
            problem = notifier.Setting == NotificationSetting.Enabled ? null : "알림 설정: " + notifier.Setting;
            return true;
        }
        catch (Exception ex)
        {
            // 알림을 못 띄워도 검사는 그대로 해요.
            problem = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    public static void ClearScanning()
    {
        try
        {
            ToastNotificationManager.History.Remove(ProgressTag, ProgressGroup, AppUserModelId);
        }
        catch (Exception)
        {
            // 이미 사라졌거나 지울 수 없으면 그냥 둬요 (35분 뒤 저절로 사라져요).
        }
    }

}

/// <summary>직접 검사하는 동안만 "검사하고 있어요" 알림을 보여줘요. 설치(알림 등록)가 안 돼 있으면 아무것도 안 해요.</summary>
internal sealed class ScanningToast : IDisposable
{
    private ScanningToast()
    {
    }

    /// <param name="log">알림을 못 띄운 이유를 남길 곳 (logs\scan.log).</param>
    public static ScanningToast? TryShow(Action<string> log)
    {
        if (!ToastNotifier.IsRegistered())
        {
            log("진행 알림: 알림 등록이 없어서 건너뛰어요 (설치하지 않고 실행)");
            return null;
        }

        var shown = ToastNotifier.TryShowScanning(out var problem);
        if (problem is not null)
        {
            log("진행 알림: " + problem);
        }

        return shown ? new ScanningToast() : null;
    }

    public void Dispose() => ToastNotifier.ClearScanning();
}
