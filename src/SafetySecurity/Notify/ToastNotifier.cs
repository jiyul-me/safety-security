using System.Globalization;
using System.Security;
using SafetySecurity.Core.Model;
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

    public static bool TryShow(IReadOnlyList<Finding> findings, string reportPath, bool firstRun, out string? error)
    {
        try
        {
            var high = findings.Count(f => f.Severity == Severity.High);
            var medium = findings.Count(f => f.Severity == Severity.Medium);
            var title = high > 0
                ? $"위험도 높은 항목 {high}개를 찾았어요"
                : $"새로 확인할 항목 {findings.Count}개가 있어요";
            var detail = string.Join(", ", findings.Take(2).Select(f => f.Title));
            if (findings.Count > 2)
            {
                detail += $" 외 {findings.Count - 2}개";
            }

            var summary = $"높음 {high} · 보통 {medium}{(firstRun ? " · 첫 검사" : string.Empty)} — 눌러서 보고서 보기";
            var uri = new Uri(reportPath).AbsoluteUri;
            var xml = string.Create(CultureInfo.InvariantCulture, $"""
<toast activationType="protocol" launch="{SecurityElement.Escape(uri)}" scenario="reminder">
  <visual>
    <binding template="ToastGeneric">
      <text>{SecurityElement.Escape("SafetySecurity: " + title)}</text>
      <text>{SecurityElement.Escape(Truncate(detail, 180))}</text>
      <text>{SecurityElement.Escape(summary)}</text>
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

    /// <summary>"검사하고 있어요" 알림. 검사가 끝나면 <see cref="ClearScanning"/>으로 알림 센터에서도 지워요.</summary>
    public static bool TryShowScanning()
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
                ExpirationTime = DateTimeOffset.Now.AddMinutes(15),
            };
            ToastNotificationManager.CreateToastNotifier(AppUserModelId).Show(toast);
            return true;
        }
        catch (Exception)
        {
            // 알림을 못 띄워도 검사는 그대로 해요.
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
            // 이미 사라졌거나 지울 수 없으면 그냥 둬요 (15분 뒤 저절로 사라져요).
        }
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}

/// <summary>직접 검사하는 동안만 "검사하고 있어요" 알림을 보여줘요. 설치(알림 등록)가 안 돼 있으면 아무것도 안 해요.</summary>
internal sealed class ScanningToast : IDisposable
{
    private ScanningToast()
    {
    }

    public static ScanningToast? TryShow() =>
        ToastNotifier.IsRegistered() && ToastNotifier.TryShowScanning() ? new ScanningToast() : null;

    public void Dispose() => ToastNotifier.ClearScanning();
}
