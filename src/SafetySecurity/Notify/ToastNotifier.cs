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

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
