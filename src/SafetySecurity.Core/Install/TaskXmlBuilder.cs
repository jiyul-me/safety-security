using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SafetySecurity.Core.Install;

public sealed record TaskSpec(string Name, string Xml);

/// <summary>
/// 작업 스케줄러에 등록할 작업 XML을 만들어요 (schtasks /create /xml용, UTF-16).
/// 모든 작업: 낮은 우선순위(7), 15분 제한, 중복 실행 안 함, 사용자 권한.
/// </summary>
public static class TaskXmlBuilder
{
    public const string Folder = OwnTasks.Folder;
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public const string ServiceInstalledQuery =
        "<QueryList><Query Id=\"0\" Path=\"System\"><Select Path=\"System\">*[System[Provider[@Name='Service Control Manager'] and (EventID=7045)]]</Select></Query></QueryList>";

    /// <summary>사용자 작업 4개 (Logon, Daily, ServiceInstalled, Retry).</summary>
    public static List<TaskSpec> BuildUserTasks(string exePath, string userSid, string userName, DateTime nowLocal)
    {
        var start = nowLocal.Date.AddHours(12).AddMinutes(37);
        return
        [
            new TaskSpec(OwnTasks.Logon.Name, Build(
                "로그온 3분 뒤 검사해요.",
                [LogonTrigger(userName, "PT3M")],
                exePath, OwnTasks.Logon.Arguments, userSid, elevated: false)),
            new TaskSpec(OwnTasks.Daily.Name, Build(
                "하루 한 번 검사해요. PC가 꺼져 있었으면 켜진 뒤 검사해요.",
                [DailyTrigger(start)],
                exePath, OwnTasks.Daily.Arguments, userSid, elevated: false)),
            new TaskSpec(OwnTasks.ServiceInstalled.Name, Build(
                "새 서비스가 설치되면(System 로그 이벤트 7045) 서비스와 예약 작업만 빠르게 검사해요.",
                [EventTrigger(ServiceInstalledQuery, "PT1M")],
                exePath, OwnTasks.ServiceInstalled.Arguments, userSid, elevated: false)),
            new TaskSpec(OwnTasks.Retry.Name, Build(
                "30분마다 깨어나서 게임 때문에 미뤄둔 검사가 있을 때만 검사해요. 없으면 바로 종료해요.",
                [RepeatTrigger(nowLocal.AddMinutes(30), "PT30M")],
                exePath, OwnTasks.Retry.Arguments, userSid, elevated: false)),
        ];
    }

    /// <summary>관리자 작업 1개 (관리자만 읽을 수 있는 항목 확인).</summary>
    public static TaskSpec BuildAdminTask(string exePath, string userSid, string userName, DateTime nowLocal) =>
        new(OwnTasks.Admin.Name, Build(
            "관리자만 읽을 수 있는 항목(Defender 제외 목록, 숨겨진 작업, WMI 구독)을 하루 한 번 검사해요. 게임 중이면 미뤄요.",
            [LogonTrigger(userName, "PT5M"), RepeatTrigger(nowLocal.AddMinutes(35), "PT30M")],
            exePath, OwnTasks.Admin.Arguments, userSid, elevated: true));

    /// <summary>관리자 설치 때, 사용자 작업이 이벤트 트리거를 못 받는 환경을 위한 예비 작업.</summary>
    public static TaskSpec BuildAdminServiceTask(string exePath, string userSid) =>
        new(OwnTasks.ServiceInstalledAdmin.Name, Build(
            "새 서비스가 설치되면 관리자 범위로 빠르게 검사해요.",
            [EventTrigger(ServiceInstalledQuery, "PT1M")],
            exePath, OwnTasks.ServiceInstalledAdmin.Arguments, userSid, elevated: true));

    public static string Build(string description, IReadOnlyList<XElement> triggers, string exePath, string arguments, string userSid, bool elevated)
    {
        var task = new XElement(Ns + "Task",
            new XAttribute("version", "1.3"),
            new XElement(Ns + "RegistrationInfo",
                new XElement(Ns + "Author", "SafetySecurity"),
                new XElement(Ns + "Description", "SafetySecurity 읽기 전용 보안 검사: " + description)),
            new XElement(Ns + "Triggers", triggers),
            new XElement(Ns + "Principals",
                new XElement(Ns + "Principal", new XAttribute("id", "Author"),
                    new XElement(Ns + "UserId", userSid),
                    new XElement(Ns + "LogonType", "InteractiveToken"),
                    new XElement(Ns + "RunLevel", elevated ? "HighestAvailable" : "LeastPrivilege"))),
            new XElement(Ns + "Settings",
                new XElement(Ns + "MultipleInstancesPolicy", "IgnoreNew"),
                new XElement(Ns + "DisallowStartIfOnBatteries", "false"),
                new XElement(Ns + "StopIfGoingOnBatteries", "false"),
                new XElement(Ns + "AllowHardTerminate", "true"),
                new XElement(Ns + "StartWhenAvailable", "true"),
                new XElement(Ns + "RunOnlyIfNetworkAvailable", "false"),
                new XElement(Ns + "IdleSettings",
                    new XElement(Ns + "StopOnIdleEnd", "false"),
                    new XElement(Ns + "RestartOnIdle", "false")),
                new XElement(Ns + "AllowStartOnDemand", "true"),
                new XElement(Ns + "Enabled", "true"),
                new XElement(Ns + "Hidden", "false"),
                new XElement(Ns + "RunOnlyIfIdle", "false"),
                new XElement(Ns + "WakeToRun", "false"),
                new XElement(Ns + "ExecutionTimeLimit", "PT15M"),
                new XElement(Ns + "Priority", "7")),
            new XElement(Ns + "Actions", new XAttribute("Context", "Author"),
                new XElement(Ns + "Exec",
                    new XElement(Ns + "Command", "\"" + exePath + "\""),
                    new XElement(Ns + "Arguments", arguments))));

        var sb = new StringBuilder();
        using (var writer = XmlWriter.Create(new Utf16StringWriter(sb), new XmlWriterSettings { Indent = true, Encoding = Encoding.Unicode }))
        {
            new XDocument(task).Save(writer);
        }

        return sb.ToString();
    }

    public static XElement LogonTrigger(string userName, string delay) =>
        new(Ns + "LogonTrigger",
            new XElement(Ns + "Enabled", "true"),
            new XElement(Ns + "UserId", userName),
            new XElement(Ns + "Delay", delay));

    public static XElement DailyTrigger(DateTime startLocal) =>
        new(Ns + "CalendarTrigger",
            new XElement(Ns + "StartBoundary", Boundary(startLocal)),
            new XElement(Ns + "Enabled", "true"),
            new XElement(Ns + "RandomDelay", "PT30M"),
            new XElement(Ns + "ScheduleByDay", new XElement(Ns + "DaysInterval", "1")));

    public static XElement EventTrigger(string query, string delay) =>
        new(Ns + "EventTrigger",
            new XElement(Ns + "Enabled", "true"),
            new XElement(Ns + "Subscription", query),
            new XElement(Ns + "Delay", delay));

    public static XElement RepeatTrigger(DateTime startLocal, string interval) =>
        new(Ns + "TimeTrigger",
            new XElement(Ns + "Repetition",
                new XElement(Ns + "Interval", interval),
                new XElement(Ns + "StopAtDurationEnd", "false")),
            new XElement(Ns + "StartBoundary", Boundary(startLocal)),
            new XElement(Ns + "Enabled", "true"));

    private static string Boundary(DateTime t) => t.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture);

    private sealed class Utf16StringWriter(StringBuilder sb) : StringWriter(sb, CultureInfo.InvariantCulture)
    {
        public override Encoding Encoding => Encoding.Unicode;
    }
}
