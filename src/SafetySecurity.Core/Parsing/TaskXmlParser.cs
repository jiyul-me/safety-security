using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace SafetySecurity.Core.Parsing;

public sealed record TaskAction(string Kind, string? Command, string? Arguments, string? ClassId);

public sealed record ScheduledTaskInfo(string Name, string? Author, bool Hidden, bool Enabled, string? RunLevel, string? UserId, IReadOnlyList<TaskAction> Actions, IReadOnlyList<string> Triggers);

/// <summary>작업 목록을 읽은 결과. <paramref name="Unreadable"/>는 XML이 깨져서 읽지 못한 작업의 이름이에요.</summary>
public sealed record TaskParseResult(List<ScheduledTaskInfo> Tasks, IReadOnlyList<string> Unreadable);

/// <summary>
/// schtasks /query /xml ONE 출력을 파싱해요. 작업 이름은 Task 앞의 주석(&lt;!-- \이름 --&gt;)에 있어요.
/// 작업 하나하나를 따로 읽어서, 작업 하나의 XML이 깨져도(예: 설명에 제어 문자, 이름에 "--") 나머지 작업은 그대로 검사해요.
/// </summary>
public static partial class TaskXmlParser
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    private static readonly XmlReaderSettings FragmentSettings = new()
    {
        // 외부 DTD·엔티티는 읽지 않고, 제어 문자가 섞인 설명도 받아들여요 (그런 작업도 검사해야 해요).
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        CheckCharacters = false,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
    };

    // 작업 이름 주석, 또는 <Task ...>...</Task> 한 덩어리. 이름은 XML 파서가 아니라 이 정규식으로 꺼내요 ("--"가 든 이름도 돼요).
    [GeneratedRegex(@"<!--(?<name>.*?)-->|<Task\b(?:[^>]*/>|[^>]*>.*?</Task\s*>)", RegexOptions.Singleline)]
    private static partial Regex Pieces();

    [GeneratedRegex(@"<Task\b")]
    private static partial Regex TaskOpening();

    public static List<ScheduledTaskInfo> Parse(string xml) => ParseAll(xml).Tasks;

    public static TaskParseResult ParseAll(string xml)
    {
        var tasks = new List<ScheduledTaskInfo>();
        var unreadable = new List<string>();
        if (string.IsNullOrWhiteSpace(xml))
        {
            return new TaskParseResult(tasks, unreadable);
        }

        string? pendingName = null;
        foreach (Match m in Pieces().Matches(xml))
        {
            if (m.Groups["name"].Success)
            {
                pendingName = m.Groups["name"].Value.Trim();
                continue;
            }

            var commentName = pendingName;
            pendingName = null;
            var task = TryParseFragment(m.Value);
            if (task is null)
            {
                unreadable.Add(string.IsNullOrEmpty(commentName) ? "(이름 없음)" : commentName);

                // 닫는 태그가 없는 작업이 다음 작업까지 삼켰으면, 삼킨 작업도 읽지 못한 것으로 세요.
                for (var i = TaskOpening().Count(m.Value); i > 1; i--)
                {
                    unreadable.Add("(이름 없음)");
                }

                continue;
            }

            var name = commentName ?? task.Element(Ns + "RegistrationInfo")?.Element(Ns + "URI")?.Value ?? "(이름 없음)";
            tasks.Add(ParseTask(name, task));
        }

        // 닫히지 않은 <Task>(출력이 잘림 등)도 읽지 못한 작업으로 세요.
        var rest = Pieces().Replace(xml, " ");
        var unclosed = TaskOpening().Count(rest);
        for (var i = 0; i < unclosed; i++)
        {
            unreadable.Add("(이름 없음, 출력이 잘림)");
        }

        return new TaskParseResult(tasks, unreadable);
    }

    private static XElement? TryParseFragment(string fragment)
    {
        try
        {
            using var reader = XmlReader.Create(new StringReader(fragment), FragmentSettings);
            var doc = XDocument.Load(reader, LoadOptions.None);
            return doc.Root is { } root && root.Name.LocalName == "Task" ? root : null;
        }
        catch (XmlException)
        {
            return null;
        }
    }

    private static ScheduledTaskInfo ParseTask(string name, XElement task)
    {
        var reg = task.Element(Ns + "RegistrationInfo");
        var settings = task.Element(Ns + "Settings");
        var principal = task.Element(Ns + "Principals")?.Element(Ns + "Principal");
        var actions = new List<TaskAction>();
        foreach (var a in task.Element(Ns + "Actions")?.Elements() ?? [])
        {
            switch (a.Name.LocalName)
            {
                case "Exec":
                    actions.Add(new TaskAction("Exec", a.Element(Ns + "Command")?.Value?.Trim(), a.Element(Ns + "Arguments")?.Value?.Trim(), null));
                    break;
                case "ComHandler":
                    actions.Add(new TaskAction("ComHandler", null, a.Element(Ns + "Data")?.Value, a.Element(Ns + "ClassId")?.Value?.Trim()));
                    break;
                default:
                    actions.Add(new TaskAction(a.Name.LocalName, null, null, null));
                    break;
            }
        }

        var triggers = (task.Element(Ns + "Triggers")?.Elements() ?? []).Select(t => t.Name.LocalName).ToList();
        return new ScheduledTaskInfo(
            name,
            reg?.Element(Ns + "Author")?.Value,
            string.Equals(settings?.Element(Ns + "Hidden")?.Value, "true", StringComparison.OrdinalIgnoreCase),
            !string.Equals(settings?.Element(Ns + "Enabled")?.Value, "false", StringComparison.OrdinalIgnoreCase),
            principal?.Element(Ns + "RunLevel")?.Value,
            principal?.Element(Ns + "UserId")?.Value,
            actions,
            triggers);
    }
}
