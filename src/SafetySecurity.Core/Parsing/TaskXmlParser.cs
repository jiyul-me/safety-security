using System.Xml;
using System.Xml.Linq;

namespace SafetySecurity.Core.Parsing;

public sealed record TaskAction(string Kind, string? Command, string? Arguments, string? ClassId);

public sealed record ScheduledTaskInfo(string Name, string? Author, bool Hidden, bool Enabled, string? RunLevel, string? UserId, IReadOnlyList<TaskAction> Actions, IReadOnlyList<string> Triggers);

/// <summary>schtasks /query /xml ONE 출력을 파싱해요. 작업 이름은 Task 앞의 주석(&lt;!-- \이름 --&gt;)에 있어요.</summary>
public static class TaskXmlParser
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public static List<ScheduledTaskInfo> Parse(string xml)
    {
        var result = new List<ScheduledTaskInfo>();
        if (string.IsNullOrWhiteSpace(xml))
        {
            return result;
        }

        // XML 선언을 모두 지우고 하나의 루트로 감싸요 (작업마다 선언이 붙는 경우도 처리).
        var body = System.Text.RegularExpressions.Regex.Replace(xml, @"<\?xml[^>]*\?>", string.Empty);
        XDocument doc;
        try
        {
            doc = XDocument.Parse("<Root>" + body + "</Root>", LoadOptions.None);
        }
        catch (XmlException)
        {
            return result;
        }

        string? pendingName = null;
        foreach (var node in doc.Descendants().SelectMany(e => e.Nodes()).Where(n => n is XComment || (n is XElement el && el.Name.LocalName == "Task")))
        {
            if (node is XComment c)
            {
                pendingName = c.Value.Trim();
                continue;
            }

            var task = (XElement)node;
            var name = pendingName ?? task.Element(Ns + "RegistrationInfo")?.Element(Ns + "URI")?.Value ?? "(이름 없음)";
            pendingName = null;
            result.Add(ParseTask(name, task));
        }

        return result;
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
