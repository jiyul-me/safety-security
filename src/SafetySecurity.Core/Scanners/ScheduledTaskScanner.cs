using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>예약 작업 (schtasks /query /xml로 읽기만 해요).</summary>
public sealed class ScheduledTaskScanner : IScanner
{
    public const string CategoryName = "ScheduledTask";

    public string Category => CategoryName;

    public string DisplayName => "예약 작업";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.User;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var findings = new List<Finding>();
        if (ctx.Tasks is null)
        {
            return findings;
        }

        var xml = ctx.Tasks.GetTasksXml(out var error);
        if (xml is null)
        {
            ctx.Coverage.Skipped("예약 작업", error ?? "작업 목록을 읽지 못했어요.");
            return findings;
        }

        foreach (var task in TaskXmlParser.Parse(xml))
        {
            ctx.Pacer.Step();
            if (ctx.SelfTaskPrefixes.Any(p => task.Name.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            foreach (var action in task.Actions)
            {
                var f = Evaluate(ctx, task, action);
                if (f is not null)
                {
                    findings.Add(f);
                }
            }
        }

        return findings;
    }

    private static Finding? Evaluate(ScanContext ctx, ScheduledTaskInfo task, TaskAction action)
    {
        if (action.Kind != "Exec" || string.IsNullOrWhiteSpace(action.Command))
        {
            return null;
        }

        var command = action.Command.StartsWith('"') ? action.Command : "\"" + action.Command + "\"";
        var raw = string.IsNullOrEmpty(action.Arguments) ? command : command + " " + action.Arguments;
        var a = CommandAssessor.Assess(ctx, raw);
        if (a.IsSelf || a.Severity is null)
        {
            return null;
        }

        // Windows 업데이트가 파일을 없애고 작업만 남기는 경우가 많아요 (예: USO_UxBroker → MusNotification.exe).
        // Microsoft 작업이 Windows 폴더의 없는 파일을 가리키는 것뿐이면 보고하지 않아요.
        if (task.Name.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase)
            && a.Severity == Severity.Low
            && a.Target is { } target
            && !ctx.Files.FileExists(target)
            && ctx.Classifier.Classify(target) == PathKind.Windows)
        {
            return null;
        }

        var severity = a.Severity.Value;
        var reasons = new List<string>(a.Reasons);
        if (task.Hidden && a.Target is not null && PathClassifier.IsUserWritable(ctx.Classifier.Classify(a.Target)))
        {
            severity = severity.Bump();
            reasons.Add("숨김 작업이에요. 작업 스케줄러 기본 화면에 보이지 않아요.");
        }

        if (string.Equals(task.RunLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase) && severity >= Severity.Medium)
        {
            reasons.Add("가장 높은 권한(관리자)으로 실행되는 작업이에요.");
        }

        if (!task.Enabled)
        {
            severity = severity.Lower();
            reasons.Add("작업이 꺼져 있어요.");
        }

        if (severity == Severity.Info)
        {
            return null;
        }

        var evidence = new List<KeyValuePair<string, string>> { new("작업 이름", task.Name) };
        if (!string.IsNullOrWhiteSpace(task.Author))
        {
            evidence.Add(new("작성자", task.Author));
        }

        if (task.Triggers.Count > 0)
        {
            evidence.Add(new("트리거", string.Join(", ", task.Triggers)));
        }

        if (task.UserId is not null)
        {
            evidence.Add(new("실행 계정", task.UserId));
        }

        evidence.AddRange(a.Evidence);
        return new Finding
        {
            RuleId = "TASK-001",
            Category = CategoryName,
            Severity = severity,
            Title = $"의심스러운 예약 작업: {task.Name}",
            Location = "작업 스케줄러" + task.Name,
            Target = a.Target,
            Reasons = reasons,
            Evidence = evidence,
            Advice = Advice.Task(task.Name),
        };
    }
}

/// <summary>
/// 작업 스케줄러 레지스트리 캐시(TaskCache\Tree)에서 보안 설명자(SD)가 지워진 '숨겨진 작업'을 찾아요.
/// SD를 지우면 schtasks나 작업 스케줄러 화면에 안 보이게 돼요 (Tarrask 수법). 관리자 권한이 필요해요.
/// </summary>
public sealed class HiddenTaskScanner : IScanner
{
    public const string CategoryName = "HiddenTask";
    private const string TreePath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

    public string Category => CategoryName;

    public string DisplayName => "숨겨진 예약 작업 (TaskCache)";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.Admin;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var findings = new List<Finding>();
        using var root = ctx.Registry.Open(RegHive.LocalMachine, TreePath);
        if (root is null)
        {
            ctx.Coverage.Skipped("숨겨진 예약 작업", "TaskCache를 읽을 권한이 없어요 (관리자 작업에서 확인해요).");
            return findings;
        }

        Walk(ctx, root, @"\", findings, depth: 0);
        return findings;
    }

    private static void Walk(ScanContext ctx, IRegistryKeyView key, string taskPath, List<Finding> findings, int depth)
    {
        if (depth > 16)
        {
            return;
        }

        foreach (var child in key.GetSubKeyNames())
        {
            ctx.Pacer.Step();
            using var sub = key.OpenSubKey(child);
            if (sub is null)
            {
                continue;
            }

            var path = taskPath + child;
            var isTask = sub.GetValue("Id") is not null;
            if (isTask && sub.GetValue("SD") is null && !ctx.SelfTaskPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(new Finding
                {
                    RuleId = "TASK-002",
                    Category = CategoryName,
                    Severity = Severity.High,
                    Title = $"보안 설명자가 지워진 숨겨진 작업: {path}",
                    Location = sub.FullPath,
                    Target = sub.GetString("Id"),
                    Reasons = ["작업의 SD 값이 없어서 작업 스케줄러 화면과 schtasks에 보이지 않아요. 악성코드가 작업을 숨기는 수법(Tarrask)이에요."],
                    Evidence = [new("작업 경로", path), new("작업 ID", sub.GetString("Id") ?? string.Empty)],
                    Advice = Advice.Task(path),
                });
            }

            if (!isTask)
            {
                Walk(ctx, sub, path + "\\", findings, depth + 1);
            }
        }
    }
}
