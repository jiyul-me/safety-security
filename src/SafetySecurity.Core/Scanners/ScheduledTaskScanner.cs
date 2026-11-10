using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Install;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>
/// 예약 작업 (schtasks /query /xml로 읽기만 해요).
/// SafetySecurity 이름(\SafetySecurity\…, \SafetySecurity-…)을 쓰는 작업은 이름만 믿지 않고 동작까지 확인해요.
/// 진짜 우리 작업이 아니면 TASK-003(위장), 진짜 우리 작업이 꺼져 있으면 TASK-004로 알려요.
/// </summary>
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
            ctx.Coverage.Incomplete(CategoryName, "예약 작업", error ?? "작업 목록을 읽지 못했어요.");
            return findings;
        }

        var parsed = TaskXmlParser.ParseAll(xml);
        if (parsed.Unreadable.Count > 0)
        {
            // 작업 하나의 XML이 깨져도 나머지 작업은 검사해요. 읽지 못한 작업은 그 자체가 수상할 수 있어서 이름을 적어 둬요.
            var names = string.Join(", ", parsed.Unreadable.Take(5));
            var more = parsed.Unreadable.Count > 5 ? $" 외 {parsed.Unreadable.Count - 5}개" : string.Empty;
            ctx.Coverage.Incomplete(CategoryName, "예약 작업", $"작업 {parsed.Unreadable.Count}개의 내용을 읽지 못했어요 ({names}{more}). 작업 스케줄러에서 직접 확인해 보세요.");
        }

        foreach (var task in parsed.Tasks)
        {
            ctx.Pacer.Step();
            if (OwnTasks.HasOwnPrefix(task.Name))
            {
                // 이름만 보고 건너뛰면, 악성 작업이 이름만 \SafetySecurity-Update처럼 지어서 숨을 수 있어요.
                var own = EvaluateOwnName(ctx, task);
                if (own is not null)
                {
                    findings.Add(own);
                }

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

        var a = CommandAssessor.Assess(ctx, RawCommand(action));
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

        var evidence = TaskEvidence(task);
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

    /// <summary>
    /// 진짜 우리 작업인지: 이름이 우리 작업 이름이고, 동작이 하나뿐이며, 그 동작이 검사기 자신(SelfPaths)을
    /// 그 작업의 인자 그대로 실행해야 해요 (TaskXmlBuilder가 만드는 모양 그대로).
    /// </summary>
    private static bool IsGenuineOwnTask(ScanContext ctx, ScheduledTaskInfo task, OwnTaskSpec spec) =>
        task.Actions.Count == 1
        && task.Actions[0] is { Kind: "Exec", Command: { } command } action
        && ctx.IsSelf(command)
        && string.Equals(action.Arguments ?? string.Empty, spec.Arguments, StringComparison.Ordinal);

    /// <summary>SafetySecurity 이름을 쓰는 작업을 확인해요. 진짜 우리 작업이 켜져 있으면 null이에요.</summary>
    private static Finding? EvaluateOwnName(ScanContext ctx, ScheduledTaskInfo task)
    {
        var spec = OwnTasks.Find(task.Name);
        if (spec is not null && IsGenuineOwnTask(ctx, task, spec))
        {
            return task.Enabled ? null : DisabledOwnTask(task, spec);
        }

        return Impersonation(ctx, task, spec);
    }

    /// <summary>TASK-004: 진짜 우리 작업이 꺼져 있어요. 자동 검사가 멈춰 있다는 뜻이라 보통으로 알려요.</summary>
    private static Finding DisabledOwnTask(ScheduledTaskInfo task, OwnTaskSpec spec)
    {
        var evidence = TaskEvidence(task);
        evidence.Add(new("명령줄", RawCommand(task.Actions[0])));
        return new Finding
        {
            RuleId = "TASK-004",
            Category = CategoryName,
            Severity = Severity.Medium,
            Title = $"SafetySecurity 자동 검사 작업이 꺼져 있어요: {task.Name}",
            Location = "작업 스케줄러" + task.Name,
            Target = null,
            Reasons =
            [
                $"이 작업이 꺼져 있어서 {spec.Purpose}를 하지 않아요.",
                "직접 끈 적이 없다면 다른 프로그램이 SafetySecurity 검사를 막으려고 껐을 수 있어요.",
            ],
            Evidence = evidence,
            Advice = Advice.DisabledOwnTask(task.Name),
        };
    }

    /// <summary>
    /// TASK-003: SafetySecurity 이름을 쓰지만 우리가 만든 작업이 아니에요 (모르는 이름, 다른 프로그램, 다른 인자, 동작 추가).
    /// 검사기 이름 뒤에 숨으려는 작업이라 무엇을 실행하든 '높음'이에요. 꺼져 있어도 다시 켜기 쉬워서 낮추지 않아요.
    /// </summary>
    private static Finding Impersonation(ScanContext ctx, ScheduledTaskInfo task, OwnTaskSpec? spec)
    {
        var reasons = new List<string>
        {
            spec is null
                ? "SafetySecurity 작업처럼 보이는 이름이지만 SafetySecurity가 만드는 작업이 아니에요. 검사를 피하려고 이름을 흉내 냈을 수 있어요."
                : "SafetySecurity 작업 이름이지만 동작이 SafetySecurity가 등록한 것과 달라요. 다른 프로그램이 작업을 바꿨을 수 있어요.",
        };
        var evidence = TaskEvidence(task);
        string? target = null;
        string? selfCommand = null;
        if (task.Actions.Count > 1)
        {
            reasons.Add($"동작이 {task.Actions.Count}개 있어요. SafetySecurity 작업은 검사기를 실행하는 동작 하나만 써요.");
        }

        foreach (var action in task.Actions)
        {
            if (action.Kind != "Exec" || string.IsNullOrWhiteSpace(action.Command))
            {
                reasons.Add($"'{action.Kind}' 동작이 있어요. SafetySecurity 작업은 프로그램 실행(Exec) 동작만 써요.");
                if (action.ClassId is { } clsid)
                {
                    evidence.Add(new("COM 클래스", clsid));
                }

                continue;
            }

            var raw = RawCommand(action);
            if (ctx.IsSelf(action.Command))
            {
                // 검사기 자신을 실행하더라도 인자가 다르면(uninstall 등) 우리 작업이 아니에요.
                var args = action.Arguments ?? string.Empty;
                if (spec is not null && !string.Equals(args, spec.Arguments, StringComparison.Ordinal))
                {
                    reasons.Add($"SafetySecurity 검사기를 이 작업이 쓰지 않는 인자로 실행해요: '{args}' (원래 인자: '{spec.Arguments}')");
                }
                else if (spec is null && !OwnTasks.All.Any(t => string.Equals(t.Arguments, args, StringComparison.Ordinal)))
                {
                    reasons.Add($"SafetySecurity 검사기를 SafetySecurity가 쓰지 않는 인자로 실행해요: '{args}'");
                }

                evidence.Add(new("명령줄", raw));

                // 대상은 명령줄 전체로 둬요. 인자가 바뀌면 ID도 바뀌어서 새 항목으로 알리고, 엔진이 '검사기 자신'으로 빼지도 않아요.
                if (!ctx.IsSelf(raw))
                {
                    selfCommand ??= raw;
                }

                continue;
            }

            var a = CommandAssessor.Assess(ctx, raw);
            reasons.AddRange(a.Reasons);
            evidence.AddRange(a.Evidence);
            if (!a.IsSelf && a.Target is { } t && !ctx.IsSelf(t))
            {
                target ??= t;
            }
        }

        if (task.Hidden)
        {
            reasons.Add("숨김 작업이에요. 작업 스케줄러 기본 화면에 보이지 않아요.");
        }

        if (!task.Enabled)
        {
            reasons.Add("작업이 꺼져 있어요. 하지만 다른 프로그램이 언제든 다시 켤 수 있어요.");
        }

        return new Finding
        {
            RuleId = "TASK-003",
            Category = CategoryName,
            Severity = Severity.High,
            Title = spec is null ? $"SafetySecurity 작업으로 위장한 예약 작업: {task.Name}" : $"SafetySecurity 작업의 동작이 바뀌었어요: {task.Name}",
            Location = "작업 스케줄러" + task.Name,
            Target = target ?? selfCommand,
            Reasons = reasons,
            Evidence = evidence,
            Advice = Advice.ImpersonatingTask(task.Name),
        };
    }

    private static string RawCommand(TaskAction action)
    {
        var command = action.Command ?? string.Empty;
        command = command.StartsWith('"') ? command : "\"" + command + "\"";
        return string.IsNullOrEmpty(action.Arguments) ? command : command + " " + action.Arguments;
    }

    private static List<KeyValuePair<string, string>> TaskEvidence(ScheduledTaskInfo task)
    {
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

        return evidence;
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
            ctx.Coverage.Incomplete(CategoryName, "숨겨진 예약 작업", "TaskCache를 읽을 권한이 없어요 (관리자 작업에서 확인해요).");
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

            // 이름으로 빼 주는 작업은 없어요. 우리 작업도 schtasks로 등록해서 항상 SD가 있어요.
            // SafetySecurity 이름을 쓰는데 SD가 없으면 오히려 검사기 이름 뒤에 숨은 작업이에요.
            if (isTask && sub.GetValue("SD") is null)
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
