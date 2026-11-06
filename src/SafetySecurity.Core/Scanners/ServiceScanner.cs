using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>Windows 서비스와 드라이버 (HKLM\SYSTEM\CurrentControlSet\Services).</summary>
public sealed class ServiceScanner : IScanner
{
    public const string CategoryName = "Service";
    private const string ServicesPath = @"SYSTEM\CurrentControlSet\Services";

    public string Category => CategoryName;

    public string DisplayName => "서비스·드라이버";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.User;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var findings = new List<Finding>();
        using var root = ctx.Registry.Open(RegHive.LocalMachine, ServicesPath);
        if (root is null)
        {
            ctx.Coverage.Skipped("서비스", "서비스 목록을 읽지 못했어요.");
            return findings;
        }

        foreach (var name in root.GetSubKeyNames())
        {
            ctx.Pacer.Step();
            using var key = root.OpenSubKey(name);
            if (key is null)
            {
                continue;
            }

            var type = key.GetInt("Type") ?? 0;
            var start = key.GetInt("Start") ?? 3;
            var imagePath = key.GetString("ImagePath")?.Trim();
            var isDriver = (type & 0x3) != 0;
            var isWin32 = (type & 0x30) != 0;
            if (!isDriver && !isWin32)
            {
                continue;
            }

            var f = isDriver
                ? EvaluateDriver(ctx, key, name, imagePath, start)
                : EvaluateService(ctx, key, name, imagePath, start);
            if (f is not null)
            {
                findings.Add(f);
            }
        }

        return findings;
    }

    private static Finding? EvaluateDriver(ScanContext ctx, IRegistryKeyView key, string name, string? imagePath, int start)
    {
        var path = NormalizeDriverPath(ctx, imagePath, name);
        if (!ctx.Files.FileExists(path))
        {
            // 오래된 드라이버 등록은 흔해서 파일이 없으면 넘어가요.
            return null;
        }

        var a = ExecutableAssessor.Assess(ctx, path);
        if (a.Severity is null && !PathClassifier.IsUserWritable(a.Kind))
        {
            return null;
        }

        var reasons = new List<string>(a.Reasons);
        var severity = a.Severity ?? Severity.Medium;
        if (PathClassifier.IsUserWritable(a.Kind))
        {
            severity = Severity.High;
            reasons.Insert(0, "커널 드라이버가 사용자 쓰기 가능 폴더에 있어요. 정상 드라이버는 System32\\drivers에 있어요.");
        }
        else if (a.Severity is not null)
        {
            severity = Severity.High;
        }

        if (start == 4)
        {
            severity = severity.Lower();
            reasons.Add("드라이버가 '사용 안 함' 상태예요.");
        }

        return Build(key, name, "SVC-002", severity, $"의심스러운 드라이버: {name}", path, reasons, a.Evidence, start);
    }

    private static Finding? EvaluateService(ScanContext ctx, IRegistryKeyView key, string name, string? imagePath, int start)
    {
        if (string.IsNullOrEmpty(imagePath))
        {
            return null;
        }

        var a = CommandAssessor.Assess(ctx, imagePath);
        if (a.IsSelf)
        {
            return null;
        }

        var reasons = new List<string>(a.Reasons);
        var evidence = new List<KeyValuePair<string, string>>(a.Evidence);
        var severity = a.Severity;
        var target = a.Target;

        // svchost 서비스: 실제 코드는 ServiceDll에 있어요.
        if (a.Parsed?.FileName == "svchost.exe")
        {
            string? dll;
            using (var parameters = key.OpenSubKey("Parameters"))
            {
                dll = parameters?.GetString("ServiceDll") ?? key.GetString("ServiceDll");
            }

            if (!string.IsNullOrWhiteSpace(dll))
            {
                var d = ExecutableAssessor.Assess(ctx, dll);
                target = d.Path;
                evidence.Add(new("ServiceDll", dll));
                foreach (var e in d.Evidence)
                {
                    evidence.Add(new("DLL " + e.Key, e.Value));
                }

                if (d.Severity is { } ds)
                {
                    severity = severity is { } s ? SeverityExtensions.Max(s, ds) : ds;
                    reasons.AddRange(d.Reasons.Select(r => "ServiceDll: " + r));
                    if (PathClassifier.IsUserWritable(d.Kind))
                    {
                        severity = Severity.High;
                    }
                }
            }
        }

        if (a.Parsed is { IsUnquotedWithSpaces: true } parsed && start != 4 && !reasons.Any(r => r.Contains("따옴표", StringComparison.Ordinal))
            && WritableHijackFolder(ctx, parsed.Executable) is { } folder)
        {
            // 따옴표 없는 경로 자체는 취약점(권한 상승 통로)이에요. 공격 흔적은 아니라서 낮게 둬요.
            // C:\Program Files\... 처럼 끼워 넣을 위치가 모두 관리자 전용이면 실제로 악용할 수 없어서 보고하지 않아요.
            severity = severity is { } s ? s : Severity.Low;
            reasons.Add($"서비스 경로에 공백이 있는데 따옴표가 없어요 ({parsed.Executable}). 일반 사용자가 쓸 수 있는 '{folder}'에 실행 파일을 넣으면 대신 실행될 수 있어요.");
        }

        if (severity is null)
        {
            return null;
        }

        if (start == 4)
        {
            severity = severity.Value.Lower();
            reasons.Add("서비스가 '사용 안 함' 상태예요.");
        }

        if (severity == Severity.Info)
        {
            return null;
        }

        return Build(key, name, "SVC-001", severity.Value, $"의심스러운 서비스: {name}", target, reasons, evidence, start);
    }

    private static Finding Build(IRegistryKeyView key, string name, string ruleId, Severity severity, string title, string? target, List<string> reasons, List<KeyValuePair<string, string>> assessmentEvidence, int start)
    {
        var evidence = new List<KeyValuePair<string, string>> { new("서비스 이름", name) };
        var display = key.GetString("DisplayName");
        if (!string.IsNullOrWhiteSpace(display) && !display.StartsWith('@'))
        {
            evidence.Add(new("표시 이름", display));
        }

        evidence.Add(new("시작 유형", start switch
        {
            0 => "부팅",
            1 => "시스템",
            2 => "자동",
            3 => "수동",
            4 => "사용 안 함",
            _ => start.ToString(System.Globalization.CultureInfo.InvariantCulture),
        }));
        if (key.GetString("ObjectName") is { } account)
        {
            evidence.Add(new("실행 계정", account));
        }

        if (key.LastWriteTime is { } t)
        {
            evidence.Add(new("키 수정 시각", ExecutableAssessor.FormatTime(t)));
        }

        evidence.AddRange(assessmentEvidence);
        return new Finding
        {
            RuleId = ruleId,
            Category = CategoryName,
            Severity = severity,
            Title = title,
            Location = key.FullPath,
            Target = target,
            Reasons = reasons,
            Evidence = evidence,
            Advice = Advice.Service(name),
        };
    }

    /// <summary>
    /// 따옴표 없는 경로 "C:\A B\C D\x.exe"에서 Windows는 C:\A.exe, C:\A B\C.exe 순서로 먼저 실행해 봐요.
    /// 그 후보 파일이 들어갈 폴더 중 일반 사용자가 쓸 수 있는 곳이 있으면 그 폴더를 돌려줘요.
    /// 시스템 드라이브 루트(C:\)와 Windows·Program Files는 관리자만 파일을 만들 수 있어요.
    /// 다른 드라이브(D:\ 등)는 기본 권한에서 일반 사용자도 파일을 만들 수 있어요.
    /// </summary>
    public static string? WritableHijackFolder(ScanContext ctx, string executable)
    {
        var systemDrive = ctx.Classifier.Normalize(ctx.Paths.SystemDrive);
        for (var i = executable.IndexOf(' '); i > 0; i = executable.IndexOf(' ', i + 1))
        {
            var candidate = executable[..i];
            var slash = candidate.LastIndexOf('\\');
            if (slash < 2)
            {
                continue;
            }

            var folder = candidate[..slash];
            var normalized = ctx.Classifier.Normalize(folder);
            var kind = ctx.Classifier.Classify(folder);
            if (PathClassifier.IsUserWritable(kind))
            {
                return folder;
            }

            var isDriveRoot = normalized.Length == 2 && normalized[1] == ':';
            if (kind == PathKind.Other && !(isDriveRoot && normalized == systemDrive))
            {
                return folder.Length == 2 ? folder + "\\" : folder;
            }
        }

        return null;
    }

    /// <summary>드라이버 ImagePath (\SystemRoot\..., System32\drivers\..., \??\C:\...)를 일반 경로로.</summary>
    public static string NormalizeDriverPath(ScanContext ctx, string? imagePath, string serviceName)
    {
        var p = string.IsNullOrWhiteSpace(imagePath) ? @"System32\drivers\" + serviceName + ".sys" : ctx.Paths.Expand(imagePath.Trim().Trim('"'));
        if (p.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            return p[4..];
        }

        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            return ctx.Paths.SystemRoot + p[11..];
        }

        if (p.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) || p.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase))
        {
            return ctx.Paths.SystemRoot + "\\" + p;
        }

        return p;
    }
}
