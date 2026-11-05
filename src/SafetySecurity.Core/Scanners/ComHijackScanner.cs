using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>
/// COM 하이재킹 (MITRE ATT&amp;CK T1546.015) 검사.
/// HKCU\Software\Classes\CLSID는 관리자 권한 없이 쓸 수 있고, Windows는 HKLM보다 HKCU를 먼저 봐요.
/// 그래서 악성코드가 HKCU에 같은 CLSID를 만들면 Chrome·탐색기 같은 정상 프로그램이 악성 DLL을 불러와요.
/// </summary>
public sealed class ComHijackScanner : IScanner
{
    public const string CategoryName = "ComHijack";

    private static readonly (string Path, string Label)[] Roots =
    [
        (@"Software\Classes\CLSID", "64비트"),
        (@"Software\Classes\Wow6432Node\CLSID", "32비트"),
    ];

    private static readonly string[] ServerKeys = ["InprocServer32", "LocalServer32", "InprocHandler32"];

    public string Category => CategoryName;

    public string DisplayName => "COM 하이재킹 (HKCU CLSID)";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.User && !quick;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var findings = new List<Finding>();
        foreach (var (rootPath, label) in Roots)
        {
            using var userRoot = ctx.Registry.Open(RegHive.CurrentUser, rootPath);
            if (userRoot is null)
            {
                continue;
            }

            foreach (var clsid in userRoot.GetSubKeyNames())
            {
                ctx.Pacer.Step();
                using var userClass = userRoot.OpenSubKey(clsid);
                if (userClass is null)
                {
                    continue;
                }

                using var machineClass = ctx.Registry.Open(RegHive.LocalMachine, rootPath + "\\" + clsid);
                ScanClass(ctx, findings, userClass, machineClass, clsid, label);
            }
        }

        return findings;
    }

    private static void ScanClass(ScanContext ctx, List<Finding> findings, IRegistryKeyView userClass, IRegistryKeyView? machineClass, string clsid, string label)
    {
        var className = machineClass?.GetString(null) ?? userClass.GetString(null);
        var keyWrite = userClass.LastWriteTime;

        using (var scriptlet = userClass.OpenSubKey("ScriptletURL"))
        {
            var url = scriptlet?.GetString(null);
            if (!string.IsNullOrWhiteSpace(url))
            {
                findings.Add(new Finding
                {
                    RuleId = "COM-003",
                    Category = CategoryName,
                    Severity = Severity.High,
                    Title = $"COM 클래스가 스크립틀릿 URL을 불러와요 ({label})",
                    Location = scriptlet!.FullPath,
                    Target = url,
                    Reasons = ["ScriptletURL은 COM 객체 대신 원격·로컬 스크립트를 실행하게 만들어요. 정상 프로그램은 거의 쓰지 않아요."],
                    Evidence = BaseEvidence(clsid, className, keyWrite),
                    Advice = Advice.ComHijack(userClass.FullPath),
                });
            }
        }

        using (var treatAs = userClass.OpenSubKey("TreatAs"))
        {
            var target = treatAs?.GetString(null)?.Trim();
            if (!string.IsNullOrEmpty(target))
            {
                using var machineTreat = machineClass?.OpenSubKey("TreatAs");
                var machineTarget = machineTreat?.GetString(null)?.Trim();
                if (!string.Equals(target, machineTarget, StringComparison.OrdinalIgnoreCase))
                {
                    var evidence = BaseEvidence(clsid, className, keyWrite);
                    evidence.Add(new("TreatAs 대상", target));
                    if (machineTarget is not null)
                    {
                        evidence.Add(new("HKLM 원래 TreatAs", machineTarget));
                    }

                    findings.Add(new Finding
                    {
                        RuleId = "COM-004",
                        Category = CategoryName,
                        Severity = machineClass is not null ? Severity.High : Severity.Medium,
                        Title = $"TreatAs로 COM 클래스를 다른 클래스로 바꿔요 ({label})",
                        Location = treatAs!.FullPath,
                        Target = target,
                        Reasons = machineClass is not null
                            ? ["HKLM에 등록된 정상 COM 클래스를 HKCU의 TreatAs로 다른 클래스에 연결했어요. 하이재킹 수법 중 하나예요."]
                            : ["HKCU에만 있는 TreatAs 설정이에요."],
                        Evidence = evidence,
                        Advice = Advice.ComHijack(userClass.FullPath),
                    });
                }
            }
        }

        foreach (var serverKeyName in ServerKeys)
        {
            using var serverKey = userClass.OpenSubKey(serverKeyName);
            var raw = serverKey?.GetString(null);
            if (serverKey is null || string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            using var machineServer = machineClass?.OpenSubKey(serverKeyName);
            var machineRaw = machineServer?.GetString(null);
            var finding = EvaluateServer(ctx, serverKey, serverKeyName, raw, machineClass is not null && machineServer is not null, machineRaw, clsid, className, keyWrite, label, userClass.FullPath);
            if (finding is not null)
            {
                findings.Add(finding);
            }
        }
    }

    private static Finding? EvaluateServer(
        ScanContext ctx,
        IRegistryKeyView serverKey,
        string serverKeyName,
        string raw,
        bool shadows,
        string? machineRaw,
        string clsid,
        string? className,
        DateTimeOffset? keyWrite,
        string label,
        string classKeyPath)
    {
        var path = ResolveServerPath(ctx, serverKeyName, raw);
        var evidence = BaseEvidence(clsid, className, keyWrite);
        evidence.Add(new("HKCU 값", raw));
        if (machineRaw is not null)
        {
            evidence.Add(new("HKLM 원래 값", machineRaw));
        }

        var reasons = new List<string>();
        var fileName = Path.GetFileName(path.Replace('\\', '/')).ToLowerInvariant();

        // .NET COM (mscoree.dll): 실제 코드는 CodeBase에 있어요.
        if (fileName == "mscoree.dll")
        {
            var codeBase = serverKey.GetString("CodeBase");
            if (!string.IsNullOrWhiteSpace(codeBase))
            {
                evidence.Add(new("CodeBase", codeBase));
                path = codeBase.StartsWith("file:", StringComparison.OrdinalIgnoreCase)
                    ? Uri.UnescapeDataString(codeBase[5..].TrimStart('/'))
                    : codeBase;
                fileName = Path.GetFileName(path.Replace('\\', '/')).ToLowerInvariant();
            }
        }

        if (ctx.IsSelf(path))
        {
            return null;
        }

        if (shadows && machineRaw is not null)
        {
            var machinePath = ResolveServerPath(ctx, serverKeyName, machineRaw);
            if (ctx.Classifier.Normalize(machinePath) == ctx.Classifier.Normalize(path))
            {
                // HKCU와 HKLM이 같은 파일을 가리키면 문제없어요 (일부 설치 프로그램이 양쪽에 등록해요).
                return null;
            }
        }

        Severity? severity;
        if (fileName == "scrobj.dll")
        {
            severity = Severity.High;
            reasons.Add("scrobj.dll(스크립트 구성 요소)을 COM 서버로 등록했어요. 스크립트를 COM 객체처럼 실행하는 수법이에요.");
        }
        else
        {
            var assessment = ExecutableAssessor.Assess(ctx, path);
            evidence.AddRange(assessment.Evidence);
            path = assessment.Path;
            if (shadows)
            {
                reasons.Add($"HKLM에 이미 있는 COM 클래스{(className is null ? string.Empty : $"({className})")}를 HKCU에서 덮어써서 다른 파일을 불러오게 해요. COM 하이재킹의 전형적인 형태예요.");
                if (!assessment.Exists)
                {
                    severity = Severity.Medium;
                }
                else if (assessment.Severity is not null)
                {
                    severity = Severity.High;
                }
                else if (PathClassifier.IsUserWritable(assessment.Kind))
                {
                    severity = Severity.Medium;
                    reasons.Add("대상 파일은 서명이 유효하지만 사용자 폴더에 있어요. 설치한 프로그램이 맞는지 확인하세요.");
                }
                else
                {
                    severity = Severity.Low;
                }
            }
            else
            {
                // HKCU에만 있는 클래스: 사용자 단위 설치 프로그램(OneDrive, Teams 등)이 정상적으로 많이 써요.
                severity = assessment.Severity;
            }

            reasons.AddRange(assessment.Reasons);
        }

        if (severity is null)
        {
            return null;
        }

        if (keyWrite is { } written && ctx.Now - written <= ExecutableAssessor.RecentWindow && severity >= Severity.Low)
        {
            severity = severity.Value.Bump();
            reasons.Add("이 레지스트리 키가 최근 7일 안에 만들어지거나 수정됐어요.");
        }

        return new Finding
        {
            RuleId = shadows ? "COM-001" : "COM-002",
            Category = CategoryName,
            Severity = severity.Value,
            Title = shadows
                ? $"HKCU가 기존 COM 클래스를 덮어써요 ({serverKeyName}, {label})"
                : $"사용자 COM 서버가 의심스러운 파일을 불러와요 ({serverKeyName}, {label})",
            Location = serverKey.FullPath,
            Target = path,
            Reasons = reasons,
            Evidence = evidence,
            Advice = Advice.ComHijack(classKeyPath),
        };
    }

    private static string ResolveServerPath(ScanContext ctx, string serverKeyName, string raw)
    {
        if (serverKeyName == "LocalServer32")
        {
            return CommandLine.Parse(raw, ctx.Paths, ctx.Files)?.Executable ?? raw;
        }

        var p = ctx.Paths.Expand(raw.Trim().Trim('"'));
        return CommandLine.ResolveExecutable(p, ctx.Paths, ctx.Files);
    }

    private static List<KeyValuePair<string, string>> BaseEvidence(string clsid, string? className, DateTimeOffset? keyWrite)
    {
        var list = new List<KeyValuePair<string, string>> { new("CLSID", clsid) };
        if (!string.IsNullOrWhiteSpace(className))
        {
            list.Add(new("클래스 이름", className));
        }

        if (keyWrite is { } t)
        {
            list.Add(new("키 수정 시각", ExecutableAssessor.FormatTime(t)));
        }

        return list;
    }
}
