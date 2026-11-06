using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>
/// 로그온할 때 자동으로 실행되는 곳들: Run 키, 시작프로그램 폴더, Winlogon, AppInit_DLLs,
/// IFEO 디버거, AppCertDlls, 로그온 스크립트, cmd AutoRun.
/// </summary>
public sealed class AutorunScanner : IScanner
{
    public const string CategoryName = "Autorun";

    private static readonly (RegHive Hive, string Path)[] RunKeys =
    [
        (RegHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (RegHive.CurrentUser, @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (RegHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (RegHive.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (RegHive.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ];

    public string Category => CategoryName;

    public string DisplayName => "자동 실행 (Run 키, 시작프로그램, Winlogon, IFEO)";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.User && !quick;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var findings = new List<Finding>();
        ScanRunKeys(ctx, findings);
        ScanStartupFolders(ctx, findings);
        ScanWinlogon(ctx, findings);
        ScanAppInit(ctx, findings);
        ScanIfeo(ctx, findings);
        ScanMisc(ctx, findings);
        return findings;
    }

    private static void ScanRunKeys(ScanContext ctx, List<Finding> findings)
    {
        foreach (var (hive, path) in RunKeys)
        {
            using var key = ctx.Registry.Open(hive, path);
            if (key is null)
            {
                continue;
            }

            foreach (var name in key.GetValueNames())
            {
                ctx.Pacer.Step();
                var raw = key.GetString(name);
                if (string.IsNullOrWhiteSpace(raw))
                {
                    continue;
                }

                var a = CommandAssessor.Assess(ctx, raw);
                if (a.IsSelf || a.Severity is null)
                {
                    continue;
                }

                var evidence = new List<KeyValuePair<string, string>> { new("값 이름", name) };
                if (key.LastWriteTime is { } t)
                {
                    evidence.Add(new("키 수정 시각", ExecutableAssessor.FormatTime(t)));
                }

                evidence.AddRange(a.Evidence);
                findings.Add(new Finding
                {
                    RuleId = "RUN-001",
                    Category = CategoryName,
                    Severity = a.Severity.Value,
                    Title = $"자동 실행 등록: {name}",
                    Location = key.FullPath + "\\" + name,
                    Target = a.Target,
                    Reasons = a.Reasons,
                    Evidence = evidence,
                    Advice = Advice.RegistryAutorun(key.FullPath, name),
                });
            }
        }
    }

    private static void ScanStartupFolders(ScanContext ctx, List<Finding> findings)
    {
        string[] folders =
        [
            ctx.Paths.AppData + @"\Microsoft\Windows\Start Menu\Programs\Startup",
            ctx.Paths.ProgramData + @"\Microsoft\Windows\Start Menu\Programs\StartUp",
        ];

        foreach (var folder in folders)
        {
            foreach (var file in ctx.Files.GetFiles(folder))
            {
                ctx.Pacer.Step();
                var name = Path.GetFileName(file.Replace('\\', '/'));
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                CommandAssessment a;
                var evidence = new List<KeyValuePair<string, string>> { new("파일", file) };
                if (name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                {
                    var bytes = ctx.Files.ReadPrefix(file, 64 * 1024);
                    var link = bytes is null ? null : LnkParser.Parse(bytes);
                    if (link?.TargetPath is null)
                    {
                        continue;
                    }

                    var cmd = Quote(link.TargetPath) + (link.Arguments is null ? string.Empty : " " + link.Arguments);
                    evidence.Add(new("바로가기 대상", link.TargetPath));
                    if (link.Arguments is not null)
                    {
                        evidence.Add(new("바로가기 인자", link.Arguments));
                    }

                    a = CommandAssessor.Assess(ctx, cmd);
                }
                else
                {
                    a = CommandAssessor.Assess(ctx, Quote(file));
                    if (a.Severity is null && CommandAssessor.IsScript(file))
                    {
                        a.Severity = Severity.Medium;
                        a.Reasons.Add("시작프로그램 폴더에 스크립트 파일이 직접 들어 있어요.");
                    }
                }

                if (a.IsSelf || a.Severity is null)
                {
                    continue;
                }

                evidence.AddRange(a.Evidence);
                findings.Add(new Finding
                {
                    RuleId = "RUN-002",
                    Category = CategoryName,
                    Severity = a.Severity.Value,
                    Title = $"시작프로그램 폴더 항목: {name}",
                    Location = file,
                    Target = a.Target,
                    Reasons = a.Reasons,
                    Evidence = evidence,
                    Advice = Advice.StartupFile,
                });
            }
        }
    }

    private static void ScanWinlogon(ScanContext ctx, List<Finding> findings)
    {
        const string path = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
        using (var machine = ctx.Registry.Open(RegHive.LocalMachine, path))
        {
            if (machine is not null)
            {
                ctx.Pacer.Step();
                var shell = machine.GetString("Shell")?.Trim();
                if (shell is not null && !IsDefaultShell(shell))
                {
                    findings.Add(Winlogon(machine.FullPath, "Shell", shell, "Windows 셸이 explorer.exe가 아닌 다른 프로그램으로 바뀌었어요."));
                }

                var userinit = machine.GetString("Userinit")?.Trim();
                if (userinit is not null && !IsDefaultUserinit(ctx, userinit))
                {
                    findings.Add(Winlogon(machine.FullPath, "Userinit", userinit, "로그온할 때 userinit.exe 말고 다른 프로그램도 실행되게 바뀌었어요."));
                }
            }
        }

        using var user = ctx.Registry.Open(RegHive.CurrentUser, path);
        if (user is not null)
        {
            var shell = user.GetString("Shell")?.Trim();
            if (!string.IsNullOrEmpty(shell))
            {
                findings.Add(Winlogon(user.FullPath, "Shell", shell, "HKCU에 Shell 값이 있어요. 이 사용자로 로그온하면 explorer.exe 대신 이 프로그램이 실행돼요."));
            }
        }
    }

    private static Finding Winlogon(string keyPath, string valueName, string value, string reason) => new()
    {
        RuleId = "RUN-003",
        Category = CategoryName,
        Severity = Severity.High,
        Title = $"Winlogon {valueName} 값이 바뀌었어요",
        Location = keyPath + "\\" + valueName,
        Target = value,
        Reasons = [reason],
        Evidence = [new("현재 값", value)],
        Advice = Advice.RegistryAutorun(keyPath, valueName),
    };

    private static bool IsDefaultShell(string shell) =>
        shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase)
        || shell.Equals("explorer.exe,", StringComparison.OrdinalIgnoreCase)
        || shell.EndsWith(@"\explorer.exe", StringComparison.OrdinalIgnoreCase);

    private static bool IsDefaultUserinit(ScanContext ctx, string value)
    {
        var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 1)
        {
            return false;
        }

        var n = ctx.Classifier.Normalize(parts[0]);
        return n == ctx.Classifier.Normalize(ctx.Paths.System32 + @"\userinit.exe") || n == "userinit.exe";
    }

    private static void ScanAppInit(ScanContext ctx, List<Finding> findings)
    {
        string[] paths =
        [
            @"Software\Microsoft\Windows NT\CurrentVersion\Windows",
            @"Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
        ];
        foreach (var path in paths)
        {
            using var key = ctx.Registry.Open(RegHive.LocalMachine, path);
            var dlls = key?.GetString("AppInit_DLLs")?.Trim();
            if (key is null || string.IsNullOrEmpty(dlls))
            {
                continue;
            }

            var enabled = key.GetInt("LoadAppInit_DLLs") == 1;
            findings.Add(new Finding
            {
                RuleId = "RUN-004",
                Category = CategoryName,
                Severity = enabled ? Severity.High : Severity.Low,
                Title = "AppInit_DLLs에 DLL이 등록돼 있어요",
                Location = key.FullPath + "\\AppInit_DLLs",
                Target = dlls,
                Reasons = enabled
                    ? ["AppInit_DLLs가 켜져 있어서 창을 쓰는 거의 모든 프로그램에 이 DLL이 주입돼요."]
                    : ["AppInit_DLLs 값은 있지만 LoadAppInit_DLLs가 꺼져 있어요."],
                Evidence = [new("AppInit_DLLs", dlls), new("LoadAppInit_DLLs", enabled ? "1 (켜짐)" : "0 (꺼짐)")],
                Advice = Advice.RegistryAutorun(key.FullPath, "AppInit_DLLs"),
            });
        }

        using var appCert = ctx.Registry.Open(RegHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls");
        if (appCert is not null)
        {
            foreach (var name in appCert.GetValueNames())
            {
                var value = appCert.GetString(name);
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                findings.Add(new Finding
                {
                    RuleId = "RUN-005",
                    Category = CategoryName,
                    Severity = Severity.High,
                    Title = $"AppCertDlls 등록: {name}",
                    Location = appCert.FullPath + "\\" + name,
                    Target = value,
                    Reasons = ["AppCertDlls에 등록된 DLL은 프로세스를 만드는 모든 프로그램에 로드돼요. 정상 프로그램은 거의 쓰지 않아요."],
                    Evidence = [new("값", value)],
                    Advice = Advice.RegistryAutorun(appCert.FullPath, name),
                });
            }
        }
    }

    private static void ScanIfeo(ScanContext ctx, List<Finding> findings)
    {
        string[] roots =
        [
            @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            @"Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        ];
        foreach (var rootPath in roots)
        {
            using var root = ctx.Registry.Open(RegHive.LocalMachine, rootPath);
            if (root is null)
            {
                continue;
            }

            foreach (var exe in root.GetSubKeyNames())
            {
                ctx.Pacer.Step();
                using var key = root.OpenSubKey(exe);
                var debugger = key?.GetString("Debugger")?.Trim();
                if (key is null || string.IsNullOrEmpty(debugger))
                {
                    continue;
                }

                var a = CommandAssessor.Assess(ctx, debugger);
                var severity = Severity.High;
                var reasons = new List<string> { $"'{exe}'를 실행하면 대신 '{debugger}'가 실행되도록 IFEO 디버거가 설정돼 있어요." };
                if (a.Severity is null && a.Target is not null && ctx.Files.FileExists(a.Target))
                {
                    // 서명된 도구 (예: Process Explorer가 작업 관리자를 대체할 때)
                    severity = Severity.Medium;
                    reasons.Add("대상 프로그램은 서명이 유효해요. 직접 설정한 도구(Process Explorer 등)인지 확인하세요.");
                }

                reasons.AddRange(a.Reasons);
                findings.Add(new Finding
                {
                    RuleId = "RUN-006",
                    Category = CategoryName,
                    Severity = severity,
                    Title = $"IFEO 디버거 설정: {exe}",
                    Location = key.FullPath + "\\Debugger",
                    Target = a.Target ?? debugger,
                    Reasons = reasons,
                    Evidence = a.Evidence,
                    Advice = Advice.RegistryAutorun(key.FullPath, "Debugger"),
                });
            }
        }

        using var silent = ctx.Registry.Open(RegHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit");
        if (silent is null)
        {
            return;
        }

        foreach (var exe in silent.GetSubKeyNames())
        {
            using var key = silent.OpenSubKey(exe);
            var monitor = key?.GetString("MonitorProcess")?.Trim();
            if (key is null || string.IsNullOrEmpty(monitor))
            {
                continue;
            }

            var a = CommandAssessor.Assess(ctx, monitor);
            findings.Add(new Finding
            {
                RuleId = "RUN-007",
                Category = CategoryName,
                Severity = Severity.High,
                Title = $"SilentProcessExit 모니터 등록: {exe}",
                Location = key.FullPath + "\\MonitorProcess",
                Target = a.Target ?? monitor,
                Reasons = [$"'{exe}'가 끝날 때마다 '{monitor}'가 실행돼요. 지속성 수법으로 알려져 있어요."],
                Evidence = a.Evidence,
                Advice = Advice.RegistryAutorun(key.FullPath, "MonitorProcess"),
            });
        }
    }

    private static void ScanMisc(ScanContext ctx, List<Finding> findings)
    {
        using (var env = ctx.Registry.Open(RegHive.CurrentUser, "Environment"))
        {
            var script = env?.GetString("UserInitMprLogonScript")?.Trim();
            if (env is not null && !string.IsNullOrEmpty(script))
            {
                var a = CommandAssessor.Assess(ctx, script);
                findings.Add(new Finding
                {
                    RuleId = "RUN-008",
                    Category = CategoryName,
                    Severity = Severity.High,
                    Title = "로그온 스크립트(UserInitMprLogonScript)가 등록돼 있어요",
                    Location = env.FullPath + "\\UserInitMprLogonScript",
                    Target = a.Target ?? script,
                    Reasons = ["로그온할 때마다 이 명령이 실행돼요. 일반 가정용 PC에서는 거의 쓰지 않는 설정이에요 (T1037.001)."],
                    Evidence = a.Evidence,
                    Advice = Advice.RegistryAutorun(env.FullPath, "UserInitMprLogonScript"),
                });
            }
        }

        foreach (var hive in new[] { RegHive.CurrentUser, RegHive.LocalMachine })
        {
            using var cmd = ctx.Registry.Open(hive, @"Software\Microsoft\Command Processor");
            var autorun = cmd?.GetString("AutoRun")?.Trim();
            if (cmd is null || string.IsNullOrEmpty(autorun))
            {
                continue;
            }

            var a = CommandAssessor.Assess(ctx, autorun);
            findings.Add(new Finding
            {
                RuleId = "RUN-009",
                Category = CategoryName,
                Severity = a.Severity is { } s ? SeverityExtensions.Max(s, Severity.Medium) : Severity.Medium,
                Title = "cmd.exe AutoRun이 설정돼 있어요",
                Location = cmd.FullPath + "\\AutoRun",
                Target = a.Target ?? autorun,
                Reasons = ["명령 프롬프트(cmd.exe)가 실행될 때마다 이 명령이 먼저 실행돼요."],
                Evidence = a.Evidence,
                Advice = Advice.RegistryAutorun(cmd.FullPath, "AutoRun"),
            });
        }
    }

    private static string Quote(string path) => path.StartsWith('"') ? path : "\"" + path + "\"";
}
