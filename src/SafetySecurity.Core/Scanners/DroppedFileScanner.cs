using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Parsing;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>
/// 사용자 폴더(AppData, LocalAppData, Temp, ProgramData, Public) 바로 아래와 한 단계 하위 폴더에서
/// 최근 14일 안에 생긴 서명 없는 실행 파일, 문서로 위장한 실행 파일을 찾아요.
/// </summary>
public sealed class DroppedFileScanner : IScanner
{
    public const string CategoryName = "DroppedFile";
    public static readonly TimeSpan Window = TimeSpan.FromDays(14);
    public const int MaxFiles = 5000;
    public const int MaxSignatureChecks = 200;

    private static readonly HashSet<string> NormalPeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".efi", ".mui", ".node", ".pyd", ".winmd", ".drv", ".ax",
        ".acm", ".ime", ".tlb", ".tsp", ".xll", ".wll", ".bpl", ".mun", ".msstyles", ".fon", ".so", ".tmp", ".bin", ".dat", ".old", ".bak", ".new", ".partial", ".crdownload",
    };

    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
        ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".hwp", ".hwpx", ".zip", ".rar", ".7z", ".html", ".htm", ".csv", ".json", ".xml",
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".js", ".jse", ".vbs", ".vbe", ".hta", ".lnk", ".msi", ".ps1",
    };

    public string Category => CategoryName;

    public string DisplayName => "사용자 폴더의 새 실행 파일";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.User && !quick;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var findings = new List<Finding>();
        var roots = new[] { ctx.Paths.AppData, ctx.Paths.LocalAppData, ctx.Paths.Temp, ctx.Paths.ProgramData, ctx.Paths.Public }
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var seen = 0;
        var signatureChecks = 0;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in roots)
        {
            var dirs = new List<(string Dir, int Depth)> { (root, 0) };
            dirs.AddRange(ctx.Files.GetDirectories(root).Select(d => (d, 1)));
            foreach (var (dir, depth) in dirs)
            {
                foreach (var file in ctx.Files.GetFiles(dir))
                {
                    if (!visited.Add(file))
                    {
                        continue;
                    }

                    if (++seen > MaxFiles)
                    {
                        ctx.Coverage.Skipped("새 실행 파일", $"파일이 {MaxFiles}개를 넘어서 나머지는 건너뛰었어요.");
                        return findings;
                    }

                    ctx.Pacer.Step();
                    var f = Evaluate(ctx, file, depth, ref signatureChecks);
                    if (f is not null)
                    {
                        findings.Add(f);
                    }
                }
            }
        }

        return findings;
    }

    private static Finding? Evaluate(ScanContext ctx, string file, int depth, ref int signatureChecks)
    {
        var meta = ctx.Files.GetMeta(file);
        if (meta is null || meta.Length < 64 || meta.Length > ExecutableAssessor.MaxHashBytes)
        {
            return null;
        }

        var age = ctx.Now - (meta.CreatedUtc > meta.ModifiedUtc ? meta.CreatedUtc : meta.ModifiedUtc);
        if (age > Window || ctx.IsSelf(file))
        {
            return null;
        }

        var name = Path.GetFileName(file.Replace('\\', '/'));
        var ext = Path.GetExtension(name);
        var reasons = new List<string>();
        Severity? severity = null;

        var doubleExt = HasDoubleExtension(name);
        if (doubleExt)
        {
            severity = Severity.High;
            reasons.Add($"'{name}'은 문서처럼 보이게 확장자를 두 번 붙인 실행 파일이에요.");
        }

        var prefix = ctx.Files.ReadPrefix(file, 4096);
        var isPe = prefix is not null && PeHeader.IsPortableExecutable(prefix, out _);
        if (!isPe && !doubleExt)
        {
            return null;
        }

        if (isPe && DocumentExtensions.Contains(ext))
        {
            severity = Severity.High;
            reasons.Add($"확장자는 {ext}인데 실제로는 Windows 실행 파일(PE)이에요. 위장 수법이에요.");
        }

        var kind = ctx.Classifier.Classify(file);
        SignatureInfo? sig = null;
        if (isPe)
        {
            if (signatureChecks >= MaxSignatureChecks)
            {
                ctx.Coverage.Skipped("새 실행 파일", $"서명 확인을 {MaxSignatureChecks}개까지만 했어요 (부하 제한).");
                if (severity is null)
                {
                    return null;
                }
            }
            else
            {
                signatureChecks++;
                ctx.Pacer.Step(5);
                sig = ctx.Signatures.Verify(file);
                if (sig.Status == SignatureStatus.Invalid)
                {
                    severity = Severity.High;
                    reasons.Add("디지털 서명이 손상됐어요. 파일이 변조됐을 수 있어요.");
                }
                else if (sig.Status is SignatureStatus.Unsigned or SignatureStatus.Untrusted && NormalPeExtensions.Contains(ext))
                {
                    var unsigned = kind == PathKind.Temp ? Severity.Low : Severity.Medium;
                    severity = severity is { } s ? SeverityExtensions.Max(s, unsigned) : unsigned;
                    reasons.Add($"최근 {Window.Days}일 안에 {PathClassifier.ToKorean(kind)}에 생긴 서명 없는 실행 파일이에요.");
                    if (depth == 0 && kind is PathKind.UserProfile or PathKind.ProgramData)
                    {
                        reasons.Add("AppData·ProgramData 바로 아래에 실행 파일이 있는 건 흔하지 않아요.");
                    }
                }
                else if (sig.Status is SignatureStatus.Unsigned or SignatureStatus.Untrusted && severity is null)
                {
                    severity = Severity.Medium;
                    reasons.Add($"확장자가 {(ext.Length > 0 ? ext : "없음")}인 서명 없는 실행 파일이에요.");
                }
            }
        }

        if ((meta.Attributes & FileAttributes.Hidden) != 0 && severity is { } current && current >= Severity.Medium)
        {
            severity = current.Bump();
            reasons.Add("숨김 속성이 붙어 있어요.");
        }

        if (severity is null)
        {
            return null;
        }

        var evidence = new List<KeyValuePair<string, string>>
        {
            new("경로 종류", PathClassifier.ToKorean(kind)),
            new("크기", meta.Length.ToString("N0", System.Globalization.CultureInfo.InvariantCulture) + " 바이트"),
            new("만든 시각", ExecutableAssessor.FormatTime(meta.CreatedUtc)),
            new("수정 시각", ExecutableAssessor.FormatTime(meta.ModifiedUtc)),
        };
        if (sig is not null)
        {
            evidence.Add(new("서명", sig.ToKorean()));
            if (sig.Signer is not null)
            {
                evidence.Add(new("서명자", sig.Signer));
            }
        }

        if (severity >= Severity.Medium && ctx.Files.Sha256(file, ExecutableAssessor.MaxHashBytes) is { } hash)
        {
            evidence.Add(new("SHA-256", hash));
        }

        return new Finding
        {
            RuleId = doubleExt || reasons.Any(r => r.Contains("위장", StringComparison.Ordinal)) ? "FILE-002" : "FILE-001",
            Category = CategoryName,
            Severity = severity.Value,
            Title = $"새 실행 파일: {name}",
            Location = file,
            Target = file,
            Reasons = reasons,
            Evidence = evidence,
            Advice = Advice.DroppedFile,
        };
    }

    public static bool HasDoubleExtension(string name)
    {
        var last = Path.GetExtension(name);
        if (!ExecutableExtensions.Contains(last))
        {
            return false;
        }

        var inner = Path.GetExtension(Path.GetFileNameWithoutExtension(name));
        return DocumentExtensions.Contains(inner);
    }
}
