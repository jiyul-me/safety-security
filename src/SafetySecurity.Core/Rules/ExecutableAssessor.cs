using System.Globalization;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Rules;

public sealed class ExecutableAssessment
{
    public required string Path { get; init; }

    public bool Exists { get; init; }

    public PathKind Kind { get; init; }

    public SignatureInfo? Signature { get; init; }

    /// <summary>파일 자체만 봤을 때의 위험도. 문제없으면 null.</summary>
    public Severity? Severity { get; init; }

    public List<string> Reasons { get; } = [];

    public List<KeyValuePair<string, string>> Evidence { get; } = [];

    public bool IsRecent { get; init; }
}

/// <summary>
/// 실행 파일/DLL 하나를 평가해요: 존재 여부, 위치 종류, 서명, 최근 생성 여부.
/// 여러 스캐너(COM, 자동 실행, 서비스, 작업)가 같은 기준을 쓰도록 한곳에 모았어요.
/// </summary>
public static class ExecutableAssessor
{
    public static readonly TimeSpan RecentWindow = TimeSpan.FromDays(7);
    public const long MaxHashBytes = 64L * 1024 * 1024;

    public static ExecutableAssessment Assess(ScanContext ctx, string rawPath, bool includeHash = true)
    {
        var path = ctx.Paths.Expand(rawPath.Trim().Trim('"'));
        var kind = ctx.Classifier.Classify(path);
        var meta = ctx.Files.GetMeta(path);
        if (meta is null)
        {
            var missing = new ExecutableAssessment { Path = path, Exists = false, Kind = kind, Severity = Model.Severity.Low };
            missing.Reasons.Add("등록된 파일이 없어요. 삭제되었거나 경로가 잘못됐을 수 있어요 (악성코드가 지운 흔적일 수도 있어요).");
            missing.Evidence.Add(new("경로 종류", PathClassifier.ToKorean(kind)));
            return missing;
        }

        ctx.Pacer.Step(5);
        var sig = ctx.Signatures.Verify(path);
        var recent = ctx.Now - meta.CreatedUtc <= RecentWindow || ctx.Now - meta.ModifiedUtc <= RecentWindow;
        Severity? sev = null;
        var reasons = new List<string>();

        switch (sig.Status)
        {
            case SignatureStatus.Invalid:
                sev = Model.Severity.High;
                reasons.Add("디지털 서명이 손상됐거나 폐기된 인증서예요. 파일이 변조됐을 수 있어요.");
                break;
            case SignatureStatus.Unsigned:
            case SignatureStatus.Untrusted:
                var what = sig.Status == SignatureStatus.Unsigned ? "디지털 서명이 없는" : "신뢰할 수 없는 서명의";
                switch (kind)
                {
                    case PathKind.Temp:
                    case PathKind.Public:
                    case PathKind.Network:
                        sev = Model.Severity.High;
                        reasons.Add($"{what} 파일이 {PathClassifier.ToKorean(kind)}에 있어요.");
                        break;
                    case PathKind.UserProfile:
                    case PathKind.ProgramData:
                        sev = Model.Severity.Medium;
                        reasons.Add($"{what} 파일이 {PathClassifier.ToKorean(kind)}에 있어요.");
                        break;
                    case PathKind.Windows:
                        sev = Model.Severity.Medium;
                        reasons.Add($"Windows 폴더에 {what} 파일이 있어요. Windows 파일은 보통 Microsoft 서명이 있어요.");
                        break;
                    default:
                        sev = Model.Severity.Low;
                        reasons.Add($"{what} 파일이에요.");
                        break;
                }

                break;
            case SignatureStatus.Error:
                if (PathClassifier.IsUserWritable(kind))
                {
                    sev = Model.Severity.Low;
                    reasons.Add("서명을 확인하지 못했어요 (파일이 잠겨 있거나 권한이 없어요).");
                }

                break;
        }

        if (sev is { } s && recent && s >= Model.Severity.Medium)
        {
            sev = s.Bump();
            reasons.Add("최근 7일 안에 만들어지거나 수정된 파일이에요.");
        }

        if ((meta.Attributes & FileAttributes.Hidden) != 0 && (meta.Attributes & FileAttributes.System) != 0 && PathClassifier.IsUserWritable(kind) && sev is not null)
        {
            sev = sev.Value.Bump();
            reasons.Add("숨김+시스템 속성이 붙어 있어요 (일반 프로그램은 거의 안 써요).");
        }

        var result = new ExecutableAssessment
        {
            Path = path,
            Exists = true,
            Kind = kind,
            Signature = sig,
            Severity = sev,
            IsRecent = recent,
        };
        result.Reasons.AddRange(reasons);
        result.Evidence.Add(new("경로 종류", PathClassifier.ToKorean(kind)));
        result.Evidence.Add(new("서명", sig.ToKorean()));
        if (!string.IsNullOrEmpty(sig.Signer))
        {
            result.Evidence.Add(new("서명자", sig.Signer));
        }

        result.Evidence.Add(new("크기", meta.Length.ToString("N0", CultureInfo.InvariantCulture) + " 바이트"));
        result.Evidence.Add(new("만든 시각", FormatTime(meta.CreatedUtc)));
        result.Evidence.Add(new("수정 시각", FormatTime(meta.ModifiedUtc)));
        if (includeHash && sev >= Model.Severity.Medium)
        {
            ctx.Pacer.Step(5);
            var hash = ctx.Files.Sha256(path, MaxHashBytes);
            if (hash is not null)
            {
                result.Evidence.Add(new("SHA-256", hash));
            }
        }

        return result;
    }

    public static string FormatTime(DateTimeOffset t) =>
        t.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
