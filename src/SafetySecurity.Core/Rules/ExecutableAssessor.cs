using System.Globalization;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Rules;

public sealed class ExecutableAssessment
{
    public required string Path { get; init; }

    public bool Exists { get; init; }

    /// <summary>
    /// 파일을 일부러 확인하지 않았어요 (네트워크 경로라서). 이때 <see cref="Exists"/>는 '없음'이 아니라 '모름'이에요.
    /// </summary>
    public bool NotChecked { get; init; }

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
    public const string NotCheckedReason = "검사기는 네트워크에 접속하지 않으려고 이 파일을 열어 보지 않았어요 (서명·크기·시각 확인 안 함).";

    /// <summary>Store·MSIX 앱 파일의 '서명' 증거. 파일 단위 서명은 없지만 패키지로 서명돼 있어요.</summary>
    public const string PackageSignatureText = "패키지 서명 (파일 단위 서명 없음, Windows가 설치 때 확인)";

    public static ExecutableAssessment Assess(ScanContext ctx, string rawPath, bool includeHash = true)
    {
        var path = ctx.Paths.Expand(rawPath.Trim().Trim('"'));
        var kind = ctx.Classifier.Classify(path);
        if (kind == PathKind.Network)
        {
            // 네트워크 경로는 정보를 읽기만 해도 다른 컴퓨터에 접속해요. 파일을 열지 않고 경로만 보고 판단해요.
            return AssessNetwork(ctx, path);
        }

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
            case SignatureStatus.Unsigned or SignatureStatus.Untrusted when kind == PathKind.PackagedApp:
                // Store·MSIX 앱은 패키지 단위로 서명되고, 설치 폴더는 Windows만 쓸 수 있어요. 파일 단위 서명이 없는 게 정상이에요.
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
        result.Evidence.Add(new("서명", kind == PathKind.PackagedApp && sig.Status is SignatureStatus.Unsigned or SignatureStatus.Untrusted
            ? PackageSignatureText
            : sig.ToKorean()));
        if (ctx.Classifier.PackageFolderName(path) is { } package)
        {
            result.Evidence.Add(new("앱 패키지", package));
        }

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

    /// <summary>
    /// 네트워크 경로를 파일을 열지 않고 평가해요.
    /// \\server\share 같은 원격 경로를 자동 실행하는 건 드물고 악성코드가 쓰는 수법이라 높음,
    /// 사용자가 연결한 네트워크 드라이브(Z: 등)는 NAS에 프로그램을 둔 경우도 있어서 보통으로 봐요.
    /// </summary>
    public static ExecutableAssessment AssessNetwork(ScanContext ctx, string path)
    {
        var remote = PathClassifier.IsRemotePath(path);
        var result = new ExecutableAssessment
        {
            Path = path,
            Exists = false,
            NotChecked = true,
            Kind = PathKind.Network,
            Severity = remote ? Model.Severity.High : Model.Severity.Medium,
        };
        result.Reasons.Add(remote
            ? "다른 컴퓨터(네트워크 경로)의 파일을 실행하도록 등록돼 있어요. 일반 프로그램은 거의 이렇게 하지 않고, 악성코드가 쓰는 수법이에요."
            : "네트워크 드라이브의 파일을 실행하도록 등록돼 있어요. 직접 NAS·공유 폴더에 둔 프로그램이 아니라면 확인하세요.");
        result.Reasons.Add(NotCheckedReason);
        result.Evidence.Add(new("경로 종류", PathClassifier.ToKorean(PathKind.Network)));
        if (ctx.Classifier.NetworkLocation(path) is { } host)
        {
            result.Evidence.Add(new("네트워크 위치", host));
        }

        result.Evidence.Add(new("파일 확인", "안 함 (네트워크에 접속하지 않으려고 열지 않았어요)"));
        return result;
    }

    public static string FormatTime(DateTimeOffset t) =>
        t.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
