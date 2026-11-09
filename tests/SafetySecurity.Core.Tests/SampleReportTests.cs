using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;

namespace SafetySecurity.Core.Tests;

/// <summary>
/// README에 쓰는 샘플 보고서. 평소에는 렌더링이 깨지지 않는지만 확인하고,
/// 환경 변수 SS_WRITE_SAMPLE=1이 있으면 docs/sample-report.html로 저장해요.
/// </summary>
public class SampleReportTests
{
    public static ReportDocument Sample() => new()
    {
        Version = "0.1.0",
        Computer = "MY-PC",
        StartedUtc = new DateTimeOffset(2026, 11, 6, 9, 12, 0, TimeSpan.Zero),
        FinishedUtc = new DateTimeOffset(2026, 11, 6, 9, 12, 4, TimeSpan.Zero),
        Scope = ScanScope.User,
        Reason = ScanReason.Logon,
        Completed = ["COM 하이재킹 (HKCU CLSID)", "자동 실행 (Run 키, 시작프로그램, Winlogon, IFEO)", "서비스·드라이버", "예약 작업", "브라우저 정책·바로가기·프록시", "Microsoft Defender 설정", "hosts 파일", "사용자 폴더의 새 실행 파일"],
        Coverage = ["Defender 로컬 제외 목록: " + Scanners.DefenderScanner.LocalExclusionsNote(adminScanInstalled: false)],
        Findings =
        [
            new ReportFinding
            {
                Id = "9f2c1a7be04d6153",
                RuleId = "COM-001",
                Category = "ComHijack",
                Severity = Severity.High,
                IsNew = true,
                Title = "HKCU가 기존 COM 클래스를 덮어써요 (InprocServer32, 64비트)",
                Location = @"HKCU\Software\Classes\CLSID\{9BA05972-F6A8-11CF-A442-00A0C90A8F39}\InprocServer32",
                Target = @"C:\Users\me\AppData\Roaming\Microsoft\Crypto\mscorsvc.dll",
                Reasons =
                [
                    "HKLM에 이미 있는 COM 클래스(ShellWindows)를 HKCU에서 덮어써서 다른 파일을 불러오게 해요. COM 하이재킹의 전형적인 형태예요.",
                    "디지털 서명이 없는 파일이 사용자 폴더 (사용자 쓰기 가능)에 있어요.",
                    "최근 7일 안에 만들어지거나 수정된 파일이에요.",
                ],
                Evidence =
                [
                    new EvidenceItem { Key = "CLSID", Value = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}" },
                    new EvidenceItem { Key = "HKLM 원래 값", Value = @"%SystemRoot%\System32\shdocvw.dll" },
                    new EvidenceItem { Key = "서명", Value = "서명 없음" },
                    new EvidenceItem { Key = "SHA-256", Value = "4b1f0c7e9a2d5c86e13f7a90b6d4e2c158a3f9d07e6b21c4a8f53d9e0b7c6a12" },
                ],
                Advice = "1) 대상 DLL의 서명자와 위치가 설치한 프로그램과 맞는지 확인하세요. 2) SHA-256 값을 VirusTotal 웹사이트에 직접 붙여 넣어 검색해 보세요.",
            },
            new ReportFinding
            {
                Id = "51d0e8c2a9f37b64",
                RuleId = "RUN-001",
                Category = "Autorun",
                Severity = Severity.High,
                IsNew = true,
                Title = "자동 실행 등록: WindowsUpdateHelper",
                Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper",
                Target = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                Reasons =
                [
                    "PowerShell이 인코딩된 명령(-EncodedCommand)을 실행해요. 내용을 숨기는 전형적인 수법이에요.",
                    "PowerShell 창을 숨겨서(-WindowStyle Hidden) 실행해요.",
                ],
                Evidence = [new EvidenceItem { Key = "명령줄", Value = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi…" }],
            },
            new ReportFinding
            {
                Id = "c47a19e05b2d8f31",
                RuleId = "FILE-001",
                Category = "DroppedFile",
                Severity = Severity.Medium,
                Title = "새 실행 파일: svchost.exe",
                Location = @"C:\Users\me\AppData\Roaming\x7f3\svchost.exe",
                Target = @"C:\Users\me\AppData\Roaming\x7f3\svchost.exe",
                Reasons = ["최근 14일 안에 사용자 폴더 (사용자 쓰기 가능)에 생긴 서명 없는 실행 파일이에요."],
            },
            new ReportFinding
            {
                Id = "0e6b93d4f1a2c758",
                RuleId = "SVC-001",
                Category = "Service",
                Severity = Severity.Low,
                Title = "의심스러운 서비스: VendorAgent",
                Location = @"HKLM\SYSTEM\CurrentControlSet\Services\VendorAgent",
                Target = @"C:\Program Files\Some Vendor\agent.exe",
                Reasons = [@"서비스 경로에 공백이 있는데 따옴표가 없어요 (C:\Program Files\Some Vendor\agent.exe). 권한 상승에 악용될 수 있는 설정이에요."],
            },
        ],
    };

    [Fact]
    public void SampleRendersAndCanBeWritten()
    {
        // 설치 프로그램으로 설치한 사람이 보는 보고서 (숨기기 안내가 Win+R 방법)
        var html = HtmlReport.Render(Sample(), runDialog: true);
        Assert.Contains("COM-001", html, StringComparison.Ordinal);
        Assert.Contains("<kbd>Win</kbd>", html, StringComparison.Ordinal);
        Assert.Contains("새 항목", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);

        if (Environment.GetEnvironmentVariable("SS_WRITE_SAMPLE") is { Length: > 0 })
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SafetySecurity.slnx")))
            {
                dir = dir.Parent;
            }

            Assert.NotNull(dir);
            File.WriteAllText(Path.Combine(dir!.FullName, "docs", "sample-report.html"), html);
        }
    }
}
