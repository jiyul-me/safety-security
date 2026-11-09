using System.Globalization;
using System.Text;
using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Reporting;

/// <summary>
/// 혼자 열리는 HTML 보고서. 외부 파일·스크립트를 쓰지 않고, CSP로 스크립트 실행을 막아요.
/// 레지스트리 값처럼 악성코드가 만든 문자열이 들어가니 모든 값을 HTML 인코딩해요.
/// </summary>
public static class HtmlReport
{
    /// <param name="doc">보고서 내용.</param>
    /// <param name="exeName">숨기기 명령에 쓸 실행 파일 이름 (명령줄 안내일 때).</param>
    /// <param name="runDialog">설치 프로그램이 Win+R 실행 이름(App Paths)을 등록했으면 true. 숨기기 안내를 Win+R 방법으로 보여줘요.</param>
    public static string Render(ReportDocument doc, string exeName = "SafetySecurity.exe", bool runDialog = false)
    {
        var sb = new StringBuilder(64 * 1024);
        var high = doc.Findings.Count(f => f.Severity == Severity.High);
        var medium = doc.Findings.Count(f => f.Severity == Severity.Medium);
        var low = doc.Findings.Count(f => f.Severity <= Severity.Low);
        var newCount = doc.Findings.Count(f => f.IsNew);
        var anyChanged = doc.Findings.Any(f => f.IsNew && f.ChangeNote is not null);

        sb.Append("<!doctype html>\n<html lang=\"ko\">\n<head>\n<meta charset=\"utf-8\">\n");
        sb.Append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">\n");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        sb.Append("<title>SafetySecurity 검사 보고서</title>\n<style>").Append(Css).Append("</style>\n</head>\n<body>\n<main>\n");

        sb.Append("<header><h1>SafetySecurity 검사 보고서</h1>");
        sb.Append("<p class=\"meta\">")
            .Append(E(Local(doc.StartedUtc))).Append(" · ")
            .Append(E(ReasonKorean(doc.Reason))).Append(doc.Quick ? " (빠른 검사)" : string.Empty).Append(" · ")
            .Append(doc.Scope == ScanScope.Admin ? "관리자 검사" : "사용자 검사").Append(" · ")
            .Append(E(Duration(doc.FinishedUtc - doc.StartedUtc)));
        if (doc.Computer is not null)
        {
            sb.Append(" · ").Append(E(doc.Computer));
        }

        sb.Append(" · v").Append(E(doc.Version)).Append("</p></header>\n");

        sb.Append("<section class=\"summary\">");
        Tile(sb, "높음", high, "high");
        Tile(sb, "보통", medium, "medium");
        Tile(sb, "낮음·참고", low, "low");
        Tile(sb, anyChanged ? "새·달라진 항목" : "새 항목", newCount, "new");
        sb.Append("</section>\n");

        sb.Append("<p class=\"note\">이 프로그램은 <strong>읽기 전용</strong>이에요. 아무것도 지우거나 고치지 않았고 인터넷도 쓰지 않았어요. ")
            .Append("아래 항목이 모두 악성이라는 뜻은 아니에요. 직접 설치한 프로그램인지 확인하고, 각 항목의 '확인하는 법'을 따라 판단하세요.</p>\n");

        if (doc.Aborted)
        {
            sb.Append("<p class=\"warn\">검사가 중간에 멈췄어요: ").Append(E(doc.AbortReason ?? "알 수 없음")).Append(". 나중에 다시 검사해요.</p>\n");
        }

        if (doc.FirstRun)
        {
            sb.Append("<p class=\"info\">첫 검사예요. 지금 있는 항목을 기준(베이스라인)으로 저장했어요. 알림은 '높음'만 띄웠고, 다음 검사부터는 새로 생긴 항목을 알려요.</p>\n");
        }

        if (doc.Findings.Count == 0)
        {
            sb.Append("<section class=\"empty\"><h2>의심 항목이 없어요</h2><p>검사한 범위 안에서는 이상한 점을 찾지 못했어요.</p></section>\n");
        }

        foreach (var f in doc.Findings)
        {
            var sev = f.Severity switch
            {
                Severity.High => "high",
                Severity.Medium => "medium",
                _ => "low",
            };
            sb.Append("<article class=\"finding ").Append(sev).Append("\">\n<div class=\"head\">");
            sb.Append("<span class=\"badge ").Append(sev).Append("\">").Append(E(f.Severity.ToKorean())).Append("</span>");
            if (f.IsNew)
            {
                sb.Append("<span class=\"badge new\">").Append(f.ChangeNote is null ? "새 항목" : "달라진 항목").Append("</span>");
            }

            if (f.IgnoreNote is not null)
            {
                sb.Append("<span class=\"badge new\">숨김 풀림</span>");
            }

            sb.Append("<span class=\"cat\">").Append(E(CategoryKorean(f.Category))).Append(" · ").Append(E(f.RuleId)).Append("</span></div>\n");
            sb.Append("<h3>").Append(E(f.Title)).Append("</h3>\n");
            if (f.ChangeNote is not null)
            {
                sb.Append("<p class=\"change\">지난 검사와 달라졌어요: ").Append(E(f.ChangeNote)).Append("</p>\n");
            }

            if (f.IgnoreNote is not null)
            {
                sb.Append("<p class=\"change\">").Append(E(f.IgnoreNote)).Append("</p>\n");
            }

            sb.Append("<dl>");
            Row(sb, "위치", f.Location, code: true);
            if (f.Target is not null)
            {
                Row(sb, "대상", f.Target, code: true);
            }

            sb.Append("</dl>\n");
            if (f.Reasons.Count > 0)
            {
                sb.Append("<h4>왜 의심스러운가요?</h4><ul>");
                foreach (var r in f.Reasons)
                {
                    sb.Append("<li>").Append(E(r)).Append("</li>");
                }

                sb.Append("</ul>\n");
            }

            if (f.Evidence.Count > 0)
            {
                sb.Append("<details><summary>증거 자세히 보기</summary><dl>");
                foreach (var e in f.Evidence)
                {
                    Row(sb, e.Key, e.Value, code: e.Key.Contains("SHA", StringComparison.Ordinal) || e.Key.Contains("명령", StringComparison.Ordinal) || e.Key.Contains("값", StringComparison.Ordinal));
                }

                sb.Append("</dl></details>\n");
            }

            if (f.Advice is not null)
            {
                sb.Append("<h4>확인하는 법</h4><p class=\"advice\">").Append(E(f.Advice)).Append("</p>\n");
            }

            IgnoreHint(sb, f.Id, doc.Scope, exeName, runDialog);
            sb.Append("</article>\n");
        }

        sb.Append("<section class=\"footer\"><h2>검사 범위</h2><ul>");
        foreach (var c in doc.Completed)
        {
            sb.Append("<li>").Append(E(c)).Append("</li>");
        }

        sb.Append("</ul>");
        if (doc.Coverage.Count > 0)
        {
            sb.Append("<h2>확인하지 못한 것</h2><ul>");
            foreach (var c in doc.Coverage)
            {
                sb.Append("<li>").Append(E(c)).Append("</li>");
            }

            sb.Append("</ul>");
        }

        if (doc.Ignored.Count > 0)
        {
            sb.Append("<h2>숨긴 항목</h2><p>직접 숨긴(ignore) 항목 ").Append(doc.Ignored.Count.ToString(CultureInfo.InvariantCulture))
                .Append("개는 위 목록에서 뺐어요. 숨긴 뒤로 더 위험해지거나 같은 위치의 파일이 바뀌면 다시 보여줘요.</p><ul class=\"hidden\">");
            foreach (var i in doc.Ignored)
            {
                sb.Append("<li><code>").Append(E(i.Id)).Append("</code> [").Append(E(i.Severity.ToKorean())).Append("] ").Append(E(i.Title))
                    .Append("<br>다시 보이게 하려면: ").Append(UndoHint(i.Id, doc.Scope, exeName, runDialog)).Append("</li>");
            }

            sb.Append("</ul>");
        }
        else if (doc.IgnoredCount > 0)
        {
            sb.Append("<p>사용자가 무시하도록 설정한 항목 ").Append(doc.IgnoredCount.ToString(CultureInfo.InvariantCulture)).Append("개는 숨겼어요.</p>");
        }

        sb.Append("</section>\n</main>\n</body>\n</html>\n");
        return sb.ToString();
    }

    /// <summary>
    /// 숨기기(ignore) 안내. 관리자 검사 항목은 관리자 기록에 숨겨야 해서 <c>--scope admin</c>을 붙여요.
    /// 설치 프로그램으로 설치했으면 PowerShell 없이 Win+R로 바로 실행할 수 있어요.
    /// </summary>
    private static void IgnoreHint(StringBuilder sb, string id, ScanScope scope, string exeName, bool runDialog)
    {
        var args = " ignore " + id + (scope == ScanScope.Admin ? " --scope admin" : string.Empty);
        sb.Append("<p class=\"ignore\">");
        if (runDialog)
        {
            sb.Append("직접 확인해서 괜찮은 항목이면 다음 검사부터 숨길 수 있어요: <kbd>Win</kbd>+<kbd>R</kbd>을 누르고 <code>")
                .Append(E("safetysecurity" + args)).Append("</code>를 입력하세요.");
        }
        else
        {
            sb.Append("직접 확인해서 괜찮은 항목이면: <code>").Append(E(exeName + args)).Append("</code>");
        }

        sb.Append("</p>\n");
    }

    /// <summary>숨김을 되돌리는(unignore) 명령 안내.</summary>
    private static string UndoHint(string id, ScanScope scope, string exeName, bool runDialog)
    {
        var args = " unignore " + id + (scope == ScanScope.Admin ? " --scope admin" : string.Empty);
        return runDialog
            ? "<kbd>Win</kbd>+<kbd>R</kbd> → <code>" + E("safetysecurity" + args) + "</code>"
            : "<code>" + E(exeName + args) + "</code>";
    }

    private static void Tile(StringBuilder sb, string label, int count, string cls) =>
        sb.Append("<div class=\"tile ").Append(cls).Append("\"><span class=\"n\">").Append(count.ToString(CultureInfo.InvariantCulture)).Append("</span><span class=\"l\">").Append(E(label)).Append("</span></div>");

    private static void Row(StringBuilder sb, string key, string value, bool code)
    {
        sb.Append("<dt>").Append(E(key)).Append("</dt><dd>");
        if (code)
        {
            sb.Append("<code>").Append(E(value)).Append("</code>");
        }
        else
        {
            sb.Append(E(value));
        }

        sb.Append("</dd>");
    }

    /// <summary>HTML 인코딩. 제어 문자는 보이는 형태(␀ 등 대신 \xNN)로 바꿔요.</summary>
    public static string E(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(text.Length + 16);
        foreach (var c in text)
        {
            switch (c)
            {
                case '&': sb.Append("&amp;"); break;
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '"': sb.Append("&quot;"); break;
                case '\'': sb.Append("&#39;"); break;
                case '`': sb.Append("&#96;"); break;
                default:
                    if (char.IsControl(c) && c != '\n' && c != '\t')
                    {
                        sb.Append("\\x").Append(((int)c).ToString("X2", CultureInfo.InvariantCulture));
                    }
                    else if (DisplayText.IsBidiControl(c))
                    {
                        // 오른쪽→왼쪽 문자로 확장자를 숨기는 수법 (예: "invoice‮fdp.exe") 표시
                        sb.Append("[U+").Append(((int)c).ToString("X4", CultureInfo.InvariantCulture)).Append(']');
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    break;
            }
        }

        return sb.ToString();
    }

    public static string CategoryKorean(string category) => category switch
    {
        "ComHijack" => "COM 하이재킹",
        "Autorun" => "자동 실행",
        "Service" => "서비스",
        "ScheduledTask" => "예약 작업",
        "HiddenTask" => "숨겨진 작업",
        "Browser" => "브라우저",
        "Defender" => "Defender",
        "Hosts" => "hosts 파일",
        "Wmi" => "WMI",
        "DroppedFile" => "새 실행 파일",
        "Discord" => "디스코드",
        _ => category,
    };

    public static string ReasonKorean(ScanReason reason) => reason switch
    {
        ScanReason.Logon => "로그온 검사",
        ScanReason.Daily => "매일 검사",
        ScanReason.Service => "서비스 설치 감지",
        ScanReason.Retry => "미뤄둔 검사",
        _ => "직접 실행",
    };

    private static string Local(DateTimeOffset t) => t.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    private static string Duration(TimeSpan d) => d.TotalSeconds < 60
        ? d.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture) + "초"
        : ((int)d.TotalMinutes).ToString(CultureInfo.InvariantCulture) + "분 " + d.Seconds.ToString(CultureInfo.InvariantCulture) + "초";

    private const string Css = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2128;--muted:#5d6675;--line:#e2e5ea;--high:#c62828;--high-bg:#fdecea;--med:#b26a00;--med-bg:#fff4e0;--low:#46607a;--low-bg:#eaf0f6;--new:#5b3cc4;--new-bg:#efeafd;--code:#f0f2f5}
@media (prefers-color-scheme: dark){:root{--bg:#14161a;--card:#1d2026;--text:#e6e8ec;--muted:#9aa3b2;--line:#2c313a;--high:#ff6b6b;--high-bg:#3a1f22;--med:#ffb84d;--med-bg:#3a2e1a;--low:#9db8d6;--low-bg:#1f2a36;--new:#b9a4ff;--new-bg:#2a2340;--code:#262a31}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 "Malgun Gothic","Apple SD Gothic Neo",system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px}h3{font-size:17px;margin:6px 0 8px;word-break:break-all}h4{font-size:14px;margin:14px 0 4px;color:var(--muted)}
.meta{color:var(--muted);margin:0 0 16px}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;display:flex;flex-direction:column}.tile .n{font-size:26px;font-weight:700}.tile .l{color:var(--muted);font-size:13px}
.tile.high .n{color:var(--high)}.tile.medium .n{color:var(--med)}.tile.low .n{color:var(--low)}.tile.new .n{color:var(--new)}
.note,.info,.warn{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.warn{border-color:var(--med)}.info{border-color:var(--new)}
.finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--low);border-radius:10px;padding:14px 16px;margin:14px 0}
.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--med)}
.head{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.badge{font-size:12px;font-weight:700;padding:2px 8px;border-radius:999px}
.badge.high{background:var(--high-bg);color:var(--high)}.badge.medium{background:var(--med-bg);color:var(--med)}.badge.low{background:var(--low-bg);color:var(--low)}.badge.new{background:var(--new-bg);color:var(--new)}
.cat{color:var(--muted);font-size:13px}dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:6px 0}dt{color:var(--muted)}dd{margin:0;min-width:0;word-break:break-all}
code{background:var(--code);border-radius:4px;padding:1px 5px;font:13px/1.5 Consolas,"D2Coding",monospace;word-break:break-all}
ul{margin:4px 0;padding-left:20px}details{margin-top:10px}summary{cursor:pointer;color:var(--muted)}.advice{margin:4px 0}.ignore{color:var(--muted);font-size:13px}
.change{color:var(--new);margin:4px 0 8px}.hidden li{margin:6px 0;word-break:break-all}
kbd{border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;padding:0 5px;font:12px/1.5 Consolas,"D2Coding",monospace;background:var(--card)}
.empty{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}.footer{margin-top:28px;color:var(--muted)}
@media (max-width:600px){.summary{grid-template-columns:repeat(2,1fr)}dl{grid-template-columns:1fr}}
""";
}
