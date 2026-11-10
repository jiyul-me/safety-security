using System.Globalization;
using System.Text;
using System.Xml;

namespace SafetySecurity.Core.Reporting;

/// <summary>
/// 항목 제목처럼 악성코드가 정할 수 있는 문자열을 화면(알림)에 안전하게 보여주는 도구.
/// 제목에는 레지스트리 값 이름 같은 남이 지은 글자가 그대로 들어가요. 제어 문자나 XML에 넣을 수 없는 글자가 있으면
/// 알림 XML이 깨져서 알림이 아예 안 뜨고, 방향 바꾸기 문자는 확장자를 숨길 수 있어요.
/// </summary>
public static class DisplayText
{
    /// <summary>오른쪽→왼쪽 문자로 확장자를 숨기는 수법(예: "invoice‮fdp.exe")에 쓰는 방향 바꾸기 문자인지.</summary>
    public static bool IsBidiControl(char c) =>
        c is '‪' or '‫' or '‬' or '‭' or '‮' or '⁦' or '⁧' or '⁨' or '⁩';

    /// <summary>
    /// 알림 한 줄에 넣을 글자로 바꿔요. XML 이스케이프(&lt; &amp; 등)는 하지 않으니, 알림 XML에 넣을 때 따로 이스케이프하세요.
    /// - 탭·줄바꿈은 빈칸, 다른 제어 문자는 \xNN으로 보여줘요.
    /// - 방향 바꾸기 문자는 [U+202E]처럼 보여줘요.
    /// - 짝이 없는 서로게이트, U+FFFE·U+FFFF처럼 XML에 넣을 수 없는 글자는 U+FFFD(�)로 바꿔요.
    /// - <paramref name="maxLength"/>를 넘으면 글자(이모지 등) 중간이 아닌 곳에서 자르고 "…"를 붙여요.
    /// </summary>
    public static string ForNotification(string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                sb.Append(c).Append(text[i + 1]);
                i++;
            }
            else if (char.IsSurrogate(c))
            {
                sb.Append('�');
            }
            else if (c is '\t' or '\n' or '\r')
            {
                sb.Append(' ');
            }
            else if (char.IsControl(c))
            {
                sb.Append("\\x").Append(((int)c).ToString("X2", CultureInfo.InvariantCulture));
            }
            else if (IsBidiControl(c))
            {
                sb.Append("[U+").Append(((int)c).ToString("X4", CultureInfo.InvariantCulture)).Append(']');
            }
            else if (!XmlConvert.IsXmlChar(c))
            {
                sb.Append('�');
            }
            else
            {
                sb.Append(c);
            }
        }

        var clean = sb.ToString();
        if (clean.Length <= maxLength)
        {
            return clean;
        }

        // 글자 단위(StringInfo)로 잘라서 이모지·결합 문자를 반으로 쪼개지 않아요.
        var cut = 0;
        var e = StringInfo.GetTextElementEnumerator(clean);
        while (e.MoveNext())
        {
            var next = e.ElementIndex + ((string)e.Current).Length;
            if (next > maxLength)
            {
                break;
            }

            cut = next;
        }

        return clean[..cut] + "…";
    }
}
