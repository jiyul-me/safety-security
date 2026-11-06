namespace SafetySecurity.Core.Model;

/// <summary>발견 항목의 위험도. 숫자가 클수록 위험해요.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

public static class SeverityExtensions
{
    public static string ToKorean(this Severity s) => s switch
    {
        Severity.High => "높음",
        Severity.Medium => "보통",
        Severity.Low => "낮음",
        _ => "참고",
    };

    public static Severity Bump(this Severity s) => s >= Severity.High ? Severity.High : s + 1;

    public static Severity Lower(this Severity s) => s <= Severity.Info ? Severity.Info : s - 1;

    public static Severity Max(Severity a, Severity b) => a >= b ? a : b;

    public static bool TryParse(string? text, out Severity severity)
    {
        severity = Severity.Medium;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        return Enum.TryParse(text.Trim(), ignoreCase: true, out severity);
    }
}
