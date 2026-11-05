using System.Text.Encodings.Web;
using System.Text.Json;

namespace SafetySecurity.Core.Reporting;

/// <summary>JSON 직렬화 (NativeAOT용 소스 생성, 한글을 \uXXXX로 바꾸지 않음).</summary>
public static class SafetyJson
{
    public static readonly SafetyJsonContext Context = new(new JsonSerializerOptions(SafetyJsonContext.Default.Options)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        PropertyNameCaseInsensitive = true,
    });
}
