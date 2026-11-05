namespace SafetySecurity.Core.Abstractions;

/// <summary>예약 작업 목록 XML (schtasks /query /xml ONE 출력).</summary>
public interface ITaskSource
{
    /// <summary>XML 문자열. 실패하면 null과 오류 메시지.</summary>
    string? GetTasksXml(out string? error);
}

/// <summary>WMI 영구 이벤트 구독 consumer 목록 (JSON).</summary>
public interface IWmiSource
{
    string? GetConsumersJson(out string? error);
}
