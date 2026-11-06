using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Engine;

public interface IScanner
{
    /// <summary>분류 이름 (Finding.Category와 같아요).</summary>
    string Category { get; }

    /// <summary>보고서에 보여줄 한국어 이름.</summary>
    string DisplayName { get; }

    /// <summary>이 범위/모드에서 실행할지.</summary>
    bool RunsIn(ScanScope scope, bool quick);

    IEnumerable<Finding> Scan(ScanContext ctx);
}
