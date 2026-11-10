using System.Security;
using System.Xml;
using SafetySecurity.Core.Reporting;

namespace SafetySecurity.Core.Tests;

/// <summary>알림에 넣는 제목(남이 지은 글자)이 알림 XML을 깨뜨리거나 확장자를 숨기지 못하게 해요.</summary>
public class DisplayTextTests
{
    private static string Toast(string text) =>
        $"<toast><visual><binding template=\"ToastGeneric\"><text>{SecurityElement.Escape(text)}</text></binding></visual></toast>";

    private static void AssertLoadsAsXml(string text)
    {
        XmlConvert.VerifyXmlChars(text);
        var doc = new XmlDocument();
        doc.LoadXml(Toast(text));
        Assert.NotNull(doc.DocumentElement);
    }

    [Theory]
    [InlineData("Updater\u0001")]
    [InlineData("a\u001Fb")]
    [InlineData("x\uFFFFy\uFFFE")]
    [InlineData("lone \uD800 high")]
    [InlineData("lone \uDC00 low")]
    [InlineData("invoice\u202Efdp.exe")]
    [InlineData("<script>&\"'")]
    public void SanitizedTextAlwaysLoadsInToastXml(string hostile)
    {
        var clean = DisplayText.ForNotification(hostile, 180);
        AssertLoadsAsXml(clean);
    }

    [Fact]
    public void RawControlCharacterBreaksToastXmlWithoutSanitizing()
    {
        // 고치기 전의 문제: 이스케이프만 하면 제어 문자가 그대로 남아서 알림 XML을 읽지 못해요.
        Assert.ThrowsAny<XmlException>(() => new XmlDocument().LoadXml(Toast("Updater\u0001")));
    }

    [Fact]
    public void ControlAndBidiCharactersAreShownVisibly()
    {
        Assert.Equal(@"Updater\x01", DisplayText.ForNotification("Updater\u0001", 180));
        Assert.Equal("a b c", DisplayText.ForNotification("a\tb\nc", 180));
        Assert.Equal("invoice[U+202E]fdp.exe", DisplayText.ForNotification("invoice\u202Efdp.exe", 180));
        Assert.Equal("x\uFFFDy", DisplayText.ForNotification("x\uD800y", 180));
    }

    [Fact]
    public void NormalTextIsUnchanged()
    {
        const string title = "자동 실행 등록: OneDrive (C:\\Users\\지율\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe) 🎮";
        Assert.Equal(title, DisplayText.ForNotification(title, 500));
        Assert.Equal(string.Empty, DisplayText.ForNotification(null, 10));
    }

    [Fact]
    public void TruncationNeverSplitsASurrogatePair()
    {
        var text = new string('a', 179) + "😀" + "tail";
        var cut = DisplayText.ForNotification(text, 180);
        Assert.Equal(new string('a', 179) + "…", cut);
        AssertLoadsAsXml(cut);

        var fits = DisplayText.ForNotification(new string('a', 178) + "😀" + "tail", 180);
        Assert.Equal(new string('a', 178) + "😀…", fits);
        AssertLoadsAsXml(fits);
    }

    [Fact]
    public void ShortTextIsNotTruncated()
    {
        Assert.Equal("abc", DisplayText.ForNotification("abc", 3));
        Assert.Equal("ab…", DisplayText.ForNotification("abcd", 2));
    }
}
