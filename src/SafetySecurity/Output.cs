using System.Text;
using SafetySecurity.Native;

namespace SafetySecurity;

/// <summary>
/// WinExe라서 콘솔이 없어요. 터미널에서 실행하면 그 콘솔에 붙어서 출력하고,
/// 더블클릭처럼 콘솔이 없으면 모아 뒀다가 메시지 창으로 보여줘요.
/// </summary>
internal sealed class Output
{
    private readonly StringBuilder _buffer = new();

    public Output()
    {
        HasConsole = IsRedirected() || NativeMethods.AttachConsole(NativeMethods.ATTACH_PARENT_PROCESS);
        if (HasConsole)
        {
            try
            {
                Console.OutputEncoding = Encoding.UTF8;
            }
            catch (IOException)
            {
            }

            // 프롬프트 다음 줄부터 깔끔하게 시작하도록
            if (!IsRedirected())
            {
                Console.WriteLine();
            }
        }
    }

    public bool HasConsole { get; }

    public bool Quiet { get; set; }

    public void Line(string text)
    {
        if (Quiet)
        {
            return;
        }

        _buffer.AppendLine(text);
        if (HasConsole)
        {
            Console.WriteLine(text);
        }
    }

    /// <summary>콘솔이 없을 때만 메시지 창을 띄워요.</summary>
    public void ShowIfNoConsole(string caption)
    {
        if (!HasConsole && !Quiet && _buffer.Length > 0)
        {
            var text = _buffer.ToString();
            NativeMethods.MessageBox(IntPtr.Zero, text.Length > 3000 ? text[..3000] + "…" : text, caption, 0x40);
        }
    }

    private static bool IsRedirected()
    {
        try
        {
            return Console.IsOutputRedirected;
        }
        catch (IOException)
        {
            return false;
        }
    }
}
