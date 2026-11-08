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
                // 콘솔 인코딩을 못 바꾸면 기본 인코딩으로 출력해요 (한글이 깨질 수는 있지만 동작은 해요).
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
            // Win+R처럼 몇 초 걸린 뒤 창을 띄우면 Windows가 다른 창 뒤에 숨길 수 있어서 맨 앞에 띄워요.
            const uint IconInformation = 0x40, SetForeground = 0x10000, TopMost = 0x40000;
            NativeMethods.MessageBox(IntPtr.Zero, text.Length > 3000 ? text[..3000] + "…" : text, caption, IconInformation | SetForeground | TopMost);
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
