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
        var redirected = OutputGoesToFileOrPipe();
        HasConsole = redirected || NativeMethods.AttachConsole(NativeMethods.ATTACH_PARENT_PROCESS);
        if (HasConsole)
        {
            try
            {
                // 파일·파이프로 보낼 때는 UTF-8로 써요 (스크립트·CI가 UTF-8로 읽어요). 이때는 붙은 콘솔이 없어서 콘솔 설정은 그대로예요.
                // 사용자의 cmd·PowerShell 창에 붙었을 때는 UTF-16(WriteConsoleW)으로 써요. 그러면 창의 코드 페이지를
                // 바꾸지 않아도(SetConsoleOutputCP를 부르지 않아요) 한글이 깨지지 않고, 끝난 뒤에도 그 창의 코드 페이지(예: 949)가 그대로예요.
                Console.OutputEncoding = redirected ? Encoding.UTF8 : Encoding.Unicode;
            }
            catch (IOException)
            {
                // 콘솔 인코딩을 못 바꾸면 기본 인코딩으로 출력해요 (한글이 깨질 수는 있지만 동작은 해요).
            }

            // 프롬프트 다음 줄부터 깔끔하게 시작하도록
            if (!redirected)
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

    /// <summary>
    /// 콘솔 없이(Win+R·바로가기) 실행했을 때 '예/아니요' 창으로 한 번 더 물어요. 콘솔이나 --quiet이면 묻지 않고 true예요
    /// (스크립트·설치 프로그램이 멈추지 않게).
    /// </summary>
    public bool Confirm(string text, string caption)
    {
        if (HasConsole || Quiet)
        {
            return true;
        }

        const uint YesNo = 0x4, IconQuestion = 0x20, SetForeground = 0x10000, TopMost = 0x40000;
        const int IdYes = 6;
        return NativeMethods.MessageBox(IntPtr.Zero, text, caption, YesNo | IconQuestion | SetForeground | TopMost) == IdYes;
    }

    /// <summary>
    /// 출력이 진짜 파일이나 파이프로 연결됐는지 (예: PowerShell 파이프, CI의 출력 파일).
    /// Console.IsOutputRedirected는 Win+R·시작 메뉴처럼 출력 핸들이 없을 때도 true라서
    /// 메시지 창과 알림이 안 떴어요 (v0.2.0-rc.2 시험에서 발견). 그래서 핸들 종류를 직접 봐요.
    /// </summary>
    private static bool OutputGoesToFileOrPipe()
    {
        var handle = NativeMethods.GetStdHandle(NativeMethods.STD_OUTPUT_HANDLE);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            return false;
        }

        var type = NativeMethods.GetFileType(handle);
        return type is NativeMethods.FILE_TYPE_DISK or NativeMethods.FILE_TYPE_PIPE;
    }
}
