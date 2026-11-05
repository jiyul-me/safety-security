using System.Buffers.Binary;

namespace SafetySecurity.Core.Parsing;

public static class PeHeader
{
    /// <summary>앞부분 바이트로 Windows 실행 파일(PE)인지 봐요. DLL이면 isDll=true.</summary>
    public static bool IsPortableExecutable(ReadOnlySpan<byte> prefix, out bool isDll)
    {
        isDll = false;
        if (prefix.Length < 0x40 || prefix[0] != (byte)'M' || prefix[1] != (byte)'Z')
        {
            return false;
        }

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(prefix[0x3C..]);
        if (peOffset < 0x40 || peOffset > prefix.Length - 24)
        {
            return false;
        }

        if (prefix[peOffset] != (byte)'P' || prefix[peOffset + 1] != (byte)'E' || prefix[peOffset + 2] != 0 || prefix[peOffset + 3] != 0)
        {
            return false;
        }

        var characteristics = BinaryPrimitives.ReadUInt16LittleEndian(prefix[(peOffset + 4 + 18)..]);
        isDll = (characteristics & 0x2000) != 0;
        return true;
    }
}
