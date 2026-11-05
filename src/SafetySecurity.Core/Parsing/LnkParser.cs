using System.Buffers.Binary;
using System.Text;

namespace SafetySecurity.Core.Parsing;

public sealed record ShortcutInfo(string? TargetPath, string? Arguments, string? WorkingDirectory, string? RelativePath);

/// <summary>
/// .lnk 바로가기 파일 파서 ([MS-SHLLINK]). Shell COM 객체를 쓰지 않고 바이트를 직접 읽어요.
/// 대상 경로와 인자만 뽑고, 형식이 이상하면 null을 돌려줘요.
/// </summary>
public static class LnkParser
{
    private const int HeaderSize = 0x4C;
    private const uint HasLinkTargetIdList = 0x1;
    private const uint HasLinkInfo = 0x2;
    private const uint HasName = 0x4;
    private const uint HasRelativePath = 0x8;
    private const uint HasWorkingDir = 0x10;
    private const uint HasArguments = 0x20;
    private const uint HasIconLocation = 0x40;
    private const uint IsUnicode = 0x80;
    private const uint EnvironmentBlockSignature = 0xA0000001;

    private static readonly byte[] LinkClsid =
    [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];

    public static ShortcutInfo? Parse(ReadOnlySpan<byte> data)
    {
        try
        {
            return ParseCore(data);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
        catch (IndexOutOfRangeException)
        {
            return null;
        }
    }

    private static ShortcutInfo? ParseCore(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize || BinaryPrimitives.ReadUInt32LittleEndian(data) != HeaderSize
            || !data.Slice(4, 16).SequenceEqual(LinkClsid))
        {
            return null;
        }

        var flags = BinaryPrimitives.ReadUInt32LittleEndian(data[0x14..]);
        var unicode = (flags & IsUnicode) != 0;
        var pos = HeaderSize;

        if ((flags & HasLinkTargetIdList) != 0)
        {
            var idListSize = BinaryPrimitives.ReadUInt16LittleEndian(data[pos..]);
            pos += 2 + idListSize;
        }

        string? target = null;
        if ((flags & HasLinkInfo) != 0)
        {
            var info = data[pos..];
            var infoSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(info);
            var infoHeaderSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[4..]);
            var infoFlags = BinaryPrimitives.ReadUInt32LittleEndian(info[8..]);
            var localBaseOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[16..]);
            var suffixOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[24..]);
            if ((infoFlags & 0x1) != 0)
            {
                string? basePath;
                string? suffix;
                if (infoHeaderSize >= 0x24)
                {
                    var localBaseUnicode = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[28..]);
                    var suffixUnicode = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[32..]);
                    basePath = localBaseUnicode > 0 ? ReadNullTerminatedUnicode(info[localBaseUnicode..infoSize]) : ReadNullTerminatedAnsi(info[localBaseOffset..infoSize]);
                    suffix = suffixUnicode > 0 ? ReadNullTerminatedUnicode(info[suffixUnicode..infoSize]) : ReadNullTerminatedAnsi(info[suffixOffset..infoSize]);
                }
                else
                {
                    basePath = ReadNullTerminatedAnsi(info[localBaseOffset..infoSize]);
                    suffix = suffixOffset > 0 ? ReadNullTerminatedAnsi(info[suffixOffset..infoSize]) : null;
                }

                target = CombineSuffix(basePath, suffix);
            }

            pos += infoSize;
        }

        string? relative = null;
        string? workingDir = null;
        string? arguments = null;
        if ((flags & HasName) != 0)
        {
            ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasRelativePath) != 0)
        {
            relative = ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasWorkingDir) != 0)
        {
            workingDir = ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasArguments) != 0)
        {
            arguments = ReadStringData(data, ref pos, unicode);
        }

        if ((flags & HasIconLocation) != 0)
        {
            ReadStringData(data, ref pos, unicode);
        }

        // ExtraData: 환경 변수 블록에 대상이 있으면 (예: %windir%\...) LinkInfo가 없을 때 써요.
        while (target is null && pos + 8 <= data.Length)
        {
            var blockSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(data[pos..]);
            if (blockSize < 4)
            {
                break;
            }

            var signature = BinaryPrimitives.ReadUInt32LittleEndian(data[(pos + 4)..]);
            if (signature == EnvironmentBlockSignature && blockSize >= 0x314)
            {
                var uni = ReadNullTerminatedUnicode(data.Slice(pos + 8 + 260, 520));
                target = string.IsNullOrEmpty(uni) ? ReadNullTerminatedAnsi(data.Slice(pos + 8, 260)) : uni;
            }

            pos += blockSize;
        }

        return new ShortcutInfo(NullIfEmpty(target), NullIfEmpty(arguments), NullIfEmpty(workingDir), NullIfEmpty(relative));
    }

    private static string ReadStringData(ReadOnlySpan<byte> data, ref int pos, bool unicode)
    {
        var count = BinaryPrimitives.ReadUInt16LittleEndian(data[pos..]);
        pos += 2;
        var byteLen = unicode ? count * 2 : count;
        var bytes = data.Slice(pos, byteLen);
        pos += byteLen;
        return unicode ? Encoding.Unicode.GetString(bytes) : Encoding.Latin1.GetString(bytes);
    }

    private static string? CombineSuffix(string? basePath, string? suffix)
    {
        if (string.IsNullOrEmpty(basePath))
        {
            return suffix;
        }

        if (string.IsNullOrEmpty(suffix))
        {
            return basePath;
        }

        return basePath.EndsWith('\\') ? basePath + suffix : basePath + "\\" + suffix;
    }

    private static string? NullIfEmpty(string? s) => string.IsNullOrEmpty(s) ? null : s;

    private static string ReadNullTerminatedAnsi(ReadOnlySpan<byte> span)
    {
        var end = span.IndexOf((byte)0);
        return Encoding.Latin1.GetString(end >= 0 ? span[..end] : span);
    }

    private static string ReadNullTerminatedUnicode(ReadOnlySpan<byte> span)
    {
        for (var i = 0; i + 1 < span.Length; i += 2)
        {
            if (span[i] == 0 && span[i + 1] == 0)
            {
                return Encoding.Unicode.GetString(span[..i]);
            }
        }

        return Encoding.Unicode.GetString(span[..(span.Length & ~1)]);
    }
}
