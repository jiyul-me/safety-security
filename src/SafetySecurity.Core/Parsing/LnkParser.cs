using System.Buffers.Binary;
using System.Text;

namespace SafetySecurity.Core.Parsing;

/// <summary>
/// .lnk 바로가기에서 읽은 내용. 대상 경로는 여러 곳에 따로 들어 있을 수 있어요:
/// 환경 변수 블록(<see cref="EnvironmentPath"/>), 셸 항목 목록(<see cref="IdListPath"/>), LinkInfo(<see cref="LinkInfoPath"/>), 상대 경로.
/// 악성 바로가기는 보이는 대상(LinkInfo)과 실제 실행 대상(환경 변수 블록·IDList)을 다르게 만들기도 해요.
/// </summary>
public sealed record ShortcutInfo(string? TargetPath, string? Arguments, string? WorkingDirectory, string? RelativePath)
{
    /// <summary>ExtraData의 환경 변수 블록 대상 (예: %windir%\system32\notepad.exe). 펼치지 않은 그대로예요.</summary>
    public string? EnvironmentPath { get; init; }

    /// <summary>HasExpString 플래그: Windows가 환경 변수 블록의 경로를 대상으로 써요.</summary>
    public bool PrefersEnvironmentPath { get; init; }

    /// <summary>LinkTargetIDList의 파일 시스템 항목으로 다시 만든 경로. 해석할 수 없는 항목이 있으면 null이에요 (추측하지 않아요).</summary>
    public string? IdListPath { get; init; }

    /// <summary>LinkInfo의 로컬 경로(LocalBasePath + CommonPathSuffix). 로컬 경로가 없으면 네트워크 경로(\\server\share\...).</summary>
    public string? LinkInfoPath { get; init; }

    /// <summary>MSI '광고' 바로가기 (Darwin 블록). 대상이 파일 경로가 아니라 설치 정보로 연결돼요 (Office 등).</summary>
    public bool IsAdvertised { get; init; }

    /// <summary>
    /// 대상 후보 (Windows가 쓰는 우선순위 순, 같은 문자열은 한 번만): HasExpString이면 환경 변수 블록, 그다음 IDList, LinkInfo.
    /// 환경 변수는 아직 펼치지 않았고, 상대 경로는 들어 있지 않아요 (바로가기 폴더 기준으로 스캐너가 붙여요).
    /// </summary>
    public IReadOnlyList<string> Candidates { get; init; } = [];
}

/// <summary>
/// .lnk 바로가기 파일 파서 ([MS-SHLLINK]). Shell COM 객체를 쓰지 않고 바이트를 직접 읽어요.
/// 대상 후보와 인자를 뽑고, 형식이 이상하면 null을 돌려줘요. 네트워크 경로도 문자열로만 읽고 열지 않아요.
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
    private const uint ForceNoLinkInfo = 0x100;
    private const uint HasExpString = 0x200;
    private const uint EnvironmentBlockSignature = 0xA0000001;
    private const uint DarwinBlockSignature = 0xA0000006;
    private const int EnvironmentBlockSize = 0x314;
    private const uint FileEntryExtensionSignature = 0xBEEF0004;

    /// <summary>셸의 '사용자 파일' 폴더(CLSID_UsersFiles). 이 루트 다음 항목은 %USERPROFILE% 아래 경로예요.</summary>
    private static readonly Guid UsersFilesFolder = new("59031A47-3F72-44A7-89C5-5595FE6B30EE");

    private static readonly byte[] LinkClsid =
    [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];

    /// <summary>바로가기를 읽을 때 앞에서부터 이만큼만 읽어요 (IDList 최대 64KB + 나머지).</summary>
    public const int MaxReadBytes = 256 * 1024;

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

        string? idListPath = null;
        if ((flags & HasLinkTargetIdList) != 0)
        {
            var idListSize = BinaryPrimitives.ReadUInt16LittleEndian(data[pos..]);
            idListPath = Safe(data.Slice(pos + 2, idListSize), ParseIdList);
            pos += 2 + idListSize;
        }

        string? linkInfoPath = null;
        if ((flags & HasLinkInfo) != 0)
        {
            var info = data[pos..];
            var infoSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(info);
            linkInfoPath = Safe(info[..infoSize], ParseLinkInfo);
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

        // ExtraData: 블록을 모두 읽어요. 환경 변수 블록이 실제 실행 대상일 수 있어서 LinkInfo가 있어도 확인해요.
        // 블록이 파일 끝을 넘으면(잘린 파일) 거기서 멈추고, 앞에서 읽은 내용은 그대로 써요.
        string? envPath = null;
        var advertised = false;
        while (pos + 8 <= data.Length)
        {
            var blockSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(data[pos..]);
            if (blockSize < 8 || blockSize > data.Length - pos)
            {
                break;
            }

            var signature = BinaryPrimitives.ReadUInt32LittleEndian(data[(pos + 4)..]);
            if (signature == EnvironmentBlockSignature && blockSize >= EnvironmentBlockSize)
            {
                var uni = ReadNullTerminatedUnicode(data.Slice(pos + 8 + 260, 520));
                envPath = string.IsNullOrEmpty(uni) ? ReadNullTerminatedAnsi(data.Slice(pos + 8, 260)) : uni;
            }
            else if (signature == DarwinBlockSignature)
            {
                advertised = true;
            }

            pos += blockSize;
        }

        envPath = NullIfEmpty(envPath?.Trim());
        idListPath = NullIfEmpty(idListPath);
        linkInfoPath = (flags & ForceNoLinkInfo) != 0 ? null : NullIfEmpty(linkInfoPath);
        var prefersEnv = (flags & HasExpString) != 0 && envPath is not null;

        // Windows가 쓰는 순서: HasExpString이면 환경 변수 블록, 그다음 IDList, LinkInfo.
        // 플래그 없이 블록만 있으면 다른 대상이 없을 때만 써요 (Windows는 이 블록을 보지 않지만, 예전 버전과 같은 동작이에요).
        var candidates = new List<string>();
        void Add(string? p)
        {
            if (p is not null && !candidates.Contains(p, StringComparer.OrdinalIgnoreCase))
            {
                candidates.Add(p);
            }
        }

        if (prefersEnv)
        {
            Add(envPath);
        }

        Add(idListPath);
        Add(linkInfoPath);
        if (candidates.Count == 0)
        {
            Add(envPath);
        }

        return new ShortcutInfo(candidates.Count > 0 ? candidates[0] : null, NullIfEmpty(arguments), NullIfEmpty(workingDir), NullIfEmpty(relative))
        {
            EnvironmentPath = envPath,
            PrefersEnvironmentPath = prefersEnv,
            IdListPath = idListPath,
            LinkInfoPath = linkInfoPath,
            IsAdvertised = advertised,
            Candidates = candidates,
        };
    }

    private delegate string? SpanParser(ReadOnlySpan<byte> data);

    /// <summary>한 부분(IDList, LinkInfo)을 못 읽어도 나머지 내용은 쓰려고, 그 부분만 null로 돌려줘요.</summary>
    private static string? Safe(ReadOnlySpan<byte> data, SpanParser parser)
    {
        try
        {
            return parser(data);
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

    /// <summary>LinkInfo: 로컬 경로(VolumeIDAndLocalBasePath)가 있으면 그것을, 없으면 네트워크 경로(CommonNetworkRelativeLink)를 돌려줘요.</summary>
    private static string? ParseLinkInfo(ReadOnlySpan<byte> info)
    {
        var infoHeaderSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[4..]);
        var infoFlags = BinaryPrimitives.ReadUInt32LittleEndian(info[8..]);
        var localBaseOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[16..]);
        var networkOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[20..]);
        var suffixOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[24..]);
        var localBaseUnicode = 0;
        var suffixUnicode = 0;
        if (infoHeaderSize >= 0x24)
        {
            localBaseUnicode = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[28..]);
            suffixUnicode = (int)BinaryPrimitives.ReadUInt32LittleEndian(info[32..]);
        }

        var suffix = suffixUnicode > 0 ? ReadNullTerminatedUnicode(info[suffixUnicode..])
            : suffixOffset > 0 ? ReadNullTerminatedAnsi(info[suffixOffset..]) : null;

        if ((infoFlags & 0x1) != 0)
        {
            var basePath = localBaseUnicode > 0 ? ReadNullTerminatedUnicode(info[localBaseUnicode..]) : ReadNullTerminatedAnsi(info[localBaseOffset..]);
            if (!string.IsNullOrEmpty(basePath))
            {
                return CombineSuffix(basePath, suffix);
            }
        }

        if ((infoFlags & 0x2) != 0 && networkOffset > 0)
        {
            // CommonNetworkRelativeLink: 크기, 플래그, NetNameOffset, DeviceNameOffset, 공급자 종류, [NetNameOffsetUnicode, DeviceNameOffsetUnicode]
            var net = info[networkOffset..];
            var netNameOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(net[8..]);
            var netName = netNameOffset > 0x14
                ? ReadNullTerminatedUnicode(net[(int)BinaryPrimitives.ReadUInt32LittleEndian(net[20..])..])
                : ReadNullTerminatedAnsi(net[netNameOffset..]);
            if (!string.IsNullOrEmpty(netName))
            {
                return CombineSuffix(netName, suffix);
            }
        }

        return null;
    }

    /// <summary>
    /// LinkTargetIDList의 셸 항목에서 파일 경로를 다시 만들어요 (드라이브·네트워크 공유 + 폴더·파일 이름).
    /// 제어판·앱·라이브러리처럼 파일 시스템이 아닌 항목이 있거나 이름을 확실히 읽지 못하면 null이에요.
    /// </summary>
    private static string? ParseIdList(ReadOnlySpan<byte> list)
    {
        string? path = null;
        var pos = 0;
        while (pos + 2 <= list.Length)
        {
            var size = BinaryPrimitives.ReadUInt16LittleEndian(list[pos..]);
            if (size == 0)
            {
                break;
            }

            if (size < 3 || size > list.Length - pos)
            {
                return null;
            }

            var item = list.Slice(pos, size);
            pos += size;
            var type = item[2];
            if (type == 0x1F)
            {
                // 루트 폴더 (내 PC, 네트워크 등). 실제 경로는 다음 항목부터 시작해요.
                if (path is not null)
                {
                    return null;
                }

                // 사용자 폴더(%USERPROFILE%)가 루트인 목록도 있어요. Windows는 사용자 폴더 안의 파일을 이렇게 저장하기도 해요.
                // 환경 변수 그대로 두면 바로가기 대상 후보를 만들 때 실제 경로로 바뀌어요 (ShortcutTargets.Candidates).
                if (item.Length >= 20 && new Guid(item.Slice(4, 16)) == UsersFilesFolder)
                {
                    path = "%USERPROFILE%";
                }

                continue;
            }

            if ((type & 0x70) == 0x20)
            {
                // 볼륨 항목: "C:\"
                if (path is not null || (type & 0x01) == 0 || item.Length < 5)
                {
                    return null;
                }

                var drive = ReadNullTerminatedAnsi(item[3..]);
                if (drive.Length < 2 || !char.IsAsciiLetter(drive[0]) || drive[1] != ':' || drive.Length > 3 || (drive.Length == 3 && drive[2] != '\\'))
                {
                    return null;
                }

                path = drive[..2] + "\\";
                continue;
            }

            if ((type & 0x70) == 0x40)
            {
                // 네트워크 위치 항목: \\server 또는 \\server\share (문자열로만 읽어요).
                if (item.Length < 6)
                {
                    return null;
                }

                var location = ReadNullTerminatedAnsi(item[5..]);
                if (!location.StartsWith(@"\\", StringComparison.Ordinal) || location.Length < 3 || HasInvalidPathChars(location[2..], allowSeparators: true))
                {
                    return null;
                }

                if (path is not null && !path.StartsWith(@"\\", StringComparison.Ordinal))
                {
                    return null;
                }

                path = location.TrimEnd('\\');
                continue;
            }

            if (type == 0x74)
            {
                // 위임 항목('CFSF'): 사용자 폴더 바로 아래 폴더(예: AppData)를 Windows가 이렇게 감싸서 저장해요.
                // 안에 보통 파일·폴더 항목이 들어 있고, 긴 이름은 뒤의 0xBEEF0004 블록에 있어요.
                if (path is null)
                {
                    return null;
                }

                var name = DelegateEntryName(item);
                if (name is null)
                {
                    return null;
                }

                path = path.EndsWith('\\') ? path + name : path + "\\" + name;
                continue;
            }

            if ((type & 0x70) == 0x30)
            {
                // 파일·폴더 항목
                if (path is null)
                {
                    return null;
                }

                var name = FileEntryName(item, type);
                if (name is null)
                {
                    return null;
                }

                path = path.EndsWith('\\') ? path + name : path + "\\" + name;
                continue;
            }

            return null;
        }

        // 드라이브나 공유만 있는 바로가기(예: C:\ 열기)는 실행 파일이 아니에요.
        return path is not null && (path.Length > 3 || path.StartsWith(@"\\", StringComparison.Ordinal)) && path.Contains('\\') ? path : null;
    }

    /// <summary>
    /// 파일 항목의 이름. 긴 이름이 있는 확장 블록(0xBEEF0004)을 먼저 보고, 없으면 기본 이름을 써요.
    /// 기본 이름이 8.3 짧은 이름(PROGRA~1)이라 긴 이름을 알 수 없으면 null이에요.
    /// </summary>
    private static string? FileEntryName(ReadOnlySpan<byte> item, byte type)
    {
        const int nameOffset = 14;
        if (item.Length <= nameOffset)
        {
            return null;
        }

        string primary;
        int afterName;
        if ((type & 0x04) != 0)
        {
            primary = ReadNullTerminatedUnicode(item[nameOffset..]);
            afterName = nameOffset + (primary.Length + 1) * 2;
        }
        else
        {
            primary = ReadNullTerminatedAnsi(item[nameOffset..]);
            afterName = nameOffset + primary.Length + 1;
            if (afterName % 2 == 1)
            {
                afterName++;
            }
        }

        var longName = ExtensionLongName(item, afterName);
        if (longName is null && item.Length >= 4)
        {
            // 확장 블록 위치는 항목의 마지막 2바이트에도 적혀 있어요.
            var extOffset = BinaryPrimitives.ReadUInt16LittleEndian(item[^2..]);
            if (extOffset != afterName)
            {
                longName = ExtensionLongName(item, extOffset);
            }
        }

        if (longName is not null && IsValidFileName(longName) && MatchesPrimary(longName, primary))
        {
            return longName;
        }

        // 기본 이름이 ANSI인데 영어가 아닌 글자가 있으면 어떤 코드 페이지인지 몰라서 쓰지 않아요.
        if (IsValidFileName(primary) && ((type & 0x04) != 0 || (!primary.Contains('~') && !HasNonAscii(primary))))
        {
            return primary;
        }

        return null;
    }

    /// <summary>
    /// 위임 항목(종류 0x74, 서명 'CFSF')의 이름. 구조: 크기(2) 종류(1) ?(1) 데이터 크기(2) 'CFSF'(4) 안쪽 항목(자기 크기 포함)
    /// 위임 GUID(16) 클래스 GUID(16) 확장 블록. 안쪽 항목이 파일·폴더 항목이 아니거나 이름을 확실히 못 읽으면 null이에요.
    /// </summary>
    private static string? DelegateEntryName(ReadOnlySpan<byte> item)
    {
        const int innerAt = 10;
        if (item.Length < innerAt + 15 || item[6] != (byte)'C' || item[7] != (byte)'F' || item[8] != (byte)'S' || item[9] != (byte)'F')
        {
            return null;
        }

        var innerSize = BinaryPrimitives.ReadUInt16LittleEndian(item[innerAt..]);
        if (innerSize < 15 || innerAt + innerSize > item.Length)
        {
            return null;
        }

        var inner = item.Slice(innerAt, innerSize);
        var innerType = inner[2];
        if ((innerType & 0x70) != 0x30)
        {
            return null;
        }

        const int nameOffset = 14;
        var primary = (innerType & 0x04) != 0 ? ReadNullTerminatedUnicode(inner[nameOffset..]) : ReadNullTerminatedAnsi(inner[nameOffset..]);

        // 확장 블록은 안쪽 항목과 GUID 두 개 뒤에 있어요. 위치가 다를 수 있어서 서명으로 찾아요.
        string? longName = null;
        for (var p = innerAt + innerSize; p + 8 <= item.Length; p += 2)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(item[(p + 4)..]) == FileEntryExtensionSignature)
            {
                longName = ExtensionLongName(item, p);
                break;
            }
        }

        if (longName is not null && IsValidFileName(longName) && MatchesPrimary(longName, primary))
        {
            return longName;
        }

        return IsValidFileName(primary) && ((innerType & 0x04) != 0 || (!primary.Contains('~') && !HasNonAscii(primary))) ? primary : null;
    }

    /// <summary>0xBEEF0004 확장 블록의 긴 이름 (버전 3·7·8·9). 형식이 다르면 null이에요.</summary>
    private static string? ExtensionLongName(ReadOnlySpan<byte> item, int offset)
    {
        if (offset <= 0 || offset + 8 > item.Length)
        {
            return null;
        }

        var ext = item[offset..];
        var extSize = BinaryPrimitives.ReadUInt16LittleEndian(ext);
        var version = BinaryPrimitives.ReadUInt16LittleEndian(ext[2..]);
        if (BinaryPrimitives.ReadUInt32LittleEndian(ext[4..]) != FileEntryExtensionSignature || extSize < 8 || extSize > ext.Length)
        {
            return null;
        }

        int nameAt = version switch
        {
            3 => 20,
            7 => 38,
            8 => 42,
            >= 9 => 46,
            _ => -1,
        };
        if (nameAt < 0 || nameAt + 2 > extSize)
        {
            return null;
        }

        var name = ReadNullTerminatedUnicode(ext[nameAt..extSize]);
        return name.Length > 0 ? name : null;
    }

    /// <summary>긴 이름이 기본 이름과 어울리는지 (잘못된 위치에서 읽은 이름을 거르려고요). 짧은 이름(~)이면 확장자만 비교해요.</summary>
    private static bool MatchesPrimary(string longName, string primary)
    {
        if (primary.Length == 0 || HasNonAscii(primary))
        {
            return true;
        }

        if (!primary.Contains('~'))
        {
            return longName.Equals(primary, StringComparison.OrdinalIgnoreCase);
        }

        var shortExt = primary.LastIndexOf('.') is var d and >= 0 ? primary[(d + 1)..] : string.Empty;
        var longExt = longName.LastIndexOf('.') is var l and >= 0 ? longName[(l + 1)..] : string.Empty;
        return shortExt.Length == 0 || longExt.Replace(" ", string.Empty, StringComparison.Ordinal).StartsWith(shortExt, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasNonAscii(string s) => s.Any(c => c > 0x7E);

    private static bool IsValidFileName(string name) =>
        name.Length > 0 && name.Length <= 255 && name != "." && name != ".." && !HasInvalidPathChars(name, allowSeparators: false);

    private static bool HasInvalidPathChars(string s, bool allowSeparators)
    {
        foreach (var c in s)
        {
            if (c < 0x20 || c is '<' or '>' or ':' or '"' or '|' or '?' or '*' or '/' || (!allowSeparators && c == '\\'))
            {
                return true;
            }
        }

        return false;
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
