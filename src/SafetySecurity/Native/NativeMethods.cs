using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafetySecurity.Native;

/// <summary>
/// 이 프로그램이 쓰는 Win32 함수 전부. 모두 자기 프로세스 안에서만 동작하는 읽기 함수예요.
/// 다른 프로세스를 여는 함수(OpenProcess 등), 메모리 접근, 후킹, 드라이버, 네트워크 함수는 없어요.
/// (tests/SafetySecurity.Core.Tests/ForbiddenApiTests.cs가 이 약속을 검사해요.)
/// </summary>
internal static unsafe partial class NativeMethods
{
    // ---------- advapi32: 레지스트리 키 정보 (마지막 수정 시각) ----------
    [LibraryImport("advapi32.dll", EntryPoint = "RegQueryInfoKeyW")]
    internal static partial int RegQueryInfoKey(
        SafeRegistryHandle hKey, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen,
        IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);

    // ---------- wintrust: Authenticode 서명 확인 ----------
    internal const uint WTD_UI_NONE = 2;
    internal const uint WTD_REVOKE_NONE = 0;
    internal const uint WTD_CHOICE_FILE = 1;
    internal const uint WTD_CHOICE_CATALOG = 2;
    internal const uint WTD_STATEACTION_VERIFY = 1;
    internal const uint WTD_STATEACTION_CLOSE = 2;
    internal const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    internal const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    internal const uint WTD_DISABLE_MD2_MD4 = 0x2000;

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CATALOG_INFO
    {
        public uint cbStruct;
        public fixed char wszCatalogFile[260];
    }

    // CRYPT_PROVIDER_SGNR / CRYPT_PROVIDER_CERT의 앞부분만 (서명자 인증서를 찾는 데 필요한 만큼)
    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_PROVIDER_SGNR_HEAD
    {
        public uint cbStruct;
        public uint ftVerifyAsOfLow;
        public uint ftVerifyAsOfHigh;
        public uint csCertChain;
        public IntPtr pasCertChain;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_PROVIDER_CERT_HEAD
    {
        public uint cbStruct;
        public IntPtr pCert;
    }

    [LibraryImport("wintrust.dll")]
    internal static partial int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [LibraryImport("wintrust.dll")]
    internal static partial IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [LibraryImport("wintrust.dll")]
    internal static partial IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner, [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, uint idxCounterSigner);

    [LibraryImport("wintrust.dll", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, byte* pbHash, uint dwFlags);

    [LibraryImport("wintrust.dll")]
    internal static partial IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte* pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    // ---------- crypt32: 인증서 이름 ----------
    internal const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;

    [LibraryImport("crypt32.dll", EntryPoint = "CertGetNameStringW")]
    internal static partial uint CertGetNameString(IntPtr pCertContext, uint dwType, uint dwFlags, IntPtr pvTypePara, char* pszNameString, uint cchNameString);

    // ---------- shell32 / user32: 게임·전체 화면 감지 (창 정보만 읽어요) ----------
    internal const int QUNS_BUSY = 2;
    internal const int QUNS_RUNNING_D3D_FULL_SCREEN = 3;
    internal const int QUNS_PRESENTATION_MODE = 4;

    [LibraryImport("shell32.dll")]
    internal static partial int SHQueryUserNotificationState(out int pquns);

    [StructLayout(LayoutKind.Sequential)]
    internal struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MONITORINFO
    {
        public uint cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    internal const uint MONITOR_DEFAULTTONEAREST = 2;
    internal const int GWL_STYLE = -16;
    internal const long WS_CAPTION = 0x00C00000;

    [LibraryImport("user32.dll")]
    internal static partial IntPtr GetForegroundWindow();

    [LibraryImport("user32.dll")]
    internal static partial IntPtr GetShellWindow();

    [LibraryImport("user32.dll")]
    internal static partial IntPtr GetDesktopWindow();

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [LibraryImport("user32.dll")]
    internal static partial IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    [LibraryImport("user32.dll", EntryPoint = "GetMonitorInfoW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    [LibraryImport("user32.dll", EntryPoint = "GetClassNameW")]
    internal static partial int GetClassName(IntPtr hWnd, char* lpClassName, int nMaxCount);

    [LibraryImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    internal static partial IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);

    [LibraryImport("user32.dll", EntryPoint = "MessageBoxW", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int MessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);

    // ---------- kernel32: 프로세스 이름 목록 (핸들을 열지 않는 스냅샷), CPU 사용률, 자기 프로세스 우선순위 ----------
    internal const uint TH32CS_SNAPPROCESS = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public UIntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        public fixed char szExeFile[260];
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [LibraryImport("kernel32.dll", EntryPoint = "Process32FirstW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [LibraryImport("kernel32.dll", EntryPoint = "Process32NextW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr hObject);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetSystemTimes(out long lpIdleTime, out long lpKernelTime, out long lpUserTime);

    /// <summary>자기 자신을 가리키는 의사 핸들(-1). 다른 프로세스를 여는 게 아니에요.</summary>
    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr GetCurrentProcess();

    internal const uint PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000;

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

    internal const int ProcessPowerThrottling = 4;
    internal const uint PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1;
    internal const uint PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_POWER_THROTTLING_STATE
    {
        public uint Version;
        public uint ControlMask;
        public uint StateMask;
    }

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetProcessInformation(IntPtr hProcess, int processInformationClass, ref PROCESS_POWER_THROTTLING_STATE processInformation, uint processInformationSize);

    internal const int ATTACH_PARENT_PROCESS = -1;

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool AttachConsole(int dwProcessId);

    [LibraryImport("kernel32.dll")]
    internal static partial uint GetOEMCP();

    internal const int STD_OUTPUT_HANDLE = -11;
    internal const uint FILE_TYPE_DISK = 0x0001;
    internal const uint FILE_TYPE_PIPE = 0x0003;

    /// <summary>자기 프로세스의 표준 출력 핸들 (출력이 어디로 가는지 확인용).</summary>
    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr GetStdHandle(int nStdHandle);

    /// <summary>핸들 종류: 파일(DISK), 파이프(PIPE), 콘솔(CHAR), 알 수 없음(UNKNOWN).</summary>
    [LibraryImport("kernel32.dll")]
    internal static partial uint GetFileType(IntPtr hFile);

    /// <summary>8.3 짧은 이름(C:\Users\RUNNER~1)을 긴 이름으로 바꿔요.</summary>
    [LibraryImport("kernel32.dll", EntryPoint = "GetLongPathNameW", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial uint GetLongPathName(string lpszShortPath, char* lpszLongPath, uint cchBuffer);

    /// <summary>
    /// 드라이브 문자(예: "Z:")가 어떤 장치에 연결돼 있는지 읽어요 (네트워크 드라이브인지 확인용).
    /// Windows 안의 이름 연결만 읽어서, 네트워크에는 접속하지 않아요.
    /// </summary>
    [LibraryImport("kernel32.dll", EntryPoint = "QueryDosDeviceW", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial uint QueryDosDevice(string lpDeviceName, char* lpTargetPath, uint ucchMax);
}
