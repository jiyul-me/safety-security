using System.Globalization;
using System.Runtime.InteropServices;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Model;
using static SafetySecurity.Native.NativeMethods;

namespace SafetySecurity.Windows;

/// <summary>
/// WinVerifyTrust로 Authenticode 서명을 확인해요.
/// - 인증서 폐기 확인(CRL/OCSP)을 끄고(WTD_REVOKE_NONE) 캐시만 쓰게 해서(WTD_CACHE_ONLY_URL_RETRIEVAL) 네트워크를 쓰지 않아요.
/// - 파일 자체에 서명이 없으면 Windows 카탈로그 서명도 확인해요 (Windows 시스템 파일 대부분이 이 방식이에요).
/// </summary>
internal sealed unsafe class AuthenticodeVerifier : ISignatureVerifier
{
    private static Guid _genericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    private const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    private const int TRUST_E_CERT_SIGNATURE = unchecked((int)0x80096004);
    private const int CERT_E_REVOKED = unchecked((int)0x800B010C);
    private const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    private const int CRYPT_E_NO_REVOCATION_CHECK = unchecked((int)0x80092012);
    private const int CRYPT_E_REVOCATION_OFFLINE = unchecked((int)0x80092013);
    private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    private const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    private const int CERT_E_CHAINING = unchecked((int)0x800B010A);

    private const uint ProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4;

    public SignatureInfo Verify(string path)
    {
        if (!File.Exists(path))
        {
            return new SignatureInfo(SignatureStatus.NotFound);
        }

        try
        {
            var embedded = VerifyEmbedded(path);
            if (embedded.Status != SignatureStatus.Unsigned)
            {
                return embedded;
            }

            return VerifyCatalog(path, "SHA256") ?? VerifyCatalog(path, "SHA1") ?? embedded;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return new SignatureInfo(SignatureStatus.Error, Detail: ex.GetType().Name);
        }
    }

    private static SignatureInfo VerifyEmbedded(string path)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)sizeof(WINTRUST_FILE_INFO),
                pcwszFilePath = pathPtr,
            };
            var data = NewData(WTD_CHOICE_FILE, (IntPtr)(&fileInfo));
            return Run(ref data, isCatalog: false);
        }
        finally
        {
            Marshal.FreeHGlobal(pathPtr);
        }
    }

    private static SignatureInfo? VerifyCatalog(string path, string algorithm)
    {
        if (!CryptCATAdminAcquireContext2(out var catAdmin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
        {
            return null;
        }

        try
        {
            byte[] hash;
            using (var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                uint size = 0;
                CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref size, null, 0);
                if (size == 0 || size > 128)
                {
                    return null;
                }

                hash = new byte[size];
                fixed (byte* p = hash)
                {
                    if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref size, p, 0))
                    {
                        return null;
                    }
                }
            }

            fixed (byte* pHash = hash)
            {
                var catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, pHash, (uint)hash.Length, 0, IntPtr.Zero);
                if (catInfo == IntPtr.Zero)
                {
                    return null;
                }

                try
                {
                    var info = new CATALOG_INFO { cbStruct = (uint)sizeof(CATALOG_INFO) };
                    if (!CryptCATCatalogInfoFromContext(catInfo, ref info, 0))
                    {
                        return null;
                    }

                    var catalogFile = new string(info.wszCatalogFile);
                    var memberTag = Convert.ToHexString(hash);
                    var catPtr = Marshal.StringToHGlobalUni(catalogFile);
                    var tagPtr = Marshal.StringToHGlobalUni(memberTag);
                    var pathPtr = Marshal.StringToHGlobalUni(path);
                    try
                    {
                        var cat = new WINTRUST_CATALOG_INFO
                        {
                            cbStruct = (uint)sizeof(WINTRUST_CATALOG_INFO),
                            pcwszCatalogFilePath = catPtr,
                            pcwszMemberTag = tagPtr,
                            pcwszMemberFilePath = pathPtr,
                            pbCalculatedFileHash = (IntPtr)pHash,
                            cbCalculatedFileHash = (uint)hash.Length,
                            hCatAdmin = catAdmin,
                        };
                        var data = NewData(WTD_CHOICE_CATALOG, (IntPtr)(&cat));
                        var result = Run(ref data, isCatalog: true);
                        return result.Status == SignatureStatus.Unsigned ? null : result;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(catPtr);
                        Marshal.FreeHGlobal(tagPtr);
                        Marshal.FreeHGlobal(pathPtr);
                    }
                }
                finally
                {
                    CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
                }
            }
        }
        finally
        {
            CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    private static WINTRUST_DATA NewData(uint unionChoice, IntPtr union) => new()
    {
        cbStruct = (uint)sizeof(WINTRUST_DATA),
        dwUIChoice = WTD_UI_NONE,
        fdwRevocationChecks = WTD_REVOKE_NONE,
        dwUnionChoice = unionChoice,
        pUnion = union,
        dwStateAction = WTD_STATEACTION_VERIFY,
        dwProvFlags = ProvFlags,
    };

    private static SignatureInfo Run(ref WINTRUST_DATA data, bool isCatalog)
    {
        // hwnd = INVALID_HANDLE_VALUE: 어떤 UI도 띄우지 않아요.
        var hr = WinVerifyTrust(new IntPtr(-1), ref _genericVerifyV2, ref data);
        string? signer = null;
        try
        {
            if (data.hWVTStateData != IntPtr.Zero && hr is 0 or CERT_E_EXPIRED or CERT_E_UNTRUSTEDROOT or CERT_E_CHAINING or CRYPT_E_NO_REVOCATION_CHECK or CRYPT_E_REVOCATION_OFFLINE)
            {
                signer = GetSigner(data.hWVTStateData);
            }
        }
        finally
        {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(new IntPtr(-1), ref _genericVerifyV2, ref data);
        }

        return hr switch
        {
            0 => new SignatureInfo(SignatureStatus.Valid, signer, isCatalog),
            CRYPT_E_NO_REVOCATION_CHECK or CRYPT_E_REVOCATION_OFFLINE => new SignatureInfo(SignatureStatus.Valid, signer, isCatalog, "폐기 여부는 확인 안 함"),
            TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN => new SignatureInfo(SignatureStatus.Unsigned),
            TRUST_E_BAD_DIGEST or TRUST_E_CERT_SIGNATURE => new SignatureInfo(SignatureStatus.Invalid, signer, isCatalog, "파일이 서명 후 변경됨"),
            CERT_E_REVOKED => new SignatureInfo(SignatureStatus.Invalid, signer, isCatalog, "폐기된 인증서"),
            TRUST_E_EXPLICIT_DISTRUST => new SignatureInfo(SignatureStatus.Invalid, signer, isCatalog, "명시적으로 불신된 인증서"),
            CERT_E_EXPIRED => new SignatureInfo(SignatureStatus.Untrusted, signer, isCatalog, "만료된 인증서"),
            CERT_E_UNTRUSTEDROOT => new SignatureInfo(SignatureStatus.Untrusted, signer, isCatalog, "신뢰할 수 없는 루트 인증서"),
            _ => new SignatureInfo(SignatureStatus.Untrusted, signer, isCatalog, "0x" + hr.ToString("X8", CultureInfo.InvariantCulture)),
        };
    }

    private static string? GetSigner(IntPtr stateData)
    {
        var provData = WTHelperProvDataFromStateData(stateData);
        if (provData == IntPtr.Zero)
        {
            return null;
        }

        var sgnr = WTHelperGetProvSignerFromChain(provData, 0, false, 0);
        if (sgnr == IntPtr.Zero)
        {
            return null;
        }

        var head = *(CRYPT_PROVIDER_SGNR_HEAD*)sgnr;
        if (head.csCertChain == 0 || head.pasCertChain == IntPtr.Zero)
        {
            return null;
        }

        var cert = *(CRYPT_PROVIDER_CERT_HEAD*)head.pasCertChain;
        if (cert.pCert == IntPtr.Zero)
        {
            return null;
        }

        var buffer = stackalloc char[256];
        var len = CertGetNameString(cert.pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, buffer, 256);
        return len > 1 ? new string(buffer, 0, (int)len - 1) : null;
    }
}
