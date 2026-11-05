using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Abstractions;

/// <summary>Authenticode 서명 확인. Windows 구현은 네트워크를 쓰지 않아요.</summary>
public interface ISignatureVerifier
{
    SignatureInfo Verify(string path);
}
