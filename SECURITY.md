# 보안 정책 / Security Policy

## 취약점 신고

SafetySecurity 자체의 보안 문제(검사기를 속이거나 우회하는 방법, 보고서에서 스크립트가 실행되는 문제 등)를 찾았다면
**공개 이슈 대신** GitHub의 [Private vulnerability reporting](../../security/advisories/new)으로 알려 주세요.

## 이 프로그램이 하지 않는 것 (설계 원칙)

- 시스템의 파일·레지스트리를 지우거나 고치지 않아요. 쓰는 곳은 자기 데이터 폴더(`%LOCALAPPDATA%\SafetySecurity`)뿐이고,
  `install`/`uninstall`을 직접 실행했을 때만 자기 예약 작업과 알림 등록 정보를 만들고 지워요.
- 네트워크를 쓰지 않아요. 인증서 폐기 확인(CRL/OCSP)도 꺼 두었어요.
- 커널 드라이버, 다른 프로세스 열기(`OpenProcess`), 메모리 읽기·쓰기, 코드 주입, 후킹을 쓰지 않아요.

이 원칙은 코드로 강제돼요.
- `BannedSymbols.txt`: 금지된 .NET API를 쓰면 빌드가 실패해요.
- `tests/SafetySecurity.Core.Tests/ForbiddenApiTests.cs`: 금지된 Win32 함수를 선언하면 테스트가 실패해요.

## 배포물 확인

릴리스마다 `SHA256SUMS.txt`와 GitHub 빌드 출처 증명(attestation)이 있어요.

```
gh attestation verify SafetySecurity.exe --repo jiyul-me/safety-security
```
