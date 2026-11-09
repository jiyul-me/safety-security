# 보안 정책 / Security Policy

## 취약점 신고

SafetySecurity 자체의 보안 문제(검사기를 속이거나 우회하는 방법, 보고서에서 스크립트가 실행되는 문제 등)를 찾았다면
**공개 이슈 대신** GitHub의 [Private vulnerability reporting](../../security/advisories/new)으로 알려 주세요.

## 이 프로그램이 하지 않는 것 (설계 원칙)

- 시스템의 파일·레지스트리를 지우거나 고치지 않아요. 쓰는 곳은 자기 데이터 폴더뿐이고,
  `install`/`uninstall`을 직접 실행했을 때만 자기 예약 작업과 알림 등록 정보를 만들고 지워요.
  - 일반 권한으로 실행하면 `%LOCALAPPDATA%\SafetySecurity`
  - 관리자 권한으로 실행하면 `C:\Program Files\SafetySecurity\data` (Program Files의 권한을 물려받아 관리자만 바꿀 수 있어요)
- 네트워크를 쓰지 않아요. 인증서 폐기 확인(CRL/OCSP)도 꺼 두었어요. 자동 실행 항목이 네트워크 위치(`\\server\share`, `\\?\UNC\…`, `\\?\GLOBALROOT\…`, WebDAV, 네트워크 드라이브)를 가리켜도 그 파일을 열거나 서명을 확인하지 않고 경로만으로 판단해요.
- 커널 드라이버, 다른 프로세스 열기(`OpenProcess`), 메모리 읽기·쓰기, 코드 주입, 후킹을 쓰지 않아요. 시간이 넘은 자식 프로세스(`schtasks.exe`, `powershell.exe`)도 이미 가진 그 핸들로 그 프로세스 하나만 끝내요.

이 원칙은 코드로 강제돼요.
- `BannedSymbols.txt`: 금지된 .NET API(네트워크, 레지스트리 쓰기, 파일 삭제, `Process.GetProcesses`, 프로세스 트리를 끝내는 `Process.Kill(bool)` 등)를 쓰면 빌드가 실패해요.
- `tests/SafetySecurity.Core.Tests/ForbiddenApiTests.cs`: 금지된 Win32 함수를 선언하거나 프로세스 트리를 끝내는 코드를 쓰면 테스트가 실패해요.

## 관리자 권한으로 실행할 때의 보호

관리자 검사(`Admin` 작업)와 관리자 설치는 일반 권한 악성코드가 끼어들 수 있는 곳을 쓰지 않아요.

- **데이터 폴더**: 관리자 권한 프로세스는 사용자가 쓸 수 있는 `%LOCALAPPDATA%\SafetySecurity`를 읽지도 쓰지도 않아요. 설정(`config.json`), 기록(`state.admin.json`), 서명 캐시, 보고서, 로그, 예약 작업 XML 임시 파일을 모두 `C:\Program Files\SafetySecurity\data`에 둬요. 그래서 일반 권한 악성코드가 관리자 검사의 게임 목록·숨김 목록을 바꾸거나, 링크(정션)를 심어서 관리자 권한으로 다른 파일을 지우게 할 수 없어요. 예약 작업 XML 임시 파일은 임의의 이름으로 새로 만들어요.
- **자식 프로세스**: `schtasks.exe`와 `powershell.exe`는 System32 전체 경로로 실행하고, 사용자 환경 변수를 물려주지 않아요. `SystemRoot`, `PATH`(System32 폴더만), `TEMP`(관리자 권한이면 `Windows\Temp`), `PSModulePath`(Windows PowerShell 시스템 모듈 폴더) 같은 최소한의 값만 `GetSystemDirectory`에서 새로 만들어요. `COR_*`·`COMPlus_*`·`DOTNET_*`나 사용자 `PSModulePath`는 넘기지 않아요. PowerShell은 `-NoProfile -NonInteractive`로 실행하고, 모듈 이름까지 적은 cmdlet만 불러요.
- **검사기 자신**: 관리자 검사는 실행 중인 exe와 `C:\Program Files\SafetySecurity\SafetySecurity.exe`만 '검사기 자신'으로 봐요. 일반 사용자가 바꿀 수 있는 `%LOCALAPPDATA%\Programs\SafetySecurity\SafetySecurity.exe`는 믿지 않아요.
- **예약 작업 이름**: `\SafetySecurity\…`·`\SafetySecurity-…` 이름만으로는 SafetySecurity 작업으로 보지 않아요. 알려진 이름, 동작 하나, 검사기 exe, 설치가 등록하는 인자가 모두 맞아야 해요. 아니면 `TASK-003`(높음)으로 알려요.

## 알려진 한계 / Known limitations

알고 있지만 아직 고치지 않은 것들이에요. 더 나은 방법을 알면 알려 주세요.

- **표준 계정에서 관리자 설치**: 표준(일반) 계정에서 '관리자 권한으로'를 고르고 다른 관리자 계정의 비밀번호를 넣으면, 설치 프로그램이 그 관리자 계정으로 실행돼요. 그래서 자동 검사 작업, 알림 등록, 기록이 모두 관리자 계정 쪽에 만들어지고, 실제로 쓰는 표준 계정에서는 자동 검사가 돌지 않아요. 표준 계정이라면 '내 계정에만'을 고르세요.
- **v0.1.0 zip의 `install --admin`에서 넘어올 때**: 예전에 zip으로 `install --admin`을 했던 PC에서 설치 프로그램으로 '내 계정에만'을 고르면, 예전 `\SafetySecurity\Admin` 작업과 `C:\Program Files\SafetySecurity`의 옛 exe가 남아서 계속 돌아요. 일반 권한으로 도는 제거 프로그램은 그 작업을 지우지 못하고 따로 알리지도 않아요. 설치 방식에서 '관리자 권한으로'를 고르거나, 먼저 예전 압축 폴더에서 관리자 PowerShell로 `.\SafetySecurity.exe uninstall`을 실행하세요.
- **관리자 설치 제거와 내 계정의 기록**: 제거 프로그램은 관리자 권한으로만 돌 수 있어서, 안전을 위해 내 계정의 `%LOCALAPPDATA%\SafetySecurity`는 지우지 않고 위치만 알려 줘요. 필요 없으면 직접 지우세요.
- **관리자 검사의 경로 분류**: 관리자 검사도 경로가 사용자 폴더·임시 폴더인지 나눌 때 실행 환경의 환경 변수를 써요. 사용자가 바꿀 수 있는 값이라, 분류가 달라질 수 있어요 (파일을 열지 않는 네트워크 경로 판단과 자식 프로세스 환경은 여기에 영향받지 않아요).
- **관리자 권한 PowerShell의 .NET 설정**: 자식 프로세스의 환경 변수는 막았지만, Windows PowerShell이 읽는 `HKCU\Software\Microsoft\.NETFramework`의 사용자 설정까지는 막지 못해요. PowerShell 대신 프로세스 안에서 WMI를 읽는 방법은 따로 검토하고 있어요.
- **검사 잠금 이름**: 검사 잠금(`Local\SafetySecurity.Scan.<범위>`) 이름은 정해져 있어서, 같은 사용자 권한의 악성코드가 잠금을 잡고 검사를 늦출 수 있어요. 그런 악성코드는 원래 `config.json`으로도 검사를 미룰 수 있어요. 겹친 자동 검사는 미뤄둔 검사로 남고 `logs\scan.log`에 기록돼요.
- **내 계정 설치의 무결성**: '내 계정에만' 설치에서는 같은 권한의 악성코드가 검사기 파일과 기록을 바꿀 수 있어요. 관리자 설치를 권장하는 이유예요.
- **없어진 자기 작업**: 꺼진 SafetySecurity 작업은 `TASK-004`로 알리지만, 지워진 작업은 알리지 않아요. 예비 이름으로 등록됐을 수도 있고, 관리자 작업은 일반 권한 조회에서 보이지 않을 수 있어서요.
- **알림 상태**: Windows 알림이 꺼져 있는지는 알 수 있지만, 집중 지원(방해 금지) 상태는 알 수 없어요.
- **디스코드 검사**: `app-*`·`discord_desktop_core-*` 폴더 자체가 링크면 목록에 보이지 않아서 조용히 건너뛰어요 (따라가지 않으니 네트워크에는 접속하지 않아요). 예전 `%APPDATA%\discord\<버전>\modules` 구조와 `resources\app.asar`를 바꾸는 방식(Vencord·OpenAsar 같은 디스코드 모드가 정상적으로 쓰는 방식)은 확인하지 않아요.
- **코드 서명**: 설치 프로그램과 exe에 코드 서명이 없어요. 처음 실행할 때 SmartScreen 경고가 뜨고, 스마트 앱 컨트롤이 켜진 PC에는 설치할 수 없어요. 아래 방법으로 파일이 진짜인지 확인하세요.

## 배포물 확인

릴리스마다 `SHA256SUMS.txt`와 GitHub 빌드 출처 증명(attestation)이 있어요. 설치 프로그램, zip, 그 안의 exe 모두 확인할 수 있어요.

```
gh attestation verify SafetySecurity-Setup-x.y.z.exe --repo jiyul-me/safety-security
gh attestation verify "$env:LOCALAPPDATA\Programs\SafetySecurity\SafetySecurity.exe" --repo jiyul-me/safety-security
```
