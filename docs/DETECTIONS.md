# 탐지 규칙 목록 / Detection rules

보고서의 각 카드에 있는 **규칙 ID**(예. `COM-001`)로 이 문서에서 설명을 찾을 수 있어요.

위험도 기준:

| 위험도 | 뜻 | 알림 |
|---|---|---|
| **높음 (High)** | 정상 프로그램은 거의 하지 않는 일이에요. 바로 확인해 보세요. | 첫 검사부터 알림 |
| **보통 (Medium)** | 정상일 수도 있지만 악성코드도 자주 쓰는 방식이에요. | 새로 생겼을 때 알림 |
| **낮음 (Low)** | 참고용이에요. 설정 실수나 오래된 흔적인 경우가 많아요. | 알림 없음 |

공통으로 위험도를 올리는 조건:
- 파일이나 레지스트리 키가 **최근 7일 안에** 만들어지거나 바뀜 → 한 단계 올림
- 사용자 폴더 안 파일에 **숨김+시스템 속성**이 붙어 있음 → 한 단계 올림
- **유효한 디지털 서명**이 있으면 대부분의 규칙에서 위험도를 낮추거나 보고하지 않아요.
- `C:\Program Files\WindowsApps`, `C:\Windows\SystemApps`의 **Windows 앱 패키지**(Store·MSIX 앱)는 파일마다 서명하지 않고 패키지 전체로 서명해요. 이 폴더는 Windows만 쓸 수 있어서, 파일 단위 서명이 없어도 의심하지 않아요. 서명이 **손상된** 경우는 그대로 '높음'이에요.

---

## COM 하이재킹 (`ComHijack`) — MITRE T1546.015

| ID | 내용 | 위험도 | 흔한 오탐 |
|---|---|---|---|
| `COM-001` | HKCU CLSID가 같은 GUID의 HKLM 등록을 **덮어써서 다른 파일**을 가리킴 | 서명 없음·변조·사용자 폴더면 **높음**, 서명이 유효한 사용자 폴더 파일이면 보통, 그 밖에는 낮음 | 일부 사용자 단위 설치 프로그램이 시스템 클래스를 덮어씀 (드물어요) |
| `COM-002` | HKCU에만 있는 CLSID가 서명 없는 파일을 불러옴 | 임시·공용 폴더 **높음**, 사용자 폴더 보통 | 서명하지 않은 개인 개발 도구·셸 확장 |
| `COM-003` | `ScriptletURL` 등록 (스크립트를 COM 객체로 실행) | **높음** | 거의 없어요 |
| `COM-004` | HKCU `TreatAs`로 클래스를 다른 클래스로 연결. 연결된 대상 클래스가 실행하는 파일까지 따라가서 판단해요 | 대상이 의심스러운 파일이면 **높음**(HKLM 클래스를 덮어쓸 때)·보통, 대상에 실행 파일이 없으면 보통·낮음, 대상이 정상이면 보고하지 않아요(HKLM을 덮어쓰면 낮음) | 새 그림판(Store 앱)이 옛 "Paintbrush 그림" 클래스를 넘겨받는 설정 → 이제 보고하지 않아요 |

니케 PC 런처 사건처럼 Chrome 같은 프로그램이 악성 DLL을 불러오게 만드는 수법이 `COM-001`이에요.

## 자동 실행 (`Autorun`)

| ID | 위치 | 위험도 |
|---|---|---|
| `RUN-001` | `Run`, `RunOnce`, `Policies\Explorer\Run` (HKCU·HKLM, 32·64비트) | 명령줄과 파일에 따라 달라요 (아래 *명령줄 판정*) |
| `RUN-002` | 시작프로그램 폴더 (.lnk 대상까지 분석) | 같음 |
| `RUN-003` | Winlogon `Shell`/`Userinit` 변경, HKCU `Shell` | **높음** |
| `RUN-004` | `AppInit_DLLs` | 켜져 있으면 **높음**, 꺼져 있으면 낮음 |
| `RUN-005` | `AppCertDlls` | **높음** |
| `RUN-006` | IFEO `Debugger` (예. sethc.exe → cmd.exe) | **높음**. 서명된 도구(Process Explorer 등)면 보통 |
| `RUN-007` | `SilentProcessExit` `MonitorProcess` | **높음** |
| `RUN-008` | 로그온 스크립트 `HKCU\Environment\UserInitMprLogonScript` (T1037.001) | **높음** |
| `RUN-009` | `Command Processor\AutoRun` | 보통 이상 |

**명령줄 판정** (자동 실행, 서비스, 예약 작업에 공통):
- **높음**: `powershell -EncodedCommand`, `IEX`/`DownloadString`, `mshta`, `regsvr32 /i:http … scrobj.dll`, `rundll32 javascript:`, `certutil -urlcache`, `bitsadmin /transfer`, 서명이 손상된 파일, 임시·공용 폴더의 서명 없는 파일
- **보통**: 숨김 창 PowerShell, `cmd /c powershell`, 사용자 폴더의 서명 없는 파일이나 스크립트, 명령줄 안의 인터넷 주소
- **낮음**: 파일이 없는 등록(남은 흔적), Program Files 등의 서명 없는 파일

## 서비스·드라이버 (`Service`)

| ID | 내용 | 위험도 |
|---|---|---|
| `SVC-001` | 서비스 실행 파일·`ServiceDll`이 의심스러움, 따옴표 없는 공백 경로 | 판정에 따라 달라요. ServiceDll이 사용자 폴더에 있으면 **높음**, 따옴표 없는 경로만 있으면 낮음 |
| `SVC-002` | 커널 드라이버가 사용자 폴더에 있거나 서명이 없음 | **높음** |

'사용 안 함' 상태인 서비스·드라이버는 한 단계 낮춰요.

## 예약 작업 (`ScheduledTask`, `HiddenTask`)

| ID | 내용 | 위험도 |
|---|---|---|
| `TASK-001` | 작업 동작이 의심스러운 명령줄·파일 | 명령줄 판정 기준. 숨김 작업이면서 사용자 폴더 파일이면 한 단계 올림 |
| `TASK-002` | `TaskCache\Tree`에서 보안 설명자(SD)가 지워진 작업 (Tarrask 수법) — 관리자 검사 | **높음** |

## 브라우저 (`Browser`)

| ID | 내용 | 위험도 |
|---|---|---|
| `WEB-001` | `ExtensionInstallForcelist` 강제 설치 확장 프로그램 | 공식 스토어가 아니면 **높음**, 스토어면 보통 |
| `WEB-002` | 브라우저 정책 프록시 (`ProxyServer`, `ProxyPacUrl`) | 보통 |
| `WEB-003` | `ExtensionSettings`의 force_installed | 보통 |
| `WEB-004` | 시스템 PAC 주소 (`AutoConfigURL`) | 외부 주소면 보통, 이 PC 안이면 낮음 |
| `WEB-005` | 시스템 프록시 켜짐 | 외부면 보통, 127.0.0.1이면 낮음 |
| `WEB-006` | 브라우저 바로가기에 `--load-extension`, `--remote-debugging`, 강제 URL | **높음** (URL만 있으면 보통) |

회사·학교 PC는 관리 정책 때문에 `WEB-001~003`이 정상으로 나올 수 있어요.

## Defender (`Defender`)

| ID | 내용 | 위험도 |
|---|---|---|
| `DEF-001` | Defender·실시간 보호를 끄는 정책 | **높음** |
| `DEF-002` | 제외 목록 (정책 제외, 관리자 검사에서는 로컬 제외도) | 드라이브 전체·사용자 폴더·실행 파일 확장자면 **높음**, 그 밖에는 보통 |

## 그 밖의 검사

| ID | 내용 | 위험도 |
|---|---|---|
| `HOST-001` | hosts 파일이 보안·업데이트·게임·포털 사이트를 막거나 다른 IP로 보냄 | **높음**. 그 밖의 외부 IP 고정은 낮음. 광고 차단용 `0.0.0.0` 목록은 무시 |
| `WMI-001` | WMI 영구 구독 (CommandLine/ActiveScript consumer) — 관리자 검사, T1546.003 | **높음** |
| `FILE-001` | 최근 14일 안에 AppData·LocalAppData·ProgramData·Public에 생긴 서명 없는 실행 파일 | 보통 (Temp는 설치 프로그램이 많이 써서 낮음) |
| `FILE-002` | `invoice.pdf.exe` 같은 이중 확장자, 확장자를 속인 실행 파일 (예. `.jpg`인데 PE) | **높음** |

---

오탐을 찾았다면 [오탐 신고](https://github.com/jiyul-me/safety-security/issues/new?template=false_positive.yml)로 알려 주세요.
