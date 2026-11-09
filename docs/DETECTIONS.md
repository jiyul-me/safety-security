# 탐지 규칙 목록 / Detection rules

보고서의 각 카드에 있는 **규칙 ID**(예. `COM-001`)로 이 문서에서 설명을 찾을 수 있어요.

위험도 기준:

| 위험도 | 뜻 | 알림 |
|---|---|---|
| **높음 (High)** | 정상 프로그램은 거의 하지 않는 일이에요. 바로 확인해 보세요. | 첫 검사부터 알림 |
| **보통 (Medium)** | 정상일 수도 있지만 악성코드도 자주 쓰는 방식이에요. | 새로 생겼을 때 알림 |
| **낮음 (Low)** | 참고용이에요. 설정 실수나 오래된 흔적인 경우가 많아요. | 알림 없음 |

알림 기준(기본 '보통', `config.json`의 `notifyMinSeverity`)과 함께 이렇게 정해요.
- 첫 검사, 그리고 처음 검사하는 분류(예: 새 버전에 생긴 디스코드, 관리자 설치가 처음 검사하는 서비스)는 '높음'만 알려요. 이미 있던 항목이 한꺼번에 쏟아지지 않게요.
- 같은 ID(분류 + 위치 + 대상)의 항목이 더 위험해지거나, 그 뒤의 파일이 바뀌면(서명 상태, 서명자, SHA-256) **달라진 항목**으로 다시 알려요. 위험도가 내려가거나 파일이 지워진 것은 달라진 것으로 보지 않아요.
- 숨긴(`ignore`) 항목은 숨길 때의 위험도·파일 지문에 묶여요. 그 뒤로 더 위험해지거나 파일이 바뀌면 **숨김 풀림**으로 다시 보여줘요.
- 끝까지 읽지 못한 분류는 보고서에 '(일부만 확인)'으로 표시하고 '확인하지 못한 것'에 이유를 적어요. 그 분류에 항목이 없다고 해서 깨끗하다는 뜻은 아니에요.

공통으로 위험도를 올리는 조건:
- 파일이나 레지스트리 키가 **최근 7일 안에** 만들어지거나 바뀜 → 한 단계 올림
- 사용자 폴더 안 파일에 **숨김+시스템 속성**이 붙어 있음 → 한 단계 올림
- **유효한 디지털 서명**이 있으면 대부분의 규칙에서 위험도를 낮추거나 보고하지 않아요.
- `C:\Program Files\WindowsApps`, `C:\Windows\SystemApps`의 **Windows 앱 패키지**(Store·MSIX 앱)는 파일마다 서명하지 않고 패키지 전체로 서명해요. 이 폴더는 Windows만 쓸 수 있어서, 파일 단위 서명이 없어도 의심하지 않아요. 서명이 **손상된** 경우는 그대로 '높음'이에요.

**네트워크 위치**: 자동 실행·서비스·예약 작업이 네트워크 경로의 파일을 가리키면, 네트워크에 접속하지 않으려고 그 파일을 열거나, 있는지 보거나, 서명을 확인하지 않아요. 경로만으로 판단해요.
- `\\server\share\…`, `\\?\UNC\…`, `\\?\GLOBALROOT\…`, WebDAV(`\\host@SSL\…`) → **높음** (다른 컴퓨터의 파일을 실행하는 건 일반 프로그램이 거의 하지 않아요)
- 네트워크 드라이브로 연결된 드라이브 문자(예: `Z:\tool.exe`) → 보통 (NAS·공유 폴더에 직접 둔 프로그램일 수 있어요)
- 증거에 '네트워크 위치'와 '파일 확인: 안 함'이 붙어요. 규칙 ID는 원래 규칙 그대로예요 (예: `RUN-001`, `COM-001`, `TASK-001`).
- 시작프로그램 폴더 자체가 네트워크 공유로 옮겨져 있으면 열지 않고 '확인하지 못한 것'에 적어요.

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
| `RUN-002` | 시작프로그램 폴더 (.lnk 대상까지 분석: 환경 변수 블록·IDList·LinkInfo를 모두 봐요) | 같음. 보이는 대상과 실제 실행 대상이 다른 위장 바로가기는 보통 이상, 대상을 해석할 수 없는 바로가기는 낮음 |
| `RUN-003` | Winlogon `Shell`/`Userinit` 변경, HKCU `Shell`. `Shell`은 `explorer.exe`·`%SystemRoot%\explorer.exe` 하나만 기본값으로 봐요 (다른 폴더의 explorer.exe, 앞에 붙인 프로그램은 보고) | **높음** |
| `RUN-004` | `AppInit_DLLs` | 켜져 있으면 **높음**, 꺼져 있으면 낮음 |
| `RUN-005` | `AppCertDlls` | **높음** |
| `RUN-006` | IFEO `Debugger` (예. sethc.exe → cmd.exe) | **높음**. 서명된 도구(Process Explorer 등)면 보통. cmd·PowerShell·스크립트 실행기는 서명이 있어도 높음 |
| `RUN-007` | `SilentProcessExit` `MonitorProcess` | **높음** |
| `RUN-008` | 로그온 스크립트 `HKCU\Environment\UserInitMprLogonScript` (T1037.001) | **높음** |
| `RUN-009` | `Command Processor\AutoRun` | 보통 이상 |

**명령줄 판정** (자동 실행, 서비스, 예약 작업에 공통):
- **높음**: `powershell -EncodedCommand` (`-enc`, `-encodedcom` 같은 줄임말과 `–`·`—` 대시 포함), `IEX`/`DownloadString`, `mshta`, `regsvr32 /i:http … scrobj.dll`, `rundll32 javascript:`, `certutil -urlcache`, `bitsadmin /transfer`, 서명이 손상된 파일, 임시·공용 폴더의 서명 없는 파일
- **보통**: 숨김 창 PowerShell, `cmd /c powershell`, 사용자 폴더의 서명 없는 파일이나 스크립트, `wscript //E:`로 스크립트가 아닌 확장자 파일을 실행, 명령줄 안의 인터넷 주소
- **낮음**: 파일이 없는 등록(남은 흔적), Program Files 등의 서명 없는 파일
- **감싼 명령**: `cmd /c`·`start`, `conhost --headless`, `explorer.exe 파일`, `forfiles /c`, `pcalua -a`, `wmic process call create`, PowerShell `Start-Process`·`&`처럼 다른 프로그램을 대신 실행하면, 감싼 프로그램(cmd.exe 등)이 아니라 **실제로 실행되는 파일**로 판정해요 (최대 3겹). 감싼 것만으로는 위험도를 올리지 않아요 (`cmd /c start "" "C:\Program Files\…"`는 정상 프로그램도 많이 써요).
  이때 항목의 대상은 실제 파일이라, 예전 버전에서 숨긴 감싼 명령 항목은 ID가 바뀌어 한 번 다시 보일 수 있어요.

## 서비스·드라이버 (`Service`)

| ID | 내용 | 위험도 |
|---|---|---|
| `SVC-001` | 서비스 실행 파일·`ServiceDll`이 의심스러움, 따옴표 없는 공백 경로 | 판정에 따라 달라요. ServiceDll이 사용자 폴더에 있으면 **높음**. 따옴표 없는 경로는 Windows가 먼저 실행해 볼 위치(예: `D:\My.exe`)를 일반 사용자가 쓸 수 있을 때만 낮음으로 보고해요. `C:\Program Files\…`처럼 관리자만 쓸 수 있는 위치뿐이면 보고하지 않아요 (예: Riot Vanguard `vgc`) |
| `SVC-002` | 커널 드라이버가 사용자 폴더에 있거나 서명이 없음 | **높음** |

'사용 안 함' 상태인 서비스·드라이버는 한 단계 낮춰요.

## 예약 작업 (`ScheduledTask`, `HiddenTask`)

| ID | 내용 | 위험도 |
|---|---|---|
| `TASK-001` | 작업 동작이 의심스러운 명령줄·파일 | 명령줄 판정 기준. 숨김 작업이면서 사용자 폴더 파일이면 한 단계 올림. `\Microsoft\` 작업이 Windows 폴더의 **없는 파일**을 가리키는 것뿐이면 업데이트가 남긴 흔적이라 보고하지 않아요 (예: `USO_UxBroker` → `MusNotification.exe`) |
| `TASK-002` | `TaskCache\Tree`에서 보안 설명자(SD)가 지워진 작업 (Tarrask 수법) — 관리자 검사. SafetySecurity 이름을 쓰는 작업도 빼 주지 않아요 (진짜 SafetySecurity 작업은 항상 SD가 있어요) | **높음** |
| `TASK-003` | SafetySecurity 이름(`\SafetySecurity\…`, `\SafetySecurity-…`)을 쓰지만 SafetySecurity가 만든 작업이 아님. 진짜 작업은 이름이 `Logon`·`Daily`·`ServiceInstalled`·`Retry`·`Admin`·`ServiceInstalledAdmin` 중 하나이고, 동작이 하나뿐이며, 검사기 자신(실행 중인 exe나 설치 위치의 `SafetySecurity.exe`)을 그 작업의 `scan …` 인자 그대로 실행해요. 모르는 이름, 다른 프로그램, 다른 인자, 동작 추가, 하위 폴더는 모두 보고해요 | **높음** (서명된 프로그램이거나 작업이 꺼져 있어도) |
| `TASK-004` | 진짜 SafetySecurity 작업이 꺼져 있음 (그 자동 검사가 돌지 않아요). 다시 켜는 것은 사용자가 직접 해요: 작업 스케줄러에서 '사용', `schtasks /change /tn <이름> /enable`(`Admin` 작업은 관리자 권한), 또는 설치 프로그램 다시 실행 | 보통 |

`TASK-003`이 나오면 그 작업의 '동작' 탭에서 무엇을 실행하는지 확인하고, `schtasks /change /tn <이름> /disable`로 먼저 꺼 두세요. 설치 프로그램을 다시 실행하면 진짜 SafetySecurity 작업이 다시 등록돼요.

## 브라우저 (`Browser`)

| ID | 내용 | 위험도 |
|---|---|---|
| `WEB-001` | `ExtensionInstallForcelist` 강제 설치 확장 프로그램 | 공식 스토어가 아니면 **높음**, 스토어면 보통 (업데이트 주소의 호스트 이름을 정확히 비교해요) |
| `WEB-002` | 브라우저 정책 프록시 (`ProxyServer`, `ProxyPacUrl`) | 보통 |
| `WEB-003` | `ExtensionSettings`의 `force_installed`·`normal_installed` (정책 값의 JSON과 확장 프로그램 ID별 하위 키 모두) | 공식 스토어가 아닌 `update_url`이면 **높음**, 그 밖에는 보통. `blocked`·`allowed`만 있으면 보고하지 않아요 |
| `WEB-004` | 시스템 PAC 주소 (`AutoConfigURL`) | 외부 주소면 보통, 이 PC 안이면 낮음 |
| `WEB-005` | 시스템 프록시 켜짐 | 외부면 보통, 127.0.0.1이면 낮음 |
| `WEB-006` | 브라우저 바로가기에 `--load-extension`, `--remote-debugging`, 강제 URL | **높음** (URL만 있으면 보통) |

회사·학교 PC는 관리 정책 때문에 `WEB-001~003`이 정상으로 나올 수 있어요.

## Defender (`Defender`)

| ID | 내용 | 위험도 |
|---|---|---|
| `DEF-001` | Defender·실시간 보호를 끄는 정책 | **높음** |
| `DEF-002` | 제외 목록 (정책 제외, 관리자 검사에서는 로컬 제외도) | 드라이브 전체·사용자 폴더·실행 파일 확장자면 **높음**, 그 밖에는 보통 |

## 디스코드 앱 변조 (`Discord`) — MITRE T1554

디스코드 토큰·비밀번호를 훔치는 악성코드(토큰 그래버)는 디스코드가 켜질 때 실행하는 시작 파일을 고쳐서, 디스코드를 켤 때마다 다시 정보를 빼 가요. 게임 치트·크랙 파일에 섞여 퍼지는 경우가 많아요.
사용자 전체 검사에서 `%LOCALAPPDATA%`의 `Discord`, `DiscordPTB`, `DiscordCanary`, `DiscordDevelopment` 폴더마다 `app-*\modules\discord_desktop_core-*\discord_desktop_core\`를 확인해요.
폴더 목록과 1MB 이하의 작은 파일(`index.js`, `package.json`)만 읽고, 디스코드가 실행 중인지는 보지 않아요(다른 프로세스를 열지 않아요). 링크(정션·심볼릭 링크)는 따라가지 않아요.

| ID | 내용 | 위험도 | 흔한 오탐 |
|---|---|---|---|
| `DISC-001` | `index.js`가 원래 한 줄(`module.exports = require('./core.asar');`)이 아님. 낱말 사이의 빈칸·줄바꿈, 맨 앞 BOM, 따옴표 종류, 끝의 세미콜론 차이는 원래 파일로 봐요 (문자열 안의 빈칸은 다른 파일이라 아니에요). `index.js`·`package.json`이 링크이거나 1MB보다 큼, `package.json`의 `main`·`exports`가 `index.js` 말고 다른 파일을 가리킴도 같아요. 토큰 탈취 도구의 첫 실행 표시인 `initiation` 폴더가 함께 있으면 이유에 적어요. 웹훅 주소·`BrowserWindow`·`webRequest`·`token` 같은 코드 조각, 앞부분 200자(제어 문자는 보이게 바꿔요), 크기, 수정 시각, SHA-256을 증거로 보여줘요 (난독화한 코드는 이런 글자가 없어도 똑같이 높음) | **높음**. 안쪽 `modules`·`discord_desktop_core` 폴더가 링크면(안쪽을 열지 않아요) 보통 | BetterDiscord가 아닌 디스코드 모드·테마 도구를 직접 설치한 경우 |
| `DISC-002` | BetterDiscord 설치 프로그램이 쓰는 모양 그대로: 정확히 `%APPDATA%\BetterDiscord\data\betterdiscord.asar`를 불러온 뒤 원래 한 줄. 다른 경로·다른 이스케이프·덧붙인 코드는 `DISC-001` | 낮음 (`initiation` 폴더나 `package.json` 변경이 함께 있으면 `DISC-001` 높음) | BetterDiscord를 직접 설치한 경우 (정상) |

- 같은 폴더에 다른 `.js` 파일이 있어도 `index.js`·`package.json`이 원래대로면 실행되지 않아서 따로 보고하지 않아요. 변조를 보고할 때 증거(같은 폴더의 다른 항목)에 함께 적어요.
- 디스코드를 업데이트하면 `app-*` 폴더 이름이 바뀌어서 항목 ID도 바뀌어요. 예전 폴더가 남아 있으면 폴더마다 따로 확인해요.
- `%LOCALAPPDATA%\Discord` 폴더 자체가 다른 곳으로 연결된 링크면 열지 않고 '확인하지 못한 것'에 적고, 분류를 '(일부만 확인)'으로 표시해요.
- 한계: `app-*`·`discord_desktop_core-*` 폴더 자체가 링크면 폴더 목록에 보이지 않아서 조용히 건너뛰어요. 예전 `%APPDATA%\discord\<버전>\modules` 구조와 `resources\app.asar`를 바꾸는 방식(Vencord·OpenAsar 같은 디스코드 모드가 정상적으로 쓰는 방식)은 오탐이 많아서 확인하지 않아요.
- `DISC-001`이 나오면: 디스코드를 끄고 Defender 오프라인 검사를 한 뒤, 그 디스코드 폴더를 지우고 discord.com에서 다시 설치하세요. 다른 기기에서 디스코드 비밀번호를 바꾸고 2단계 인증을 켜면 훔친 토큰을 못 쓰게 돼요. 다른 기기를 모두 로그아웃하고, 같은 비밀번호를 쓰던 게임·메일 계정도 바꾸세요. SafetySecurity는 파일을 고치거나 지우지 않아요.

## 그 밖의 검사

| ID | 내용 | 위험도 |
|---|---|---|
| `HOST-001` | hosts 파일이 보안·업데이트·게임·포털 사이트를 막거나 다른 IP로 보냄. 항목 ID에 줄 번호를 넣지 않아서 줄이 늘거나 줄어도 숨김이 유지돼요 | **높음**. 단, 큰 포털(microsoft.com, google.com, naver.com 등)의 텔레메트리·광고 주소(예. `vortex.data.microsoft.com`, `adservice.google.com`)를 `0.0.0.0`·`127.0.0.1`로 막은 줄은 참고 (업데이트·로그인·보안 주소는 계속 높음). 그 밖의 외부 IP 고정은 낮음. 그 밖의 광고 차단용 `0.0.0.0` 목록은 무시 |
| `WMI-001` | WMI 영구 구독 (CommandLine/ActiveScript consumer) — 관리자 검사, T1546.003 | **높음** |
| `FILE-001` | 최근 14일 안에 AppData·LocalAppData·ProgramData·Public에 생긴 서명 없는 실행 파일 | 보통 (Temp는 설치 프로그램이 많이 써서 낮음) |
| `FILE-002` | `invoice.pdf.exe` 같은 이중 확장자, 확장자를 속인 실행 파일 (예. `.jpg`인데 PE) | **높음** |

---

오탐을 찾았다면 [오탐 신고](https://github.com/jiyul-me/safety-security/issues/new?template=false_positive.yml)로 알려 주세요.
