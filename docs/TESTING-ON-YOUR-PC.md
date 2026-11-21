# 내 PC에서 시험하기

CI(GitHub의 Windows 서버)로는 확인할 수 없는 것들을 실제 PC에서 확인하는 순서다. 40분쯤 걸린다.

| CI로 확인한 것 | PC에서 확인할 것 |
|---|---|
| 빌드, 단위 테스트 500여 개, 가짜 COM 하이재킹·Run 키·감싼 명령·디스코드 변조·위장 예약 작업 탐지, 네트워크 경로를 열지 않는지, 베이스라인과 달라진 항목, 무시 목록과 `ignored`, 게임 프로세스로 연기, 겹친 검사·밀린 검사, 작업 등록과 삭제, 설치 프로그램 조용히 설치·다시 설치·제거 (두 방식 모두), 다른 방식 설치 거절, 바탕화면 바로가기 생성·삭제, 관리자 데이터 폴더 권한 | 알림이 실제로 화면에 뜨는지, 알림을 껐을 때의 안내, **전체 화면 게임** 감지, **뱅가드와 함께** 써도 괜찮은지, 일반 사용자 작업이 **서비스 설치 이벤트**로 깨어나는지, 실제 PC의 **오탐** 개수(바로가기·디스코드 포함), **설치 프로그램** 화면·바탕화면 아이콘·시작 메뉴·Win+R 메시지 창·제거 화면, 스마트 앱 컨트롤 |

## 0. 준비

1. [Releases](https://github.com/jiyul-me/safety-security/releases)에서 가장 최근 버전의 두 파일을 받는다 (사전 릴리스 `-rc`도 괜찮다).
   - `SafetySecurity-Setup-….exe`: 설치할 때 쓴다.
   - `SafetySecurity-…-win-x64.zip`: 안내형 시험 스크립트(`tools\Test-OnMyPC.ps1`)가 들어 있다.
2. 처음 실행할 때 **SmartScreen**("Windows의 PC 보호")이 뜨면 '추가 정보' → '실행'을 누른다. 코드 서명 인증서가 없어서 생기는 일이다.
3. **스마트 앱 컨트롤**이 켜진 PC에서는 설치 프로그램이 '실행' 버튼 없이 막힌다. 그러면 어떤 창이 떴는지 캡처하고 여기서 멈춘다. 시험하려고 스마트 앱 컨트롤을 **끄면 안 된다** (Windows 버전에 따라 다시 켜려면 Windows를 새로 설치해야 한다). 켜져 있는지는 Windows 보안 → 앱 및 브라우저 컨트롤 → 스마트 앱 컨트롤 설정에서 볼 수 있다.
4. Defender가 파일을 지웠다면 Windows 보안 → 보호 기록에서 어떤 이름으로 탐지했는지 메모한다 (그것도 중요한 결과다).
5. **v0.1.0을 zip으로 설치했던 PC만**: 예전 압축 폴더에서 관리자 PowerShell로 `.\SafetySecurity.exe uninstall`을 실행한다. 그다음 `C:\Program Files\SafetySecurity`와 `%LOCALAPPDATA%\Programs\SafetySecurity` 폴더가 남아 있으면 지운다. 그러지 않고 '내 계정에만'을 고르면 예전 관리자 작업이 남는다.

## 1. 설치 프로그램으로 설치

먼저 **내 계정에만**으로 설치한다. 관리자 설치는 4장에서 따로 시험한다.

1. Setup을 더블클릭 → '추가 정보' → '실행' → **내 계정에만** → 다음
   - 확인: 권한 요청 창이 안 뜨는지
2. **추가 작업** 화면: '바탕화면 바로가기 만들기'가 **기본으로 켜져 있는지** 보고, 켠 채로 설치한다.
3. 마지막 화면의 "지금 첫 검사하기"를 켠 채로 마침
   - 확인: "검사하고 있어요" 알림이 뜨는지, 검사가 끝나면 그 알림이 사라지고 보고서가 열리는지
4. **바탕화면**: 방패 아이콘의 **SafetySecurity**가 생겼는지, 더블클릭하면 다시 검사하고 보고서가 열리는지
   - 검사 중에 한 번 더 누르면 "다른 검사가 이미 실행 중이에요" 창이 떠야 한다.
5. **시작 메뉴**: 방패 아이콘의 **SafetySecurity**가 있는지, 누르면 바탕화면 아이콘과 똑같이 검사하는지
6. **Win+R**: <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity status` → 상태 창에 아래가 보이는지
   - `데이터 폴더: C:\Users\내이름\AppData\Local\SafetySecurity`
   - 등록된 작업 4개 (`Logon`, `Daily`, `ServiceInstalled`, `Retry`)
   - `알림: 켜져 있어요`
7. **작업 스케줄러**(`taskschd.msc`) → 작업 스케줄러 라이브러리 → `SafetySecurity` 폴더에 작업 4개가 보이면 성공이다.

> `safetysecurity`를 Win+R에서 쓸 수 있는 건 설치 프로그램이 등록해 두었기 때문이다. PowerShell 창에서는 이 이름이 통하지 않으니, PowerShell에서는 설치된 exe의 전체 경로를 쓴다 (예: `& "$env:LOCALAPPDATA\Programs\SafetySecurity\SafetySecurity.exe" status`).

## 2. 안내형 시험 스크립트

1. 받은 zip 파일을 오른쪽 클릭 → **압축 풀기**(모두 압축 풀기)로 푼다. zip 안을 열어 보기만 한 상태에서는 실행되지 않는다.
2. **관리자 PowerShell**을 연다 (시작 메뉴 → PowerShell 오른쪽 클릭 → 관리자 권한으로 실행). 4단계(서비스 설치 시험)에 관리자 권한이 필요하다.
3. **압축을 푼 폴더로 이동**한다. 관리자 PowerShell은 처음에 `C:\Windows\System32`에서 시작하고, `.\tools\…`는 "지금 있는 폴더 안의 파일"이라는 뜻이라 이동하지 않으면 "인식되지 않습니다"나 "찾을 수 없습니다" 오류가 난다.

   ```powershell
   cd "$env:USERPROFILE\Downloads\SafetySecurity-0.2.0-win-x64"
   ```

   > 팁: 폴더 이름은 받은 버전에 따라 다르다 (예: 사전 릴리스는 `SafetySecurity-0.2.0-rc.1-win-x64`). 폴더 이름이 다르면 `cd `(뒤에 띄어쓰기)까지 입력하고, 탐색기에서 압축을 푼 폴더를 PowerShell 창으로 **끌어다 놓은 뒤** Enter를 누르면 된다.

4. `dir`을 입력해서 `SafetySecurity.exe`와 `tools` 폴더가 보이는지 확인한다.
5. 설치된 exe로 시험한다.

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1 -Exe "$env:LOCALAPPDATA\Programs\SafetySecurity\SafetySecurity.exe"
   ```

   `-Exe`를 빼면 zip 안의 `SafetySecurity.exe`(같은 버전)로 시험한다.

스크립트는 단계마다 설명하고 Enter를 기다린다. 다음 순서로 진행한다.

1. **기본 동작**: 버전, 도움말, Windows 파일 서명 확인, 기본 데이터 폴더, 알림 테스트 ("알림이 떴나요?"에 y/n으로 답한다)
2. **가짜 탐지**: 존재하지 않는 GUID로 만든 가짜 COM 등록과, 무해한 명령을 넣은 가짜 Run 항목을 만들고 검사한다. 둘 다 '높음'으로 나오면 통과다. 설치된 SafetySecurity 작업을 위장 작업(`TASK-003`)으로 잘못 보지 않는지도 확인한다. 그다음 보고서가 열리는데, 빨간 카드 2개가 가짜 항목이고 **나머지는 내 PC의 실제 항목**이다. 의심되는 게 있으면 메모해 둔다.
3. **게임 시험**: 게임을 켜고 Enter를 누른 뒤 20초 안에 게임 화면으로 돌아간다. 검사가 미뤄지면 통과다. 게임을 끄면 미뤄둔 검사가 실행되는지 확인한다.
4. **서비스 설치 시험**: 아무 일도 하지 않는 시험 서비스를 잠깐 만들었다가 지운다. 사용자 작업이 깨어났는지 확인한다.
5. **정리**: 가짜 항목은 성공하든 실패하든 **항상** 지운다.

시험용 검사 기록은 임시 폴더에 따로 저장하므로, 설치된 SafetySecurity의 기록(베이스라인)에 섞이지 않는다.
관리자 PowerShell이 아니면 스크립트가 처음에 "관리자 권한으로 다시 열까요?"라고 묻는다.

특정 단계만 다시 하고 싶으면 `-Only`를 붙인다. 예를 들어 4단계만 하려면:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1 -Only 4
```

끝나면 결과가 `%LOCALAPPDATA%\SafetySecurity\pc-test-result.txt`에 저장된다. 이 PC에서 나온 실제 항목(규칙, 위험도, 대상, 서명자)도 함께 기록되므로 오탐인지 판단할 수 있다. 감싼 명령(`cmd /c …`)은 실제로 실행되는 파일의 서명을 적고, 보이는 대상과 실제 대상이 다르다고 본 바로가기가 있으면 따로 적는다. 사용자 이름과 PC 이름은 `<user>`, `<pc>`로 가려져 있다.

## 3. 직접 확인할 것

### 뱅가드 (발로란트)
1. 발로란트를 켜고 경쟁전이나 사격장에 들어간다.
2. Alt+Tab이나 다른 모니터에서 바탕화면의 **SafetySecurity**를 더블클릭하거나, <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity scan --force`를 실행한다. 직접 시작한 검사는 게임 중에도 바로 실행된다.
3. 확인할 것: **VAN 오류가 없는지**, 게임이 튕기지 않는지, 끊김(프레임 드롭)이 없는지, 검사가 끝나면 보고서가 열리는지.
4. 자동 검사가 게임 중에 미뤄지는지는 2장 스크립트의 3단계로 확인한다 (`-Only 3`). 방금 전체 검사를 했으면 하루 한 번 검사는 '방금 검사함'으로 건너뛰므로, 스크립트가 빈 기록 폴더로 따로 시험한다.

### 리소스 사용량
작업 관리자 → 세부 정보 탭에서 `SafetySecurity.exe`를 찾아 검사하는 동안 CPU·디스크를 본다. 첫 검사는 서명 확인 때문에 30~60초쯤 걸릴 수 있고, 두 번째부터는 몇 초 만에 끝나야 한다.

### 실제 PC의 오탐
보고서(또는 `pc-test-result.txt`)에서 특히 아래를 본다.
- **디스코드**: 디스코드를 쓰고 있다면 `DISC-001`이 **없어야** 한다. 있으면 디스코드 종류(일반·PTB·Canary)와 버전, 보고서의 '앞부분' 증거를 알려 준다. BetterDiscord를 설치했다면 `DISC-002`(낮음)가 나오는 게 맞다.
- **바로가기**: 시작프로그램 바로가기가 "표시되는 대상과 실제 실행 대상이 달라요"로 나오면, 그 바로가기를 만든 프로그램 이름을 알려 준다.
- **감싼 명령**: '실제로 실행되는 파일'이 정상 프로그램인데 위험하게 나오면 알려 준다.
- **SafetySecurity 작업**: 설치된 작업이 `TASK-003`이나 `TASK-004`로 나오면 안 된다 (일부러 끄지 않았다면).

### 알림이 꺼져 있을 때 (선택)
1. 설정 → 시스템 → 알림 → **SafetySecurity**를 끈다.
2. 바탕화면의 SafetySecurity로 검사한다.
3. 확인: 보고서의 **확인하지 못한 것**에 "새 항목을 알려드릴 수 없어요"와 켜는 법이 있는지, <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity status`에 `알림:` 줄이 꺼진 이유로 나오는지
4. 다시 SafetySecurity 알림을 켠다.

### 숨기기 (Win+R 메시지 창)
1. <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity ignore 12345678` → "찾지 못했어요" 같은 거절 창이 뜨고 아무것도 숨기지 않는지
2. 보고서에 항목이 있다면, 그 항목의 숨기기 명령을 앞 8자리만 적어서 실행한다 (예: `safetysecurity ignore 4d446635`).
   - 확인: 항목의 위험도와 제목을 보여 주고 예/아니요로 묻는지. **아니요**를 누르면 아무것도 바뀌지 않아야 한다.
3. 숨겼다면 `safetysecurity ignored`로 목록에 보이는지, `safetysecurity unignore <ID>`로 되돌려지는지

### 꺼진 SafetySecurity 작업 (선택)
1. 작업 스케줄러 → `SafetySecurity` 폴더 → `Retry` 오른쪽 클릭 → **사용 안 함**
2. 바탕화면의 SafetySecurity로 검사한다 → 보고서에 `TASK-004`(보통) "꺼져 있어요" 항목과 다시 켜는 법이 있는지
3. `Retry` 오른쪽 클릭 → **사용**으로 다시 켠다. 다음 검사에서 그 항목이 사라진다.

### 며칠 사용해 보기
- 평소처럼 쓰다가 알림이 오면 보고서를 열어 본다.
- <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity status`로 마지막 검사와 미뤄둔 검사를 확인한다. 게임을 오래 켜 둬서 검사가 하루 넘게 밀리면 몇 시간 밀렸는지 나오고, "검사가 밀렸어요" 알림이 한 번 떠야 한다.
- `%LOCALAPPDATA%\SafetySecurity\logs\scan.log`에서 언제 검사했고, 언제 미루거나 건너뛰었는지(방금 검사함, 다른 검사와 겹침) 볼 수 있다.

## 4. 관리자 권한으로 다시 설치

1. **(선택) 다른 방식 거절**: 아직 '내 계정에만' 설치가 있을 때, 일반 PowerShell에서 Setup을 `/ALLUSERS`로 실행한다 (파일 이름은 받은 버전에 맞게 바꾼다).

   ```powershell
   & "$env:USERPROFILE\Downloads\SafetySecurity-Setup-0.2.0.exe" /ALLUSERS
   ```

   권한 요청 창에서 '예'를 누르면 "SafetySecurity가 이미 '내 계정에만' 설치돼 있어요" 창이 뜨고, 아무것도 바뀌지 않아야 한다 (앱 목록에 SafetySecurity가 하나뿐인지 확인한다).
2. **제거**: 설정 → 앱 → 설치된 앱 → SafetySecurity → 제거 → "검사 기록과 보고서도 지울까요?"에서 **아니요**
   - 확인: 시작 메뉴와 **바탕화면 아이콘**이 사라졌는지, 작업 스케줄러의 `SafetySecurity` 폴더가 비었는지, `%LOCALAPPDATA%\Programs\SafetySecurity` 폴더가 없어졌는지, `%LOCALAPPDATA%\SafetySecurity`(검사 기록)는 남았는지
3. **설치**: Setup → **관리자 권한으로** → 권한 요청 창에서 '예' → 추가 작업에서 바탕화면 바로가기를 켠 채로 설치
   - 확인: `C:\Program Files\SafetySecurity`에 설치됐는지, 작업 스케줄러에 `Admin` 작업이 있는지, 바탕화면 아이콘이 **모든 사용자 바탕화면**(`C:\Users\Public\Desktop`)에 생겼는지
4. **관리자 검사**: 게임과 무거운 프로그램을 끈 채로 작업 스케줄러 → `SafetySecurity` → `Admin` 오른쪽 클릭 → **실행** → 1~2분 기다린다 (바쁘면 검사가 미뤄진다).
   - 확인: `C:\Program Files\SafetySecurity\data\reports`에 `_admin` 보고서가 생겼는지 (관리자 검사 기록은 이제 여기 있다)
   - 확인: <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity status`에 `관리자 검사 데이터 폴더: C:\Program Files\SafetySecurity\data`와 `[관리자 검사]`가 보이는지
   - 확인: 탐색기에서 그 `data` 폴더에 새 파일을 만들려고 하면 관리자 권한을 요구하는지 (일반 사용자는 바꿀 수 없어야 한다)
   - 관리자 보고서에 항목이 있다면, 보고서의 숨기기 명령(`--scope admin`)을 Win+R로 실행해 **UAC 창**이 뜨는지
5. (선택) 서비스 설치 시험: zip을 푼 폴더의 관리자 PowerShell에서
   `powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1 -Exe "C:\Program Files\SafetySecurity\SafetySecurity.exe" -Only 4`
6. **게임과 함께**: 발로란트를 켠 채로 바탕화면의 SafetySecurity를 누른다. VAN 오류, 튕김, 끊김이 없는지 확인한다.
7. **제거**: 설정 → 앱에서 제거한다.
   - 확인: 기록을 지울지 **묻지 않고**, 끝에 관리자 검사 기록은 지웠고 내 계정의 검사 기록 폴더(`%LOCALAPPDATA%\SafetySecurity`)는 안전을 위해 지우지 않았다는 안내 창이 뜨는지
   - 확인: `C:\Program Files\SafetySecurity` 폴더(관리자 검사 기록 포함)와 모든 사용자 바탕화면의 아이콘이 사라졌는지
8. 다 끝나면 원하는 방식으로 다시 설치해서 쓰면 된다.

## 5. 결과 알려주기

- 시험 결과: `pc-test-result.txt` 내용과, 1장·3장·4장에서 무엇이 달랐는지를 [버그 신고](https://github.com/jiyul-me/safety-security/issues/new?template=bug_report.yml)나 대화에 붙여 준다. 캡처가 있으면 더 좋다.
- 정상 프로그램이 잡혔다면: [오탐 신고](https://github.com/jiyul-me/safety-security/issues/new?template=false_positive.yml)
- 실제로 의심스러운 게 나왔다면: 지우기 전에 보고서의 "확인하는 법"을 먼저 따라 한다. 이 프로그램은 아무것도 지우지 않는다.

## 지우고 싶을 때

설치 프로그램으로 설치했다면 설정 → 앱 → 설치된 앱 → **SafetySecurity** → 제거하면 끝이다. 예약 작업과 파일까지 지워진다.
관리자 설치였다면 관리자 검사 기록(`C:\Program Files\SafetySecurity\data`)도 지워지고, 내 계정의 `%LOCALAPPDATA%\SafetySecurity`는 남는다. 필요 없으면 직접 지운다.

zip으로 설치했다면 압축을 푼 폴더에서:

```powershell
.\SafetySecurity.exe uninstall --purge
```

관리자로 설치했다면 관리자 PowerShell에서 실행하고(이때 `--purge`는 관리자 검사 기록만 지운다), 마지막에 안내하는 폴더를 직접 지우면 끝이다.
