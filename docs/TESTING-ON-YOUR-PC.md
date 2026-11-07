# 내 PC에서 시험하기

CI(GitHub의 Windows 서버)로는 확인할 수 없는 것들을 실제 PC에서 확인하는 순서예요. 30분쯤 걸려요.

| CI로 확인한 것 | PC에서 확인할 것 |
|---|---|
| 빌드, 단위 테스트 90여 개, 가짜 COM 하이재킹·Run 키 탐지, 베이스라인, 무시 목록, 게임 프로세스로 연기, 작업 등록과 삭제, 설치 프로그램 조용히 설치·다시 설치·제거 (두 방식 모두) | 알림이 실제로 화면에 뜨는지, **전체 화면 게임** 감지, **뱅가드와 함께** 써도 괜찮은지, 일반 사용자 작업이 **서비스 설치 이벤트**로 깨어나는지, 실제 PC의 **오탐** 개수, **설치 프로그램** 화면·시작 메뉴·제거 |

## 0. 준비

1. [Releases](https://github.com/jiyul-me/safety-security/releases)에서 가장 최근 `SafetySecurity-…-win-x64.zip`을 받아 압축을 풀어요.
   (사전 릴리스 `-rc`도 괜찮아요. 아직 릴리스가 없으면 [Actions](https://github.com/jiyul-me/safety-security/actions/workflows/ci.yml) → 최근 성공한 실행 → Artifacts에서 받아도 돼요.)
2. 처음 실행할 때 **SmartScreen**("Windows의 PC 보호")이 뜨면 '추가 정보' → '실행'을 눌러요. 코드 서명 인증서가 없어서 생기는 일이에요.
3. Defender가 파일을 지웠다면 Windows 보안 → 보호 기록에서 어떤 이름으로 탐지했는지 메모해 주세요 (그것도 중요한 결과예요).

## 1. 설치

1. 받은 zip 파일을 오른쪽 클릭 → **압축 풀기**(모두 압축 풀기)로 풀어요. zip 안을 열어 보기만 한 상태에서는 실행되지 않아요.
2. **관리자 PowerShell**을 열어요 (시작 메뉴 → PowerShell 오른쪽 클릭 → 관리자 권한으로 실행).
3. **압축을 푼 폴더로 이동**해요. PowerShell은 처음에 `C:\Users\내이름`에서 시작하고, `.\SafetySecurity.exe`는 "지금 있는 폴더 안의 파일"이라는 뜻이라 이동하지 않으면 "인식되지 않습니다" 오류가 나요.

   ```powershell
   cd "$env:USERPROFILE\Downloads\SafetySecurity-0.1.0-win-x64"
   ```

   > 팁: 폴더 이름은 받은 버전에 따라 달라요 (예: 사전 릴리스는 `SafetySecurity-0.2.0-rc.1-win-x64`). 폴더 이름이 다르면 `cd `(뒤에 띄어쓰기)까지 입력하고, 탐색기에서 압축을 푼 폴더를 PowerShell 창으로 **끌어다 놓은 뒤** Enter를 누르면 돼요.

4. `dir`을 입력해서 `SafetySecurity.exe`와 `tools` 폴더가 보이는지 확인해요.
5. 설치해요. 명령은 항상 **`.\`(점 + 역슬래시)** 로 시작해요.

   ```powershell
   .\SafetySecurity.exe install --admin
   ```

작업 스케줄러(`taskschd.msc`) → 작업 스케줄러 라이브러리 → `SafetySecurity` 폴더에 작업 5개(Logon, Daily, ServiceInstalled, Retry, Admin)가 보이면 성공이에요.

## 2. 안내형 시험 스크립트

같은 관리자 PowerShell, 같은 폴더에서:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1
```

스크립트는 단계마다 설명하고 Enter를 기다려요. 이런 순서로 진행해요.

1. **기본 동작**: 버전, Windows 파일 서명 확인, 알림 테스트 ("알림이 떴나요?"에 y/n으로 답해요)
2. **가짜 탐지**: 존재하지 않는 GUID로 만든 가짜 COM 등록과, 무해한 명령을 넣은 가짜 Run 항목을 만들고 검사해요. 둘 다 '높음'으로 나오면 통과예요. 그다음 보고서가 열리는데, 빨간 카드 2개가 가짜 항목이고 **나머지는 내 PC의 실제 항목**이에요. 의심되는 게 있으면 메모해 두세요.
3. **게임 시험**: 게임을 켜고 Enter를 누른 뒤 20초 안에 게임 화면으로 돌아가요. 검사가 미뤄지면 통과예요. 게임을 끄면 미뤄둔 검사가 실행되는지 확인해요.
4. **서비스 설치 시험**: 아무 일도 하지 않는 시험 서비스를 잠깐 만들었다가 지워요. 사용자 작업이 깨어났는지 확인해요.
5. **정리**: 가짜 항목은 성공하든 실패하든 **항상** 지워요.

관리자 PowerShell이 아니면 스크립트가 처음에 "관리자 권한으로 다시 열까요?"라고 물어봐요. 4단계는 관리자 권한이 있어야 해요.

특정 단계만 다시 하고 싶으면 `-Only`를 붙여요. 예를 들어 4단계만 하려면:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1 -Only 4
```

끝나면 결과가 `%LOCALAPPDATA%\SafetySecurity\pc-test-result.txt`에 저장돼요. 이 PC에서 나온 실제 항목(규칙, 위험도, 대상, 서명자)도 함께 기록돼서 오탐인지 판단할 수 있어요. 사용자 이름과 PC 이름은 `<user>`, `<pc>`로 가려져 있어요.

## 3. 직접 확인할 것

### 뱅가드 (발로란트)
1. 발로란트를 켜고 경쟁전이나 사격장에 들어가요.
2. 다른 모니터나 Alt+Tab으로 관리자 PowerShell을 열고 `SafetySecurity.exe scan --force`를 실행해요. 게임 중이어도 일부러 검사하는 거예요.
3. 확인할 것: **VAN 오류가 없는지**, 게임이 튕기지 않는지, 끊김(프레임 드롭)이 없는지.
4. `--force` 없이 `SafetySecurity.exe scan --reason daily`를 실행하면 "검사를 미뤘어요"가 나와야 해요.

### 리소스 사용량
작업 관리자 → 세부 정보 탭에서 `SafetySecurity.exe`를 찾아 검사하는 동안 CPU·디스크를 봐요. 첫 검사는 서명 확인 때문에 30~60초쯤 걸릴 수 있고, 두 번째부터는 몇 초 만에 끝나야 해요.

### 며칠 사용해 보기
- 평소처럼 쓰다가 알림이 오면 보고서를 열어 봐요.
- `SafetySecurity.exe status`로 마지막 검사와 미뤄둔 검사를 확인해요.
- `%LOCALAPPDATA%\SafetySecurity\logs\scan.log`에서 언제 검사했고 언제 미뤘는지 볼 수 있어요.

## 4. 결과 알려주기

- 시험 결과: `pc-test-result.txt` 내용을 [버그 신고](https://github.com/jiyul-me/safety-security/issues/new?template=bug_report.yml)나 대화에 붙여 주세요.
- 정상 프로그램이 잡혔다면: [오탐 신고](https://github.com/jiyul-me/safety-security/issues/new?template=false_positive.yml)
- 실제로 의심스러운 게 나왔다면: 지우기 전에 보고서의 "확인하는 법"을 먼저 따라 하세요. 이 프로그램은 아무것도 지우지 않아요.

## 5. 설치 프로그램 시험 (v0.2.0부터)

PowerShell 없이 쓰는 방법이 잘 되는지 확인해요. 사전 릴리스(`-rc`)의 `SafetySecurity-Setup-….exe`로 해요.

**먼저 예전 수동 설치 지우기** (zip으로 `install`을 했던 PC만): 예전 압축 폴더에서 관리자 PowerShell로 `.\SafetySecurity.exe uninstall`을 실행해요. 그다음 `C:\Program Files\SafetySecurity`와 `%LOCALAPPDATA%\Programs\SafetySecurity` 폴더가 남아 있으면 지워요.

1. **설치**: Setup을 더블클릭 → '추가 정보' → '실행' → **내 계정에만** → 설치 → 마지막 화면의 "지금 첫 검사하기"를 켠 채로 마침
   - 확인: 권한 요청 창이 안 뜨는지, "검사하고 있어요" 알림이 뜨는지, 검사가 끝나면 그 알림이 사라지고 보고서가 열리는지
2. **시작 메뉴**: 방패 아이콘의 **SafetySecurity**가 있는지, 누르면 다시 검사하고 보고서가 열리는지
   - 검사 중에 한 번 더 누르면 "다른 검사가 이미 실행 중이에요" 창이 떠야 해요.
3. **Win+R**: <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity status` → 상태 창에 등록된 작업 4개가 보이는지
4. **제거**: 설정 → 앱 → 설치된 앱 → SafetySecurity → 제거 → "검사 기록과 보고서도 지울까요?"에서 **아니요**
   - 확인: 시작 메뉴에서 사라졌는지, 작업 스케줄러의 `SafetySecurity` 폴더가 비었는지, `%LOCALAPPDATA%\Programs\SafetySecurity` 폴더가 없어졌는지
5. **관리자 권한으로 다시 설치**: Setup → **관리자 권한으로** → 권한 요청 창에서 '예' → 설치
   - 확인: `C:\Program Files\SafetySecurity`에 설치됐는지, 작업 스케줄러에 `Admin` 작업이 있는지
   - (선택) 서비스 설치 시험: zip을 푼 폴더의 관리자 PowerShell에서 `powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1 -Exe "C:\Program Files\SafetySecurity\SafetySecurity.exe" -Only 4`
6. **게임과 함께**: 발로란트를 켠 채로 시작 메뉴의 SafetySecurity를 눌러요. 직접 검사는 게임 중에도 바로 해요. VAN 오류, 튕김, 끊김이 없는지 확인해요.
7. 다 끝나면 그대로 써도 되고, 설정 → 앱에서 제거해도 돼요.

어느 단계에서 무엇이 달랐는지 대화나 이슈에 적어 주세요. 캡처가 있으면 더 좋아요.

## 지우고 싶을 때

설치 프로그램으로 설치했다면 설정 → 앱 → 설치된 앱 → **SafetySecurity** → 제거하면 끝이에요. 예약 작업과 파일까지 지워요.

zip으로 설치했다면:

```powershell
.\SafetySecurity.exe uninstall --purge
```

관리자로 설치했다면 관리자 PowerShell에서 실행하고, 마지막에 안내하는 폴더를 직접 지우면 끝이에요.
