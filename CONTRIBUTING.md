# 기여 안내 / Contributing

SafetySecurity에 관심을 가져 줘서 고맙다. 오탐 신고 한 건도 큰 도움이 된다.

- 정상 프로그램이 잡혔다면 → [오탐 신고](https://github.com/jiyul-me/safety-security/issues/new?template=false_positive.yml)
- 새 수법을 잡고 싶다면 → [탐지 아이디어](https://github.com/jiyul-me/safety-security/issues/new?template=detection_idea.yml)
- 검사기를 우회하는 방법을 찾았다면 → 공개 이슈 대신 [비공개 보안 신고](SECURITY.md)

## 지켜야 할 원칙

SafetySecurity의 존재 이유다. 이 원칙을 어기는 PR은 받을 수 없다.

1. **읽기 전용**: 시스템 레지스트리·파일을 만들거나 바꾸거나 지우지 않는다. 쓰기는 자기 데이터 폴더(`DataStore`)와 사용자가 직접 실행한 `install`/`uninstall`(`TaskInstaller`)에서만 한다. 관리자 권한 프로세스는 사용자가 쓸 수 있는 폴더를 쓰지 않는다 (`DataRoots`).
2. **오프라인**: 네트워크 코드를 넣지 않는다. 서명 확인도 폐기 확인을 끈 채로 한다. 네트워크 경로(공유 폴더, WebDAV, 네트워크 드라이브)의 파일은 열지도 않는다 (`ctx.Files`·`ctx.Signatures`가 막는다).
3. **안티치트 안전**: 커널 드라이버, 다른 프로세스 열기(`OpenProcess`), 프로세스 목록·트리 종료(`Process.GetProcesses`, `Process.Kill(bool)`), 메모리 읽기·쓰기, 코드 주입, 후킹을 쓰지 않는다.
4. **가볍게**: 단일 스레드로 돌리고, 반복문 안에서는 `ctx.Pacer.Step()`을 부르고, 비싼 작업(서명·해시)은 캐시한다.

빌드(`BannedSymbols.txt`)와 테스트(`ForbiddenApiTests`)가 이 원칙을 자동으로 검사한다.

## 브랜치 전략 (GitHub Flow)

```
main ─────●──────────●──────────●───── (항상 릴리스 가능, 태그 v0.2.0 …)
           \        /  \        /
   feat/hosts-ipv6 ●    rule/appinit-wow64 ●
```

- `main`은 보호된다: 직접 push 금지, PR과 CI 통과 필수, **squash merge**만 허용한다.
- 작업은 `main`에서 새 브랜치를 만들어서 한다. 이름 규칙:

| 접두사 | 용도 | 예 |
|---|---|---|
| `feat/` | 기능 | `feat/json-export` |
| `rule/` | 새 탐지 규칙·규칙 수정 | `rule/com-treatas-wow64` |
| `fix/` | 버그·오탐 수정 | `fix/discord-false-positive` |
| `docs/` | 문서 | `docs/detections-table` |
| `ci/` | 워크플로·빌드 | `ci/arm64-release` |
| `chore/` | 그 밖의 정리 | `chore/deps` |

### 커밋·PR 제목 ([Conventional Commits](https://www.conventionalcommits.org/ko/v1.0.0/))

```
feat(scanner): detect AppInit_DLLs in WOW64 view
fix(com): ignore signed OneDrive shell extensions
docs: add Vanguard test steps
```

squash merge를 하므로 **PR 제목**이 `main`의 커밋 메시지가 된다. PR 제목은 위 형식으로 쓴다.

### 릴리스

1. `CHANGELOG.md`의 `[Unreleased]`를 새 버전으로 옮기는 PR을 머지한다.
2. 둘 중 편한 방법으로 릴리스를 시작한다 (`v0.2.0-rc.1`처럼 `-`가 있으면 사전 릴리스):
   - **Actions** 탭 → **Release** → **Run workflow** → Branch `main`, 버전에 `v0.2.0` 입력 → Run
   - 또는 `main`에서 태그 push: `git tag v0.2.0 && git push origin v0.2.0`
3. Release 워크플로가 테스트 → NativeAOT 빌드 → 통합 테스트 → 설치 프로그램 빌드·설치 시험 → 설치 프로그램(`SafetySecurity-Setup-<버전>.exe`)·zip·SHA256·출처 증명이 붙은 **초안 릴리스**를 만든다. 설치 프로그램은 `installer/SafetySecurity.iss`(Inno Setup)로 만들고, 그 안의 `AppId`는 절대 바꾸지 않는다. 릴리스 노트는 `CHANGELOG.md`의 해당 버전 섹션(사전 릴리스는 `[Unreleased]`)과 파일 확인법으로 채워진다 (`.github/scripts/release-notes.ps1`).
4. 초안을 확인하고 "Publish release"를 누른다. (Actions에서 시작했다면 이때 태그가 만들어진다.)

릴리스 실행이 실패하면 그 실행에서 **Re-run jobs**를 누른다 (같은 커밋). 반쯤 만들어진 초안을 그대로 써서 세 파일(설치 프로그램, zip, `SHA256SUMS.txt`)을 모두 다시 올리고, 초안의 노트는 그대로 둔다. 마지막 단계가 올라간 파일이 빌드와 같은지 확인한다.

- 같은 버전을 더 새로운 `main`에서 다시 시작하면 안 된다. 태그 `vX.Y.Z`가 이미 다른 커밋을 가리키면 워크플로가 실패한다. 새 커밋으로 릴리스하려면 태그를 옮기거나 지우거나, 새 버전 번호를 쓰면 된다.
- 태그를 push하기 전에 웹 화면에서 초안을 먼저 만들어 두었다면, 빌드한 파일로 채우고 그 노트는 그대로 둔다.
- 같은 버전의 실행은 한 번에 하나씩만 돈다 (concurrency group).

## 개발 환경

- [.NET 10 SDK](https://dotnet.microsoft.com/download) (macOS·Linux·Windows 모두에서 쓸 수 있다)
- Windows에서 NativeAOT exe를 만들려면 Visual Studio Build Tools의 "C++를 사용한 데스크톱 개발" 구성 요소가 필요하다.

```bash
dotnet build SafetySecurity.slnx
dotnet test tests/SafetySecurity.Core.Tests
```

- `*.ps1`(`tests/integration`, `tools`, `.github/scripts`)와 `installer/*.iss`는 **UTF-8 BOM + CRLF**로 저장한다. BOM이 없으면 Windows PowerShell 5.1과 Inno Setup이 한국어를 깨진 글자로 읽는다. `ScriptEncodingTests`가 BOM을 검사하고, 통합 시험 스크립트는 잘못 읽히면 시작하자마자 멈춘다.
- 그 밖의 `*.cs`·`*.md`·`*.yml`은 BOM 없는 UTF-8 + LF로 저장한다.

## 새 탐지 규칙 만들기

1. `src/SafetySecurity.Core/Scanners/`에 `IScanner`를 구현한다. 기존 스캐너(예: `HostsScanner`)가 가장 단순한 예시다.
   - 레지스트리는 `ctx.Registry`, 파일은 `ctx.Files`, 서명은 `ctx.Signatures`로만 읽는다. 네트워크 경로는 이 보기들이 막아 준다.
   - 목록이나 파일을 끝까지 읽지 못했으면 `ctx.Coverage.Incomplete(분류, 무엇, 왜)`로 남긴다. 그래야 그 분류가 깨끗한 것처럼 보이지 않고, 베이스라인의 예전 항목도 지워지지 않는다.
   - 실행 파일 평가는 `ExecutableAssessor`, 명령줄 평가는 `CommandAssessor`를 다시 쓴다.
   - 규칙 ID는 `분류-번호`(예: `RUN-010`)로 새로 붙이고 `docs/DETECTIONS.md`에 적는다.
   - `Reasons`에는 "왜 의심스러운지"를 한국어 한 문장으로, `Advice`에는 사용자가 직접 확인하는 법을 적는다.
2. `ScanEngine.AllScanners()`에 추가한다.
3. `tests/SafetySecurity.Core.Tests/`에 `FakeRegistry`·`FakeFileSystem`으로 **탐지되는 경우와 정상 프로그램이 탐지되지 않는 경우**를 둘 다 테스트한다.
4. 정말 Windows가 필요한 부분이면 `tests/integration/Run-Integration.ps1`에 가짜 항목을 만들고 지우는 시험을 추가한다.

---

## English (short)

- Rules: read-only, offline, anti-cheat safe (no drivers, no `OpenProcess`, no memory access, no injection, no hooks), lightweight. These are enforced by `BannedSymbols.txt` and `ForbiddenApiTests`.
- Branching: GitHub Flow. Protected `main`, short-lived branches (`feat/`, `rule/`, `fix/`, `docs/`, `ci/`, `chore/`), squash merge, Conventional Commits PR titles.
- Releases: tag `vX.Y.Z` on `main` → the Release workflow builds, tests and drafts a release with SHA-256 sums and build provenance.
- New scanners live in `src/SafetySecurity.Core/Scanners`, must use the read-only views on `ScanContext`, and need unit tests for both a detection and a benign case.
