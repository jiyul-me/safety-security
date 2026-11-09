# Changelog

이 프로젝트의 주요 변경 사항이에요. 형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고,
버전은 [유의적 버전(SemVer)](https://semver.org/lang/ko/)을 따라요.

## [Unreleased]

### 추가
- 설치 프로그램 `SafetySecurity-Setup-<버전>.exe` (Inno Setup): 더블클릭으로 설치하고 '내 계정에만'(권한 요청 없음)이나 '관리자 권한으로'(더 깊게 검사)를 골라요. 시작 메뉴와 설정 → 앱 목록에 등록되고, 제거하면 예약 작업과 파일까지 지워요. PowerShell이 필요 없어요.
- 시작 메뉴나 더블클릭으로 직접 검사할 때 "검사하고 있어요" 알림을 띄우고, 끝나면 지워요
- Win+R에서 `safetysecurity <명령>`으로 실행 (설치 프로그램이 App Paths를 등록해요)
- 앱 아이콘 (방패)
- 공통 옵션 `--quiet`: 메시지 없이 종료 코드만 돌려줘요 (설치 프로그램용)
- CI가 설치 프로그램을 빌드하고, 두 방식으로 조용히 설치·다시 설치·제거해서 확인해요

### 변경
- 릴리스 파일: 설치 프로그램, zip(명령줄·시험용), `SHA256SUMS.txt`. exe 단독 파일은 빠졌어요 (zip 안에 있어요). 출처 증명은 설치 프로그램, zip, exe에 모두 붙어서 설치된 exe도 `gh attestation verify`로 확인할 수 있어요
- 보고서의 숨기기 안내: 설치 프로그램으로 설치했으면 Win+R 방법으로 보여줘요
- 검사가 이미 실행 중일 때 직접 검사를 누르면 메시지 창으로 알려줘요
- 작업 등록에 실패하면 원인을 `logs\scan.log`에도 남겨요
- 메시지 창(`status` 등)을 항상 맨 앞에 띄워요. Win+R로 실행하면 몇 초 뒤 뜬 창이 다른 창 뒤에 숨을 수 있었어요 (rc.1 시험에서 발견)
- 제거할 때 실행 중인 SafetySecurity를 먼저 끝내서 exe가 남지 않게 해요

- "검사하고 있어요" 알림을 못 띄우면 이유(설치 안 됨, 앱 알림 꺼짐, 오류)를, 콘솔 없이 실행한 명령은 그 이름을 `logs\scan.log`에 남겨요

### 고침
- Win+R·시작 메뉴처럼 콘솔 없이 실행하면 출력이 "파일로 연결됐다"고 잘못 판단해서, `status` 같은 메시지 창과 "검사하고 있어요" 알림이 뜨지 않던 문제. 이제 표준 출력이 진짜 파일이나 파이프일 때만 콘솔로 봐요 (rc.2 시험에서 발견)
- 관리자 검사 보고서의 숨기기 명령에 `--scope admin`이 빠져 있어서, 안내대로 해도 관리자 검사 항목이 숨겨지지 않던 문제

## [0.1.0] - 2026-11-07

첫 정식 버전이에요. 실제 Windows 11 게임 PC(뱅가드 사용)에서 사전 릴리스 두 번(rc.1, rc.2)으로 시험했고, 찾은 오탐을 모두 고친 뒤 냈어요.

### 추가
- 읽기 전용 Windows 지속성 검사기 (NativeAOT 단일 exe, .NET 10)
- 스캐너 10개: COM 하이재킹(HKCU CLSID), 자동 실행(Run·시작프로그램·Winlogon·AppInit·AppCert·IFEO·SilentProcessExit·로그온 스크립트·cmd AutoRun), 서비스·드라이버, 예약 작업, 숨겨진 작업(관리자), 브라우저 정책·바로가기·프록시, Defender 정책·제외, hosts, WMI 구독(관리자), 사용자 폴더의 새 실행 파일
- 오프라인 Authenticode + Windows 카탈로그 서명 확인과 캐시
- 작업 스케줄러 연동 (로그온, 매일, 서비스 설치 이벤트 7045, 30분 재시도), 게임·전체 화면·높은 CPU 사용률일 때 연기
- 베이스라인 비교, 무시 목록, HTML·JSON 보고서, 토스트 알림
- 금지 API 분석기와 금지 P/Invoke 테스트로 읽기 전용·오프라인·안티치트 안전 원칙 강제
- 내 PC 시험 스크립트 `tools/Test-OnMyPC.ps1`: 존재하지 않는 GUID의 가짜 항목으로 탐지를 확인하고 항상 정리, 관리자 권한으로 다시 열기, `-Only`로 단계 골라 실행, 사용자 이름을 가린 결과 파일
- CI (Linux 단위 테스트, Windows NativeAOT + 통합 테스트), 출처 증명이 붙은 릴리스 워크플로 (태그 push 또는 Actions 화면에서 시작)

### 실제 PC 시험에서 다듬은 것
- Store·MSIX 앱 설치 폴더(`WindowsApps`, `SystemApps`)의 파일은 파일 단위 서명이 없어도 의심하지 않아요 (그림판 `COM-002` 오탐)
- `COM-004` TreatAs가 연결된 대상 클래스의 실행 파일까지 확인해요. 대상이 정상이면 보고하지 않아요 (그림판 `COM-004` 오탐)
- `TASK-001`: Microsoft 작업이 Windows 폴더의 없는 파일을 가리키면 업데이트가 남긴 흔적으로 보고 넘어가요 (`USO_UxBroker` → `MusNotification.exe`)
- `SVC-001`: 따옴표 없는 서비스 경로는 끼워 넣을 위치를 일반 사용자가 쓸 수 있을 때만 보고해요 (Riot Vanguard `vgc` 오탐)
- `%TEMP%`가 8.3 짧은 이름(`C:\Users\RUNNER~1\…`)이어도 임시 폴더로 올바르게 분류해요 (CI에서 발견)

### 확인됨 (Windows 11 build 26300)
- 알림 표시, 발로란트 전체 화면(D3D) 감지로 검사 연기, 뱅가드와 함께 실행해도 VAN 오류·튕김·끊김 없음
- 일반 사용자 작업이 새 서비스 설치 이벤트(7045)로 깨어남
- rc.2 시험에서 이 PC의 실제 항목 0개 (일부러 만든 가짜 시험 항목만 '높음'으로 탐지)

[Unreleased]: https://github.com/jiyul-me/safety-security/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jiyul-me/safety-security/releases/tag/v0.1.0
