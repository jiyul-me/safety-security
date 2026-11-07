# Changelog

이 프로젝트의 주요 변경 사항이에요. 형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고,
버전은 [유의적 버전(SemVer)](https://semver.org/lang/ko/)을 따라요.

## [Unreleased]

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
