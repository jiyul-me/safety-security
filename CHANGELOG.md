# Changelog

이 프로젝트의 주요 변경 사항이에요. 형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고,
버전은 [유의적 버전(SemVer)](https://semver.org/lang/ko/)을 따라요.

## [Unreleased]

## [0.1.0] - 첫 버전

### 추가
- 읽기 전용 Windows 지속성 검사기 (NativeAOT 단일 exe, .NET 10)
- 스캐너 10개: COM 하이재킹(HKCU CLSID), 자동 실행(Run·시작프로그램·Winlogon·AppInit·AppCert·IFEO·SilentProcessExit·로그온 스크립트·cmd AutoRun), 서비스·드라이버, 예약 작업, 숨겨진 작업(관리자), 브라우저 정책·바로가기·프록시, Defender 정책·제외, hosts, WMI 구독(관리자), 사용자 폴더의 새 실행 파일
- 오프라인 Authenticode + Windows 카탈로그 서명 확인과 캐시
- 작업 스케줄러 연동 (로그온, 매일, 서비스 설치 이벤트 7045, 30분 재시도), 게임·전체 화면·높은 CPU 사용률일 때 연기
- 베이스라인 비교, 무시 목록, HTML·JSON 보고서, 토스트 알림
- 금지 API 분석기와 금지 P/Invoke 테스트로 읽기 전용·오프라인·안티치트 안전 원칙 강제
- CI (Linux 단위 테스트, Windows NativeAOT + 통합 테스트), 출처 증명이 붙은 릴리스 워크플로

[Unreleased]: https://github.com/jiyul-me/safety-security/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jiyul-me/safety-security/releases/tag/v0.1.0
