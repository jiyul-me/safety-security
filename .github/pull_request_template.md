## 요약 / Summary

<!-- 무엇을 왜 바꿨는지 적어 주세요. 관련 이슈가 있으면 함께 적어 주세요 (Closes #).
     What changed and why? Link the related issue if there is one (Closes #). -->

## 변경 종류 / Type

- [ ] 새 탐지 규칙 / New detection rule (`rule`)
- [ ] 기능 / Feature (`feat`)
- [ ] 버그 수정 / Bug fix (`fix`)
- [ ] 문서 / Docs (`docs`)
- [ ] CI·빌드 / CI and build (`ci` / `chore`)

## 안전 원칙 / Safety rules

- [ ] 시스템을 바꾸지 않습니다 (레지스트리·파일은 읽기만 하고, 쓰기는 자기 데이터 폴더에만 합니다). / Does not change the system (reads only; writes go to its own data folder).
- [ ] 네트워크를 쓰지 않습니다. / Uses no network.
- [ ] 드라이버, 다른 프로세스 열기·메모리 접근, 주입, 후킹을 쓰지 않습니다. / No drivers, no opening other processes or reading their memory, no injection, no hooks.
- [ ] 새 Win32 함수를 썼다면 `ForbiddenApiTests` 목록에 걸리지 않는지 확인했습니다. / Any new Win32 function was checked against `ForbiddenApiTests`.

## 테스트 / Tests

- [ ] `dotnet test` 통과 / `dotnet test` passes
- [ ] 새 규칙이면 가짜 레지스트리·파일 시스템으로 단위 테스트를 추가했습니다. / New rules come with unit tests on the fake registry and file system.
- [ ] 오탐 가능성을 검토했습니다 (어떤 정상 프로그램이 걸릴 수 있는지). / False positives were considered (which legitimate programs could match?).
