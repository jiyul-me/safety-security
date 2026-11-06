# 저장소 관리 (관리자용)

GitHub 설정 중에는 파일로 커밋할 수 없어서 직접 눌러야 하는 것들이 있어요. 처음 한 번만 하면 돼요.

## 1. 기본 브랜치

Settings → General → **Default branch** → ⇄ 버튼 → `main` → Update

## 2. 머지 방식

Settings → General → **Pull Requests**
- ☑ Allow squash merging → Default commit message: **Pull request title**
- ☐ Allow merge commits
- ☐ Allow rebase merging
- ☑ Always suggest updating pull request branches
- ☑ **Automatically delete head branches**

## 3. main 보호 규칙 (Ruleset)

Settings → Rules → **Rulesets** → New ruleset ▾ → **Import a ruleset** → `.github/rulesets/main.json` 선택 → Create

이 규칙이 하는 일:
- `main` 삭제·강제 push 금지, 선형 히스토리
- PR로만 머지, 리뷰 대화가 모두 해결돼야 머지, squash만 허용
- CI의 `Core tests (Linux)`, `Windows build + integration`이 통과해야 머지

> 비공개 저장소에서는 Ruleset이 GitHub Pro 이상에서만 적용돼요. 학생이라면 [GitHub Student Developer Pack](https://education.github.com/pack)으로 Pro를 무료로 쓸 수 있어요. 저장소를 공개로 바꾸면 무료 플랜에서도 바로 적용돼요.

## 4. 보안 기능 (공개 전후)

Settings → **Code security**
- ☑ Private vulnerability reporting (SECURITY.md의 비공개 신고 링크가 이걸 써요)
- ☑ Dependabot alerts, Dependabot security updates
- ☑ Secret scanning, Push protection
- CodeQL은 `.github/workflows/codeql.yml`이 공개된 뒤 자동으로 돌아요.

## 5. 라벨

자동 릴리스 노트(`.github/release.yml`)와 이슈 템플릿이 쓰는 라벨이에요. Issues → Labels에서 만들어요.

| 라벨 | 색 | 용도 |
|---|---|---|
| `false-positive` | `#fbca04` | 오탐 신고 |
| `detection` | `#5319e7` | 새 탐지 아이디어·규칙 |
| `bug` | `#d73a4a` | 버그 (기본 라벨) |
| `enhancement` | `#a2eeef` | 기능 (기본 라벨) |
| `documentation` | `#0075ca` | 문서 (기본 라벨) |
| `skip-changelog` | `#ededed` | 릴리스 노트에서 빼기 |

## 6. 공개로 바꾸기 전 체크리스트

- [ ] README·문서에 개인정보(실명, 학교, 이메일)가 없는지
- [ ] Actions 로그·아티팩트에 민감한 정보가 없는지 (이 프로젝트는 비밀 값을 쓰지 않아요)
- [ ] Settings → General → Danger Zone → **Change visibility** → Public
- [ ] 공개 직후 CodeQL 워크플로가 실행되는지 Actions에서 확인
