<#
  CHANGELOG.md에서 릴리스 노트를 만들어요 (release.yml이 사용).
  - 정식 버전(예: 0.1.0)은 "## [0.1.0]" 섹션을, 사전 릴리스(예: 0.2.0-rc.1)는 "## [Unreleased]" 섹션을 써요.
  - 섹션이 비어 있으면 파일을 만들지 않아요. 그러면 워크플로가 GitHub 자동 노트(--generate-notes)를 써요.
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$Changelog = 'CHANGELOG.md',
    [string]$Repo = 'jiyul-me/safety-security',
    [string]$Out = 'release-notes.md'
)

$ErrorActionPreference = 'Stop'
$section = if ($Version.Contains('-')) { 'Unreleased' } else { $Version }
$lines = Get-Content -LiteralPath $Changelog -Encoding utf8

$start = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match ('^## \[' + [regex]::Escape($section) + '\]')) { $start = $i; break }
}

$body = New-Object System.Collections.Generic.List[string]
if ($start -ge 0) {
    for ($j = $start + 1; $j -lt $lines.Count; $j++) {
        if ($lines[$j] -match '^## \[') { break }
        if ($lines[$j] -match '^\[[^\]]+\]:\s*https?://') { continue }   # 맨 아래 비교 링크 줄
        $body.Add($lines[$j])
    }
}

$text = ($body -join "`n").Trim()
if (-not $text) {
    Write-Host "CHANGELOG에 [$section] 내용이 없어요. 자동 노트를 쓸게요."
    if (Test-Path -LiteralPath $Out) { Remove-Item -LiteralPath $Out }
    exit 0
}

$heading = if ($section -eq 'Unreleased') { "> 사전 릴리스예요. 다음 정식 버전에 들어갈 변경을 미리 시험하는 빌드예요.`n`n" } else { '' }
$setupName = "SafetySecurity-Setup-$Version.exe"
$footer = @"

---

### 설치
1. ``$setupName``를 받아 더블클릭해요.
2. "Windows의 PC 보호" 창이 뜨면 '추가 정보' → '실행'을 눌러요. 코드 서명 인증서가 아직 없어서 떠요. 아래 방법으로 파일이 진짜인지 먼저 확인할 수 있어요.
3. 설치 방식(내 계정에만 / 관리자 권한으로)을 고르고 설치하면 끝이에요. 시작 메뉴의 **SafetySecurity**로 언제든 검사하고, 설정 → 앱에서 제거해요.
   이미 설치돼 있으면 묻지 않고 같은 방식으로 업데이트해요. 설치 방식을 바꾸려면 설정 → 앱에서 먼저 제거한 뒤 다시 설치하세요.

명령줄로 쓰거나 내 PC 시험 스크립트가 필요하면 zip을 받으세요. 자세한 방법은 [README](https://github.com/$Repo#빠른-시작)와 [내 PC에서 시험하기](https://github.com/$Repo/blob/main/docs/TESTING-ON-YOUR-PC.md)를 보세요.

### 받은 파일 확인하기
- ``SHA256SUMS.txt``와 비교: ``Get-FileHash .\$setupName -Algorithm SHA256``
- 이 저장소의 GitHub Actions가 만든 파일인지 확인 (빌드 출처 증명): ``gh attestation verify .\$setupName --repo $Repo``
- 설치된 실행 파일도 확인할 수 있어요: ``gh attestation verify "`$env:LOCALAPPDATA\Programs\SafetySecurity\SafetySecurity.exe" --repo $Repo``
"@

Set-Content -LiteralPath $Out -Value ($heading + $text + "`n" + $footer) -Encoding utf8
Write-Host "릴리스 노트를 만들었어요: $Out ([$section] 섹션)"
