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
$footer = @"

---

### 받은 파일 확인하기
- ``SHA256SUMS.txt``와 비교: ``Get-FileHash .\SafetySecurity.exe -Algorithm SHA256``
- 이 저장소의 GitHub Actions가 만든 파일인지 확인 (빌드 출처 증명): ``gh attestation verify .\SafetySecurity.exe --repo $Repo``
- 코드 서명 인증서가 아직 없어서 처음 실행할 때 SmartScreen("Windows의 PC 보호")이 뜰 수 있어요. 위 방법으로 파일이 진짜인지 먼저 확인한 뒤 '추가 정보' → '실행'을 누르세요.

### 설치
zip을 풀고, 관리자 PowerShell에서 그 폴더로 이동한 뒤 ``.\SafetySecurity.exe install --admin``을 실행해요. 자세한 방법은 [README](https://github.com/$Repo#빠른-시작)와 [내 PC에서 시험하기](https://github.com/$Repo/blob/main/docs/TESTING-ON-YOUR-PC.md)를 보세요.
"@

Set-Content -LiteralPath $Out -Value ($heading + $text + "`n" + $footer) -Encoding utf8
Write-Host "릴리스 노트를 만들었어요: $Out ([$section] 섹션)"
