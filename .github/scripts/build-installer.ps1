<#
  Inno Setup으로 설치 프로그램(SafetySecurity-Setup-<버전>.exe)을 만들어요. CI와 release.yml이 사용해요.
  GitHub Windows 러너에는 Inno Setup이 미리 설치돼 있어요. 없으면 Chocolatey로 설치해요.

  예: ./.github/scripts/build-installer.ps1 -Version 0.2.0-rc.1 -Exe out/SafetySecurity.exe -OutDir dist-installer
  만든 Setup 파일의 전체 경로를 출력해요 (변수로 받을 수 있어요).
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Exe,
    [string]$OutDir = 'dist-installer'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Version -notmatch '^(\d+\.\d+\.\d+)(-[0-9A-Za-z.]+)?$') {
    throw "버전은 1.2.3 또는 1.2.3-rc.1 형식이어야 해요: $Version"
}
$numeric = $Matches[1]

function Find-Iscc {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    $cmd = Get-Command 'ISCC.exe' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$iscc = Find-Iscc
if (-not $iscc) {
    Write-Host 'Inno Setup이 없어서 Chocolatey로 설치해요.'
    choco install innosetup -y --no-progress | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "choco install innosetup 실패 (종료 코드 $LASTEXITCODE)" }
    $iscc = Find-Iscc
    if (-not $iscc) { throw 'Inno Setup을 설치했는데 ISCC.exe를 찾지 못했어요.' }
}
Write-Host "ISCC: $iscc"

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script = Join-Path $root 'installer\SafetySecurity.iss'
$exePath = (Resolve-Path $Exe).Path
New-Item -ItemType Directory -Force $OutDir | Out-Null
$outPath = (Resolve-Path $OutDir).Path

& $iscc "/DAppVersion=$Version" "/DNumericVersion=$numeric" "/DSourceExe=$exePath" "/O$outPath" $script | Out-Host
if ($LASTEXITCODE -ne 0) { throw "ISCC 실패 (종료 코드 $LASTEXITCODE)" }

$setup = Join-Path $outPath "SafetySecurity-Setup-$Version.exe"
if (-not (Test-Path -LiteralPath $setup)) { throw "만든 설치 프로그램이 없어요: $setup" }
Write-Host ('Setup: {0} ({1:N2} MB)' -f $setup, ((Get-Item -LiteralPath $setup).Length / 1MB))
$setup
