<#
  SafetySecurity installer tests (Windows only, run in CI on windows-latest).
  Silently installs the Setup, checks everything it should create, reinstalls, uninstalls,
  and checks that everything is gone. Runs for both install modes:
    - my account only (/CURRENTUSER): %LOCALAPPDATA%\Programs\SafetySecurity, HKCU
    - administrator   (/ALLUSERS):   C:\Program Files\SafetySecurity, HKLM, + admin scan task (needs an elevated shell)
  Usage: pwsh tests/integration/Test-Installer.ps1 -Setup dist-installer/SafetySecurity-Setup-0.2.0.exe -Version 0.2.0
#>
param(
    [Parameter(Mandatory = $true)][string]$Setup,
    [Parameter(Mandatory = $true)][string]$Version,
    [switch]$SkipAdmin
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Setup = (Resolve-Path $Setup).Path

# installer/SafetySecurity.iss의 AppId와 같아야 해요.
$AppId = '{64EA0F9C-E539-4775-B5E3-063E9FF952D5}'
$UserTasks = @('Logon', 'Daily', 'ServiceInstalled', 'Retry')
$ToastKey = 'HKCU:\Software\Classes\AppUserModelId\SafetySecurity.Scanner'
$root = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$work = Join-Path $root 'ss-setup'
New-Item -ItemType Directory -Force $work | Out-Null

$script:failures = 0
function Check([bool]$cond, [string]$what) {
    if ($cond) { Write-Host "  PASS  $what" -ForegroundColor Green }
    else { Write-Host "  FAIL  $what" -ForegroundColor Red; $script:failures++ }
}

function Get-Layout([bool]$Admin) {
    if ($Admin) {
        $dir = Join-Path $env:ProgramFiles 'SafetySecurity'
        $hive = 'HKLM:'
        $lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\SafetySecurity.lnk'
    }
    else {
        $dir = Join-Path $env:LOCALAPPDATA 'Programs\SafetySecurity'
        $hive = 'HKCU:'
        $lnk = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\SafetySecurity.lnk'
    }
    return [pscustomobject]@{
        Admin     = $Admin
        Dir       = $dir
        Exe       = Join-Path $dir 'SafetySecurity.exe'
        Uninstall = Join-Path $dir 'unins000.exe'
        Shortcut  = $lnk
        AppPaths  = "$hive\Software\Microsoft\Windows\CurrentVersion\App Paths\SafetySecurity.exe"
        AppsEntry = "$hive\Software\Microsoft\Windows\CurrentVersion\Uninstall\$($AppId)_is1"
    }
}

function Invoke-Quiet([string]$File, [string[]]$ArgList, [string]$Name) {
    $p = Start-Process -FilePath $File -ArgumentList $ArgList -Wait -PassThru
    Write-Host "> $Name $($ArgList -join ' ')  (exit $($p.ExitCode))"
    return $p.ExitCode
}

function Install-Setup($L, [string]$Name) {
    $log = Join-Path $work "$Name.log"
    $mode = if ($L.Admin) { '/ALLUSERS' } else { '/CURRENTUSER' }
    $code = Invoke-Quiet $Setup @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', $mode, "/LOG=`"$log`"") "Setup ($Name)"
    if ($code -ne 0 -and (Test-Path $log)) { Get-Content $log -Tail 40 | Out-Host }
    return $code
}

function Get-TaskExe([string]$Name) {
    $t = Get-ScheduledTask -TaskPath '\SafetySecurity\' -TaskName $Name -ErrorAction SilentlyContinue
    if (-not $t) { return $null }
    return "$(@($t.Actions)[0].Execute)".Trim('"')   # 작업 XML은 경로를 따옴표로 감싸요 (TaskXmlBuilder)
}

function Get-DefaultValue([string]$Key) {
    $item = Get-Item -LiteralPath $Key -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    return $item.GetValue('')
}

# 아이콘이 exe에 들어갔는지 PE 리소스 디렉터리에서 RT_GROUP_ICON(14)을 찾아요 (NativeAOT가 Win32 리소스를 옮겼는지 확인).
function Get-ResourceTypes([string]$Path) {
    $b = [IO.File]::ReadAllBytes($Path)
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    $sections = [BitConverter]::ToUInt16($b, $pe + 6)
    $optSize = [BitConverter]::ToUInt16($b, $pe + 20)
    $opt = $pe + 24
    $dirs = $opt + $(if ([BitConverter]::ToUInt16($b, $opt) -eq 0x10b) { 96 } else { 112 })
    $rva = [int64][BitConverter]::ToUInt32($b, $dirs + 16)
    for ($i = 0; $i -lt $sections; $i++) {
        $s = $opt + $optSize + 40 * $i
        $vsize = [int64][BitConverter]::ToUInt32($b, $s + 8)
        $vaddr = [int64][BitConverter]::ToUInt32($b, $s + 12)
        $raw = [int64][BitConverter]::ToUInt32($b, $s + 16)
        $ptr = [int64][BitConverter]::ToUInt32($b, $s + 20)
        if ($rva -gt 0 -and $rva -ge $vaddr -and $rva -lt $vaddr + [Math]::Max($vsize, $raw)) {
            $base = [int]($ptr + $rva - $vaddr)
            $count = [BitConverter]::ToUInt16($b, $base + 12) + [BitConverter]::ToUInt16($b, $base + 14)
            if ($count -eq 0) { return @() }
            return @(0..($count - 1) | ForEach-Object { [BitConverter]::ToUInt32($b, $base + 16 + 8 * $_) })
        }
    }
    return @()
}

function Assert-Installed($L) {
    Check (Test-Path -LiteralPath $L.Exe) "exe installed: $($L.Exe)"
    Check (Test-Path -LiteralPath $L.Uninstall) 'uninstaller present'
    foreach ($n in $UserTasks) {
        Check ((Get-TaskExe $n) -eq $L.Exe) "task \SafetySecurity\$n runs the installed exe"
    }
    if ($L.Admin) {
        Check ((Get-TaskExe 'Admin') -eq $L.Exe) 'task \SafetySecurity\Admin runs the installed exe'
    }
    else {
        Check ($null -eq (Get-TaskExe 'Admin')) 'no admin task for a my-account install'
    }

    Check (Test-Path -LiteralPath $L.Shortcut) "Start menu shortcut: $($L.Shortcut)"
    if (Test-Path -LiteralPath $L.Shortcut) {
        $lnk = (New-Object -ComObject WScript.Shell).CreateShortcut($L.Shortcut)
        Check ($lnk.TargetPath -eq $L.Exe) 'shortcut points to the installed exe'
        Check ([string]::IsNullOrEmpty($lnk.Arguments)) 'shortcut has no arguments (scan now + open report)'
    }

    Check ((Get-DefaultValue $L.AppPaths) -eq $L.Exe) 'App Paths: Win+R "safetysecurity" runs the installed exe'
    $entry = Get-ItemProperty -LiteralPath $L.AppsEntry -ErrorAction SilentlyContinue
    Check ($null -ne $entry) 'Apps list entry'
    if ($entry) {
        Check ($entry.DisplayVersion -eq $Version) "Apps list version is $Version (got $($entry.DisplayVersion))"
        Check ($entry.DisplayName -eq 'SafetySecurity') 'Apps list name'
    }
    Check (Test-Path $ToastKey) 'notification identity registered'

    if (Test-Path -LiteralPath $L.Exe) {
        Check ((Get-ResourceTypes $L.Exe) -contains 14) 'exe has an icon (RT_GROUP_ICON)'
        $out = Join-Path $work 'version.txt'
        $p = Start-Process -FilePath $L.Exe -ArgumentList 'version' -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out
        $text = Get-Content $out -Raw -Encoding utf8 -ErrorAction SilentlyContinue
        Check ($p.ExitCode -eq 0 -and "$text" -match [regex]::Escape("SafetySecurity $Version")) "installed exe runs: $("$text".Trim())"
    }
}

function Uninstall-And-Assert($L) {
    if (-not (Test-Path -LiteralPath $L.Uninstall)) {
        Check $false 'uninstaller present (cannot uninstall)'
        return
    }
    # 검사가 도는 중(exe 잠김)에 제거해도 exe까지 지워져야 해요.
    $scan = Start-Process -FilePath $L.Exe -ArgumentList 'scan', '--force', '--no-toast' -PassThru
    Start-Sleep -Seconds 1
    $code = Invoke-Quiet $L.Uninstall @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') 'unins000.exe'
    Check ($code -eq 0) 'uninstaller exits 0'
    # 제거 프로그램은 임시 폴더의 복사본이 마저 지우고 끝나요. 다 지워질 때까지 최대 60초 기다려요.
    $deadline = (Get-Date).AddSeconds(60)
    # unins000.exe와 설치 폴더는 앱 목록 항목보다 늦게, 맨 마지막에 지워져요.
    while ((Get-Date) -lt $deadline -and ((Test-Path -LiteralPath $L.Exe) -or (Test-Path -LiteralPath $L.AppsEntry) -or (Test-Path -LiteralPath $L.Dir))) {
        Start-Sleep -Milliseconds 500
    }
    Check (-not (Test-Path -LiteralPath $L.Exe)) 'exe removed (even with a scan running)'
    Check ($scan.HasExited) 'running scan was closed by the uninstaller'
    Check (-not (Test-Path -LiteralPath $L.Dir)) 'install folder removed'
    if (Test-Path -LiteralPath $L.Dir) {
        Get-ChildItem -LiteralPath $L.Dir -Force -Recurse | ForEach-Object { Write-Host "        left: $($_.FullName)" }
    }
    foreach ($n in $UserTasks + 'Admin') {
        Check ($null -eq (Get-TaskExe $n)) "task \SafetySecurity\$n removed"
    }
    Check (-not (Test-Path -LiteralPath $L.Shortcut)) 'Start menu shortcut removed'
    Check (-not (Test-Path -LiteralPath $L.AppPaths)) 'App Paths removed'
    Check (-not (Test-Path -LiteralPath $L.AppsEntry)) 'Apps list entry removed'
    Check (-not (Test-Path $ToastKey)) 'notification identity removed'
    Check (Test-Path (Join-Path $env:LOCALAPPDATA 'SafetySecurity\config.json')) 'scan history kept (a silent uninstall does not purge)'
}

function Test-Mode([bool]$Admin) {
    $L = Get-Layout $Admin
    $label = if ($Admin) { 'administrator' } else { 'my account only' }
    Write-Host "== Setup: $label"
    if (-not $Admin) {
        # zip으로 install 한 적이 있는 PC처럼 설치 폴더가 이미 있는 경우도 확인해요 (제거할 때 폴더까지 지워져야 해요).
        New-Item -ItemType Directory -Force $L.Dir | Out-Null
    }
    Check ((Install-Setup $L "install-$($Admin)") -eq 0) 'Setup exits 0'
    Assert-Installed $L

    Write-Host "== Setup again over the existing install ($label)"
    Check ((Install-Setup $L "reinstall-$($Admin)") -eq 0) 'Setup exits 0 when reinstalling'
    Assert-Installed $L

    Write-Host "== Uninstall ($label)"
    Uninstall-And-Assert $L
}

Test-Mode $false

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($SkipAdmin -or -not $elevated) {
    Write-Host '== Administrator install skipped (needs an elevated shell)'
}
else {
    Test-Mode $true
}

Write-Host ''
if ($script:failures -gt 0) {
    Write-Host "$script:failures check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'All installer checks passed' -ForegroundColor Green
exit 0
