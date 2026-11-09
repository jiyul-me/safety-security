<#
  SafetySecurity installer tests (Windows only, run in CI on windows-latest).
  Silently installs the Setup, checks everything it should create, reinstalls, uninstalls,
  and checks that everything is gone. Runs for both install modes:
    - my account only (/CURRENTUSER): %LOCALAPPDATA%\Programs\SafetySecurity, HKCU
    - administrator   (/ALLUSERS):   C:\Program Files\SafetySecurity, HKLM, + admin scan task (needs an elevated shell)
      and the admin scan data in C:\Program Files\SafetySecurity\data (standard users cannot write there)
  When both modes can be tested, it also checks that Setup in the other mode stops and changes nothing
  while SafetySecurity is installed (two installs would share and delete each other's scheduled tasks).
  Usage: pwsh tests/integration/Test-Installer.ps1 -Setup dist-installer/SafetySecurity-Setup-0.2.0.exe -Version 0.2.0
#>
param(
    [Parameter(Mandatory = $true)][string]$Setup,
    [Parameter(Mandatory = $true)][string]$Version,
    [switch]$SkipAdmin
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# 이 파일은 UTF-8(BOM 있음)로 저장해야 해요. BOM이 없으면 Windows PowerShell 5.1이 시스템 코드 페이지로 읽어서
# 한글 비교('작업 스케줄러\...')가 늘 어긋나고, 그런 검사는 아무것도 확인하지 않은 채 통과해요. 그럴 때는 바로 멈춰요.
if ('작업'.Length -ne 2) { throw 'Test-Installer.ps1 was read with the wrong encoding. Save it as UTF-8 with BOM (see .editorconfig) or run it with pwsh.' }
$Setup = (Resolve-Path $Setup).Path

# installer/SafetySecurity.iss의 AppId와 같아야 해요.
$AppId = '{64EA0F9C-E539-4775-B5E3-063E9FF952D5}'
$UserTasks = @('Logon', 'Daily', 'ServiceInstalled', 'Retry')
$ToastKey = 'HKCU:\Software\Classes\AppUserModelId\SafetySecurity.Scanner'
$root = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$work = Join-Path $root 'ss-setup'
New-Item -ItemType Directory -Force $work | Out-Null
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# exe의 데이터 폴더 (src/SafetySecurity.Core/Install/DataRoots.cs와 같아야 해요).
# 관리자 권한으로 실행한 exe는 사용자 폴더 대신 관리자만 쓸 수 있는 Program Files\SafetySecurity\data를 써요.
# CI 러너는 관리자 권한이라, 내 계정에만 설치해도 설치 프로그램이 실행한 exe는 이 폴더를 써요.
$AdminData = Join-Path $env:ProgramFiles 'SafetySecurity\data'
$DataRoot = if ($elevated) { $AdminData } else { Join-Path $env:LOCALAPPDATA 'SafetySecurity' }
$canAdmin = $elevated -and -not $SkipAdmin

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
        $desk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'SafetySecurity.lnk'
    }
    else {
        $dir = Join-Path $env:LOCALAPPDATA 'Programs\SafetySecurity'
        $hive = 'HKCU:'
        $lnk = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\SafetySecurity.lnk'
        $desk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'SafetySecurity.lnk'
    }
    return [pscustomobject]@{
        Admin     = $Admin
        Dir       = $dir
        Exe       = Join-Path $dir 'SafetySecurity.exe'
        Uninstall = Join-Path $dir 'unins000.exe'
        Shortcut  = $lnk
        Desktop   = $desk
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
    Check (Test-Path -LiteralPath $L.Desktop) "desktop shortcut (default task): $($L.Desktop)"
    if (Test-Path -LiteralPath $L.Desktop) {
        Check ((New-Object -ComObject WScript.Shell).CreateShortcut($L.Desktop).TargetPath -eq $L.Exe) 'desktop shortcut points to the installed exe'
    }
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

# 일반 사용자(Users, Authenticated Users, Everyone, INTERACTIVE)가 쓰기·고치기·지우기 권한을 가진 ACE를 찾아요.
function Get-UserWriteRules([string]$Path) {
    $sids = @('S-1-5-32-545', 'S-1-5-11', 'S-1-1-0', 'S-1-5-4')
    # WriteData|AppendData|WriteEA|DeleteChild|WriteAttributes|Delete|WriteDAC|WriteOwner|GenericAll|GenericWrite
    $mask = [int64]0x500D0156
    $acl = Get-Acl -LiteralPath $Path
    return @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
            "$($_.AccessControlType)" -eq 'Allow' -and $sids -contains $_.IdentityReference.Value -and (([int64]$_.FileSystemRights.value__) -band $mask) -ne 0
        })
}

# 관리자 검사는 사용자 폴더가 아니라 관리자만 쓸 수 있는 Program Files\SafetySecurity\data에 기록해요.
function Assert-AdminData($L) {
    $out = Join-Path $work 'admin-scan.txt'
    $p = Start-Process -FilePath $L.Exe -ArgumentList 'scan', '--scope', 'admin', '--quick', '--force', '--no-toast' -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out
    Write-Host "> SafetySecurity scan --scope admin --quick --force --no-toast  (exit $($p.ExitCode))"
    Check ($p.ExitCode -eq 0) 'admin scan (default data folder) exits 0'
    Check (Test-Path -LiteralPath (Join-Path $AdminData 'state.admin.json')) "admin scan state written to $AdminData"
    Check (@(Get-ChildItem -LiteralPath (Join-Path $AdminData 'reports') -Filter '*_admin.json' -ErrorAction SilentlyContinue).Count -ge 1) 'admin report written to the protected data folder'
    Check (@(Get-ChildItem -LiteralPath $AdminData -Filter 'task-*.xml' -ErrorAction SilentlyContinue).Count -eq 0) 'no temporary task XML left in the data folder'
    # 숨겨진 작업 검사(TASK-002)는 이제 SafetySecurity 이름도 빼 주지 않아요. 설치가 만든 진짜 작업은 SD가 있어서 보고되면 안 돼요.
    $adminReport = Get-ChildItem -LiteralPath (Join-Path $AdminData 'reports') -Filter '*_admin.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($adminReport) {
        $rep = Get-Content -LiteralPath $adminReport.FullName -Raw -Encoding utf8 | ConvertFrom-Json
        $own = @($rep.findings | Where-Object { $_.ruleId -eq 'TASK-002' -and "$($_.title)" -like '*\SafetySecurity*' })
        Check ($own.Count -eq 0) "installed tasks are not reported as hidden tasks ($(@($own | ForEach-Object { $_.title }) -join ', '))"
    }
    foreach ($item in @($AdminData, (Join-Path $AdminData 'reports'), (Join-Path $AdminData 'state.admin.json'))) {
        if (-not (Test-Path -LiteralPath $item)) { continue }
        $bad = @(Get-UserWriteRules $item)
        Check ($bad.Count -eq 0) "standard users cannot write or modify $item"
        $bad | ForEach-Object { Write-Host "        $($_.IdentityReference.Value): $($_.FileSystemRights)" }
    }
}

# 설치된 exe로 검사해도 설치가 만든 작업을 우리 작업으로 알아봐야 해요 (이름이 아니라 실행 파일·인자로 확인해요).
# 위장 작업(TASK-003)이나 꺼진 작업(TASK-004)으로 보고되면 안 돼요. 시험용 기록은 임시 폴더에 따로 둬요.
function Assert-OwnTasksRecognised($L) {
    if (-not (Test-Path -LiteralPath $L.Exe)) { return }
    $name = if ($L.Admin) { 'admin' } else { 'user' }
    $data = Join-Path $work "own-$name-data"
    $reports = Join-Path $work "own-$name-reports"
    Remove-Item -Recurse -Force $data, $reports -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $data, $reports | Out-Null
    $out = Join-Path $work "own-$name.txt"
    $p = Start-Process -FilePath $L.Exe -ArgumentList 'scan', '--quick', '--force', '--no-toast', '--data-dir', "`"$data`"", '--report-dir', "`"$reports`"" -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out
    Write-Host "> SafetySecurity scan --quick --force --no-toast (own tasks, $name)  (exit $($p.ExitCode))"
    Check ($p.ExitCode -eq 0) 'quick scan with the installed tasks exits 0'
    $f = Get-ChildItem -LiteralPath $reports -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Check ($null -ne $f) 'quick scan wrote a json report'
    if ($f) {
        $rep = Get-Content -LiteralPath $f.FullName -Raw -Encoding utf8 | ConvertFrom-Json
        $own = @($rep.findings | Where-Object { "$($_.location)" -like '작업 스케줄러\SafetySecurity*' })
        Check ($own.Count -eq 0) "installed tasks are recognised as our own ($(@($own | ForEach-Object { "$($_.ruleId) $($_.location)" }) -join ', '))"
    }
}

# 다른 방식으로 이미 설치돼 있으면 설치 프로그램은 아무것도 바꾸지 않고 멈춰야 해요 (SafetySecurity.iss의 InitializeSetup).
# 두 방식이 함께 설치되면 같은 이름의 예약 작업을 서로 덮어쓰고, 한쪽을 제거할 때 다른 쪽의 작업까지 지워요.
function Assert-OtherModeBlocked($L, [string]$Name) {
    $other = Get-Layout (-not $L.Admin)
    $log = Join-Path $work "$Name.log"
    $mode = if ($other.Admin) { '/ALLUSERS' } else { '/CURRENTUSER' }
    Check (-not (Test-Path -LiteralPath $other.AppsEntry)) "only one install before the test: $($other.AppsEntry) is absent"
    # 시험 전부터 있던 파일(예: zip으로 install 한 exe)은 그대로 두고, 설치 프로그램이 새로 만들지 않았는지만 봐요.
    $paths = @($other.Exe, $other.Shortcut, $other.Desktop, $other.AppPaths)
    $before = @($paths | ForEach-Object { Test-Path -LiteralPath $_ })
    $code = Invoke-Quiet $Setup @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', $mode, "/LOG=`"$log`"") "Setup ($Name)"
    Check ($code -ne 0) "Setup $mode stops while SafetySecurity is installed the other way (exit $code)"
    $logText = if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Raw } else { '' }
    $why = "$logText" -match 'already installed in the other install mode'
    Check $why 'Setup log says it stopped because of the other install'
    if (-not $why -and (Test-Path -LiteralPath $log)) { Get-Content -LiteralPath $log -Tail 20 | Out-Host }
    Check (-not (Test-Path -LiteralPath $other.AppsEntry)) "no second Apps list entry: $($other.AppsEntry)"
    for ($i = 0; $i -lt $paths.Count; $i++) {
        Check ((Test-Path -LiteralPath $paths[$i]) -eq $before[$i]) "Setup did not create or remove $($paths[$i])"
    }
    # 원래 설치는 그대로여야 해요 (작업이 여전히 원래 exe를 실행하는지도 봐요).
    Assert-Installed $L
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
    Check (-not (Test-Path -LiteralPath $L.Desktop)) 'desktop shortcut removed'
    Check (-not (Test-Path -LiteralPath $L.AppPaths)) 'App Paths removed'
    Check (-not (Test-Path -LiteralPath $L.AppsEntry)) 'Apps list entry removed'
    Check (-not (Test-Path $ToastKey)) 'notification identity removed'
    if ($L.Admin) {
        # 관리자 설치의 데이터 폴더(설치 폴더 안의 data)는 제거할 때 함께 지워져요.
        Check (-not (Test-Path -LiteralPath $AdminData)) "admin data folder removed: $AdminData"
    }
    else {
        Check (Test-Path (Join-Path $DataRoot 'config.json')) "scan history kept (a silent uninstall does not purge): $DataRoot"
    }
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
    Assert-OwnTasksRecognised $L
    if ($Admin) { Assert-AdminData $L }

    Write-Host "== Setup again over the existing install ($label)"
    Check ((Install-Setup $L "reinstall-$($Admin)") -eq 0) 'Setup exits 0 when reinstalling'
    Assert-Installed $L

    if ($canAdmin) {
        Write-Host "== Setup in the other install mode while installed ($label)"
        Assert-OtherModeBlocked $L "other-mode-$($Admin)"
    }

    Write-Host "== Uninstall ($label)"
    Uninstall-And-Assert $L
}

Test-Mode $false

if (-not $canAdmin) {
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
