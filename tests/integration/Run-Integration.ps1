<#
  SafetySecurity integration tests (Windows only, run in CI on windows-latest).
  Creates fake persistence entries in HKCU, runs the real exe, checks the JSON report, then cleans up.
  Usage: pwsh tests/integration/Run-Integration.ps1 -Exe out/SafetySecurity.exe
#>
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Exe = (Resolve-Path $Exe).Path
$root = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$work = Join-Path $root 'ss-it'
$data = Join-Path $work 'data'
$reports = Join-Path $work 'reports'
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $data, $reports | Out-Null

$script:failures = 0
function Check([bool]$cond, [string]$what) {
    if ($cond) { Write-Host "  PASS  $what" -ForegroundColor Green }
    else { Write-Host "  FAIL  $what" -ForegroundColor Red; $script:failures++ }
}

function Invoke-SS([string[]]$ArgList) {
    $id = [guid]::NewGuid().ToString('N')
    $out = Join-Path $work "out-$id.txt"
    $err = Join-Path $work "err-$id.txt"
    $quoted = $ArgList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $Exe -ArgumentList $quoted -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
    $sw.Stop()
    $text = (Get-Content $out -Raw -Encoding utf8 -ErrorAction SilentlyContinue)
    Write-Host "> SafetySecurity $($ArgList -join ' ')  (exit $($p.ExitCode), $([int]$sw.Elapsed.TotalMilliseconds) ms)"
    if ($text) { Write-Host ($text.TrimEnd()) }
    return [pscustomobject]@{ Code = $p.ExitCode; Text = $text; Ms = $sw.Elapsed.TotalMilliseconds }
}

function Latest-Report {
    $f = Get-ChildItem $reports -Filter *.json | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $f) { return $null }
    return Get-Content $f.FullName -Raw -Encoding utf8 | ConvertFrom-Json
}

function Scan([string[]]$Extra = @()) {
    return Invoke-SS (@('scan', '--force', '--no-toast', '--data-dir', $data, '--report-dir', $reports) + $Extra)
}

# ---- fake persistence -------------------------------------------------------
$evilDir = Join-Path $env:LOCALAPPDATA 'Temp\ss-it-evil'
New-Item -ItemType Directory -Force $evilDir | Out-Null
$evilDll = Join-Path $evilDir 'mscorsvc.dll'
$bytes = New-Object byte[] 1024
$bytes[0] = 0x4D; $bytes[1] = 0x5A; $bytes[0x3C] = 0x80; $bytes[0x80] = 0x50; $bytes[0x81] = 0x45
[IO.File]::WriteAllBytes($evilDll, $bytes)

# HKLM에 있고 HKCU에는 없는 CLSID 하나를 골라서 덮어써요.
$clsid = Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' |
    Where-Object { $_.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$' -and (Test-Path (Join-Path $_.PSPath 'InprocServer32')) -and -not (Test-Path "HKCU:\Software\Classes\CLSID\$($_.PSChildName)") } |
    Select-Object -Skip 50 -First 1 | ForEach-Object PSChildName
if (-not $clsid) { throw 'no suitable CLSID found' }
$comKey = "HKCU:\Software\Classes\CLSID\$clsid"
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runName = 'SafetySecurityIT'

try {
    Write-Host "== 1. version / verify"
    $v = Invoke-SS @('version')
    Check ($v.Code -eq 0 -and $v.Text -match 'SafetySecurity \d') 'version prints'
    $sys = Invoke-SS @('verify', "$env:SystemRoot\System32\kernel32.dll")
    Check ($sys.Code -eq 0 -and $sys.Text -match '^Valid\|') 'kernel32.dll is signed (catalog or embedded)'
    $np = Invoke-SS @('verify', "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe")
    Check ($np.Code -eq 0 -and $np.Text -match 'Microsoft') 'powershell.exe signer is Microsoft'
    $un = Invoke-SS @('verify', $evilDll)
    Check ($un.Code -eq 5 -and $un.Text -match '^Unsigned\|') 'fake DLL is unsigned'

    Write-Host "== 2. clean scan (baseline)"
    $r0 = Scan
    Check ($r0.Code -eq 0) 'scan exits 0'
    $rep0 = Latest-Report
    Check ($null -ne $rep0) 'json report written'
    Check (@(Get-ChildItem $reports -Filter *.html).Count -ge 1) 'html report written'
    $sysUnsigned = @($rep0.findings | Where-Object { $_.target -like "$env:SystemRoot\System32\*" -and ($_.evidence | Where-Object { $_.key -eq '서명' -and $_.value -eq '서명 없음' }) })
    Check ($sysUnsigned.Count -eq 0) "no System32 file reported as unsigned (found $($sysUnsigned.Count))"
    Write-Host "  baseline findings on runner: $(@($rep0.findings).Count)"
    $dupes = @($rep0.findings | Group-Object { $_.location.ToLowerInvariant() } | Where-Object Count -gt 1)
    Check ($dupes.Count -eq 0) 'no duplicate findings'
    $tempMis = @($rep0.findings | Where-Object { $_.category -eq 'DroppedFile' -and $_.location -like '*\AppData\Local\Temp\*' -and $_.severity -eq 'Medium' -and $_.location -notmatch '\.(pdf|jpg|png|txt|docx?)' })
    Check ($tempMis.Count -eq 0) "Temp files classified as Temp, not user profile (found $($tempMis.Count))"
    $rep0.findings | Select-Object -First 20 | ForEach-Object { Write-Host "    [$($_.severity)] $($_.title) :: $($_.location)" }
    $rep0.coverage | ForEach-Object { Write-Host "    (coverage) $_" }

    Write-Host "== 3. COM hijack ($clsid) + Run key"
    New-Item -Path "$comKey\InprocServer32" -Force | Out-Null
    Set-ItemProperty -Path "$comKey\InprocServer32" -Name '(default)' -Value $evilDll
    Set-ItemProperty -Path "$comKey\InprocServer32" -Name 'ThreadingModel' -Value 'Apartment'
    Set-ItemProperty -Path $runKey -Name $runName -Value 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AA=='
    $r1 = Scan
    Check ($r1.Code -eq 0) 'scan exits 0'
    $rep1 = Latest-Report
    $com = @($rep1.findings | Where-Object { $_.category -eq 'ComHijack' -and $_.location -like "*$clsid*" })
    Check ($com.Count -ge 1) 'COM hijack detected'
    if ($com.Count -ge 1) {
        Check ($com[0].severity -eq 'High') "COM hijack severity High (got $($com[0].severity))"
        Check ($com[0].ruleId -eq 'COM-001') "COM hijack rule COM-001 (got $($com[0].ruleId))"
        Check ($com[0].target -eq $evilDll) 'COM hijack target is the fake DLL'
        Check ($com[0].isNew -eq $true) 'COM hijack marked new'
    }
    $run = @($rep1.findings | Where-Object { $_.category -eq 'Autorun' -and $_.location -like "*\$runName" })
    Check ($run.Count -eq 1 -and $run[0].severity -eq 'High') 'encoded PowerShell Run entry is High'

    Write-Host "== 4. second scan: same items are no longer new"
    $null = Scan
    $rep2 = Latest-Report
    $com2 = @($rep2.findings | Where-Object { $_.category -eq 'ComHijack' -and $_.location -like "*$clsid*" })
    Check ($com2.Count -ge 1 -and $com2[0].isNew -eq $false) 'baseline remembers COM finding'

    Write-Host "== 5. ignore"
    $ig = Invoke-SS @('ignore', $com2[0].id, '--data-dir', $data)
    Check ($ig.Code -eq 0) 'ignore exits 0'
    $null = Scan
    $rep3 = Latest-Report
    Check (@($rep3.findings | Where-Object { $_.id -eq $com2[0].id }).Count -eq 0 -and $rep3.ignoredCount -ge 1) 'ignored finding hidden'

    Write-Host "== 6. game deferral and retry"
    $cfg = @{ gameProcesses = @('pwsh.exe', 'powershell.exe'); notifyMinSeverity = 'Medium'; cpuBusyPercent = 0; deferOnFullscreen = $false } | ConvertTo-Json
    Set-Content -Path (Join-Path $data 'config.json') -Value $cfg -Encoding utf8
    $d = Invoke-SS @('scan', '--reason', 'daily', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($d.Code -eq 2) "scan deferred while game process runs (exit $($d.Code))"
    $state = Get-Content (Join-Path $data 'state.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Check ($null -ne $state.pending -and $state.pending.reason -eq 'Daily') 'pending scan recorded'
    $d2 = Invoke-SS @('scan', '--reason', 'retry', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($d2.Code -eq 2) 'retry still deferred'
    $cfg2 = @{ gameProcesses = @(); cpuBusyPercent = 0; deferOnFullscreen = $false } | ConvertTo-Json
    Set-Content -Path (Join-Path $data 'config.json') -Value $cfg2 -Encoding utf8
    $d3 = Invoke-SS @('scan', '--reason', 'retry', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($d3.Code -eq 0) 'retry runs the pending scan once free'
    $state2 = Get-Content (Join-Path $data 'state.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Check ($null -eq $state2.pending) 'pending cleared'
    $idle = Invoke-SS @('scan', '--reason', 'retry', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($idle.Code -eq 0 -and $idle.Ms -lt 3000) "retry with nothing pending exits fast ($([int]$idle.Ms) ms)"

    Write-Host "== 7. quick scan (service event)"
    $q = Invoke-SS @('scan', '--reason', 'service', '--quick', '--force', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($q.Code -eq 0) 'quick scan exits 0'
    $repq = Latest-Report
    Check ($repq.quick -eq $true -and @($repq.findings | Where-Object { $_.category -eq 'ComHijack' }).Count -eq 0) 'quick scan skips COM scanner'

    Write-Host "== 8. admin scope (runner is elevated)"
    $a = Invoke-SS @('scan', '--scope', 'admin', '--force', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($a.Code -eq 0) 'admin scope scan exits 0'

    if (-not $SkipInstall) {
        Write-Host "== 9. install / uninstall"
        $i = Invoke-SS @('install', '--data-dir', $data)
        Check ($i.Code -eq 0) 'install exits 0'
        foreach ($t in 'Logon', 'Daily', 'ServiceInstalled', 'Retry') {
            $null = schtasks /query /tn "\SafetySecurity\$t" 2>&1
            Check ($LASTEXITCODE -eq 0) "task \SafetySecurity\$t registered"
        }
        $xml = schtasks /query /tn '\SafetySecurity\Daily' /xml | Out-String
        Check ($xml -match '<Priority>7</Priority>') 'task priority 7'
        $tn = Invoke-SS @('test-notify', '--data-dir', $data)
        if ($tn.Code -ne 0) { Write-Host "  (info) toast could not be shown on this runner: exit $($tn.Code)" -ForegroundColor Yellow }
        Check ($tn.Text -notmatch 'TypeInitialization|MissingMetadata|NotSupported|PlatformNotSupported|COMException.*0x80040154') 'toast code path does not crash (WinRT projection works under AOT)'
        $st = Invoke-SS @('status', '--data-dir', $data)
        Check ($st.Text -match 'Daily') 'status lists tasks'
        $u = Invoke-SS @('uninstall', '--data-dir', $data)
        Check ($u.Code -eq 0) 'uninstall exits 0'
        $null = schtasks /query /tn '\SafetySecurity\Daily' 2>&1
        Check ($LASTEXITCODE -ne 0) 'tasks removed'
    }
}
finally {
    Remove-Item -Path $comKey -Recurse -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $runKey -Name $runName -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $evilDir -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "$($script:failures) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'All integration checks passed' -ForegroundColor Green
