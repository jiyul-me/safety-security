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
# 네트워크 경로 자동 실행 (203.0.113.0/24는 문서용 주소라 실제로는 아무 데도 없어요). 검사기는 이 경로를 열면 안 돼요.
$netName = 'SafetySecurityITNet'
$netTarget = '\\203.0.113.5\ss-it\update.exe'
# cmd /c start로 감싼 자동 실행: 감싼 cmd.exe가 아니라 실제로 실행되는 파일을 평가해야 해요.
$evilExe = Join-Path $evilDir 'upd.exe'
[IO.File]::WriteAllBytes($evilExe, $bytes)
$wrapName = 'SafetySecurityITWrap'
$wrapOkName = 'SafetySecurityITWrapOk'
# 시작프로그램 폴더 바로가기 (Windows가 만든 진짜 .lnk로 파서를 확인해요)
$startup = [Environment]::GetFolderPath('Startup')
$lnkTemp = Join-Path $startup 'ss-it-temp.lnk'
$lnkIdList = Join-Path $startup 'ss-it-idlist.lnk'
$lnkOk = Join-Path $startup 'ss-it-ok.lnk'
$lnkCmd = Join-Path $startup 'ss-it-cmd.lnk'
# SafetySecurity 이름을 흉내 낸 예약 작업 (루트의 예비 이름 꼴). 5년 뒤에만 실행되게 해서 실제로는 돌지 않아요.
$fakeTaskName = 'SafetySecurity-ITFake'

function New-Shortcut([string]$Path, [string]$Target, [string]$Arguments = '') {
    $shell = New-Object -ComObject WScript.Shell
    $s = $shell.CreateShortcut($Path)
    $s.TargetPath = $Target
    $s.Arguments = $Arguments
    $s.Save()
}

# 바로가기에서 LinkInfo와 상대 경로를 지워서 IDList(셸 항목)만 남겨요. 검사기가 IDList만으로 대상을 찾는지 확인해요.
function Save-IdListOnlyShortcut([string]$Source, [string]$Dest) {
    $b = [IO.File]::ReadAllBytes($Source)
    $flags = [BitConverter]::ToUInt32($b, 0x14)
    if (($flags -band 0x1) -eq 0) { throw "shortcut has no IDList: $Source" }
    $out = New-Object 'System.Collections.Generic.List[byte]'
    $out.AddRange([byte[]]$b[0..0x4B])
    $pos = 0x4C
    $idSize = [BitConverter]::ToUInt16($b, $pos)
    $out.AddRange([byte[]]$b[$pos..($pos + 1 + $idSize)])
    $pos += 2 + $idSize
    if ($flags -band 0x2) { $pos += [BitConverter]::ToUInt32($b, $pos) }
    $charSize = if ($flags -band 0x80) { 2 } else { 1 }
    foreach ($bit in 0x4, 0x8, 0x10, 0x20, 0x40) {
        if ($flags -band $bit) {
            $len = 2 + [BitConverter]::ToUInt16($b, $pos) * $charSize
            if ($bit -ne 0x8) { $out.AddRange([byte[]]$b[$pos..($pos + $len - 1)]) }
            $pos += $len
        }
    }
    if ($pos -lt $b.Length) { $out.AddRange([byte[]]$b[$pos..($b.Length - 1)]) }
    $newFlags = [long]$flags
    if ($newFlags -band 0x2) { $newFlags -= 0x2 }
    if ($newFlags -band 0x8) { $newFlags -= 0x8 }
    $bytesOut = $out.ToArray()
    [BitConverter]::GetBytes([uint32]$newFlags).CopyTo($bytesOut, 0x14)
    [IO.File]::WriteAllBytes($Dest, $bytesOut)
}

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
    # 우리가 '서명 없음'이라고 한 System32 파일은 Windows(Get-AuthenticodeSignature)도 NotSigned여야 해요.
    $disagree = 0
    foreach ($f in $sysUnsigned) {
        $win = (Get-AuthenticodeSignature -FilePath $f.target -ErrorAction SilentlyContinue).Status
        Write-Host "    System32 unsigned: $($f.target) (Windows says: $win)"
        if ("$win" -ne 'NotSigned') { $disagree++ }
    }
    Check ($disagree -eq 0) "unsigned verdicts agree with Get-AuthenticodeSignature ($($sysUnsigned.Count) checked)"
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
    if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
    Set-ItemProperty -Path $runKey -Name $runName -Value 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AA=='
    Set-ItemProperty -Path $runKey -Name $netName -Value "`"$netTarget`" /silent"
    Set-ItemProperty -Path $runKey -Name $wrapName -Value "cmd.exe /c start `"`" `"$evilExe`" -q"
    Set-ItemProperty -Path $runKey -Name $wrapOkName -Value "`"$env:SystemRoot\System32\cmd.exe`" /c start `"`" `"$env:SystemRoot\System32\whoami.exe`""
    New-Shortcut $lnkTemp $evilExe '-q'
    Save-IdListOnlyShortcut $lnkTemp $lnkIdList
    New-Shortcut $lnkOk '%SystemRoot%\System32\whoami.exe'
    New-Shortcut $lnkCmd "$env:SystemRoot\System32\cmd.exe" "/c start `"`" `"$evilExe`""
    Register-ScheduledTask -TaskName $fakeTaskName -TaskPath '\' -Action (New-ScheduledTaskAction -Execute $evilExe -Argument '-q') -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(5)) -Force | Out-Null
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
    $net = @($rep1.findings | Where-Object { $_.category -eq 'Autorun' -and $_.location -like "*\$netName" })
    Check ($net.Count -eq 1 -and $net[0].severity -eq 'High') 'network-path Run entry is High'
    if ($net.Count -eq 1) {
        Check (@($net[0].evidence | Where-Object { $_.key -eq '네트워크 위치' -and $_.value -eq '203.0.113.5' }).Count -eq 1) 'network-path finding names the host'
        Check (@($net[0].evidence | Where-Object { $_.key -eq '서명' -or $_.key -eq 'SHA-256' }).Count -eq 0) 'network-path file was not opened (no signature or hash)'
    }

    $wrap = @($rep1.findings | Where-Object { $_.category -eq 'Autorun' -and $_.location -like "*\$wrapName" })
    Check ($wrap.Count -eq 1 -and $wrap[0].severity -eq 'High') 'cmd /c start wrapped Run entry is High'
    if ($wrap.Count -eq 1) {
        Check ($wrap[0].target -eq $evilExe) "wrapped Run entry targets the real payload (got $($wrap[0].target))"
    }
    $wrapOk = @($rep1.findings | Where-Object { $_.category -eq 'Autorun' -and $_.location -like "*\$wrapOkName" })
    Check ($wrapOk.Count -eq 0) 'cmd /c start of a signed Windows program is not reported'
    foreach ($case in @(@{ Path = $lnkTemp; What = 'Windows-made shortcut' }, @{ Path = $lnkIdList; What = 'IDList-only shortcut' }, @{ Path = $lnkCmd; What = 'shortcut to cmd /c start' })) {
        $lf = @($rep1.findings | Where-Object { $_.ruleId -eq 'RUN-002' -and $_.location -eq $case.Path })
        Check ($lf.Count -eq 1 -and $lf[0].severity -eq 'High') "$($case.What) to a Temp payload is High"
        if ($lf.Count -eq 1) {
            Check ($lf[0].target -eq $evilExe) "$($case.What) targets the payload (got $($lf[0].target))"
            Check (@($lf[0].reasons | Where-Object { "$_" -like '*실제 실행 대상이 달라요*' }).Count -eq 0) "$($case.What) is not mistaken for a disguised shortcut"
        }
    }
    $lnkOkFindings = @($rep1.findings | Where-Object { $_.location -eq $lnkOk })
    Check ($lnkOkFindings.Count -eq 0) "Windows-made shortcut to a signed program is not reported $(($lnkOkFindings | ForEach-Object { $_.reasons -join ' / ' }) -join ' | ')"
    # 러너의 진짜 바로가기(시작 메뉴 등)를 대상 위장으로 잘못 보면 안 돼요.
    $disguised = @($rep1.findings | Where-Object { @($_.reasons | Where-Object { "$_" -like '*실제 실행 대상이 달라요*' }).Count -gt 0 })
    Check ($disguised.Count -eq 0) "no real shortcut on the runner is flagged as disguised ($(@($disguised.location) -join ', '))"
    # 이름만 SafetySecurity인 작업은 건너뛰지 않고 위장(TASK-003)으로 알려야 해요 (예전에는 이름만 보고 건너뛰었어요).
    $fake = @($rep1.findings | Where-Object { $_.location -eq "작업 스케줄러\$fakeTaskName" })
    Check ($fake.Count -eq 1 -and $fake[0].ruleId -eq 'TASK-003' -and $fake[0].severity -eq 'High') "task only named like SafetySecurity is TASK-003 High (got $(@($fake | ForEach-Object { "$($_.ruleId) $($_.severity)" }) -join ', '))"
    if ($fake.Count -eq 1) {
        Check ($fake[0].target -eq $evilExe) "look-alike task targets the program it runs (got $($fake[0].target))"
    }
    Unregister-ScheduledTask -TaskName $fakeTaskName -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue

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
    $repa = Latest-Report
    $wmiNote = @($repa.coverage | Where-Object { "$_" -like 'WMI*' })
    # PowerShell을 최소 환경(물려받지 않은 환경 변수)으로 실행해도 WMI 조회가 돼야 해요.
    Check ($wmiNote.Count -eq 0) "WMI subscriptions queried with the minimal child environment $($wmiNote -join ' ')"
    $aid = 'feedc0de12345678'
    $ia = Invoke-SS @('ignore', $aid, '--scope', 'admin', '--data-dir', $data)
    $adminState = Get-Content (Join-Path $data 'state.admin.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Check ($ia.Code -eq 0 -and @($adminState.ignored) -contains $aid) 'ignore --scope admin with --data-dir writes that folder directly'
    $null = Invoke-SS @('unignore', $aid, '--scope', 'admin', '--data-dir', $data)

    Write-Host "== 8b. default data folder of an elevated process"
    # 관리자 권한 프로세스는 사용자 폴더(%LOCALAPPDATA%)가 아니라 관리자만 쓸 수 있는 폴더를 써요 (status는 아무것도 만들지 않아요).
    $adminRoot = Join-Path $env:ProgramFiles 'SafetySecurity\data'
    $sd = Invoke-SS @('status')
    Check ($sd.Text -match [regex]::Escape("데이터 폴더: $adminRoot")) "elevated default data folder is $adminRoot"

    if (-not $SkipInstall) {
        Write-Host "== 9. install / uninstall"
        $i = Invoke-SS @('install', '--data-dir', $data)
        Check ($i.Code -eq 0) 'install exits 0'
        foreach ($t in 'Logon', 'Daily', 'ServiceInstalled', 'Retry') {
            $null = schtasks /query /tn "\SafetySecurity\$t" 2>&1
            Check ($LASTEXITCODE -eq 0) "task \SafetySecurity\$t registered"
        }
        $task = Get-ScheduledTask -TaskPath '\SafetySecurity\' -TaskName 'Daily'
        Check ($task.Settings.Priority -eq 7) "task priority 7 (got $($task.Settings.Priority))"
        Check ($task.Settings.ExecutionTimeLimit -eq 'PT15M') "task time limit 15 min (got $($task.Settings.ExecutionTimeLimit))"
        Check ($task.Principal.RunLevel -eq 'Limited') "task runs with least privilege (got $($task.Principal.RunLevel))"
        # 진짜 작업은 schtasks가 돌려주는 XML 그대로 검사해도 우리 작업으로 알아봐야 해요 (이름이 아니라 실행 파일·인자로 확인).
        $ownScan = Scan @('--quick')
        Check ($ownScan.Code -eq 0) 'scan with our own tasks installed exits 0'
        $repOwn = Latest-Report
        $ownHits = @($repOwn.findings | Where-Object { $_.location -like '작업 스케줄러\SafetySecurity*' })
        Check ($ownHits.Count -eq 0) "our own tasks are recognised and not reported ($(@($ownHits | ForEach-Object { "$($_.ruleId) $($_.location)" }) -join ', '))"
        # 우리 작업을 끄면 자동 검사가 멈춘 것이라 보통(TASK-004)으로 알려야 해요. 시험이 끝나면 uninstall이 작업을 지워요.
        $null = schtasks /change /tn '\SafetySecurity\Retry' /disable 2>&1
        Check ($LASTEXITCODE -eq 0) 'test disabled \SafetySecurity\Retry'
        $null = Scan @('--quick')
        $repOff = Latest-Report
        $off = @($repOff.findings | Where-Object { $_.location -eq '작업 스케줄러\SafetySecurity\Retry' })
        Check ($off.Count -eq 1 -and $off[0].ruleId -eq 'TASK-004' -and $off[0].severity -eq 'Medium') "disabled own task is TASK-004 Medium (got $(@($off | ForEach-Object { "$($_.ruleId) $($_.severity)" }) -join ', '))"
        $null = schtasks /change /tn '\SafetySecurity\Retry' /enable 2>&1
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
    Remove-ItemProperty -Path $runKey -Name $netName -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $runKey -Name $wrapName -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $runKey -Name $wrapOkName -ErrorAction SilentlyContinue
    Remove-Item -Force $lnkTemp, $lnkIdList, $lnkOk, $lnkCmd -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $fakeTaskName -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $evilDir -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "$($script:failures) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'All integration checks passed' -ForegroundColor Green
exit 0
