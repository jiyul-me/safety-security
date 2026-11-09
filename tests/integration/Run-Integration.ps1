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
# 이 파일은 UTF-8(BOM 있음)로 저장해야 해요. BOM이 없으면 Windows PowerShell 5.1이 시스템 코드 페이지(CP949·CP1252)로 읽어서
# '서명 없음' 같은 한글 비교가 늘 어긋나고, 그런 검사는 아무것도 확인하지 않은 채 통과해요. 그럴 때는 바로 멈춰요.
if ('서명'.Length -ne 2) { throw 'Run-Integration.ps1 was read with the wrong encoding. Save it as UTF-8 with BOM (see .editorconfig) or run it with pwsh.' }
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

# state.json의 시각 칸 하나를 바꿔요 (예: 마지막 전체 검사를 3시간 전으로). JSON 전체를 다시 쓰지 않고 그 값만 바꿔요.
function Set-StateTime([string]$Field, [datetime]$Utc) {
    $path = Join-Path $data 'state.json'
    $raw = [IO.File]::ReadAllText($path)
    $value = $Utc.ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + '+00:00'
    $new = [regex]::Replace($raw, '("' + $Field + '"\s*:\s*)"[^"]*"', ('${1}"' + $value + '"'))
    if ($new -eq $raw) { throw "state.json has no $Field to change" }
    [IO.File]::WriteAllText($path, $new, (New-Object Text.UTF8Encoding $false))
}

function Read-State { return Get-Content (Join-Path $data 'state.json') -Raw -Encoding utf8 | ConvertFrom-Json }

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

# 가짜 디스코드 폴더 (러너에 진짜 디스코드가 없을 때만 만들어요). index.js가 $null이면 만들지 않아요.
$discordRoot = Join-Path $env:LOCALAPPDATA 'DiscordDevelopment'
$discordCreated = $false
$discordStock = "module.exports = require('./core.asar');"
function New-DiscordCore([string]$App, [AllowNull()][string]$Index) {
    $dir = Join-Path $discordRoot "$App\modules\discord_desktop_core-1\discord_desktop_core"
    New-Item -ItemType Directory -Force $dir | Out-Null
    $utf8 = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllBytes((Join-Path $dir 'core.asar'), (New-Object byte[] 2048))
    [IO.File]::WriteAllText((Join-Path $dir 'package.json'), '{"name":"discord_desktop_core","version":"0.0.0","private":"true","main":"index.js"}', $utf8)
    if ($Index) { [IO.File]::WriteAllText((Join-Path $dir 'index.js'), $Index, $utf8) }
    return $dir
}

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
    # --version·--help는 예전에 '-'로 시작해서 명령으로 안 보고 바로 검사(보고서 열기)를 시작했어요.
    $flagData = Join-Path $work 'flag-data'
    $vv = Invoke-SS @('--version', '--data-dir', $flagData)
    Check ($vv.Code -eq 0 -and $vv.Text -match 'SafetySecurity \d') '--version prints the version'
    foreach ($h in '--help', '-h', '/?') {
        $hh = Invoke-SS @($h, '--data-dir', $flagData)
        Check ($hh.Code -eq 0 -and "$($hh.Text)".Contains('사용법')) "$h prints help"
    }
    $bogusFlag = Invoke-SS @('--frobnicate', '--data-dir', $flagData)
    Check ($bogusFlag.Code -eq 1 -and "$($bogusFlag.Text)".Contains('알 수 없는 명령')) 'an unknown leading option shows help instead of scanning'
    Check (-not (Test-Path (Join-Path $flagData 'reports')) -and -not (Test-Path (Join-Path $flagData 'state.json'))) 'help, version and unknown options do not scan'

    # 사용자의 cmd 창에 붙어서 출력해도 그 창의 코드 페이지를 바꾸면 안 돼요 (예전에는 65001(UTF-8)로 바꿔 놓고 끝났어요).
    # 진짜 콘솔이 있어야 해서 숨긴 cmd 창에서 실행하고, 끝난 뒤 chcp 결과를 파일로 받아요.
    # --quiet: 콘솔에 붙고 출력 인코딩을 정하는 것까지는 똑같이 하지만, 혹시 콘솔에 못 붙어도 메시지 창을 띄워 멈추지 않아요.
    $cpOut = Join-Path $work 'chcp.txt'
    $cpLine = '/d /c chcp 437 >nul & start "" /wait "' + $Exe + '" version --quiet --data-dir "' + $flagData + '" & chcp > "' + $cpOut + '"'
    $null = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList $cpLine -Wait -PassThru -WindowStyle Hidden
    $cpText = if (Test-Path $cpOut) { [IO.File]::ReadAllText($cpOut) } else { '' }
    if ($cpText -match '(\d{3,5})') { Check ($Matches[1] -eq '437') "console code page is left as it was after the exe ran in it (got $($Matches[1]))" }
    else { Write-Host "  (info) could not read the console code page on this runner: '$cpText'" -ForegroundColor Yellow }
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
    # hosts 항목은 위치가 모두 hosts 파일이라(줄 번호는 ID에 넣지 않아요) 위치와 대상(IP 주소)을 같이 봐요.
    $dupes = @($rep0.findings | Group-Object { if ($_.category -eq 'Hosts') { "$($_.location)|$($_.target)".ToLowerInvariant() } else { $_.location.ToLowerInvariant() } } | Where-Object Count -gt 1)
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
        # 2단계의 System32 서명 비교는 보통 대상이 0개라서, 한글 증거 이름·값이 보고서와 맞는지 여기서 꼭 확인해요.
        # (가짜 DLL은 서명이 없어요. 맞지 않으면 그 비교가 아무것도 확인하지 않은 채 통과해요.)
        Check (@($com[0].evidence | Where-Object { $_.key -eq '서명' -and $_.value -eq '서명 없음' }).Count -ge 1) "unsigned evidence label matches the report ('서명' = '서명 없음')"
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

    Write-Host "== 3b. Discord client injection"
    if (Test-Path -LiteralPath $discordRoot) {
        Write-Host "  (info) $discordRoot already exists on this machine; Discord checks skipped" -ForegroundColor Yellow
    }
    else {
        $discordCreated = $true
        # 원래 파일(CRLF로 끝나도 원래 파일이에요), 토큰 그래버처럼 코드를 넣은 파일, 다른 파일을 가리키는 심볼릭 링크.
        $dStock = New-DiscordCore 'app-0.0.1' ($discordStock + "`r`n")
        $dEvil = New-DiscordCore 'app-0.0.2' ("const hook = 'https://discord.com/api/webhooks/000/ss-it';`n" + $discordStock)
        $dLink = New-DiscordCore 'app-0.0.3' $null
        $linkMade = $false
        try {
            New-Item -ItemType SymbolicLink -Path (Join-Path $dLink 'index.js') -Target (Join-Path $dEvil 'index.js') -ErrorAction Stop | Out-Null
            $linkMade = $true
        }
        catch { Write-Host "  (info) could not create a symbolic link on this runner: $($_.Exception.Message)" -ForegroundColor Yellow }
        $rd = Scan
        Check ($rd.Code -eq 0) 'scan with fake Discord folders exits 0'
        $repd = Latest-Report
        $disc = @($repd.findings | Where-Object { $_.category -eq 'Discord' })
        $disc | ForEach-Object { Write-Host "    [$($_.severity)] $($_.ruleId) $($_.title) :: $($_.location)" }
        Check (@($disc | Where-Object { $_.location.StartsWith($dStock, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) 'stock Discord index.js is not reported'
        $inj = @($disc | Where-Object { $_.location -eq (Join-Path $dEvil 'index.js') })
        Check ($inj.Count -eq 1 -and $inj[0].ruleId -eq 'DISC-001' -and $inj[0].severity -eq 'High') "injected Discord index.js is DISC-001 High (got $(@($inj | ForEach-Object { "$($_.ruleId) $($_.severity)" }) -join ', '))"
        if ($inj.Count -eq 1) {
            $dHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $dEvil 'index.js')).Hash.ToLowerInvariant()
            Check (@($inj[0].evidence | Where-Object { $_.key -eq 'SHA-256' -and $_.value -eq $dHash }).Count -eq 1) 'injected index.js evidence has its SHA-256'
            Check (@($inj[0].evidence | Where-Object { $_.key -eq '의심스러운 코드' -and "$($_.value)" -like '*webhooks*' }).Count -eq 1) 'injected index.js evidence names the webhook code'
        }
        if ($linkMade) {
            $lk = @($disc | Where-Object { $_.location -eq (Join-Path $dLink 'index.js') })
            Check ($lk.Count -eq 1 -and $lk[0].severity -eq 'High') "symbolic-link index.js is High (found $($lk.Count))"
            if ($lk.Count -eq 1) {
                Check (@($lk[0].evidence | Where-Object { $_.key -eq 'SHA-256' }).Count -eq 0) 'symbolic-link index.js was not followed (no hash)'
            }
        }
        Remove-Item -Recurse -Force -LiteralPath $discordRoot -ErrorAction SilentlyContinue
    }

    Write-Host "== 4. second scan: same items are no longer new"
    $null = Scan
    $rep2 = Latest-Report
    $com2 = @($rep2.findings | Where-Object { $_.category -eq 'ComHijack' -and $_.location -like "*$clsid*" })
    Check ($com2.Count -ge 1 -and $com2[0].isNew -eq $false) 'baseline remembers COM finding'

    Write-Host "== 5. ignore"
    # 기록에 없는 ID(오타)는 저장하지 않고 거절해야 해요.
    $bogus = Invoke-SS @('ignore', '0123456789abcdef', '--data-dir', $data)
    $stBogus = Get-Content (Join-Path $data 'state.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Check ($bogus.Code -eq 1 -and @($stBogus.ignored) -notcontains '0123456789abcdef') "ignore refuses an ID that is not in the records (exit $($bogus.Code))"
    $ig = Invoke-SS @('ignore', $com2[0].id, '--data-dir', $data)
    Check ($ig.Code -eq 0) 'ignore exits 0'
    Check ("$($ig.Text)".Contains($com2[0].title)) 'ignore shows the title of the item it hides'
    $null = Scan
    $rep3 = Latest-Report
    Check (@($rep3.findings | Where-Object { $_.id -eq $com2[0].id }).Count -eq 0 -and $rep3.ignoredCount -ge 1) 'ignored finding hidden'
    Check (@($rep3.ignored | Where-Object { $_.id -eq $com2[0].id }).Count -eq 1) 'report lists the hidden item'
    $il = Invoke-SS @('ignored', '--data-dir', $data)
    Check ($il.Code -eq 0 -and "$($il.Text)".Contains($com2[0].id)) 'ignored command lists the hidden item'
    $ub = Invoke-SS @('unignore', '0123456789abcdef', '--data-dir', $data)
    Check ($ub.Code -eq 1) "unignore refuses an ID that is not hidden (exit $($ub.Code))"

    Write-Host "== 5b. a swapped file at the same place is shown again"
    # 같은 경로의 DLL을 다른 내용으로 바꾸고 시각을 되돌려요(timestomp). ID는 같지만 SHA-256이 달라서 숨김이 풀려야 해요.
    $oldDll = Get-Item $evilDll
    $created = $oldDll.CreationTimeUtc
    $written = $oldDll.LastWriteTimeUtc
    $swap = [byte[]]$bytes.Clone()
    $swap[0x200] = 0x42
    [IO.File]::WriteAllBytes($evilDll, $swap)
    (Get-Item $evilDll).CreationTimeUtc = $created
    (Get-Item $evilDll).LastWriteTimeUtc = $written
    $null = Scan
    $rep4 = Latest-Report
    $back = @($rep4.findings | Where-Object { $_.id -eq $com2[0].id })
    Check ($back.Count -eq 1 -and $null -ne $back[0].ignoreNote -and $back[0].isNew -eq $true) "hidden COM finding is shown again after its DLL was swapped (found $($back.Count))"
    $re = Invoke-SS @('ignore', $com2[0].id.Substring(0, 10), '--data-dir', $data)
    Check ($re.Code -eq 0) 'ignore accepts a unique ID prefix and hides the changed item again'
    $null = Scan
    $rep5 = Latest-Report
    Check (@($rep5.findings | Where-Object { $_.id -eq $com2[0].id }).Count -eq 0) 'item hidden again with its new state'

    Write-Host "== 5c. no second full scan right after one"
    # 로그온·하루 한 번 검사는 방금(2시간 안) 전체 검사를 끝냈으면 같은 검사를 또 하지 않아요.
    $before = @(Get-ChildItem $reports -Filter *.json).Count
    $lg = Invoke-SS @('scan', '--reason', 'logon', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    $after = @(Get-ChildItem $reports -Filter *.json).Count
    Check ($lg.Code -eq 0 -and $after -eq $before -and $lg.Ms -lt 5000) "logon scan right after a full scan is skipped (exit $($lg.Code), reports $before -> $after, $([int]$lg.Ms) ms)"

    Write-Host "== 6. game deferral and retry"
    # 마지막 전체 검사를 3시간 전으로 돌려서, 하루 한 번 검사가 '방금 검사함'으로 건너뛰지 않게 해요.
    Set-StateTime 'lastFullScanUtc' ((Get-Date).ToUniversalTime().AddHours(-3))
    $cfg = @{ gameProcesses = @('pwsh.exe', 'powershell.exe'); notifyMinSeverity = 'Medium'; cpuBusyPercent = 0; deferOnFullscreen = $false } | ConvertTo-Json
    Set-Content -Path (Join-Path $data 'config.json') -Value $cfg -Encoding utf8
    $d = Invoke-SS @('scan', '--reason', 'daily', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($d.Code -eq 2) "scan deferred while game process runs (exit $($d.Code))"
    $state = Read-State
    Check ($null -ne $state.pending -and $state.pending.reason -eq 'Daily') 'pending scan recorded'
    $d2 = Invoke-SS @('scan', '--reason', 'retry', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($d2.Code -eq 2) 'retry still deferred'
    # 하루 넘게 밀려도 게임 프로세스가 실행 중이면 절대 검사하지 않아요 (대신 한 번만 알려요. 여기서는 --no-toast라 기록만 남아요).
    Set-StateTime 'sinceUtc' ((Get-Date).ToUniversalTime().AddHours(-30))
    $d2b = Invoke-SS @('scan', '--reason', 'retry', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    $stateOver = Read-State
    Check ($d2b.Code -eq 2) "overdue scan still waits while a game process runs (exit $($d2b.Code))"
    Check ($null -ne $stateOver.pending -and $null -ne $stateOver.pending.overdueNoticeUtc) 'overdue warning recorded once'
    $st6 = Invoke-SS @('status', '--data-dir', $data)
    Check ("$($st6.Text)" -match '시간째 밀려') 'status says the scan is overdue'
    $cfg2 = @{ gameProcesses = @(); cpuBusyPercent = 0; deferOnFullscreen = $false } | ConvertTo-Json
    Set-Content -Path (Join-Path $data 'config.json') -Value $cfg2 -Encoding utf8
    $d3 = Invoke-SS @('scan', '--reason', 'retry', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($d3.Code -eq 0) 'retry runs the pending scan once free'
    $state2 = Get-Content (Join-Path $data 'state.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Check ($null -eq $state2.pending) 'pending cleared'
    $idle = Invoke-SS @('scan', '--reason', 'retry', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($idle.Code -eq 0 -and $idle.Ms -lt 3000) "retry with nothing pending exits fast ($([int]$idle.Ms) ms)"

    Write-Host "== 6b. a scan that overlaps another one is kept for later"
    # 전체 검사가 도는 동안 새 서비스 검사가 오면 버리지 않고 미뤄둔 빠른 검사로 남겨야 해요 (Retry가 해요).
    $holdOut = Join-Path $work 'hold-out.txt'
    $holder = Start-Process -FilePath $Exe -ArgumentList @('scan', '--force', '--no-toast', '--data-dir', ('"' + $data + '"'), '--report-dir', ('"' + $reports + '"')) -PassThru -NoNewWindow -RedirectStandardOutput $holdOut
    $null = $holder.Handle  # 끝난 뒤에도 종료 코드를 읽을 수 있게 핸들을 잡아 둬요 (PowerShell의 알려진 문제).
    Start-Sleep -Milliseconds 700
    $svc = Invoke-SS @('scan', '--reason', 'service', '--quick', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    $holder.WaitForExit()
    if ($svc.Code -eq 2) {
        $stateHold = Read-State
        Check ($holder.ExitCode -eq 0) "the running full scan finished (exit $($holder.ExitCode))"
        Check ($null -ne $stateHold.pending -and $stateHold.pending.quick -eq $true) 'the overlapping service scan is kept as a pending quick scan after the full scan saved'
        $rr = Invoke-SS @('scan', '--reason', 'retry', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
        Check ($rr.Code -eq 0 -and $null -eq (Read-State).pending) 'retry runs the kept quick scan'
    }
    else {
        Write-Host "  (info) the full scan finished before the service scan started (exit $($svc.Code)); overlap check skipped" -ForegroundColor Yellow
    }

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
    # 관리자 검사 잠금은 일반 권한 프로그램이 이름을 먼저 차지할 수 있는 Local\ 뮤텍스가 아니라, 관리자·SYSTEM만 여는 잠금 파일이에요.
    # 예전 이름의 뮤텍스를 먼저 잡아 둬도 관리자 검사는 막히지 않아야 해요.
    $squat = [System.Threading.Mutex]::new($true, 'Local\SafetySecurity.Scan.Admin')
    try {
        $sq = Invoke-SS @('scan', '--scope', 'admin', '--quick', '--force', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
        Check ($sq.Code -eq 0) "admin scan is not blocked by a squatted Local\ mutex (exit $($sq.Code))"
    }
    finally { $squat.Dispose() }
    $lockPath = Join-Path $data 'scan.admin.lock'
    Check (Test-Path -LiteralPath $lockPath) 'admin scan lock file exists in the data folder'
    if (Test-Path -LiteralPath $lockPath) {
        $acl = Get-Acl -LiteralPath $lockPath
        $sids = @($acl.Access | ForEach-Object { try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { "$($_.IdentityReference)" } })
        $okSids = @('S-1-5-32-544', 'S-1-5-18')
        Check ($acl.AreAccessRulesProtected -and @($sids | Where-Object { $okSids -notcontains $_ }).Count -eq 0) "admin lock file is only for Administrators/SYSTEM, not inherited ($($sids -join ', '))"
        # 다른 관리자 검사가 잠금 파일을 잡고 있으면 직접 검사는 '이미 실행 중'(4)으로 끝나야 해요.
        $held = [System.IO.File]::Open($lockPath, 'Open', 'ReadWrite', 'None')
        try {
            $busyA = Invoke-SS @('scan', '--scope', 'admin', '--quick', '--force', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
            Check ($busyA.Code -eq 4) "admin scan reports already running while the lock file is held (exit $($busyA.Code))"
        }
        finally { $held.Dispose() }
    }
    $aq = Invoke-SS @('scan', '--scope', 'admin', '--reason', 'service', '--quick', '--force', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    $repaq = Latest-Report
    # 관리자 설치의 예비 작업(ServiceInstalledAdmin)이 하는 검사: 서비스를 정말 검사해야 해요.
    Check ($aq.Code -eq 0 -and $repaq.quick -eq $true -and @($repaq.completed) -contains '서비스·드라이버') "admin quick scan checks services ($(@($repaq.completed) -join ', '))"
    $aid = 'feedc0de12345678'
    $ia = Invoke-SS @('ignore', $aid, '--scope', 'admin', '--data-dir', $data)
    $adminState = Get-Content (Join-Path $data 'state.admin.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Check ($ia.Code -eq 1 -and @($adminState.ignored) -notcontains $aid) "ignore --scope admin refuses an ID that is not in the admin records (exit $($ia.Code))"
    $userIds = @((Get-Content (Join-Path $data 'state.json') -Raw -Encoding utf8 | ConvertFrom-Json).baseline.PSObject.Properties | ForEach-Object Name)
    $adminOnly = @($repa.findings | Where-Object { $userIds -notcontains $_.id } | Select-Object -First 1)
    if ($adminOnly.Count -eq 1) {
        $aid2 = $adminOnly[0].id
        # --scope 없이 적어도 관리자 검사 기록에서 찾아서, --data-dir 폴더의 관리자 기록에 바로 써요.
        $ia2 = Invoke-SS @('ignore', $aid2, '--data-dir', $data)
        $adminState2 = Get-Content (Join-Path $data 'state.admin.json') -Raw -Encoding utf8 | ConvertFrom-Json
        Check ($ia2.Code -eq 0 -and @($adminState2.ignored) -contains $aid2) 'ignore finds an admin-only item without --scope and writes the admin records'
        $ua = Invoke-SS @('unignore', $aid2, '--data-dir', $data)
        $adminState3 = Get-Content (Join-Path $data 'state.admin.json') -Raw -Encoding utf8 | ConvertFrom-Json
        Check ($ua.Code -eq 0 -and @($adminState3.ignored) -notcontains $aid2) 'unignore removes the admin item again'
    }
    else {
        Write-Host '  (info) the admin scan reported nothing that only the admin scope has; admin ignore round trip skipped' -ForegroundColor Yellow
    }

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
    if ($discordCreated) { Remove-Item -Recurse -Force -LiteralPath $discordRoot -ErrorAction SilentlyContinue }
}

if ($script:failures -gt 0) {
    Write-Host "$($script:failures) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'All integration checks passed' -ForegroundColor Green
exit 0
