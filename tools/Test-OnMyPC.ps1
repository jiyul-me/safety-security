<#
.SYNOPSIS
  SafetySecurity를 내 PC에서 안전하게 시험해 보는 안내형 스크립트.

.DESCRIPTION
  - 실제 시스템 항목은 건드리지 않아요. 존재하지 않는 가짜 GUID와 임시 폴더의 가짜 DLL만 만들고, 끝나면 반드시 지워요.
  - 시험용 검사 기록은 임시 폴더에 따로 저장해서, 설치된 SafetySecurity의 기록(베이스라인)에 섞이지 않아요.
  - 결과 요약은 사용자 이름·PC 이름을 가린 채로 %LOCALAPPDATA%\SafetySecurity\pc-test-result.txt에 저장돼요.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1 -Only 4
  (4단계 '서비스 설치 시험'만 다시 해요. 관리자 PowerShell에서 실행하세요.)
#>
param(
    [string]$Exe,
    [switch]$NonInteractive,
    # 실행할 단계 번호 (예: "4" 또는 "1,4"). 비우면 전부 실행해요.
    [string]$Only
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- 준비
if (-not $Exe) {
    $candidates = @(
        (Join-Path $PSScriptRoot '..\SafetySecurity.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\SafetySecurity\SafetySecurity.exe'),
        (Join-Path $env:ProgramFiles 'SafetySecurity\SafetySecurity.exe')
    )
    foreach ($c in $candidates) { if (Test-Path $c) { $Exe = $c; break } }
}
if (-not $Exe -or -not (Test-Path $Exe)) {
    Write-Host 'SafetySecurity.exe를 찾지 못했어요. -Exe 경로\SafetySecurity.exe 로 알려 주세요.' -ForegroundColor Red
    exit 1
}
$Exe = (Resolve-Path $Exe).Path

$work = Join-Path $env:TEMP ('ss-pctest-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$data = Join-Path $work 'data'
$reports = Join-Path $work 'reports'
$fakeDir = Join-Path $work 'fake'
New-Item -ItemType Directory -Force $data, $reports, $fakeDir | Out-Null
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$script:results = New-Object System.Collections.Generic.List[string]
$script:failures = 0

function Say([string]$text, [string]$color = 'Gray') { Write-Host $text -ForegroundColor $color }
function Title([string]$text) { Write-Host ''; Write-Host "=== $text ===" -ForegroundColor Cyan; $script:results.Add("== $text") }
function Check([bool]$ok, [string]$what) {
    if ($ok) { Say "  [통과] $what" 'Green'; $script:results.Add("PASS  $what") }
    else { Say "  [실패] $what" 'Red'; $script:results.Add("FAIL  $what"); $script:failures++ }
}
function Note([string]$what) { Say "  [참고] $what" 'Yellow'; $script:results.Add("NOTE  $what") }
function Pause-Step([string]$prompt = '계속하려면 Enter를 누르세요') {
    if ($NonInteractive) { return }
    [void](Read-Host $prompt)
}
function Ask([string]$question) {
    if ($NonInteractive) { return $false }
    $a = Read-Host "$question (y/n)"
    return $a -match '^(y|yes|ㅇ|예|네)$'
}

function Invoke-SS([string[]]$ArgList) {
    $id = [guid]::NewGuid().ToString('N')
    $out = Join-Path $work "out-$id.txt"
    $err = Join-Path $work "err-$id.txt"
    $quoted = $ArgList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $Exe -ArgumentList $quoted -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
    $sw.Stop()
    $text = ''
    if (Test-Path $out) { $text = [IO.File]::ReadAllText($out, [Text.Encoding]::UTF8) }
    return New-Object psobject -Property @{ Code = $p.ExitCode; Text = $text; Ms = [int]$sw.Elapsed.TotalMilliseconds }
}

function Latest-Report {
    $f = Get-ChildItem $reports -Filter *.json | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $f) { return $null }
    return ([IO.File]::ReadAllText($f.FullName, [Text.Encoding]::UTF8) | ConvertFrom-Json)
}

$script:onlySteps = @()
if ($Only) { $script:onlySteps = @($Only -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { [int]$_ }) }
function Want([int]$step) { return ($script:onlySteps.Count -eq 0) -or ($script:onlySteps -contains $step) }

function Redact([string]$s) {
    if (-not $s) { return $s }
    if ($env:USERNAME) { $s = $s -replace [regex]::Escape($env:USERNAME), '<user>' }
    if ($env:COMPUTERNAME) { $s = $s -replace [regex]::Escape($env:COMPUTERNAME), '<pc>' }
    return $s
}

# 4단계(서비스 설치 시험)는 관리자 권한이 필요해요. 관리자가 아니면 다시 열어 줄지 물어봐요.
if (-not $isAdmin -and -not $NonInteractive -and (Want 4)) {
    Say ''
    Say '지금은 관리자 권한이 아니에요. 4단계(서비스 설치 시험)는 관리자 권한이 필요해요.' 'Yellow'
    if (Ask '관리자 권한 PowerShell로 다시 열까요? (UAC 창에서 "예")') {
        $relaunch = @('-NoExit', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), '-Exe', ('"' + $Exe + '"'))
        if ($Only) { $relaunch += @('-Only', $Only) }
        try {
            Start-Process powershell -Verb RunAs -ArgumentList $relaunch -WorkingDirectory (Split-Path $Exe)
            Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
            exit 0
        }
        catch { Say '관리자 권한으로 열지 못했어요. 이대로 진행할게요 (4단계는 건너뛰어요).' 'Yellow' }
    }
}

Say ''
Say 'SafetySecurity PC 시험' 'Cyan'
Say "  실행 파일: $Exe"
Say "  시험 폴더: $work (끝나면 지워도 돼요)"
Say "  관리자 권한: $(if ($isAdmin) { '예' } else { '아니요 (서비스 설치 시험은 건너뛰어요)' })"
Say '  실제 시스템은 바꾸지 않아요. 가짜 항목은 마지막에 모두 지워요.'
Pause-Step

$comKey = $null
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runName = 'SafetySecurityPcTest'

try {
    # ------------------------------------------------------------ 1. 기본 동작
    if (Want 1) {
    Title '1. 기본 동작'
    $hash = (Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower()
    Say "  SHA-256: $hash"
    Say '  (릴리스의 SHA256SUMS.txt와 같은지 확인하세요)'
    $script:results.Add("sha256 $hash")
    $v = Invoke-SS @('version')
    Check ($v.Code -eq 0 -and $v.Text -match 'SafetySecurity \d') "버전 확인: $($v.Text.Trim())"
    $h = Invoke-SS @('--help')
    Check ($h.Code -eq 0 -and $h.Text -match '사용법') '도움말 (--help는 검사를 시작하지 않고 도움말을 보여줘요)'
    $script:results.Add("windows $([Environment]::OSVersion.Version) admin=$isAdmin")
    $k = Invoke-SS @('verify', "$env:SystemRoot\System32\kernel32.dll")
    Check ($k.Code -eq 0) 'Windows 파일 서명 확인 (kernel32.dll = 유효)'
    # 기본 데이터 폴더: 관리자 권한이면 관리자만 쓸 수 있는 Program Files\SafetySecurity\data, 아니면 %LOCALAPPDATA%\SafetySecurity
    # (status는 읽기만 하고 아무것도 만들지 않아요.)
    $expectedData = if ($isAdmin) { Join-Path $env:ProgramFiles 'SafetySecurity\data' } else { Join-Path $env:LOCALAPPDATA 'SafetySecurity' }
    $st = Invoke-SS @('status')
    Check ($st.Text -match [regex]::Escape("데이터 폴더: $expectedData")) "기본 데이터 폴더 ($(if ($isAdmin) { '관리자 권한' } else { '일반 권한' })): $expectedData"
    $n = Invoke-SS @('test-notify', '--data-dir', $data)
    Check ($n.Code -eq 0) '알림 보내기'
    if (-not $NonInteractive) {
        Check (Ask '  화면 오른쪽 아래에 "알림 테스트예요" 알림이 떴나요?') '알림이 화면에 보임'
    }

    }

    # ------------------------------------------------------------ 2. 가짜 악성 등록 탐지
    if (Want 2) {
    Title '2. 가짜 COM 하이재킹·자동 실행 탐지'
    do { $guid = '{' + [guid]::NewGuid().ToString().ToUpper() + '}' }
    while ((Test-Path "HKLM:\SOFTWARE\Classes\CLSID\$guid") -or (Test-Path "HKCU:\Software\Classes\CLSID\$guid"))
    $comKey = "HKCU:\Software\Classes\CLSID\$guid"
    $fakeDll = Join-Path $fakeDir 'update.dll'
    $bytes = New-Object byte[] 1024
    $bytes[0] = 0x4D; $bytes[1] = 0x5A; $bytes[0x3C] = 0x80; $bytes[0x80] = 0x50; $bytes[0x81] = 0x45
    [IO.File]::WriteAllBytes($fakeDll, $bytes)
    New-Item -Path "$comKey\InprocServer32" -Force | Out-Null
    Set-ItemProperty -Path "$comKey\InprocServer32" -Name '(default)' -Value $fakeDll
    # 무해한 명령 ('SafetySecurity test' 출력)을 인코딩해서 넣어요. 혹시 재부팅해도 아무 일도 안 일어나요.
    $harmless = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'SafetySecurity test'"))
    if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
    Set-ItemProperty -Path $runKey -Name $runName -Value "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $harmless"
    Say "  가짜 CLSID: $guid → 임시 폴더의 서명 없는 DLL"
    Say "  가짜 자동 실행: HKCU Run\$runName → 숨김 PowerShell -EncodedCommand"

    $s = Invoke-SS @('scan', '--force', '--no-toast', '--data-dir', $data, '--report-dir', $reports)
    Check ($s.Code -eq 0) "검사 실행 ($([math]::Round($s.Ms / 1000, 1))초)"
    $rep = Latest-Report
    $com = @($rep.findings | Where-Object { $_.category -eq 'ComHijack' -and $_.location -like "*$guid*" })
    Check ($com.Count -eq 1 -and $com[0].severity -eq 'High') '가짜 COM 하이재킹을 위험도 높음으로 탐지'
    $run = @($rep.findings | Where-Object { $_.category -eq 'Autorun' -and $_.location -like "*\$runName" })
    Check ($run.Count -eq 1 -and $run[0].severity -eq 'High') '가짜 자동 실행을 위험도 높음으로 탐지'

    # 실제 PC의 결과 (가짜 항목 제외) — 오탐이 얼마나 나오는지 보는 용도
    $real = @($rep.findings | Where-Object { $_.location -notlike "*$guid*" -and $_.location -notlike "*\$runName" -and $_.location -notlike "*ss-pctest*" })
    $byRule = $real | Group-Object ruleId, severity | Sort-Object Name
    Note "이 PC의 실제 항목: $($real.Count)개 (가짜 항목 제외)"
    foreach ($g in $byRule) { $script:results.Add("rule $($g.Name) x$($g.Count)") }
    # 오탐 판단에 필요한 정보만 남겨요 (사용자 이름·PC 이름은 Redact로 가려요).
    foreach ($f in $real) {
        # cmd /c 등으로 감싼 명령은 감싼 cmd.exe가 아니라 실제로 실행되는 파일('실제 파일 서명')의 서명을 적어요.
        $sig = @($f.evidence | Where-Object { $_.key -eq '실제 파일 서명' } | Select-Object -First 1)
        if ($sig.Count -eq 0) { $sig = @($f.evidence | Where-Object { $_.key -eq '서명' -or $_.key -eq 'DLL 서명' -or $_.key -eq '페이로드 서명' } | Select-Object -First 1) }
        $signer = @($f.evidence | Where-Object { $_.key -eq '실제 파일 서명자' } | Select-Object -First 1)
        if ($signer.Count -eq 0) { $signer = @($f.evidence | Where-Object { $_.key -like '*서명자' } | Select-Object -First 1) }
        $sigText = if ($sig.Count -gt 0) { $sig[0].value } else { '-' }
        $signerText = if ($signer.Count -gt 0) { $signer[0].value } else { '-' }
        $script:results.Add((Redact "item  $($f.ruleId) $($f.severity) | $($f.title) | $($f.target) | 서명: $sigText | 서명자: $signerText"))
    }
    foreach ($c in $rep.coverage) { $script:results.Add((Redact "coverage $c")) }
    # 바로가기 대상 위장(보이는 대상과 실제 실행 대상이 다름)은 실제 PC에서는 거의 없어야 해요. 있으면 오탐인지 확인해 주세요.
    $disguised = @($real | Where-Object { @($_.reasons | Where-Object { "$_" -like '*실제 실행 대상이 달라요*' }).Count -gt 0 })
    if ($disguised.Count -gt 0) { Note (Redact "바로가기 대상 위장으로 본 항목 $($disguised.Count)개: $(@($disguised | ForEach-Object { $_.location }) -join ', ')") }
    # 설치된 SafetySecurity 작업(이름·실행 파일·인자가 설치가 만든 그대로인 것)을 위장 작업(TASK-003)으로 잘못 보면 안 돼요.
    # (src/SafetySecurity.Core/Install/OwnTasks.cs의 이름·인자와 같아야 해요.)
    $ownArgs = @{
        'Logon' = 'scan --reason logon'; 'Daily' = 'scan --reason daily'; 'ServiceInstalled' = 'scan --reason service --quick'; 'Retry' = 'scan --reason retry'
        'Admin' = 'scan --scope admin --reason retry'; 'ServiceInstalledAdmin' = 'scan --scope admin --reason service --quick'
    }
    $ownExes = @((Join-Path $env:LOCALAPPDATA 'Programs\SafetySecurity\SafetySecurity.exe'), (Join-Path $env:ProgramFiles 'SafetySecurity\SafetySecurity.exe'), $Exe)
    $ownTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $short = if ($_.TaskPath -eq '\SafetySecurity\') { $_.TaskName } elseif ($_.TaskPath -eq '\' -and $_.TaskName -like 'SafetySecurity-*') { $_.TaskName.Substring(15) } else { $null }
            $actions = @($_.Actions)
            $short -and $ownArgs.ContainsKey($short) -and $actions.Count -eq 1 -and ($ownExes -contains "$($actions[0].Execute)".Trim('"')) -and "$($actions[0].Arguments)" -eq $ownArgs[$short]
        })
    if ($ownTasks.Count -gt 0) {
        $ownLocations = @($ownTasks | ForEach-Object { '작업 스케줄러' + $_.TaskPath + $_.TaskName })
        $misflagged = @($rep.findings | Where-Object { $_.ruleId -eq 'TASK-003' -and $ownLocations -contains $_.location })
        Check ($misflagged.Count -eq 0) "설치된 SafetySecurity 작업 $($ownTasks.Count)개를 위장 작업으로 잘못 보지 않음 $(@($misflagged | ForEach-Object { $_.location }) -join ', ')"
    }
    $selfFindings = @($rep.findings | Where-Object { $_.ruleId -eq 'TASK-003' -or $_.ruleId -eq 'TASK-004' })
    if ($selfFindings.Count -gt 0) { Note (Redact "SafetySecurity 작업 확인: $(@($selfFindings | ForEach-Object { "$($_.ruleId) $($_.location)" }) -join ', ')") }

    if (-not $NonInteractive) {
        Say '  보고서를 열게요. 빨간 카드 2개가 가짜 항목이고, 나머지는 이 PC의 실제 항목이에요.'
        Start-Process ((Get-ChildItem $reports -Filter *.html | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName)
        Pause-Step '보고서를 다 봤으면 Enter (실제 항목 중 의심되는 게 있으면 메모해 두세요)'
    }

    }

    # ------------------------------------------------------------ 3. 게임 중 연기
    if (Want 3) {
    Title '3. 게임 중에는 검사를 미루는지'
    if ($NonInteractive) {
        Note '자동 실행 모드라 건너뛰었어요.'
    }
    elseif (Ask '  게임(발로란트, 롤 등)으로 시험해 볼까요?') {
        Say '  1) 게임을 켜서 로비나 게임 화면까지 들어가세요.'
        Say '  2) 이 창으로 돌아와 Enter를 누르고, 20초 안에 게임 화면으로 돌아가세요 (전체 화면 감지 시험).'
        Pause-Step '게임을 켰으면 Enter'
        Say '  20초 뒤에 검사를 시도해요. 지금 게임 화면으로 돌아가세요...' 'Yellow'
        Start-Sleep -Seconds 20
        # 2단계에서 방금 전체 검사를 해서, 같은 기록으로는 하루 한 번 검사가 '방금 검사함'으로 건너뛰어요. 그래서 빈 기록 폴더를 따로 써요.
        $gameData = Join-Path $work 'data-game'
        New-Item -ItemType Directory -Force $gameData | Out-Null
        $d = Invoke-SS @('scan', '--reason', 'daily', '--no-toast', '--data-dir', $gameData, '--report-dir', $reports)
        Check ($d.Code -eq 2) "게임 중 검사 미룸 (종료 코드 $($d.Code)) $($d.Text.Trim())"
        Pause-Step '이제 게임을 완전히 끄고 Enter'
        $r = Invoke-SS @('scan', '--reason', 'retry', '--no-toast', '--data-dir', $gameData, '--report-dir', $reports)
        Check ($r.Code -eq 0) "게임을 끈 뒤 미뤄둔 검사 실행 (종료 코드 $($r.Code))"
        $vg = Get-Service -Name vgc -ErrorAction SilentlyContinue
        if ($vg) { Note "Riot Vanguard 서비스 상태: $($vg.Status)" }
        Check (-not (Ask '  게임 중에 VAN 오류가 뜨거나, 게임이 튕기거나, 끊김이 있었나요?')) '게임 중 문제 없음 (VAN 오류·튕김·끊김 없음)'
    }
    else { Note '게임 시험은 건너뛰었어요.' }

    }

    # ------------------------------------------------------------ 4. 서비스 설치 감지
    if (Want 4) {
    Title '4. 새 서비스 설치 때 깨어나는지 (설치된 작업 필요)'
    $task = Get-ScheduledTask -TaskPath '\SafetySecurity\' -TaskName 'ServiceInstalled' -ErrorAction SilentlyContinue
    if ($NonInteractive) { Note '자동 실행 모드라 건너뛰었어요.' }
    elseif (-not $task) { Note 'SafetySecurity가 아직 설치되지 않았어요 (SafetySecurity.exe install 후 다시 해 보세요).' }
    elseif (-not $isAdmin) { Note '관리자 PowerShell에서 실행해야 시험할 수 있어요 (서비스를 잠깐 만들었다 지워요).' }
    elseif (Ask '  아무 일도 안 하는 시험 서비스를 잠깐 만들었다가 지울까요?') {
        $before = (Get-ScheduledTaskInfo -TaskPath '\SafetySecurity\' -TaskName 'ServiceInstalled').LastRunTime
        & sc.exe create SafetySecurityProbe binPath= "$env:SystemRoot\System32\cmd.exe /c exit" start= demand | Out-Null
        try {
            Say '  최대 3분 기다려요 (작업은 이벤트 1분 뒤에 실행돼요)...'
            $ran = $false
            for ($i = 0; $i -lt 36 -and -not $ran; $i++) {
                Start-Sleep -Seconds 5
                $after = (Get-ScheduledTaskInfo -TaskPath '\SafetySecurity\' -TaskName 'ServiceInstalled').LastRunTime
                $ran = $after -gt $before -and $after.Year -gt 2000
            }
            Check $ran '서비스 설치 이벤트(7045)로 사용자 작업이 실행됨'
            if (-not $ran) { Note '실패하면 관리자 권한으로 설치했을 때 만들어지는 예비 작업(ServiceInstalledAdmin)이 대신 서비스를 검사해요. 이 결과를 이슈로 알려 주세요.' }
        }
        finally {
            & sc.exe delete SafetySecurityProbe | Out-Null
        }
    }
    else { Note '서비스 시험은 건너뛰었어요.' }
    }
}
finally {
    # ------------------------------------------------------------ 정리 (항상 실행)
    if ($comKey) { Remove-Item -Path $comKey -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-ItemProperty -Path $runKey -Name $runName -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $fakeDir -ErrorAction SilentlyContinue
    $leftCom = $comKey -and (Test-Path $comKey)
    $leftRun = $null -ne (Get-ItemProperty -Path $runKey -Name $runName -ErrorAction SilentlyContinue)
    Title '정리'
    Check (-not $leftCom -and -not $leftRun) '가짜 항목을 모두 지웠어요'
}

# ---------------------------------------------------------------- 결과 저장
$outDir = Join-Path $env:LOCALAPPDATA 'SafetySecurity'
New-Item -ItemType Directory -Force $outDir | Out-Null
$resultPath = Join-Path $outDir 'pc-test-result.txt'
$header = "SafetySecurity PC test $(Get-Date -Format 'yyyy-MM-dd HH:mm')  failures=$($script:failures)"
[IO.File]::WriteAllLines($resultPath, [string[]](@($header) + @($script:results | ForEach-Object { Redact $_ })), (New-Object Text.UTF8Encoding $false))
Say ''
if ($script:failures -eq 0) { Say '모든 시험을 통과했어요!' 'Green' } else { Say "실패 $($script:failures)개" 'Red' }
Say "결과 요약: $resultPath"
if (-not $isAdmin -and (Want 4) -and -not $NonInteractive) {
    Say '서비스 설치 시험(4단계)은 관리자 PowerShell에서 이렇게 따로 할 수 있어요:' 'Yellow'
    Say '  powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1 -Only 4'
}
Say '이 파일을 GitHub 이슈에 붙여 주면 돼요 (사용자 이름·PC 이름은 이미 가렸어요).'
if ($script:failures -gt 0) { exit 1 }
exit 0
