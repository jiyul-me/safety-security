; SafetySecurity 설치 프로그램 (Inno Setup 6.3 이상, https://jrsoftware.org/isinfo.php)
;
; 빌드: .github/scripts/build-installer.ps1 -Version 0.2.0 -Exe out\SafetySecurity.exe
;   (직접 하려면) ISCC.exe /DAppVersion=0.2.0 /DNumericVersion=0.2.0 /DSourceExe=<exe 경로> installer\SafetySecurity.iss
;
; 설치 프로그램은 파일·바로가기·앱 목록만 맡고, 작업 스케줄러와 알림 등록은 exe가 해요.
;   설치 끝: SafetySecurity.exe install --quiet [--admin]
;   제거:    SafetySecurity.exe uninstall --quiet [--purge]
; 설치 폴더는 exe의 TaskInstaller와 같아야 해요 (src/SafetySecurity/Install/TaskInstaller.cs).
;   내 계정에만 = {userpf}\SafetySecurity = %LOCALAPPDATA%\Programs\SafetySecurity
;   관리자 권한 = {commonpf64}\SafetySecurity = C:\Program Files\SafetySecurity
; 데이터 폴더(검사 기록·설정·보고서·로그)도 exe의 DataStore와 같아야 해요 (src/SafetySecurity.Core/Install/DataRoots.cs).
;   일반 권한으로 실행한 exe = %LOCALAPPDATA%\SafetySecurity
;   관리자 권한으로 실행한 exe = C:\Program Files\SafetySecurity\data (관리자만 쓸 수 있어요)

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif
#ifndef NumericVersion
  #define NumericVersion "0.0.0"
#endif
#ifndef SourceExe
  #define SourceExe "..\out\SafetySecurity.exe"
#endif

[Setup]
; AppId는 절대 바꾸지 마세요. 바꾸면 Windows가 다른 프로그램으로 알아서 업데이트·제거가 꼬여요.
AppId={{64EA0F9C-E539-4775-B5E3-063E9FF952D5}
AppName=SafetySecurity
AppVersion={#AppVersion}
AppVerName=SafetySecurity {#AppVersion}
AppPublisher=jiyul-me
AppPublisherURL=https://github.com/jiyul-me/safety-security
AppSupportURL=https://github.com/jiyul-me/safety-security/issues
AppUpdatesURL=https://github.com/jiyul-me/safety-security/releases
AppCopyright=MIT License
VersionInfoVersion={#NumericVersion}
VersionInfoProductVersion={#NumericVersion}
VersionInfoProductTextVersion={#AppVersion}
VersionInfoDescription=SafetySecurity Setup
DefaultDirName={autopf}\SafetySecurity
DisableDirPage=yes
DisableProgramGroupPage=yes
AlwaysShowDirOnReadyPage=yes
; 기본은 '내 계정에만' (권한 요청 없음). 처음 화면에서 '관리자 권한으로'를 고를 수 있어요.
; 명령줄: /CURRENTUSER 또는 /ALLUSERS
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
UsePreviousPrivileges=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
; 검사가 도는 중에 업데이트하면 검사를 끝내요. 읽기 전용이라 끊겨도 다음 검사에서 다시 해요.
CloseApplications=force
RestartApplications=no
WizardStyle=modern
SetupIconFile=..\src\SafetySecurity\app.ico
UninstallDisplayIcon={app}\SafetySecurity.exe
UninstallDisplayName=SafetySecurity
OutputBaseFilename=SafetySecurity-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
SetupLogging=yes
ShowLanguageDialog=auto

[Languages]
; Windows 표시 언어가 한국어면 한국어, 그 밖에는 영어로 보여요.
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"

[Messages]
english.PrivilegesRequiredOverrideTitle=Choose how to install
english.PrivilegesRequiredOverrideInstruction=How should SafetySecurity be installed?
english.PrivilegesRequiredOverrideText1=%1 can be installed with administrator rights for a deeper scan, or for your account only.%n%nWith administrator rights it also checks Defender exclusions, hidden scheduled tasks and WMI subscriptions, and keeps the scanner in Program Files where malware can't easily replace it. Windows will ask for permission.
english.PrivilegesRequiredOverrideText2=%1 can be installed for your account only, or with administrator rights for a deeper scan.%n%nWith administrator rights it also checks Defender exclusions, hidden scheduled tasks and WMI subscriptions, and keeps the scanner in Program Files where malware can't easily replace it. Windows will ask for permission.
english.PrivilegesRequiredOverrideAllUsers=Install with &administrator rights (deeper scan)
english.PrivilegesRequiredOverrideAllUsersRecommended=Install with &administrator rights (deeper scan, recommended)
english.PrivilegesRequiredOverrideCurrentUser=Install for &my account only (no permission prompt)
english.PrivilegesRequiredOverrideCurrentUserRecommended=Install for &my account only (recommended, no permission prompt)
english.FinishedLabel=Setup has finished installing [name].%n%nIt stays off most of the time and only scans briefly when you sign in, once a day, and when a new service is installed. It waits while you are gaming, and notifies you when there is something to check.%n%nOpen SafetySecurity from the Start menu to scan any time.
korean.PrivilegesRequiredOverrideTitle=설치 방식 고르기
korean.PrivilegesRequiredOverrideInstruction=어떻게 설치할까요?
korean.PrivilegesRequiredOverrideText1=%1을(를) 관리자 권한으로 설치해서 더 깊게 검사하거나, 내 계정에만 설치할 수 있어요.%n%n관리자 권한으로 설치하면 Defender 제외 목록, 숨겨진 예약 작업, WMI 구독까지 검사하고, 검사기를 악성코드가 바꾸기 어려운 Program Files에 둬요. 권한 요청 창이 떠요.
korean.PrivilegesRequiredOverrideText2=%1을(를) 내 계정에만 설치하거나, 관리자 권한으로 설치해서 더 깊게 검사할 수 있어요.%n%n관리자 권한으로 설치하면 Defender 제외 목록, 숨겨진 예약 작업, WMI 구독까지 검사하고, 검사기를 악성코드가 바꾸기 어려운 Program Files에 둬요. 권한 요청 창이 떠요.
korean.PrivilegesRequiredOverrideAllUsers=관리자 권한으로 설치(&A) - 더 깊게 검사
korean.PrivilegesRequiredOverrideAllUsersRecommended=관리자 권한으로 설치(&A) - 더 깊게 검사 (권장)
korean.PrivilegesRequiredOverrideCurrentUser=내 계정에만 설치(&M) - 권한 요청 없음
korean.PrivilegesRequiredOverrideCurrentUserRecommended=내 계정에만 설치(&M) - 권한 요청 없음 (권장)
korean.FinishedLabel=[name] 설치를 마쳤어요.%n%n평소엔 꺼져 있다가 로그온할 때, 하루 한 번, 새 서비스가 설치될 때만 잠깐 검사해요. 게임 중이면 미루고, 확인할 항목이 생기면 알림을 띄워요.%n%n시작 메뉴의 SafetySecurity를 누르면 언제든 바로 검사할 수 있어요.

[CustomMessages]
english.FirstScan=Scan now (the report opens when it finishes)
english.ShortcutComment=Scan now and open the report
english.RegisterFailed=Automatic scans could not be registered (code %1).%n%nYou can still scan from SafetySecurity in the Start menu. Details are in:%n%2
english.PurgeQuestion=Also delete scan history and reports?%n%nChoose No to keep them for a later reinstall.
english.AdminUserDataKept=The administrator scan history was removed.%n%nYour account's own scan history (%1) is not deleted with administrator rights, for safety. Delete that folder yourself if you no longer need it.
korean.FirstScan=지금 첫 검사하기 (끝나면 보고서가 열려요)
korean.ShortcutComment=지금 검사하고 보고서 보기
korean.RegisterFailed=자동 검사를 등록하지 못했어요 (코드 %1).%n%n시작 메뉴의 SafetySecurity로 직접 검사할 수는 있어요. 자세한 내용은 아래 파일에 있어요:%n%2
korean.PurgeQuestion=검사 기록과 보고서도 지울까요?%n%n'아니요'를 누르면 남겨 두고, 다시 설치했을 때 이어서 써요.
korean.AdminUserDataKept=관리자 검사 기록은 지웠어요.%n%n내 계정의 검사 기록 폴더(%1)는 안전을 위해 관리자 권한으로 지우지 않아요. 더 필요 없으면 직접 지워 주세요.

[Dirs]
; 예전에 zip으로 install 해서 폴더가 이미 있었어도, 제거할 때 비어 있으면 지워요.
; (Inno Setup은 원래 자기가 만든 폴더만 지워요.)
Name: "{app}"; Flags: uninsalwaysuninstall

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Tasks]
; 바탕화면 바로가기 (기본으로 켜져 있어요). 누르면 지금 검사하고 보고서를 열어요.
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Icons]
; 인자 없이 실행하면 지금 검사하고 보고서를 열어요. AppUserModelID를 붙여야 알림에 이 앱 이름·아이콘이 보여요.
Name: "{autoprograms}\SafetySecurity"; Filename: "{app}\SafetySecurity.exe"; Comment: "{cm:ShortcutComment}"; AppUserModelID: "SafetySecurity.Scanner"
Name: "{autodesktop}\SafetySecurity"; Filename: "{app}\SafetySecurity.exe"; Comment: "{cm:ShortcutComment}"; AppUserModelID: "SafetySecurity.Scanner"; Tasks: desktopicon

[Registry]
; Win+R에서 'safetysecurity'로 실행할 수 있게 해요 (보고서의 숨기기 안내가 이 방법을 써요).
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\SafetySecurity.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\SafetySecurity.exe"; Flags: uninsdeletekey

[UninstallDelete]
; 관리자 설치의 데이터 폴더(관리자 검사 기록·설정·보고서·로그)를 지워요. 내 계정에만 설치했으면 이 폴더가 없어요.
; 이 항목은 제거의 맨 마지막에 처리돼서, 비게 된 설치 폴더도 이어서 지워요.
Type: filesandordirs; Name: "{app}\data"
Type: dirifempty; Name: "{app}"

[Run]
Filename: "{app}\SafetySecurity.exe"; Description: "{cm:FirstScan}"; Flags: postinstall nowait skipifsilent runasoriginaluser

[Code]
function SafetySecurityExe(): String;
begin
  Result := ExpandConstant('{app}\SafetySecurity.exe');
end;

{ exe가 쓰는 로그 위치. 관리자 권한으로 실행한 exe는 보호된 관리자 데이터 폴더를 써요 (DataRoots.cs와 같아요). }
function SafetySecurityLog(): String;
begin
  if IsAdmin() then
    Result := ExpandConstant('{commonpf64}\SafetySecurity\data\logs\scan.log')
  else
    Result := ExpandConstant('{localappdata}\SafetySecurity\logs\scan.log');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Params: String;
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    { 작업 스케줄러·알림 등록은 exe가 해요. 관리자 설치면 관리자 검사 작업도 함께 등록해요. }
    Params := 'install --quiet';
    if IsAdminInstallMode() then
      Params := Params + ' --admin';
    if not Exec(SafetySecurityExe(), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      ResultCode := -1;
    Log(Format('SafetySecurity %s -> exit code %d', [Params, ResultCode]));
    if ResultCode <> 0 then
      SuppressibleMsgBox(FmtMessage(CustomMessage('RegisterFailed'), [IntToStr(ResultCode), SafetySecurityLog()]), mbError, MB_OK, IDOK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Params: String;
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    { 검사나 메시지 창이 떠 있으면 exe 파일이 잠겨서 안 지워져요. 이 프로그램(SafetySecurity.exe)만 먼저 끝내요. }
    if Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM SafetySecurity.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      Log(Format('taskkill SafetySecurity.exe -> exit code %d', [ResultCode]));
    { 예약 작업과 알림 등록을 지워요. 파일·바로가기·앱 목록은 Inno Setup이 지워요. }
    // 관리자 설치는 기록을 지울지 묻지 않아요. 관리자 데이터 폴더(app 폴더의 data)는 [UninstallDelete]가 지우고,
    // 사용자 폴더(%LOCALAPPDATA%\SafetySecurity)는 관리자 권한으로 지우면 위험해서(링크를 심어 다른 파일을 지우게 할 수 있어요) 남겨요.
    // 제거 프로그램은 원래 사용자 권한으로 실행할 수 없어서(ExecAsOriginalUser는 제거 때 쓸 수 없어요) 끝에 안내만 해요.
    Params := 'uninstall --quiet';
    if (not IsAdminInstallMode()) and (not UninstallSilent()) and (MsgBox(CustomMessage('PurgeQuestion'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then
      Params := Params + ' --purge';
    if not Exec(SafetySecurityExe(), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      ResultCode := -1;
    Log(Format('SafetySecurity %s -> exit code %d', [Params, ResultCode]));
  end;
  if (CurUninstallStep = usPostUninstall) and IsAdminInstallMode() and (not UninstallSilent()) then
    MsgBox(FmtMessage(CustomMessage('AdminUserDataKept'), ['%LOCALAPPDATA%\SafetySecurity']), mbInformation, MB_OK);
end;
