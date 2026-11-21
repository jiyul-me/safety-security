# Detection rules

[한국어](DETECTIONS.md) · **English**

Every card in the report shows a **rule ID** (e.g. `COM-001`). Look it up here for an explanation.

Severity levels:

| Severity | Meaning | Notification |
|---|---|---|
| **High** (높음) | Legitimate programs almost never do this. Check it right away. | Notified from the first scan |
| **Medium** (보통) | Could be legitimate, but malware often uses this technique too. | Notified when newly found |
| **Low** (낮음) | For reference. Often a configuration mistake or an old leftover. | No notification |

Together with the notification threshold (default Medium, `notifyMinSeverity` in `config.json`), notifications work like this:
- On the first scan, and for a category scanned for the first time (e.g. Discord, added in a new version, or services, first scanned by an admin install), only High findings are notified. This keeps findings that were already there from arriving all at once.
- If a finding with the same ID (category + location + target) becomes more severe, or the file behind it changes (signature status, signer, SHA-256), it is notified again as a **changed finding**. A lower severity or a deleted file does not count as a change.
- A hidden (`ignore`) finding is tied to the severity and file fingerprint it had when you hid it. If it later becomes more severe or the file changes, it is shown again as **unhidden**.
- A category that could not be read completely is marked "(partially checked)" (일부만 확인) in the report, with the reason listed under "Not checked" (확인하지 못한 것). No findings in such a category does not mean it is clean.

Conditions that raise severity across rules:
- The file or registry key was created or modified **in the last 7 days** → one level up
- A file in a user folder has the **Hidden + System attributes** → one level up
- A **valid digital signature** lowers the severity, or suppresses the finding, for most rules.
- **Windows app packages** (Store/MSIX apps) in `C:\Program Files\WindowsApps` and `C:\Windows\SystemApps` are signed as a whole package, not file by file. Only Windows can write to these folders, so a missing per-file signature there is not treated as suspicious. A **broken** signature is still High.

**Network locations**: when an autorun, service, or scheduled task points to a file on a network path, the scanner does not open the file, check that it exists, or verify its signature, so that it never connects to the network. It judges by the path alone.
- `\\server\share\…`, `\\?\UNC\…`, `\\?\GLOBALROOT\…`, WebDAV (`\\host@SSL\…`) → **High** (ordinary programs almost never run files from another computer)
- A drive letter mapped to a network drive (e.g. `Z:\tool.exe`) → Medium (it may be a program you keep on a NAS or shared folder)
- The evidence is tagged "Network location" and "File check: skipped". The rule ID stays that of the original rule (e.g. `RUN-001`, `COM-001`, `TASK-001`).
- If the Startup folder itself has been redirected to a network share, it is not opened and is listed under "Not checked".

---

## COM hijacking (`ComHijack`) — MITRE T1546.015

| ID | What it detects | Severity | Common false positives |
|---|---|---|---|
| `COM-001` | An HKCU CLSID **overrides** the HKLM registration of the same GUID and points to **a different file** | **High** if unsigned, tampered, or in a user folder; Medium for a validly signed file in a user folder; Low otherwise | Some per-user installers override a system class (rare) |
| `COM-002` | A CLSID that exists only in HKCU loads an unsigned file | **High** in temp/public folders, Medium in user folders | Unsigned personal dev tools or shell extensions |
| `COM-003` | `ScriptletURL` registration (runs a script as a COM object) | **High** | Almost none |
| `COM-004` | HKCU `TreatAs` redirects a class to another class. The scanner follows the target class to the file it runs and judges that | **High** (when overriding an HKLM class) or Medium if the target is a suspicious file; Medium or Low if the target has no executable; not reported if the target is legitimate (Low if it overrides HKLM) | The new Paint (Store app) taking over the old "Paintbrush Picture" class → no longer reported |

`COM-001` is the technique used in the NIKKE PC launcher incident, where a program such as Chrome is made to load a malicious DLL.

## Autorun (`Autorun`)

| ID | Location | Severity |
|---|---|---|
| `RUN-001` | `Run`, `RunOnce`, `Policies\Explorer\Run` (HKCU and HKLM, 32- and 64-bit) | Depends on the command line and file (see *Command-line rules* below) |
| `RUN-002` | Startup folders (.lnk targets are resolved, including the environment variable block, IDList, and LinkInfo) | Same. A disguised shortcut whose visible target differs from what it actually runs is Medium or higher; a shortcut whose target cannot be resolved is Low |
| `RUN-003` | Changes to Winlogon `Shell`/`Userinit`, HKCU `Shell`. For `Shell`, only `explorer.exe` or `%SystemRoot%\explorer.exe` alone counts as the default (an explorer.exe in another folder, or a program prepended to it, is reported) | **High** |
| `RUN-004` | `AppInit_DLLs` | **High** if enabled, Low if disabled |
| `RUN-005` | `AppCertDlls` | **High** |
| `RUN-006` | IFEO `Debugger` (e.g. sethc.exe → cmd.exe) | **High**. Medium for a signed tool (Process Explorer, etc.). cmd, PowerShell, and script hosts stay High even when signed |
| `RUN-007` | `SilentProcessExit` `MonitorProcess` | **High** |
| `RUN-008` | Logon script `HKCU\Environment\UserInitMprLogonScript` (T1037.001) | **High** |
| `RUN-009` | `Command Processor\AutoRun` | Medium or higher |

**Command-line rules** (shared by autoruns, services, and scheduled tasks):
- **High**: `powershell -EncodedCommand` (including abbreviations such as `-enc` and `-encodedcom`, and `–`/`—` dashes), `IEX`/`DownloadString`, `mshta`, `regsvr32 /i:http … scrobj.dll`, `rundll32 javascript:`, `certutil -urlcache`, `bitsadmin /transfer`, a file with a broken signature, an unsigned file in a temp or public folder
- **Medium**: hidden-window PowerShell, `cmd /c powershell`, an unsigned file or script in a user folder, `wscript //E:` running a file whose extension is not a script, an internet address in the command line
- **Low**: a registration whose file is missing (a leftover), an unsigned file in Program Files or similar
- **Wrapped commands**: when something runs another program on its behalf, such as `cmd /c`/`start`, `conhost --headless`, `explorer.exe <file>`, `forfiles /c`, `pcalua -a`, `wmic process call create`, or PowerShell `Start-Process`/`&`, the verdict is based on **the file that actually runs**, not the wrapper (cmd.exe, etc.), up to 3 layers deep. Wrapping alone does not raise the severity (plenty of legitimate programs use `cmd /c start "" "C:\Program Files\…"`).
  Because the finding's target is now the real file, a wrapped-command finding you hid in an earlier version gets a new ID and may show up once more.

## Services and drivers (`Service`)

| ID | What it detects | Severity |
|---|---|---|
| `SVC-001` | Suspicious service executable or `ServiceDll`, unquoted path with spaces | Depends on the verdict. **High** if the ServiceDll is in a user folder. An unquoted path is reported as Low only when a regular user can write to a location Windows would try first (e.g. `D:\My.exe`). If the only such locations are admin-only, like `C:\Program Files\…`, it is not reported (e.g. Riot Vanguard `vgc`) |
| `SVC-002` | Kernel driver in a user folder or unsigned | **High** |

Disabled services and drivers are lowered by one level.

## Scheduled tasks (`ScheduledTask`, `HiddenTask`)

| ID | What it detects | Severity |
|---|---|---|
| `TASK-001` | A task action with a suspicious command line or file | Per the command-line rules. One level up for a hidden task running a file in a user folder. A `\Microsoft\` task that only points to a **missing file** in the Windows folder is a leftover from an update and is not reported (e.g. `USO_UxBroker` → `MusNotification.exe`) |
| `TASK-002` | A task whose security descriptor (SD) was removed from `TaskCache\Tree` (Tarrask technique) — admin scan. Tasks using the SafetySecurity name are not exempt (genuine SafetySecurity tasks always have an SD) | **High** |
| `TASK-003` | A task uses the SafetySecurity name (`\SafetySecurity\…`, `\SafetySecurity-…`) but was not created by SafetySecurity. A genuine task is named one of `Logon`, `Daily`, `ServiceInstalled`, `Retry`, `Admin`, `ServiceInstalledAdmin`, has exactly one action, and runs the scanner itself (the running exe or `SafetySecurity.exe` in the install location) with exactly that task's `scan …` arguments. Unknown names, other programs, other arguments, extra actions, and subfolders are all reported | **High** (even if the program is signed or the task is disabled) |
| `TASK-004` | A genuine SafetySecurity task is disabled (that automatic scan does not run). Re-enabling it is up to you: "Enable" in Task Scheduler, `schtasks /change /tn <name> /enable` (the `Admin` task needs administrator rights), or run the installer again | Medium |

If `TASK-003` appears, check what the task runs on its Actions tab and disable it first with `schtasks /change /tn <name> /disable`. Running the installer again re-registers the genuine SafetySecurity tasks.

## Browsers (`Browser`)

| ID | What it detects | Severity |
|---|---|---|
| `WEB-001` | Force-installed extensions via `ExtensionInstallForcelist` | **High** if not from the official store, Medium if from the store (the update URL's host name is matched exactly) |
| `WEB-002` | Browser policy proxy (`ProxyServer`, `ProxyPacUrl`) | Medium |
| `WEB-003` | `force_installed`/`normal_installed` in `ExtensionSettings` (both the JSON policy value and per-extension-ID subkeys) | **High** with an `update_url` that is not the official store, Medium otherwise. Not reported if only `blocked`/`allowed` are set |
| `WEB-004` | System PAC address (`AutoConfigURL`) | Medium for an external address, Low if on this PC |
| `WEB-005` | System proxy enabled | Medium if external, Low for 127.0.0.1 |
| `WEB-006` | Browser shortcut with `--load-extension`, `--remote-debugging`, or a forced URL | **High** (Medium if only a URL) |

On work or school PCs, `WEB-001~003` may show up for legitimate management policies.

## Defender (`Defender`)

| ID | What it detects | Severity |
|---|---|---|
| `DEF-001` | A policy that turns off Defender or real-time protection | **High** |
| `DEF-002` | Exclusions (policy exclusions; local exclusions too in an admin scan) | **High** for a whole drive, a user folder, or an executable file extension; Medium otherwise |

## Discord app tampering (`Discord`) — MITRE T1554

Malware that steals Discord tokens and passwords (token grabbers) modifies the startup file Discord runs when it launches, so it steals the data again every time Discord starts. It often spreads bundled with game cheats and cracks.
The per-user full scan checks `app-*\modules\discord_desktop_core-*\discord_desktop_core\` in each of the `Discord`, `DiscordPTB`, `DiscordCanary`, and `DiscordDevelopment` folders under `%LOCALAPPDATA%`.
It reads only folder listings and small files of 1 MB or less (`index.js`, `package.json`), and does not check whether Discord is running (it does not open other processes). It does not follow links (junctions or symbolic links).

| ID | What it detects | Severity | Common false positives |
|---|---|---|---|
| `DISC-001` | `index.js` is not the original single line (`module.exports = require('./core.asar');`). Differences in spaces or line breaks between tokens, a leading BOM, quote style, or a trailing semicolon still count as the original (different spaces inside the string count as a different file). The same applies if `index.js` or `package.json` is a link or larger than 1 MB, or if `main`/`exports` in `package.json` points to a file other than `index.js`. If an `initiation` folder (the first-run marker of token stealers) is also present, the reason says so. The evidence shows code fragments such as webhook URLs, `BrowserWindow`, `webRequest`, and `token`, the first 200 characters (control characters made visible), size, modification time, and SHA-256 (obfuscated code is equally High even without these strings) | **High**. Medium if the inner `modules` or `discord_desktop_core` folder is a link (its contents are not opened) | You installed a Discord mod or theme tool other than BetterDiscord yourself |
| `DISC-002` | Exactly the form the BetterDiscord installer writes: loads exactly `%APPDATA%\BetterDiscord\data\betterdiscord.asar`, followed by the original line. Any other path, other escaping, or added code is `DISC-001` | Low (`DISC-001` High if an `initiation` folder or a `package.json` change is also present) | You installed BetterDiscord yourself (legitimate) |

- Other `.js` files in the same folder are not reported separately: they do not run as long as `index.js` and `package.json` are original. When tampering is reported, they are listed in the evidence (other items in the same folder).
- Updating Discord renames the `app-*` folder, so the finding ID changes too. If old folders remain, each one is checked separately.
- If the `%LOCALAPPDATA%\Discord` folder itself is a link to somewhere else, it is not opened; it is listed under "Not checked" and the category is marked "(partially checked)".
- Limitations: if an `app-*` or `discord_desktop_core-*` folder itself is a link, it does not appear in the folder listing and is silently skipped. The old `%APPDATA%\discord\<version>\modules` layout and modifications to `resources\app.asar` (the method Discord mods such as Vencord and OpenAsar legitimately use) are not checked, because they produce too many false positives.
- If `DISC-001` appears: quit Discord and run a Microsoft Defender Offline scan, then delete that Discord folder and reinstall from discord.com. Changing your Discord password and turning on two-factor authentication from another device makes stolen tokens useless. Log out all other devices, and also change the passwords of any game or email accounts that used the same password. SafetySecurity does not modify or delete any files.

## Other checks

| ID | What it detects | Severity |
|---|---|---|
| `HOST-001` | The hosts file blocks security, update, game, or portal sites, or redirects them to another IP. Finding IDs do not include the line number, so hidden findings stay hidden when lines are added or removed | **High**. However, lines that block telemetry or ad addresses of major portals (microsoft.com, google.com, naver.com, etc.; e.g. `vortex.data.microsoft.com`, `adservice.google.com`) with `0.0.0.0`/`127.0.0.1` are informational (update, sign-in, and security addresses stay High). Other external IP pinning is Low. Other ad-blocking `0.0.0.0` lists are ignored |
| `WMI-001` | WMI permanent subscription (CommandLine/ActiveScript consumer) — admin scan, T1546.003 | **High** |
| `FILE-001` | Unsigned executable created in the last 14 days in AppData, LocalAppData, ProgramData, or Public | Medium (Low in Temp, which installers use heavily) |
| `FILE-002` | Double extensions like `invoice.pdf.exe`, or executables with a fake extension (e.g. a PE file named `.jpg`) | **High** |

---

Found a false positive? Please let us know with a [false positive report](https://github.com/jiyul-me/safety-security/issues/new?template=false_positive.yml).
