# Security Policy

[한국어](SECURITY.md) · **English**

## Reporting a vulnerability

If you find a security problem in SafetySecurity itself (a way to fool or bypass the scanner, a report that can run scripts, and so on),
please report it through GitHub's [Private vulnerability reporting](../../security/advisories/new) **instead of a public issue**.

## What this program never does (design principles)

- It never deletes or modifies system files or registry keys. The only place it writes to is its own data folder,
  and it creates or removes its own scheduled tasks and notification registration only when you run `install`/`uninstall` yourself.
  - When run with standard rights: `%LOCALAPPDATA%\SafetySecurity`
  - When run as administrator: `C:\Program Files\SafetySecurity\data` (it inherits the Program Files permissions, so only administrators can change it)
- It never uses the network. Certificate revocation checks (CRL/OCSP) are turned off too. If an autostart entry points to a network location (`\\server\share`, `\\?\UNC\…`, `\\?\GLOBALROOT\…`, WebDAV, a mapped network drive), it judges the entry by its path alone, without opening the file or checking its signature.
- It never uses kernel drivers, opens other processes (`OpenProcess`), reads or writes memory, injects code or installs hooks. When a child process (`schtasks.exe`, `powershell.exe`) runs past its time limit, it ends only that one process, using the handle it already holds.

These principles are enforced in code.

- `BannedSymbols.txt`: the build fails if code uses a banned .NET API (networking, registry writes, file deletion, `Process.GetProcesses`, `Process.Kill(bool)` which ends a whole process tree, and so on).
- `tests/SafetySecurity.Core.Tests/ForbiddenApiTests.cs`: the tests fail if code declares a forbidden Win32 function or ends a process tree.

## Protections when running as administrator

The administrator scan (the `Admin` task) and the administrator install never use locations that malware running with standard rights could tamper with.

- **Data folder**: an elevated process neither reads nor writes `%LOCALAPPDATA%\SafetySecurity`, which the user can write to. Settings (`config.json`), history (`state.admin.json`), the signature cache, reports, logs and temporary scheduled-task XML files all live in `C:\Program Files\SafetySecurity\data`. So malware with standard rights can't change the administrator scan's game list or ignore list, or plant a link (junction) to trick the elevated process into deleting other files. Temporary scheduled-task XML files are always created fresh with a random name.
- **Child processes**: `schtasks.exe` and `powershell.exe` are started by their full System32 path and do not inherit the user's environment variables. Only a minimal set of values, such as `SystemRoot`, `PATH` (the System32 folder only), `TEMP` (`Windows\Temp` when elevated) and `PSModulePath` (the Windows PowerShell system module folder), is rebuilt from `GetSystemDirectory`. `COR_*`, `COMPlus_*`, `DOTNET_*` and the user's `PSModulePath` are never passed on. PowerShell runs with `-NoProfile -NonInteractive` and calls only module-qualified cmdlets.
- **The scanner itself**: the administrator scan treats only the running exe and `C:\Program Files\SafetySecurity\SafetySecurity.exe` as "the scanner itself". It does not trust `%LOCALAPPDATA%\Programs\SafetySecurity\SafetySecurity.exe`, which a standard user can replace.
- **Scheduled task names**: a name under `\SafetySecurity\…` or starting with `\SafetySecurity-…` is not enough to count as a SafetySecurity task. The known name, a single action, the scanner exe and the arguments the installer registers must all match. Otherwise it is reported as `TASK-003` (High).

## Known limitations

These are issues we know about but haven't fixed yet. If you know a better approach, please let us know.

- **Administrator install from a standard account**: if you choose **Install with administrator rights** (관리자 권한으로) on a standard account and enter the password of a different administrator account, the installer runs as that administrator account. The automatic scan task, notification registration and history are then all created for the administrator account, and automatic scans never run on the standard account you actually use. On a standard account, choose **Install for my account only** (내 계정에만) instead.
- **Upgrading from a v0.1.0 zip `install --admin`**: on a PC where you previously ran `install --admin` from the zip, choosing *my account only* in the installer leaves the old `\SafetySecurity\Admin` task and the old exe in `C:\Program Files\SafetySecurity` in place, and they keep running. The uninstaller runs with standard rights, so it can't remove that task and doesn't warn you about it either. Choose *administrator rights* as the install type, or first run `.\SafetySecurity.exe uninstall` from the old extracted folder in an administrator PowerShell.
- **Uninstalling an administrator install and your own account's history**: the uninstaller can only run elevated, so for safety it does not delete `%LOCALAPPDATA%\SafetySecurity` in your account; it only tells you where it is. Delete it yourself if you don't need it.
- **Path classification in the administrator scan**: the administrator scan still uses the environment variables of the running environment to decide whether a path is in a user folder or a temp folder. The user can change those values, so the classification may differ. (Network-path decisions, which never open the file, and the child process environment are not affected by this.)
- **.NET settings for elevated PowerShell**: child process environment variables are locked down, but the user settings under `HKCU\Software\Microsoft\.NETFramework` that Windows PowerShell reads are not. Reading WMI in-process instead of through PowerShell is being considered separately.
- **Scan lock name**: the scan lock name (`Local\SafetySecurity.Scan.<scope>`) is fixed, so malware running as the same user could hold the lock and delay scans. Such malware could already postpone scans through `config.json` anyway. An automatic scan that overlaps another remains as a postponed scan and is logged in `logs\scan.log`.
- **Integrity of a "my account only" install**: with this install type, malware running with the same rights can modify the scanner's files and history. This is why the administrator install is recommended.
- **Missing own tasks**: a disabled SafetySecurity task is reported as `TASK-004`, but a deleted one is not. It may have been registered under a fallback name, and administrator tasks may not be visible to a standard-rights query.
- **Notification state**: the app can tell whether Windows notifications are turned off, but not whether Focus Assist (Do Not Disturb) is on.
- **Discord scan**: if an `app-*` or `discord_desktop_core-*` folder is itself a link, it doesn't show up in the listing and is silently skipped (links aren't followed, so nothing is accessed over the network). The older `%APPDATA%\discord\<version>\modules` layout and modifications to `resources\app.asar` (the method legitimate Discord mods such as Vencord and OpenAsar use) are not checked.
- **Code signing**: the installer and exe are not code-signed. SmartScreen shows a warning the first time you run them, and they can't be installed on a PC with Smart App Control turned on. Use the method below to verify that the files are genuine.

## Verifying downloads

Every release includes `SHA256SUMS.txt` and a GitHub build provenance attestation. You can verify the installer, the zip and the exe inside it.

```
gh attestation verify SafetySecurity-Setup-x.y.z.exe --repo jiyul-me/safety-security
gh attestation verify "$env:LOCALAPPDATA\Programs\SafetySecurity\SafetySecurity.exe" --repo jiyul-me/safety-security
```
