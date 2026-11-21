# Testing on Your PC

[한국어](TESTING-ON-YOUR-PC.md) · **English**

This is a step-by-step guide for checking, on a real PC, the things CI (GitHub's Windows runners) can't check. It takes about 40 minutes.

> SafetySecurity's interface, notifications and reports are in Korean only. This guide quotes the Korean text you will see and gives the English meaning the first time it appears.

| Checked by CI | Check on your PC |
|---|---|
| Build, ~500 unit tests, detection of a fake COM hijack, Run key, wrapped command, Discord tampering and disguised scheduled task, never opening network paths, items that changed from the baseline, the ignore list and `ignored`, deferring for game processes, overlapping and overdue scans, task registration and removal, silent install, reinstall and uninstall of the installer (both modes), refusing an install in the other mode, creating and removing the desktop shortcut, admin data folder permissions | Notifications actually appearing on screen, the guidance shown when notifications are off, **full-screen game** detection, whether it's fine **alongside Vanguard**, whether the per-user task wakes up on a **service install event**, the number of **false positives** on a real PC (including shortcuts and Discord), the **installer** screens, desktop icon, Start menu, Win+R message boxes and uninstall screens, Smart App Control |

## 0. Preparation

1. From [Releases](https://github.com/jiyul-me/safety-security/releases), download two files from the latest version (a `-rc` pre-release is fine too).
   - `SafetySecurity-Setup-….exe`: used for installing.
   - `SafetySecurity-…-win-x64.zip`: contains the guided test script (`tools\Test-OnMyPC.ps1`).
2. If **SmartScreen** ("Windows protected your PC") appears on first run, click "More info" → "Run anyway". This happens because there is no code signing certificate.
3. On a PC with **Smart App Control** turned on, the installer is blocked with no "Run anyway" button. If that happens, take a screenshot of the window and stop here. **Do not turn off** Smart App Control just to test (depending on your Windows version, turning it back on requires reinstalling Windows). You can see whether it's on in Windows Security → App & browser control → Smart App Control settings.
4. If Defender removed a file, note the detection name from Windows Security → Protection history (that is an important result too).
5. **Only on PCs where you installed v0.1.0 from the zip**: in the old extracted folder, run `.\SafetySecurity.exe uninstall` from an admin PowerShell. Then delete the `C:\Program Files\SafetySecurity` and `%LOCALAPPDATA%\Programs\SafetySecurity` folders if they still exist. Otherwise, if you choose "my account only", the old admin task stays behind.

## 1. Install with the installer

Install **for your account only** first. The admin install is tested separately in section 4.

Setup shows its screens in English or Korean depending on your Windows display language; the labels below are the English ones, with the Korean in parentheses.

1. Double-click Setup → "More info" → "Run anyway" → **Install for my account only** (내 계정에만) → Next
   - Check: no permission (UAC) prompt appears
2. **Additional tasks** screen: check that "Create a desktop shortcut" is **on by default**, and install with it on.
3. On the last screen, leave "Scan now (the report opens when it finishes)" (지금 첫 검사하기) on and click Finish
   - Check: a "검사하고 있어요" ("Scanning…") notification appears, and when the scan ends that notification disappears and the report opens
4. **Desktop**: a **SafetySecurity** shield icon was created, and double-clicking it scans again and opens the report
   - Clicking it again during a scan should show a "다른 검사가 이미 실행 중이에요" ("Another scan is already running") box.
5. **Start menu**: a **SafetySecurity** shield icon is there, and clicking it scans exactly like the desktop icon
6. **Win+R**: <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity status` → the status box shows the following
   - `데이터 폴더: C:\Users\<your name>\AppData\Local\SafetySecurity` ("Data folder")
   - 4 registered tasks (`Logon`, `Daily`, `ServiceInstalled`, `Retry`)
   - `알림: 켜져 있어요` ("Notifications: on")
7. **Task Scheduler** (`taskschd.msc`) → Task Scheduler Library → if you see 4 tasks in the `SafetySecurity` folder, it worked.

> `safetysecurity` works in Win+R because the installer registers it. The name doesn't work in a PowerShell window, so in PowerShell use the full path of the installed exe (for example, `& "$env:LOCALAPPDATA\Programs\SafetySecurity\SafetySecurity.exe" status`).

## 2. Guided test script

1. Right-click the downloaded zip → **Extract All**. It won't run if you only opened the zip to look inside.
2. Open an **admin PowerShell** (Start menu → right-click PowerShell → Run as administrator). Step 4 (the service install test) needs admin rights.
3. **Go to the extracted folder.** An admin PowerShell starts in `C:\Windows\System32`, and `.\tools\…` means "a file inside the current folder", so if you don't change folders you get a "not recognized" or "cannot find" error.

   ```powershell
   cd "$env:USERPROFILE\Downloads\SafetySecurity-0.2.0-win-x64"
   ```

   > Tip: the folder name depends on the version you downloaded (for example, a pre-release is `SafetySecurity-0.2.0-rc.1-win-x64`). If the name is different, type `cd ` (with a trailing space), **drag** the extracted folder from File Explorer into the PowerShell window, and press Enter.

4. Type `dir` and check that you see `SafetySecurity.exe` and the `tools` folder.
5. Test with the installed exe.

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1 -Exe "$env:LOCALAPPDATA\Programs\SafetySecurity\SafetySecurity.exe"
   ```

   Without `-Exe`, the script tests the `SafetySecurity.exe` inside the zip (the same version).

The script explains each step and waits for Enter. It goes in this order:

1. **Basics**: version, help, Windows file signature checks, the default data folder, and a notification test (answer y/n to "알림이 떴나요?", "Did the notification appear?")
2. **Fake detections**: creates a fake COM registration using a GUID that doesn't exist and a fake Run entry containing a harmless command, then scans. It passes if both come out as '높음' (High). It also checks that the installed SafetySecurity tasks are not mistaken for disguised tasks (`TASK-003`). Then the report opens: the 2 red cards are the fake items, and **everything else is a real item on your PC**. Note down anything that looks suspicious.
3. **Game test**: start a game, press Enter, and return to the game within 20 seconds. It passes if the scan is deferred. When you close the game, check that the deferred scan runs.
4. **Service install test**: briefly creates a test service that does nothing, then removes it. Checks that the per-user task woke up.
5. **Cleanup**: the fake items are **always** removed, whether the tests passed or failed.

Test scan history is stored separately in a temporary folder, so it doesn't mix with the installed SafetySecurity's history (its baseline).
If you're not in an admin PowerShell, the script first asks "관리자 권한으로 다시 열까요?" ("Reopen as administrator?").

To redo a specific step only, add `-Only`. For example, to run only step 4:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1 -Only 4
```

When it finishes, the results are saved to `%LOCALAPPDATA%\SafetySecurity\pc-test-result.txt`. The real items found on this PC (rule, risk level, target, signer) are recorded too, so you can judge whether something is a false positive. For wrapped commands (`cmd /c …`) it records the signature of the file that actually runs, and it lists separately any shortcut whose displayed target was found to differ from its real target. User and PC names are masked as `<user>` and `<pc>`.

## 3. Things to check by hand

### Vanguard (Valorant)
1. Start Valorant and enter a competitive match or the Range.
2. Using Alt+Tab or another monitor, double-click **SafetySecurity** on the desktop, or run <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity scan --force`. A scan you start yourself runs immediately, even during a game.
3. Check: **no VAN errors**, the game doesn't crash, no stutter (frame drops), and the report opens when the scan ends.
4. Whether automatic scans are deferred during a game is checked by step 3 of the script in section 2 (`-Only 3`). If you just ran a full scan, the once-a-day scan is skipped as "scanned just now", so the script tests with a separate, empty history folder.

### Resource usage
In Task Manager → Details tab, find `SafetySecurity.exe` and watch CPU and disk while it scans. The first scan can take about 30–60 seconds because of signature checks; from the second scan on, it should finish in a few seconds.

### False positives on a real PC
In the report (or `pc-test-result.txt`), look especially at the following.
- **Discord**: if you use Discord, there should be **no** `DISC-001`. If there is one, please tell us which Discord (Stable, PTB or Canary), its version, and the "앞부분" ("beginning") evidence from the report. If you installed BetterDiscord, `DISC-002` (Low) is expected.
- **Shortcuts**: if a startup shortcut shows up as "표시되는 대상과 실제 실행 대상이 달라요" ("The displayed target differs from what actually runs"), please tell us the name of the program that created that shortcut.
- **Wrapped commands**: if the "file that actually runs" is a legitimate program but is shown as risky, please tell us.
- **SafetySecurity tasks**: the installed tasks must not show up as `TASK-003` or `TASK-004` (unless you turned them off on purpose).

### When notifications are off (optional)
1. Settings → System → Notifications → turn off **SafetySecurity**.
2. Scan with SafetySecurity on the desktop.
3. Check: the report's **확인하지 못한 것** ("What couldn't be checked") section has "새 항목을 알려드릴 수 없어요" ("Can't notify you about new items") with instructions to turn notifications on, and in <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity status` the `알림:` ("Notifications:") line shows why they're off
4. Turn SafetySecurity notifications back on.

### Hiding items (Win+R message boxes)
1. <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity ignore 12345678` → a refusal box such as "찾지 못했어요" ("Not found") appears and nothing is hidden
2. If the report has items, run that item's hide command using only the first 8 characters (for example, `safetysecurity ignore 4d446635`).
   - Check: it shows the item's risk level and title and asks Yes/No. If you click **No**, nothing should change.
3. If you hid an item, check that it appears in the list with `safetysecurity ignored` and can be restored with `safetysecurity unignore <ID>`

### A disabled SafetySecurity task (optional)
1. Task Scheduler → `SafetySecurity` folder → right-click `Retry` → **Disable**
2. Scan with SafetySecurity on the desktop → the report has a `TASK-004` (Medium) "꺼져 있어요" ("is turned off") item with instructions to turn it back on
3. Right-click `Retry` → **Enable** to turn it back on. The item disappears on the next scan.

### Using it for a few days
- Use your PC as usual, and when a notification arrives, open the report.
- Check the last scan and any deferred scan with <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity status`. If a scan is overdue by more than a day because a game was running for a long time, it shows how many hours it's overdue, and a "검사가 밀렸어요" ("Scan is overdue") notification should appear once.
- In `%LOCALAPPDATA%\SafetySecurity\logs\scan.log` you can see when scans ran and when they were deferred or skipped (scanned just now, overlapped with another scan).

## 4. Reinstall with admin rights

1. **(Optional) Refusing the other mode**: while the "my account only" install is still there, run Setup with `/ALLUSERS` from a normal PowerShell (change the file name to match the version you downloaded).

   ```powershell
   & "$env:USERPROFILE\Downloads\SafetySecurity-Setup-0.2.0.exe" /ALLUSERS
   ```

   After you click "Yes" in the permission prompt, a "SafetySecurity is already installed for your account only" box should appear and nothing should change (check that SafetySecurity appears only once in the app list).
2. **Uninstall**: Settings → Apps → Installed apps → SafetySecurity → Uninstall → answer **No** to "Also delete scan history and reports?" (검사 기록과 보고서도 지울까요?)
   - Check: the Start menu entry and the **desktop icon** are gone, the `SafetySecurity` folder in Task Scheduler is empty, the `%LOCALAPPDATA%\Programs\SafetySecurity` folder is gone, and `%LOCALAPPDATA%\SafetySecurity` (scan history) remains
3. **Install**: Setup → **Install with administrator rights** (관리자 권한으로) → "Yes" in the permission prompt → install with the desktop shortcut on in Additional tasks
   - Check: it installed to `C:\Program Files\SafetySecurity`, Task Scheduler has an `Admin` task, and the desktop icon was created on the **all-users desktop** (`C:\Users\Public\Desktop`)
4. **Admin scan**: with games and heavy programs closed, Task Scheduler → `SafetySecurity` → right-click `Admin` → **Run** → wait 1–2 minutes (if the PC is busy, the scan is deferred).
   - Check: an `_admin` report was created in `C:\Program Files\SafetySecurity\data\reports` (admin scan history now lives here)
   - Check: <kbd>Win</kbd>+<kbd>R</kbd> → `safetysecurity status` shows `관리자 검사 데이터 폴더: C:\Program Files\SafetySecurity\data` ("Admin scan data folder") and `[관리자 검사]` ("[Admin scan]")
   - Check: trying to create a new file in that `data` folder from File Explorer asks for admin rights (normal users must not be able to change it)
   - If the admin report has items, run the report's hide command (`--scope admin`) from Win+R and check that a **UAC prompt** appears
5. (Optional) Service install test: from an admin PowerShell in the extracted zip folder, run
   `powershell -ExecutionPolicy Bypass -File .\tools\Test-OnMyPC.ps1 -Exe "C:\Program Files\SafetySecurity\SafetySecurity.exe" -Only 4`
6. **With a game**: with Valorant running, click SafetySecurity on the desktop. Check for VAN errors, crashes and stutter.
7. **Uninstall**: uninstall from Settings → Apps.
   - Check: it **doesn't ask** whether to delete history, and at the end a box says the admin scan history was deleted and your account's scan history folder (`%LOCALAPPDATA%\SafetySecurity`) was left alone for safety
   - Check: the `C:\Program Files\SafetySecurity` folder (including admin scan history) and the icon on the all-users desktop are gone
8. When you're done, reinstall it whichever way you like and keep using it.

## 5. Reporting results

- Test results: please paste the contents of `pc-test-result.txt`, plus anything that behaved differently in sections 1, 3 and 4, into a [bug report](https://github.com/jiyul-me/safety-security/issues/new?template=bug_report.yml) or our conversation. Screenshots help even more.
- If a legitimate program was flagged: [false positive report](https://github.com/jiyul-me/safety-security/issues/new?template=false_positive.yml)
- If something actually suspicious showed up: before deleting anything, first follow the report's "확인하는 법" ("How to check") steps. This program never deletes anything.

## Removing it

If you installed with the installer, just go to Settings → Apps → Installed apps → **SafetySecurity** → Uninstall. Its scheduled tasks and files are removed too.
For an admin install, the admin scan history (`C:\Program Files\SafetySecurity\data`) is also removed, but your account's `%LOCALAPPDATA%\SafetySecurity` stays. Delete it yourself if you don't need it.

If you installed from the zip, run this in the extracted folder:

```powershell
.\SafetySecurity.exe uninstall --purge
```

For an admin install, run it from an admin PowerShell (in that case `--purge` deletes only the admin scan history), then delete the folders it lists at the end yourself.
