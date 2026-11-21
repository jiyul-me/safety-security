# Contributing

[한국어](CONTRIBUTING.md) · **English**

Thanks for your interest in SafetySecurity. Even a single false-positive report helps a lot.

- A legitimate program was flagged → [Report a false positive](https://github.com/jiyul-me/safety-security/issues/new?template=false_positive.yml)
- You want to catch a new technique → [Suggest a detection](https://github.com/jiyul-me/safety-security/issues/new?template=detection_idea.yml)
- You found a way to bypass the scanner → [report it privately](SECURITY.en.md) instead of opening a public issue

## Ground rules

These rules are the reason SafetySecurity exists. PRs that break them can't be accepted.

1. **Read-only**: never create, modify or delete system registry keys or files. Writes happen only in the app's own data folder (`DataStore`) and in `install`/`uninstall` (`TaskInstaller`) when the user runs them explicitly. An elevated process never writes to a folder a standard user can write to (`DataRoots`).
2. **Offline**: no networking code. Signature checks run with revocation checking turned off. Files on network paths (shares, WebDAV, mapped network drives) are never even opened (`ctx.Files` and `ctx.Signatures` block them).
3. **Anti-cheat safe**: no kernel drivers, no opening other processes (`OpenProcess`), no enumerating processes or killing process trees (`Process.GetProcesses`, `Process.Kill(bool)`), no reading or writing memory, no code injection, no hooking.
4. **Lightweight**: run on a single thread, call `ctx.Pacer.Step()` inside loops, and cache expensive work (signatures, hashes).

The build (`BannedSymbols.txt`) and the tests (`ForbiddenApiTests`) enforce these rules automatically.

## Branching (GitHub Flow)

```
main ─────●──────────●──────────●───── (always releasable, tags v0.2.0 …)
           \        /  \        /
   feat/hosts-ipv6 ●    rule/appinit-wow64 ●
```

- `main` is protected: no direct pushes, a PR with passing CI is required, and only **squash merge** is allowed.
- Do your work on a new branch created from `main`. Naming:

| Prefix | Purpose | Example |
|---|---|---|
| `feat/` | Features | `feat/json-export` |
| `rule/` | New or changed detection rules | `rule/com-treatas-wow64` |
| `fix/` | Bug and false-positive fixes | `fix/discord-false-positive` |
| `docs/` | Documentation | `docs/detections-table` |
| `ci/` | Workflows and build | `ci/arm64-release` |
| `chore/` | Other housekeeping | `chore/deps` |

### Commit and PR titles ([Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/))

```
feat(scanner): detect AppInit_DLLs in WOW64 view
fix(com): ignore signed OneDrive shell extensions
docs: add Vanguard test steps
```

Because we squash merge, the **PR title** becomes the commit message on `main`. Write PR titles in the format above.

### Releases

1. Merge a PR that moves `[Unreleased]` in `CHANGELOG.md` to the new version.
2. Start the release whichever way you prefer (a version containing `-`, such as `v0.2.0-rc.1`, becomes a pre-release):
   - **Actions** tab → **Release** → **Run workflow** → Branch `main`, enter `v0.2.0` as the version → Run
   - Or push a tag from `main`: `git tag v0.2.0 && git push origin v0.2.0`
3. The Release workflow runs tests → NativeAOT build → integration tests → installer build and install test, then creates a **draft release** with the installer (`SafetySecurity-Setup-<version>.exe`), the zip, SHA-256 sums and build provenance. The installer is built from `installer/SafetySecurity.iss` (Inno Setup); never change the `AppId` in it. The release notes are filled in from that version's section of `CHANGELOG.md` (`[Unreleased]` for pre-releases) plus instructions for verifying the files (`.github/scripts/release-notes.ps1`).
4. Review the draft and click "Publish release". (If you started from Actions, the tag is created at this point.)

If a release run fails, click **Re-run jobs** on that run (same commit). It reuses the half-finished draft, re-uploads all three files (installer, zip, `SHA256SUMS.txt`) and leaves the draft's notes as they are. The last step verifies that the uploaded files match the build.

- Don't restart the same version from a newer `main`. If the tag `vX.Y.Z` already points to a different commit, the workflow fails. To release a newer commit, move or delete the tag, or use a new version number.
- If you created the draft in the web UI before pushing the tag, the workflow fills it with the built files and keeps its notes.
- Only one run per version executes at a time (concurrency group).

## Development setup

- [.NET 10 SDK](https://dotnet.microsoft.com/download) (works on macOS, Linux and Windows)
- To build the NativeAOT exe on Windows, you need the "Desktop development with C++" workload from Visual Studio Build Tools.

```bash
dotnet build SafetySecurity.slnx
dotnet test tests/SafetySecurity.Core.Tests
```

- Save `*.ps1` files (`tests/integration`, `tools`, `.github/scripts`) and `installer/*.iss` as **UTF-8 with BOM + CRLF**. Without the BOM, Windows PowerShell 5.1 and Inno Setup read the Korean text as garbled characters. `ScriptEncodingTests` checks for the BOM, and the integration test script stops right away if it was read with the wrong encoding.
- Save all other `*.cs`, `*.md` and `*.yml` files as UTF-8 without BOM + LF.

## Adding a detection rule

1. Implement `IScanner` in `src/SafetySecurity.Core/Scanners/`. An existing scanner such as `HostsScanner` is the simplest example.
   - Read the registry only through `ctx.Registry`, files only through `ctx.Files`, and signatures only through `ctx.Signatures`. These views block network paths for you.
   - If you couldn't read a list or file to the end, record it with `ctx.Coverage.Incomplete(category, what, why)`. That way the category doesn't look clean, and old entries in the baseline aren't removed.
   - Reuse `ExecutableAssessor` to assess executables and `CommandAssessor` to assess command lines.
   - Give each new rule an ID of the form `CATEGORY-NUMBER` (e.g. `RUN-010`) and document it in `docs/DETECTIONS.md` (and `docs/DETECTIONS.en.md`).
   - In `Reasons`, write one Korean sentence explaining why the item is suspicious; in `Advice`, explain how the user can check it themselves. (The app's UI and reports are Korean only.)
2. Add the scanner to `ScanEngine.AllScanners()`.
3. In `tests/SafetySecurity.Core.Tests/`, use `FakeRegistry` and `FakeFileSystem` to test **both a case that is detected and a case where a legitimate program is not detected**.
4. If a part really needs Windows, add a test to `tests/integration/Run-Integration.ps1` that creates and removes a fake entry.
