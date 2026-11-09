using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Scanners;

/// <summary>
/// 디스코드 앱이 켜질 때 실행하는 시작 파일(discord_desktop_core\index.js)이 바뀌었는지 봐요.
/// 디스코드 토큰·비밀번호를 훔치는 악성코드(토큰 그래버)는 이 파일에 코드를 넣어서, 디스코드를 켤 때마다 다시 정보를 빼 가요.
/// 폴더 목록과 1MB 이하의 작은 파일 몇 개만 읽어요. 디스코드가 실행 중인지는 보지 않고(다른 프로세스를 열지 않아요),
/// 파일을 고치거나 지우지도 않아요.
/// </summary>
public sealed partial class DiscordScanner : IScanner
{
    public const string CategoryName = "Discord";

    /// <summary>이보다 큰 파일은 읽지 않아요. 원래 index.js는 40바이트 정도, package.json은 100바이트 정도예요.</summary>
    public const int MaxBytes = 1024 * 1024;

    /// <summary>증거에 보여줄 앞부분 글자 수.</summary>
    public const int SnippetChars = 200;

    /// <summary>%LOCALAPPDATA% 아래 디스코드 폴더 이름과 보고서에 보여줄 이름 (정식판, PTB, Canary, Development).</summary>
    public static readonly IReadOnlyList<(string Folder, string Label)> Flavors =
    [
        ("Discord", "Discord"),
        ("DiscordPTB", "Discord PTB"),
        ("DiscordCanary", "Discord Canary"),
        ("DiscordDevelopment", "Discord Development"),
    ];

    private const string CoreModule = "discord_desktop_core";

    /// <summary>토큰 탈취 도구가 처음 실행 표시로 만드는 폴더 (디스코드를 처음 켤 때 로그아웃시켜 비밀번호를 다시 넣게 해요).</summary>
    private const string InitiationFolder = "initiation";

    /// <summary>원래 discord_desktop_core 폴더에 있는 파일.</summary>
    private static readonly HashSet<string> KnownFiles = new(StringComparer.OrdinalIgnoreCase) { "index.js", "core.asar", "package.json" };

    /// <summary>
    /// 토큰 그래버가 자주 쓰는 코드 조각. 증거로만 보여줘요. 난독화한 악성코드는 이런 글자를 숨기기 때문에,
    /// 이게 없어도 원래 한 줄이 아니면 똑같이 '높음'이에요.
    /// </summary>
    private static readonly string[] Markers =
    [
        "api/webhooks", "webhook", "https://", "http://", "BrowserWindow", "webRequest", "onBeforeRequest", "onCompleted",
        "executeJavaScript", "token", "password", "child_process", "eval(", "atob(", "fromCharCode", "Buffer.from",
    ];

    // 원래 파일: module.exports = require('./core.asar');
    // 낱말 사이의 빈칸·줄바꿈, 따옴표 종류, 끝의 세미콜론만 달라도 돼요. 문자열 안의 빈칸(예: './core.asar ')은 다른 파일이라 허용하지 않아요.
    private const string StockPattern = @"module[ \t\r\n]*\.[ \t\r\n]*exports[ \t\r\n]*=[ \t\r\n]*require[ \t\r\n]*\([ \t\r\n]*(?<sq>['""])\./core\.asar\k<sq>[ \t\r\n]*\)[ \t\r\n;]*";

    [GeneratedRegex(@"\A[ \t\r\n]*" + StockPattern + @"\z")]
    private static partial Regex StockRegex();

    // BetterDiscord 설치 프로그램이 쓰는 모양: require("…\\BetterDiscord\\data\\betterdiscord.asar"); 다음 줄에 원래 한 줄.
    // 문자열 안의 이스케이프는 \\ \" \' 만 허용해요 (\x41 같은 다른 이스케이프로 경로를 숨기지 못하게).
    [GeneratedRegex(@"\A[ \t\r\n]*require[ \t\r\n]*\([ \t\r\n]*(?<q>['""])(?<p>(?:\\[\\'""]|(?!\k<q>)[^\\\r\n])*)\k<q>[ \t\r\n]*\)[ \t\r\n;]*" + StockPattern + @"\z")]
    private static partial Regex BetterDiscordRegex();

    public string Category => CategoryName;

    public string DisplayName => "디스코드 앱 변조 (토큰 탈취)";

    public bool RunsIn(ScanScope scope, bool quick) => scope == ScanScope.User && !quick;

    public IEnumerable<Finding> Scan(ScanContext ctx)
    {
        var findings = new List<Finding>();
        var local = ctx.Paths.LocalAppData.TrimEnd('\\');

        // 디스코드 폴더는 %LOCALAPPDATA% 목록에서 찾아요. 목록은 링크(정션·심볼릭 링크)를 빼고 보여줘서,
        // 다른 곳(네트워크 위치일 수도 있어요)으로 연결된 폴더를 따라 들어가지 않아요.
        var listed = ctx.Files.GetDirectories(local);
        foreach (var (folder, label) in Flavors)
        {
            ctx.Pacer.Step();
            var root = listed.FirstOrDefault(d => Name(d).Equals(folder, StringComparison.OrdinalIgnoreCase));
            if (root is null)
            {
                var path = local + "\\" + folder;
                if (ctx.Files.DirectoryExists(path))
                {
                    ctx.Coverage.Incomplete(
                        CategoryName,
                        $"{label} 폴더 ({path})",
                        "폴더 목록에 보이지 않아서(다른 위치로 연결된 링크일 수 있어요) 열지 않았어요. 링크는 네트워크 위치를 가리킬 수도 있어서 따라가지 않아요.");
                }

                continue;
            }

            foreach (var appDir in ctx.Files.GetDirectories(root)
                .Where(d => Name(d).StartsWith("app-", StringComparison.OrdinalIgnoreCase))
                .Order(StringComparer.OrdinalIgnoreCase))
            {
                ctx.Pacer.Step();
                var app = new AppFolder(label, root, Name(appDir));
                var modules = FixedChild(ctx, appDir, "modules", app, findings);
                if (modules is null)
                {
                    continue;
                }

                foreach (var coreDir in ctx.Files.GetDirectories(modules)
                    .Where(d => Name(d).StartsWith(CoreModule + "-", StringComparison.OrdinalIgnoreCase))
                    .Order(StringComparer.OrdinalIgnoreCase))
                {
                    ctx.Pacer.Step();
                    var inner = FixedChild(ctx, coreDir, CoreModule, app, findings);
                    if (inner is not null && Inspect(ctx, inner, app) is { } finding)
                    {
                        findings.Add(finding);
                    }
                }
            }
        }

        return findings;
    }

    private sealed record AppFolder(string Label, string Root, string Name)
    {
        public string Display => $"{Label} {Name}";
    }

    private enum FileState
    {
        Missing,
        Link,
        TooLarge,
        Unreadable,
        Read,
    }

    private sealed record SmallFile(FileState State, FileMeta? Meta = null, byte[]? Data = null);

    /// <summary>
    /// 이름이 정해진 하위 폴더(modules, discord_desktop_core)를 목록에서 찾아요. 목록에는 없는데 있다고 나오면 링크예요.
    /// 디스코드는 이런 링크를 만들지 않아서 '보통'으로 알리고, 링크 안쪽은 열지 않아요.
    /// </summary>
    private static string? FixedChild(ScanContext ctx, string parent, string name, AppFolder app, List<Finding> findings)
    {
        var found = ctx.Files.GetDirectories(parent).FirstOrDefault(d => Name(d).Equals(name, StringComparison.OrdinalIgnoreCase));
        if (found is not null)
        {
            return found;
        }

        var path = parent.TrimEnd('\\') + "\\" + name;
        if (ctx.Files.DirectoryExists(path))
        {
            findings.Add(new Finding
            {
                RuleId = "DISC-001",
                Category = CategoryName,
                Severity = Severity.Medium,
                Title = $"디스코드 앱 폴더가 다른 곳으로 연결돼 있어요 ({app.Display})",
                Location = path,
                Reasons =
                [
                    $"'{name}' 폴더가 다른 위치를 가리키는 링크(정션·심볼릭 링크)예요. 디스코드는 이런 링크를 만들지 않아요. 바뀐 시작 파일을 다른 곳에 숨기는 수법일 수 있어요.",
                    "링크는 따라가지 않았어요 (네트워크 위치일 수도 있어서요). 그래서 안쪽 파일은 확인하지 못했어요.",
                ],
                Evidence = [new("디스코드", app.Display)],
                Advice = Advice.Discord(app.Root),
            });
        }

        return null;
    }

    /// <summary>discord_desktop_core 폴더 하나를 확인해요. 원래 상태면 null.</summary>
    private static Finding? Inspect(ScanContext ctx, string dir, AppFolder app)
    {
        var indexPath = dir.TrimEnd('\\') + @"\index.js";
        var packagePath = dir.TrimEnd('\\') + @"\package.json";
        var reasons = new List<string>();
        var evidence = new List<KeyValuePair<string, string>> { new("디스코드", app.Display) };
        Severity? severity = null;
        string? target = null;
        var modified = false;

        var index = ReadSmall(ctx, indexPath);
        switch (index.State)
        {
            case FileState.Link:
                severity = Severity.High;
                reasons.Add("시작 파일(index.js)이 다른 파일을 가리키는 링크예요. 디스코드는 이렇게 설치하지 않아요. 링크는 따라가서 열지 않았어요 (네트워크 위치일 수도 있어서요).");
                evidence.Add(new("파일 종류", "링크 (따라가서 열지 않았어요)"));
                break;
            case FileState.TooLarge:
                severity = Severity.High;
                modified = true;
                reasons.Add($"시작 파일(index.js)이 {MaxBytes / (1024 * 1024)}MB보다 커요. 원래 파일은 한 줄(40바이트 정도)뿐이라 다른 코드가 들어 있어요. 너무 커서 내용은 읽지 않았어요.");
                AddMeta(evidence, index.Meta!);
                break;
            case FileState.Unreadable:
                ctx.Coverage.Incomplete(CategoryName, $"{app.Label} 시작 파일 ({indexPath})", "파일을 읽지 못했어요 (잠겨 있거나 권한이 없어요).");
                break;
            case FileState.Read:
                var text = Decode(index.Data!);
                if (StockRegex().IsMatch(text))
                {
                    break;
                }

                AddMeta(evidence, index.Meta!);
                evidence.Add(new("앞부분", Snippet(text)));
                if (BetterDiscordPath(text, ctx.Paths) is { } asar)
                {
                    severity = Severity.Low;
                    target = asar;
                    reasons.Add($"BetterDiscord(디스코드 테마·플러그인 모드)가 설치하는 모양 그대로예요: {asar}를 불러온 뒤 원래 코드를 실행해요.");
                }
                else
                {
                    severity = Severity.High;
                    modified = true;
                    reasons.Add("디스코드를 켤 때마다 실행되는 시작 파일(index.js)이 원래 내용이 아니에요. 원래 파일은 './core.asar'를 불러오는 한 줄(module.exports = require('./core.asar');)뿐이에요.");
                    var markers = Markers.Where(m => text.Contains(m, StringComparison.OrdinalIgnoreCase)).ToList();
                    if (markers.Count > 0)
                    {
                        reasons.Add("인터넷으로 정보를 보내거나 로그인 정보를 가로챌 때 쓰는 코드가 들어 있어요.");
                        evidence.Add(new("의심스러운 코드", string.Join(", ", markers)));
                    }
                }

                evidence.Add(new("SHA-256", Convert.ToHexStringLower(SHA256.HashData(index.Data!))));
                break;
        }

        // package.json의 main·exports를 바꾸면 index.js는 그대로 두고 다른 파일을 먼저 실행할 수 있어요.
        var package = ReadSmall(ctx, packagePath);
        switch (package.State)
        {
            case FileState.Link:
                severity = Severity.High;
                reasons.Add("package.json이 다른 파일을 가리키는 링크예요. 디스코드는 이렇게 설치하지 않아요. 링크는 따라가서 열지 않았어요.");
                break;
            case FileState.TooLarge:
                severity = Severity.High;
                reasons.Add($"package.json이 {MaxBytes / (1024 * 1024)}MB보다 커요. 원래 파일은 100바이트 정도예요. 너무 커서 내용은 읽지 않았어요.");
                break;
            case FileState.Unreadable:
                ctx.Coverage.Incomplete(CategoryName, $"{app.Label} 모듈 설정 ({packagePath})", "파일을 읽지 못했어요 (잠겨 있거나 권한이 없어요).");
                break;
            case FileState.Read when RedirectedEntry(package.Data!) is { } entry:
                severity = Severity.High;
                reasons.Add($"package.json이 index.js 대신 다른 파일을 먼저 실행하게 바뀌었어요 ({entry.Field}: {DisplayText.ForNotification(entry.Value, 120)}). 원래는 \"main\": \"index.js\"뿐이에요.");
                evidence.Add(new("package.json " + entry.Field, Snippet(entry.Value)));
                evidence.Add(new("package.json SHA-256", Convert.ToHexStringLower(SHA256.HashData(package.Data!))));
                target = entry.Path is { } p ? (IsAbsolute(p) ? p : dir.TrimEnd('\\') + "\\" + p) : null;
                break;
        }

        if (severity is null)
        {
            // 원래 상태예요. 같은 폴더에 다른 .js 파일이 있어도 index.js·package.json이 불러오지 않으면 실행되지 않아요.
            return null;
        }

        var subdirs = ctx.Files.GetDirectories(dir).Select(Name).ToList();
        if (subdirs.Any(n => n.Equals(InitiationFolder, StringComparison.OrdinalIgnoreCase)))
        {
            severity = Severity.High;
            reasons.Add($"토큰 탈취 도구가 처음 실행 표시로 만드는 '{InitiationFolder}' 폴더가 있어요. 디스코드를 처음 켤 때 로그아웃시켜서 비밀번호를 다시 넣게 하는 수법이에요.");
        }

        var extra = ctx.Files.GetFiles(dir).Select(Name).Where(n => !KnownFiles.Contains(n))
            .Concat(subdirs.Select(n => n + "\\"))
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (extra.Count > 0)
        {
            var shown = string.Join(", ", extra.Take(10).Select(n => DisplayText.ForNotification(n, 80)));
            evidence.Add(new("같은 폴더의 다른 항목", extra.Count > 10 ? $"{shown} 외 {extra.Count - 10}개" : shown));
        }

        if (modified)
        {
            reasons.Add("디스코드 토큰·비밀번호를 훔치는 악성코드(토큰 그래버)가 이 파일을 고쳐서, 디스코드를 켤 때마다 다시 정보를 빼 가요. 게임 치트·크랙 파일에 섞여 퍼지는 경우가 많아요.");
            reasons.Add("BetterDiscord가 아닌 디스코드 모드·테마 도구를 직접 설치했다면 그 도구가 바꾼 것일 수도 있어요. 기억에 없다면 감염으로 보고 아래 방법대로 하세요.");
        }

        // '낮음'은 BetterDiscord 모양일 때뿐이에요. 다른 이상한 점(package.json, initiation 폴더)이 있으면 위에서 '높음'이 됐어요.
        var isMod = severity == Severity.Low;
        if (isMod)
        {
            reasons.Add("BetterDiscord를 직접 설치하지 않았다면 DISC-001(변조)처럼 보세요. BetterDiscord인 척하는 악성코드일 수도 있어요.");
        }

        return new Finding
        {
            RuleId = isMod ? "DISC-002" : "DISC-001",
            Category = CategoryName,
            Severity = severity.Value,
            Title = isMod
                ? $"BetterDiscord가 디스코드 앱을 바꿨어요 ({app.Display})"
                : $"디스코드 앱이 변조됐어요 ({app.Display})",
            Location = index.State == FileState.Missing && package.State != FileState.Missing ? packagePath : indexPath,
            Target = target,
            Reasons = reasons,
            Evidence = evidence,
            Advice = isMod ? Advice.DiscordMod(app.Root) : Advice.Discord(app.Root),
        };
    }

    /// <summary>파일을 읽기 전에 링크인지, 너무 큰지 봐요. 링크는 따라가지 않아요 (네트워크 위치를 가리킬 수 있어서요).</summary>
    private static SmallFile ReadSmall(ScanContext ctx, string path)
    {
        var meta = ctx.Files.GetMeta(path);
        if (meta is null)
        {
            return new SmallFile(FileState.Missing);
        }

        if ((meta.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            return new SmallFile(FileState.Link, meta);
        }

        if (meta.Length > MaxBytes)
        {
            return new SmallFile(FileState.TooLarge, meta);
        }

        ctx.Pacer.Step();
        var data = ctx.Files.ReadAll(path, MaxBytes);
        return data is null ? new SmallFile(FileState.Unreadable, meta) : new SmallFile(FileState.Read, meta, data);
    }

    private static void AddMeta(List<KeyValuePair<string, string>> evidence, FileMeta meta)
    {
        evidence.Add(new("크기", meta.Length.ToString("N0", CultureInfo.InvariantCulture) + " 바이트"));
        evidence.Add(new("수정 시각", ExecutableAssessor.FormatTime(meta.ModifiedUtc)));
    }

    /// <summary>UTF-8로 읽어요. Node.js처럼 맨 앞의 BOM은 빼요. 잘못된 바이트는 U+FFFD가 돼서 원래 한 줄과 같아지지 않아요.</summary>
    private static string Decode(byte[] data)
    {
        var text = Encoding.UTF8.GetString(data);
        return text.Length > 0 && text[0] == '﻿' ? text[1..] : text;
    }

    /// <summary>
    /// 증거에 넣을 앞부분. 줄바꿈은 ↵, 제어 문자는 \xNN, 방향 바꾸기 문자는 [U+202E]처럼 보이게 바꾸고 <see cref="SnippetChars"/>자에서 잘라요.
    /// </summary>
    public static string Snippet(string text)
    {
        var visible = text.Replace("\r\n", "↵", StringComparison.Ordinal).Replace('\n', '↵').Replace('\r', '↵');
        return DisplayText.ForNotification(visible, SnippetChars);
    }

    /// <summary>
    /// BetterDiscord 설치 프로그램이 쓰는 모양이면 불러오는 asar 경로를, 아니면 null을 돌려줘요.
    /// 경로는 정확히 %APPDATA%\BetterDiscord\data\betterdiscord.asar여야 해요 (대소문자·/와 \ 차이만 허용).
    /// </summary>
    public static string? BetterDiscordPath(string text, SystemPaths paths)
    {
        var m = BetterDiscordRegex().Match(text);
        if (!m.Success)
        {
            return null;
        }

        var raw = m.Groups["p"].Value;
        var sb = new StringBuilder(raw.Length);
        for (var i = 0; i < raw.Length; i++)
        {
            // 정규식이 \\ \" \' 만 허용해서, 역슬래시 다음 글자를 그대로 넣으면 돼요.
            sb.Append(raw[i] == '\\' && i + 1 < raw.Length ? raw[++i] : raw[i]);
        }

        var path = sb.ToString().Replace('/', '\\');
        var expected = paths.AppData.TrimEnd('\\') + @"\BetterDiscord\data\betterdiscord.asar";
        return path.Equals(expected, StringComparison.OrdinalIgnoreCase) ? expected : null;
    }

    /// <summary>package.json이 index.js 말고 다른 파일을 먼저 실행하게 하는 칸. Path는 폴더 안의 상대 경로(알 수 있을 때).</summary>
    public sealed record RedirectEntry(string Field, string Value, string? Path);

    /// <summary>
    /// package.json의 "main"·"exports"가 index.js 말고 다른 파일을 가리키는지 봐요. Node.js처럼 같은 이름이 여러 번 있으면 마지막 값을 써요.
    /// JSON이 깨졌으면 디스코드가 이 모듈을 아예 못 불러와서(실행되는 게 없어서) null이에요.
    /// </summary>
    public static RedirectEntry? RedirectedEntry(byte[] data)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(Decode(data));
        }
        catch (JsonException)
        {
            return null;
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            JsonElement? main = null, exports = null;
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (p.Name == "main")
                {
                    main = p.Value;
                }
                else if (p.Name == "exports")
                {
                    exports = p.Value;
                }
            }

            // "exports"가 있으면 Node.js는 "main"보다 먼저 써요. 원래 디스코드 package.json에는 없어요.
            if (exports is { } e && !(e.ValueKind == JsonValueKind.String && IsIndex(e.GetString()!)))
            {
                return new RedirectEntry("exports", e.ValueKind == JsonValueKind.String ? e.GetString()! : e.GetRawText(), e.ValueKind == JsonValueKind.String ? RelativePath(e.GetString()!) : null);
            }

            // 문자열이 아닌 "main"은 Node.js가 모듈을 못 불러와서(오류) 실행되는 게 없어요. 빈 문자열이면 index.js를 써요.
            if (main is { ValueKind: JsonValueKind.String } m && m.GetString() is { Length: > 0 } value && !IsIndex(value))
            {
                return new RedirectEntry("main", value, RelativePath(value));
            }

            return null;
        }
    }

    /// <summary>index.js 자신을 가리키는지 ("index.js", "./index.js", ".\index.js"). "index"처럼 확장자가 없으면 다른 파일을 먼저 찾아서 아니에요.</summary>
    private static bool IsIndex(string value)
    {
        var v = value.Replace('\\', '/');
        if (v.StartsWith("./", StringComparison.Ordinal))
        {
            v = v[2..];
        }

        return v.Equals("index.js", StringComparison.OrdinalIgnoreCase);
    }

    private static string? RelativePath(string value)
    {
        var v = value.Replace('/', '\\');
        while (v.StartsWith(@".\", StringComparison.Ordinal))
        {
            v = v[2..];
        }

        return v.Length == 0 ? null : v;
    }

    /// <summary>드라이브 문자(C:\…)나 \로 시작하는 경로인지. 그런 값은 폴더 경로를 앞에 붙이지 않고 그대로 보여줘요 (열지는 않아요).</summary>
    private static bool IsAbsolute(string path) => path.StartsWith('\\') || (path.Length >= 2 && path[1] == ':');

    private static string Name(string path) => Path.GetFileName(path.TrimEnd('\\').Replace('\\', '/'));
}
