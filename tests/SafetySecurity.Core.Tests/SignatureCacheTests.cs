using System.Text.Json;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Reporting;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Tests;

/// <summary>
/// 서명 캐시(sigcache.json)가 언제 다시 확인하는지 확인해요. 캐시가 바뀐 파일에 예전 결과를 돌려주면
/// 서명된 DLL을 서명 없는 DLL로 바꿔치기해도 '유효'로 보여서 COM·자동 실행 항목이 낮게 평가돼요.
/// </summary>
public class SignatureCacheTests
{
    private const string Dll = @"C:\Users\jiyul\AppData\Roaming\x\a.dll";

    private static readonly DateTimeOffset FileTime = DateTimeOffset.Parse("2025-06-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

    private static string Key(string path, long length, DateTimeOffset modified) =>
        $"{path.ToLowerInvariant()}|{length}|{modified.UtcTicks}";

    private static CachedSignature Entry(DateTimeOffset checkedUtc) => new() { Status = SignatureStatus.Valid, Signer = "Microsoft Windows", CheckedUtc = checkedUtc };

    [Fact]
    public void UnchangedFileIsServedFromTheCache()
    {
        var env = new TestEnv();
        env.Files.Add(Dll, new byte[1024], FileTime);
        env.Signatures.Signed(Dll);
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, [], () => TestEnv.Now);

        Assert.Equal(SignatureStatus.Valid, v.Verify(Dll).Status);
        // 파일이 그대로면 다시 확인하지 않아요 (확인기가 지금은 다른 답을 줘도 캐시 결과를 써요).
        env.Signatures.Set(Dll, new SignatureInfo(SignatureStatus.Unsigned));
        var again = v.Verify(Dll);

        Assert.Equal(SignatureStatus.Valid, again.Status);
        Assert.Equal("Microsoft Windows", again.Signer);
        Assert.Equal(1, env.Signatures.Calls);
        Assert.Equal(1, v.Hits);
        Assert.Equal(1, v.Misses);
    }

    [Fact]
    public void SwappedFileOfAnotherSizeIsVerifiedAgain()
    {
        var env = new TestEnv();
        env.Files.Add(Dll, new byte[1024], FileTime);
        env.Signatures.Signed(Dll);
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, [], () => TestEnv.Now);
        Assert.Equal(SignatureStatus.Valid, v.Verify(Dll).Status);

        // 서명된 DLL을 크기가 다른 서명 없는 DLL로 바꿔치기했어요 (수정 시각은 되돌려 놓았어요).
        env.Files.Add(Dll, new byte[2048], FileTime);
        env.Signatures.Set(Dll, new SignatureInfo(SignatureStatus.Unsigned));
        var swapped = v.Verify(Dll);

        Assert.Equal(SignatureStatus.Unsigned, swapped.Status);
        Assert.Equal(2, env.Signatures.Calls);
        Assert.Equal(2, v.Misses);
        Assert.Equal(0, v.Hits);
    }

    [Fact]
    public void SwappedFileWithAnotherModifiedTimeIsVerifiedAgain()
    {
        var env = new TestEnv();
        env.Files.Add(Dll, new byte[1024], FileTime);
        env.Signatures.Signed(Dll);
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, [], () => TestEnv.Now);
        v.Verify(Dll);

        // 크기는 같고 수정 시각만 달라요.
        env.Files.Add(Dll, new byte[1024], FileTime.AddSeconds(1));
        env.Signatures.Set(Dll, new SignatureInfo(SignatureStatus.Invalid));
        var swapped = v.Verify(Dll);

        Assert.Equal(SignatureStatus.Invalid, swapped.Status);
        Assert.Equal(2, env.Signatures.Calls);
        Assert.Equal(0, v.Hits);
    }

    [Fact]
    public void OtherPathWithTheSameSizeAndTimeIsNotServedFromTheCache()
    {
        const string Other = @"C:\Users\jiyul\AppData\Roaming\x\b.dll";
        var env = new TestEnv();
        env.Files.Add(Dll, new byte[1024], FileTime);
        env.Files.Add(Other, new byte[1024], FileTime);
        env.Signatures.Signed(Dll);
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, [], () => TestEnv.Now);

        Assert.Equal(SignatureStatus.Valid, v.Verify(Dll).Status);
        Assert.Equal(SignatureStatus.Unsigned, v.Verify(Other).Status);
        Assert.Equal(2, env.Signatures.Calls);
        Assert.Equal(0, v.Hits);
    }

    [Fact]
    public void PathCaseDoesNotMatter()
    {
        var env = new TestEnv();
        env.Files.Add(Dll, new byte[1024], FileTime);
        env.Signatures.Signed(Dll);
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, [], () => TestEnv.Now);

        v.Verify(Dll);
        var upper = v.Verify(Dll.ToUpperInvariant());

        Assert.Equal(SignatureStatus.Valid, upper.Status);
        Assert.Equal(1, env.Signatures.Calls);
        Assert.Equal(1, v.Hits);
        Assert.Single(v.Cache);
    }

    [Fact]
    public void ErrorResultIsNeverServedFromTheCache()
    {
        var env = new TestEnv();
        env.Files.Add(Dll, new byte[1024], FileTime);
        env.Signatures.Set(Dll, new SignatureInfo(SignatureStatus.Error, Detail: "잠긴 파일"));
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, [], () => TestEnv.Now);

        Assert.Equal(SignatureStatus.Error, v.Verify(Dll).Status);
        Assert.Equal(SignatureStatus.Error, v.Verify(Dll).Status);
        Assert.Equal(2, env.Signatures.Calls);
        Assert.Equal(0, v.Hits);

        // 다음 확인이 성공하면 그 결과를 기억해요.
        env.Signatures.Signed(Dll);
        Assert.Equal(SignatureStatus.Valid, v.Verify(Dll).Status);
        Assert.Equal(SignatureStatus.Valid, v.Verify(Dll).Status);
        Assert.Equal(3, env.Signatures.Calls);
        Assert.Equal(1, v.Hits);
    }

    [Fact]
    public void EntryExpiresAfterThirtyDays()
    {
        var env = new TestEnv();
        env.Files.Add(Dll, new byte[1024], FileTime);
        env.Signatures.Signed(Dll);
        var now = TestEnv.Now;
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, [], () => now);
        v.Verify(Dll);

        now = TestEnv.Now.AddDays(29);
        v.Verify(Dll);
        Assert.Equal(1, env.Signatures.Calls);

        // 30일이 지나면 파일이 그대로여도 다시 확인해요 (인증서 폐기·만료가 바뀔 수 있어요).
        now = TestEnv.Now.AddDays(30);
        env.Signatures.Set(Dll, new SignatureInfo(SignatureStatus.Untrusted));
        Assert.Equal(SignatureStatus.Untrusted, v.Verify(Dll).Status);
        Assert.Equal(2, env.Signatures.Calls);

        // 다시 확인한 시각부터 새로 30일이에요.
        Assert.Equal(now, v.Cache[Key(Dll, 1024, FileTime)].CheckedUtc);
        Assert.Equal(SignatureStatus.Untrusted, v.Verify(Dll).Status);
        Assert.Equal(2, env.Signatures.Calls);
    }

    [Fact]
    public void MissingFileIsNotFoundAndNotCached()
    {
        var env = new TestEnv();
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, [], () => TestEnv.Now);

        Assert.Equal(SignatureStatus.NotFound, v.Verify(Dll).Status);
        Assert.Equal(0, env.Signatures.Calls);
        Assert.Empty(v.Cache);
        Assert.Equal(0, v.Hits + v.Misses);
    }

    [Fact]
    public void TrimRemovesOnlyStaleEntriesThisScanDidNotUse()
    {
        var env = new TestEnv();
        env.Files.Add(Dll, new byte[1024], FileTime);
        env.Signatures.Signed(Dll);
        var now = TestEnv.Now;
        var cache = new Dictionary<string, CachedSignature>
        {
            ["c:\\old.dll|1|1"] = Entry(TestEnv.Now.AddDays(-30)),
            ["c:\\older.dll|1|1"] = Entry(TestEnv.Now.AddDays(-400)),
            ["c:\\recent.dll|1|1"] = Entry(TestEnv.Now.AddDays(-29)),
        };
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, cache, () => now);
        v.Verify(Dll);
        v.Trim();

        // 30일이 된 항목부터 지워요. 아직 30일이 안 된 항목과 이번 검사에서 쓴 항목은 남아요.
        Assert.Contains(Key(Dll, 1024, FileTime), cache.Keys);
        Assert.DoesNotContain("c:\\old.dll|1|1", cache.Keys);
        Assert.DoesNotContain("c:\\older.dll|1|1", cache.Keys);
        Assert.Contains("c:\\recent.dll|1|1", cache.Keys);

        // 검사가 끝날 때 시계가 31일 뒤라도, 이번 검사에서 쓴 항목은 남겨요.
        now = TestEnv.Now.AddDays(31);
        v.Trim();
        Assert.Contains(Key(Dll, 1024, FileTime), cache.Keys);
        Assert.DoesNotContain("c:\\recent.dll|1|1", cache.Keys);
    }

    [Fact]
    public void TrimCapsTheCacheByRemovingTheOldestUnusedEntries()
    {
        var env = new TestEnv();
        env.Files.Add(Dll, new byte[1024], FileTime);
        env.Signatures.Signed(Dll);
        var cache = new Dictionary<string, CachedSignature>();
        var total = CachingSignatureVerifier.MaxEntries + 10;
        for (var i = 0; i < total; i++)
        {
            // i가 작을수록 오래된 항목이에요 (모두 30일 안이라 오래돼서 지워지지는 않아요).
            cache[$"c:\\f{i}.dll|1|1"] = Entry(TestEnv.Now.AddDays(-20).AddSeconds(i));
        }

        var v = new CachingSignatureVerifier(env.Signatures, env.Files, cache, () => TestEnv.Now);
        v.Verify(Dll);
        // 이번 검사에서 쓴 항목이 가장 오래됐어도 남아야 해요.
        cache[Key(Dll, 1024, FileTime)].CheckedUtc = TestEnv.Now.AddDays(-25);
        v.Trim();

        Assert.Equal(CachingSignatureVerifier.MaxEntries, cache.Count);
        Assert.Contains(Key(Dll, 1024, FileTime), cache.Keys);
        for (var i = 0; i < 11; i++)
        {
            Assert.DoesNotContain($"c:\\f{i}.dll|1|1", cache.Keys);
        }

        Assert.Contains("c:\\f11.dll|1|1", cache.Keys);
        Assert.Contains($"c:\\f{total - 1}.dll|1|1", cache.Keys);
    }

    [Fact]
    public void TrimKeepsEveryEntryThisScanUsedEvenOverTheCap()
    {
        var env = new TestEnv();
        var used = CachingSignatureVerifier.MaxEntries + 5;
        for (var i = 0; i < used; i++)
        {
            env.Files.Add($@"C:\Program Files\App\m{i}.dll", new byte[16], FileTime);
        }

        var cache = new Dictionary<string, CachedSignature>
        {
            ["c:\\unused1.dll|1|1"] = Entry(TestEnv.Now.AddDays(-1)),
            ["c:\\unused2.dll|1|1"] = Entry(TestEnv.Now.AddDays(-2)),
        };
        var v = new CachingSignatureVerifier(env.Signatures, env.Files, cache, () => TestEnv.Now);
        for (var i = 0; i < used; i++)
        {
            v.Verify($@"C:\Program Files\App\m{i}.dll");
        }

        v.Trim();

        Assert.Equal(used, cache.Count);
        Assert.DoesNotContain("c:\\unused1.dll|1|1", cache.Keys);
        Assert.DoesNotContain("c:\\unused2.dll|1|1", cache.Keys);
    }

    [Fact]
    public void CacheSurvivesSavingAndLoading()
    {
        var env = new TestEnv();
        env.Files.Add(Dll, new byte[1024], FileTime);
        env.Signatures.Set(Dll, new SignatureInfo(SignatureStatus.Valid, "Contoso Ltd", IsCatalog: true, Detail: "폐기 여부는 확인 안 함"));
        var first = new CachingSignatureVerifier(env.Signatures, env.Files, [], () => TestEnv.Now);
        first.Verify(Dll);

        // DataStore가 sigcache.json에 쓰고 읽는 것과 같은 직렬화예요.
        var json = JsonSerializer.Serialize(first.Cache, SafetyJson.Context.DictionaryStringCachedSignature);
        var loaded = JsonSerializer.Deserialize(json, SafetyJson.Context.DictionaryStringCachedSignature)!;
        var entry = Assert.Single(loaded).Value;
        Assert.Equal(TestEnv.Now, entry.CheckedUtc);

        var second = new CachingSignatureVerifier(env.Signatures, env.Files, loaded, () => TestEnv.Now.AddDays(1));
        var info = second.Verify(Dll);

        Assert.Equal(new SignatureInfo(SignatureStatus.Valid, "Contoso Ltd", IsCatalog: true, Detail: "폐기 여부는 확인 안 함"), info);
        Assert.Equal(1, env.Signatures.Calls);
        Assert.Equal(1, second.Hits);
    }
}
