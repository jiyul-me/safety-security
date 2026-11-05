using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Model;

namespace SafetySecurity.Core.Rules;

public sealed class CachedSignature
{
    public SignatureStatus Status { get; set; }

    public string? Signer { get; set; }

    public bool IsCatalog { get; set; }

    public string? Detail { get; set; }

    public DateTimeOffset CheckedUtc { get; set; }
}

/// <summary>
/// 서명 확인 결과를 (경로, 크기, 수정 시각) 기준으로 기억해요. 파일이 안 바뀌었으면 다시 확인하지 않아서
/// 두 번째 검사부터는 디스크·CPU를 훨씬 덜 써요.
/// </summary>
public sealed class CachingSignatureVerifier(ISignatureVerifier inner, IFileSystemView files, Dictionary<string, CachedSignature> cache, Func<DateTimeOffset> clock) : ISignatureVerifier
{
    public const int MaxEntries = 8000;
    private static readonly TimeSpan MaxAge = TimeSpan.FromDays(30);
    private readonly HashSet<string> _used = [];

    public Dictionary<string, CachedSignature> Cache => cache;

    public int Hits { get; private set; }

    public int Misses { get; private set; }

    public SignatureInfo Verify(string path)
    {
        var meta = files.GetMeta(path);
        if (meta is null)
        {
            return new SignatureInfo(SignatureStatus.NotFound);
        }

        var key = $"{path.ToLowerInvariant()}|{meta.Length}|{meta.ModifiedUtc.UtcTicks}";
        _used.Add(key);
        if (cache.TryGetValue(key, out var c) && clock() - c.CheckedUtc < MaxAge && c.Status != SignatureStatus.Error)
        {
            Hits++;
            return new SignatureInfo(c.Status, c.Signer, c.IsCatalog, c.Detail);
        }

        Misses++;
        var info = inner.Verify(path);
        cache[key] = new CachedSignature { Status = info.Status, Signer = info.Signer, IsCatalog = info.IsCatalog, Detail = info.Detail, CheckedUtc = clock() };
        return info;
    }

    /// <summary>오래된 항목을 정리해요 (이번 검사에서 쓴 항목은 남겨요).</summary>
    public void Trim()
    {
        var now = clock();
        foreach (var k in cache.Where(kv => now - kv.Value.CheckedUtc >= MaxAge && !_used.Contains(kv.Key)).Select(kv => kv.Key).ToList())
        {
            cache.Remove(k);
        }

        if (cache.Count > MaxEntries)
        {
            foreach (var k in cache.Where(kv => !_used.Contains(kv.Key)).OrderBy(kv => kv.Value.CheckedUtc).Take(cache.Count - MaxEntries).Select(kv => kv.Key).ToList())
            {
                cache.Remove(k);
            }
        }
    }
}
