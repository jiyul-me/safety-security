using System.Security.Cryptography;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Core.Engine;
using SafetySecurity.Core.Model;
using SafetySecurity.Core.Rules;

namespace SafetySecurity.Core.Tests;

public sealed class FakeRegistry : IRegistryView
{
    private sealed class Node
    {
        public Dictionary<string, Node> Children { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, object> Values { get; } = new(StringComparer.OrdinalIgnoreCase);
        public DateTimeOffset? LastWrite { get; set; }
        public bool Denied { get; set; }
    }

    private readonly Dictionary<RegHive, Node> _roots = new() { [RegHive.CurrentUser] = new Node(), [RegHive.LocalMachine] = new Node() };

    public FakeRegistry Set(RegHive hive, string path, string? name, object value, DateTimeOffset? lastWrite = null)
    {
        var node = Ensure(hive, path);
        node.Values[name ?? string.Empty] = value;
        if (lastWrite is not null)
        {
            node.LastWrite = lastWrite;
        }

        return this;
    }

    public FakeRegistry Key(RegHive hive, string path, DateTimeOffset? lastWrite = null)
    {
        var node = Ensure(hive, path);
        node.LastWrite = lastWrite ?? node.LastWrite;
        return this;
    }

    public FakeRegistry Deny(RegHive hive, string path)
    {
        Ensure(hive, path).Denied = true;
        return this;
    }

    private Node Ensure(RegHive hive, string path)
    {
        var node = _roots[hive];
        foreach (var part in path.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!node.Children.TryGetValue(part, out var child))
            {
                child = new Node { LastWrite = DateTimeOffset.UnixEpoch };
                node.Children[part] = child;
            }

            node = child;
        }

        return node;
    }

    private Node? Find(RegHive hive, string path, out bool denied)
    {
        denied = false;
        var node = _roots[hive];
        foreach (var part in path.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!node.Children.TryGetValue(part, out var child))
            {
                return null;
            }

            node = child;
        }

        if (node.Denied)
        {
            denied = true;
            return null;
        }

        return node;
    }

    public IRegistryKeyView? Open(RegHive hive, string path)
    {
        var node = Find(hive, path, out _);
        return node is null ? null : new KeyView(node, hive.HiveName() + "\\" + path.Trim('\\'));
    }

    public bool IsAccessDenied(RegHive hive, string path)
    {
        Find(hive, path, out var denied);
        return denied;
    }

    private sealed class KeyView(Node node, string fullPath) : IRegistryKeyView
    {
        public string FullPath => fullPath;

        public DateTimeOffset? LastWriteTime => node.LastWrite;

        public IReadOnlyList<string> GetSubKeyNames() => [.. node.Children.Keys];

        public IReadOnlyList<string> GetValueNames() => [.. node.Values.Keys.Where(k => k.Length > 0)];

        public object? GetValue(string? name) => node.Values.TryGetValue(name ?? string.Empty, out var v) ? v : null;

        public IRegistryKeyView? OpenSubKey(string name) =>
            node.Children.TryGetValue(name, out var c) && !c.Denied ? new KeyView(c, fullPath + "\\" + name) : null;

        public void Dispose()
        {
        }
    }
}

public sealed class FakeFileSystem : IFileSystemView
{
    private readonly Dictionary<string, (byte[] Data, FileMeta Meta)> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _dirs = new(StringComparer.OrdinalIgnoreCase);

    public FakeFileSystem Add(string path, byte[]? data = null, DateTimeOffset? created = null, FileAttributes attributes = FileAttributes.Normal)
    {
        data ??= new byte[1024];
        var t = created ?? DateTimeOffset.Parse("2024-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        _files[path] = (data, new FileMeta(data.Length, t, t, attributes));
        var dir = path;
        while (dir.LastIndexOf('\\') is var i && i > 2)
        {
            dir = dir[..i];
            _dirs.Add(dir);
        }

        return this;
    }

    public bool FileExists(string path) => _files.ContainsKey(path);

    public bool DirectoryExists(string path) => _dirs.Contains(path.TrimEnd('\\'));

    public FileMeta? GetMeta(string path) => _files.TryGetValue(path, out var f) ? f.Meta : null;

    public IReadOnlyList<string> GetFiles(string directory)
    {
        var d = directory.TrimEnd('\\') + "\\";
        return [.. _files.Keys.Where(k => k.StartsWith(d, StringComparison.OrdinalIgnoreCase) && !k[d.Length..].Contains('\\'))];
    }

    public IReadOnlyList<string> GetDirectories(string directory)
    {
        var d = directory.TrimEnd('\\') + "\\";
        return [.. _dirs.Where(k => k.StartsWith(d, StringComparison.OrdinalIgnoreCase) && !k[d.Length..].Contains('\\'))];
    }

    public byte[]? ReadPrefix(string path, int maxBytes) => _files.TryGetValue(path, out var f) ? f.Data.Take(maxBytes).ToArray() : null;

    public byte[]? ReadAll(string path, long maxBytes) => _files.TryGetValue(path, out var f) && f.Data.Length <= maxBytes ? f.Data : null;

    public string? Sha256(string path, long maxBytes) => _files.TryGetValue(path, out var f) ? Convert.ToHexStringLower(SHA256.HashData(f.Data)) : null;
}

public sealed class FakeSignatures : ISignatureVerifier
{
    private readonly Dictionary<string, SignatureInfo> _map = new(StringComparer.OrdinalIgnoreCase);

    public SignatureInfo Default { get; set; } = new(SignatureStatus.Unsigned);

    public int Calls { get; private set; }

    public FakeSignatures Signed(string path, string signer = "Microsoft Windows")
    {
        _map[path] = new SignatureInfo(SignatureStatus.Valid, signer);
        return this;
    }

    public FakeSignatures Set(string path, SignatureInfo info)
    {
        _map[path] = info;
        return this;
    }

    public SignatureInfo Verify(string path)
    {
        Calls++;
        return _map.TryGetValue(path, out var s) ? s : Default;
    }
}

public sealed class TestEnv
{
    public static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-05T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

    public FakeRegistry Registry { get; } = new();

    public FakeFileSystem Files { get; } = new();

    public FakeSignatures Signatures { get; } = new();

    public string? TasksXml { get; set; }

    public string? WmiJson { get; set; }

    public static SystemPaths Paths { get; } = new(new Dictionary<string, string>
    {
        ["SystemRoot"] = @"C:\Windows",
        ["SystemDrive"] = "C:",
        ["ProgramFiles"] = @"C:\Program Files",
        ["ProgramFiles(x86)"] = @"C:\Program Files (x86)",
        ["ProgramData"] = @"C:\ProgramData",
        ["USERPROFILE"] = @"C:\Users\jiyul",
        ["APPDATA"] = @"C:\Users\jiyul\AppData\Roaming",
        ["LOCALAPPDATA"] = @"C:\Users\jiyul\AppData\Local",
        ["TEMP"] = @"C:\Users\jiyul\AppData\Local\Temp",
        ["PUBLIC"] = @"C:\Users\Public",
    });

    public ScanContext Context(
        ScanScope scope = ScanScope.User,
        bool elevated = false,
        IEnumerable<string>? self = null,
        IFileSystemView? files = null,
        ISignatureVerifier? signatures = null,
        IReadOnlySet<char>? networkDrives = null)
    {
        var classifier = new PathClassifier(Paths) { NetworkDrives = networkDrives ?? new HashSet<char>() };
        return new ScanContext
        {
            Registry = Registry,
            Files = files ?? Files,
            Signatures = signatures ?? Signatures,
            Classifier = classifier,
            Now = Now,
            Scope = scope,
            IsElevated = elevated,
            Tasks = new StaticTasks(() => TasksXml),
            Wmi = new StaticWmi(() => WmiJson),
            SelfPaths = (self ?? []).Select(classifier.Normalize).ToHashSet(),
        };
    }

    private sealed class StaticTasks(Func<string?> get) : ITaskSource
    {
        public string? GetTasksXml(out string? error)
        {
            error = null;
            return get();
        }
    }

    private sealed class StaticWmi(Func<string?> get) : IWmiSource
    {
        public string? GetConsumersJson(out string? error)
        {
            error = get() is null ? "denied" : null;
            return get();
        }
    }

    public static byte[] FakePe(bool dll = false)
    {
        var b = new byte[1024];
        b[0] = (byte)'M';
        b[1] = (byte)'Z';
        b[0x3C] = 0x80;
        b[0x80] = (byte)'P';
        b[0x81] = (byte)'E';
        if (dll)
        {
            b[0x80 + 4 + 18 + 1] = 0x20;
        }

        return b;
    }
}
