namespace SafetySecurity.Core.Tests;

/// <summary>
/// PowerShell 스크립트와 Inno Setup 스크립트는 UTF-8(BOM 있음)이어야 해요 (.editorconfig).
/// BOM이 없으면 Windows PowerShell 5.1이 시스템 코드 페이지(CP949·CP1252)로 읽어서 한글 비교가 늘 어긋나고,
/// 그런 통합 검사는 아무것도 확인하지 않은 채 통과해요. ISCC도 BOM이 있어야 한글 문구를 UTF-8로 읽어요.
/// </summary>
public class ScriptEncodingTests
{
    private static readonly string[] SkippedDirectories = [".git", "bin", "obj", "node_modules", ".vs"];

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SafetySecurity.slnx")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static IEnumerable<string> Scripts(string dir)
    {
        foreach (var file in Directory.EnumerateFiles(dir))
        {
            var ext = Path.GetExtension(file);
            if (ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase) || ext.Equals(".iss", StringComparison.OrdinalIgnoreCase))
            {
                yield return file;
            }
        }

        foreach (var sub in Directory.EnumerateDirectories(dir))
        {
            if (SkippedDirectories.Contains(Path.GetFileName(sub), StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var file in Scripts(sub))
            {
                yield return file;
            }
        }
    }

    [Fact]
    public void ScriptsStartWithUtf8Bom()
    {
        var root = RepoRoot();
        var scripts = Scripts(root).ToList();

        // 확인할 파일이 하나도 없으면 이 테스트가 아무것도 확인하지 않은 거예요.
        Assert.Contains(scripts, f => f.EndsWith("Run-Integration.ps1", StringComparison.Ordinal));
        Assert.Contains(scripts, f => f.EndsWith("SafetySecurity.iss", StringComparison.Ordinal));

        var missing = scripts
            .Where(f =>
            {
                var head = new byte[3];
                using var fs = File.OpenRead(f);
                return fs.Read(head, 0, 3) < 3 || head[0] != 0xEF || head[1] != 0xBB || head[2] != 0xBF;
            })
            .Select(f => Path.GetRelativePath(root, f))
            .ToList();

        Assert.True(missing.Count == 0, "UTF-8 BOM이 없는 스크립트: " + string.Join(", ", missing));
    }
}
