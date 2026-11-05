using System.Security;
using Microsoft.Win32;
using SafetySecurity.Core.Abstractions;
using SafetySecurity.Native;

namespace SafetySecurity.Windows;

/// <summary>
/// 읽기 전용 레지스트리. RegistryKey.OpenSubKey(string)은 항상 KEY_READ로 열어요.
/// 쓰기 가능하게 여는 오버로드는 BannedSymbols.txt로 막혀 있어요.
/// </summary>
internal sealed class WinRegistryView : IRegistryView
{
    private readonly RegistryKey _hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
    private readonly RegistryKey _hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

    private RegistryKey Root(RegHive hive) => hive == RegHive.CurrentUser ? _hkcu : _hklm;

    public IRegistryKeyView? Open(RegHive hive, string path)
    {
        try
        {
            var key = Root(hive).OpenSubKey(path);
            return key is null ? null : new KeyView(key, hive.HiveName() + "\\" + path.Trim('\\'));
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    public bool IsAccessDenied(RegHive hive, string path)
    {
        try
        {
            using var key = Root(hive).OpenSubKey(path);
            return false;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            return true;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private sealed class KeyView(RegistryKey key, string fullPath) : IRegistryKeyView
    {
        public string FullPath => fullPath;

        public DateTimeOffset? LastWriteTime
        {
            get
            {
                try
                {
                    var rc = NativeMethods.RegQueryInfoKey(key.Handle, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, out var ft);
                    return rc == 0 && ft > 0 ? DateTimeOffset.FromFileTime(ft) : null;
                }
                catch (Exception ex) when (ex is ObjectDisposedException or IOException or UnauthorizedAccessException)
                {
                    return null;
                }
            }
        }

        public IReadOnlyList<string> GetSubKeyNames()
        {
            try
            {
                return key.GetSubKeyNames();
            }
            catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
            {
                return [];
            }
        }

        public IReadOnlyList<string> GetValueNames()
        {
            try
            {
                return key.GetValueNames();
            }
            catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
            {
                return [];
            }
        }

        public object? GetValue(string? name)
        {
            try
            {
                return key.GetValue(name ?? string.Empty, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            }
            catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
            {
                return null;
            }
        }

        public IRegistryKeyView? OpenSubKey(string name)
        {
            try
            {
                var sub = key.OpenSubKey(name);
                return sub is null ? null : new KeyView(sub, fullPath + "\\" + name);
            }
            catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
            {
                return null;
            }
        }

        public void Dispose() => key.Dispose();
    }
}
