using Conexoes.Core.Models;
using Conexoes.Core.Security;
using Microsoft.Win32;

namespace Conexoes.Core.Collectors;

/// <summary>Programas que iniciam com o Windows: chaves Run/RunOnce, pastas Startup e Winlogon.</summary>
public static class StartupCollector
{
    private static readonly (RegistryHive Hive, RegistryView View, string Key)[] RunKeys =
    [
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ];

    public static List<StartupEntryInfo> Collect()
    {
        var list = new List<StartupEntryInfo>();

        foreach (var (hive, view, keyPath) in RunKeys)
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var key = root.OpenSubKey(keyPath);
                if (key is null) continue;
                var prefix = (hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU") +
                             (view == RegistryView.Registry32 ? @"\WOW6432Node" : "");
                var fullKey = (hive == RegistryHive.LocalMachine ? "HKEY_LOCAL_MACHINE" : "HKEY_CURRENT_USER") + @"\" +
                              (view == RegistryView.Registry32 ? @"Software\WOW6432Node\" + keyPath[@"Software\".Length..] : keyPath);
                foreach (var name in key.GetValueNames())
                {
                    var cmd = key.GetValue(name)?.ToString();
                    if (string.IsNullOrWhiteSpace(cmd)) continue;
                    list.Add(Make($@"{prefix}\{keyPath[(keyPath.IndexOf("CurrentVersion", StringComparison.Ordinal))..]}",
                        string.IsNullOrEmpty(name) ? "(padrão)" : name, cmd, registryKey: fullKey));
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
        }

        foreach (var (folder, label) in new[]
                 {
                     (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Pasta Inicializar (todos)"),
                     (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Pasta Inicializar (usuário)"),
                 })
        {
            if (!Directory.Exists(folder)) continue;
            foreach (var file in Directory.EnumerateFiles(folder))
            {
                if (Path.GetFileName(file).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                var target = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? ResolveShortcut(file) : null;
                list.Add(Make(label, Path.GetFileName(file), target ?? $"\"{file}\"", filePath: file));
            }
        }

        // Winlogon: valores diferentes do padrão são técnica conhecida de persistência.
        try
        {
            using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var winlogon = root.OpenSubKey(WinlogonKey);
            if (winlogon is not null)
            {
                const string fullKey = @"HKEY_LOCAL_MACHINE\" + WinlogonKey;
                var shell = winlogon.GetValue("Shell")?.ToString();
                if (shell is not null)
                {
                    var e = Make(@"HKLM\Winlogon", "Shell", shell, registryKey: fullKey);
                    if (!shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                        e.AddRisk(RiskLevel.Alto, "Shell do Winlogon diferente de explorer.exe");
                    list.Add(e);
                }
                var userinit = winlogon.GetValue("Userinit")?.ToString();
                if (userinit is not null)
                {
                    var e = Make(@"HKLM\Winlogon", "Userinit", userinit, registryKey: fullKey);
                    var normalized = userinit.Trim().TrimEnd(',').ToLowerInvariant();
                    if (!normalized.EndsWith(@"\system32\userinit.exe") && normalized != "userinit.exe")
                        e.AddRisk(RiskLevel.Alto, "Userinit do Winlogon diferente do padrão");
                    list.Add(e);
                }
            }
        }
        catch (UnauthorizedAccessException) { }

        Parallel.ForEach(list, e =>
        {
            e.Signature = SignatureVerifier.Verify(e.ExecutablePath);
            e.AddRisks(RiskRules.ForExecutable(e.ExecutablePath, e.Signature));
            e.AddRisks(RiskRules.ForCommandLine(e.Command));
        });
        return list;
    }

    private const string WinlogonKey = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";

    private static StartupEntryInfo Make(string location, string name, string command,
        string? registryKey = null, string? filePath = null) => new()
    {
        Location = location,
        Name = name,
        Command = command,
        ExecutablePath = CommandLineParser.ExtractExecutable(command),
        RegistryKey = registryKey,
        FilePath = filePath,
    };

    private static string? ResolveShortcut(string lnk)
    {
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type is null) return null;
            dynamic shell = Activator.CreateInstance(type)!;
            try
            {
                dynamic sc = shell.CreateShortcut(lnk);
                string target = sc.TargetPath;
                string args = sc.Arguments;
                if (string.IsNullOrEmpty(target)) return null;
                return string.IsNullOrEmpty(args) ? $"\"{target}\"" : $"\"{target}\" {args}";
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ReleaseComObject(shell);
            }
        }
        catch
        {
            return null;
        }
    }
}
