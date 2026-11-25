using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Conexoes.Core.Models;
using Conexoes.Core.Security;

namespace Conexoes.Core.Collectors;

/// <summary>Equivalente a <c>tasklist /v</c>, com caminho, linha de comando, processo pai e dono.</summary>
public static class ProcessCollector
{
    public static List<ProcessInfo> Collect(bool verifySignatures = true)
    {
        var list = new List<ProcessInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, CreationDate FROM Win32_Process");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    var pid = Convert.ToInt32(mo["ProcessId"]);
                    var path = mo["ExecutablePath"] as string ?? QueryImagePath(pid);
                    DateTime? start = null;
                    if (mo["CreationDate"] is string cd && cd.Length > 0)
                        try { start = ManagementDateTimeConverter.ToDateTime(cd); } catch { }
                    list.Add(new ProcessInfo
                    {
                        Pid = pid,
                        Name = mo["Name"] as string ?? "?",
                        ParentPid = Convert.ToInt32(mo["ParentProcessId"]),
                        Path = path,
                        CommandLine = mo["CommandLine"] as string,
                        User = GetOwner(pid),
                        StartTime = start,
                    });
                }
            }
        }
        catch (ManagementException)
        {
            // WMI indisponível: usa a API básica.
            foreach (var p in Process.GetProcesses())
                using (p)
                    list.Add(new ProcessInfo { Pid = p.Id, Name = p.ProcessName + ".exe", Path = QueryImagePath(p.Id), User = GetOwner(p.Id) });
        }

        var byPid = list.ToDictionary(p => p.Pid);
        foreach (var p in list)
            if (byPid.TryGetValue(p.ParentPid, out var parent) && parent.Pid != p.Pid &&
                (parent.StartTime is null || p.StartTime is null || parent.StartTime <= p.StartTime))
                p.ParentName = parent.Name;

        if (verifySignatures)
            Parallel.ForEach(list, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, p =>
            {
                p.Signature = SignatureVerifier.Verify(p.Path);
                p.AddRisks(RiskRules.ForExecutable(p.Path, p.Signature));
                p.AddRisks(RiskRules.ForCommandLine(p.CommandLine));
            });

        return list;
    }

    /// <summary>Mapa rápido PID → (nome, caminho) para enriquecer conexões sem consultar o WMI.</summary>
    public static Dictionary<int, (string Name, string? Path)> QuickMap()
    {
        var map = new Dictionary<int, (string, string?)>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                var path = QueryImagePath(p.Id);
                var name = path is not null ? System.IO.Path.GetFileName(path) : p.ProcessName;
                if (p.Id == 0) name = "System Idle Process";
                if (p.Id == 4) name = "System";
                map[p.Id] = (name, path);
            }
        }
        return map;
    }

    public static string? QueryImagePath(int pid)
    {
        if (pid is 0 or 4) return null;
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            var size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    public static string? GetOwner(int pid)
    {
        if (pid == 0) return null;
        if (pid == 4) return SystemAccountName.Value;
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            if (!OpenProcessToken(h, TOKEN_QUERY, out var token)) return null;
            try
            {
                using var identity = new WindowsIdentity(token);
                return identity.Name;
            }
            catch
            {
                return null;
            }
            finally
            {
                CloseHandle(token);
            }
        }
        finally
        {
            CloseHandle(h);
        }
    }

    // Nome localizado da conta SYSTEM (ex.: "AUTORIDADE NT\SISTEMA").
    private static readonly Lazy<string> SystemAccountName = new(() =>
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Translate(typeof(NTAccount)).Value);

    private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
}
