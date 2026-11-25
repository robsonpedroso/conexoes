using Conexoes.Core.Models;
using Conexoes.Core.Net;
using Conexoes.Core.Security;

namespace Conexoes.Core.Collectors;

/// <summary>Equivalente a <c>netstat -ano</c> + <c>tasklist /fi "pid eq N"</c>, com classificação e assinatura.</summary>
public static class ConnectionCollector
{
    public static List<ConnectionInfo> Collect()
    {
        var raw = IpHelperTables.GetAll();
        var processes = ProcessCollector.QuickMap();
        var list = new List<ConnectionInfo>(raw.Count);

        foreach (var r in raw)
        {
            processes.TryGetValue(r.Pid, out var proc);
            var exposed = (r.State == "LISTEN" || r.Protocol == "UDP") && IpClassifier.IsUnspecified(r.LocalAddress);
            var c = new ConnectionInfo
            {
                Protocol = r.Protocol + (r.LocalAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "v6" : ""),
                LocalAddress = r.LocalAddress,
                LocalPort = r.LocalPort,
                RemoteAddress = r.RemoteAddress,
                RemotePort = r.RemotePort,
                Pid = r.Pid,
                Scope = r.RemoteAddress is null ? IpScope.Indefinido : IpClassifier.Classify(r.RemoteAddress),
                ExposedListener = exposed,
                State = r.Protocol == "UDP" ? "(UDP)" : r.State,
                ProcessName = r.Pid == 0 ? "(encerrada, sem processo)" : proc.Name ?? $"PID {r.Pid}",
                ProcessPath = proc.Path,
            };
            list.Add(c);
        }

        // Assinatura só é verificada para quem tem conexão externa ou porta exposta (o resto não usa).
        var paths = list.Where(c => c.Scope == IpScope.Externo || c.ExposedListener)
            .Select(c => c.ProcessPath).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var signatures = new System.Collections.Concurrent.ConcurrentDictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase);
        Parallel.ForEach(paths, p => signatures[p] = SignatureVerifier.Verify(p));

        foreach (var c in list)
        {
            if (c.ProcessPath is not null && signatures.TryGetValue(c.ProcessPath, out var sig)) c.Signature = sig;
            c.AddRisks(RiskRules.ForConnection(c));
        }

        return list;
    }
}
