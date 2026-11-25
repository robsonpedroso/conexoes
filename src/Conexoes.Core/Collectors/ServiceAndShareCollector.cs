using System.Management;
using Conexoes.Core.Models;
using Conexoes.Core.Security;

namespace Conexoes.Core.Collectors;

/// <summary>Equivalente a <c>sc query</c> (serviços) e <c>net share</c> (compartilhamentos).</summary>
public static class ServiceAndShareCollector
{
    public static List<ServiceInfo> CollectServices()
    {
        var list = new List<ServiceInfo>();
        using var searcher = new ManagementObjectSearcher(
            "SELECT Name, DisplayName, State, StartMode, PathName, StartName, ProcessId, Description FROM Win32_Service");
        foreach (ManagementObject mo in searcher.Get())
            using (mo)
            {
                var pathName = mo["PathName"] as string;
                list.Add(new ServiceInfo
                {
                    Name = mo["Name"] as string ?? "?",
                    DisplayNameText = mo["DisplayName"] as string,
                    State = Translate(mo["State"] as string),
                    StartMode = Translate(mo["StartMode"] as string),
                    PathName = pathName,
                    Account = mo["StartName"] as string,
                    Pid = Convert.ToInt32(mo["ProcessId"] ?? 0),
                    Description = mo["Description"] as string,
                    ExecutablePath = CommandLineParser.ExtractExecutable(pathName),
                });
            }

        Parallel.ForEach(list, s =>
        {
            s.Signature = SignatureVerifier.Verify(s.ExecutablePath);
            s.AddRisks(RiskRules.ForExecutable(s.ExecutablePath, s.Signature));
            s.AddRisks(RiskRules.ForCommandLine(s.PathName));
            if (CommandLineParser.IsUnquotedPathWithSpaces(s.PathName) && s.StartMode != "Desativado")
                s.AddRisk(RiskLevel.Medio, "Caminho do serviço com espaços e sem aspas (unquoted service path)");
        });
        return list;
    }

    public static List<ShareInfo> CollectShares()
    {
        var list = new List<ShareInfo>();
        using var searcher = new ManagementObjectSearcher("SELECT Name, Path, Description, Type FROM Win32_Share");
        foreach (ManagementObject mo in searcher.Get())
            using (mo)
            {
                var type = Convert.ToUInt32(mo["Type"] ?? 0u);
                var isAdmin = (type & 0x80000000) != 0;
                var share = new ShareInfo
                {
                    Name = mo["Name"] as string ?? "?",
                    Path = mo["Path"] as string,
                    Description = mo["Description"] as string,
                    Type = (type & 0xFF) switch
                    {
                        0 => isAdmin ? "Disco (administrativo)" : "Disco",
                        1 => "Impressora",
                        2 => "Dispositivo",
                        3 => "IPC",
                        _ => type.ToString(),
                    },
                    IsAdministrative = isAdmin,
                };
                if (!isAdmin && (type & 0xFF) == 0)
                    share.AddRisk(RiskLevel.Baixo, "Pasta compartilhada na rede");
                if (!isAdmin && share.Path is { Length: <= 3 } p && p.EndsWith(":\\"))
                    share.AddRisk(RiskLevel.Alto, "Unidade inteira compartilhada");
                list.Add(share);
            }
        return list;
    }

    private static string? Translate(string? v) => v switch
    {
        "Running" => "Em execução",
        "Stopped" => "Parado",
        "Paused" => "Pausado",
        "Start Pending" => "Iniciando",
        "Stop Pending" => "Parando",
        "Auto" => "Automático",
        "Manual" => "Manual",
        "Disabled" => "Desativado",
        "Boot" => "Boot",
        "System" => "Sistema",
        _ => v,
    };
}
