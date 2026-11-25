using System.Text.RegularExpressions;
using Conexoes.Core.Models;

namespace Conexoes.Core.Security;

/// <summary>Heurísticas simples para destacar itens que merecem atenção. Não substituem um antivírus.</summary>
public static partial class RiskRules
{
    private static readonly string[] HighRiskFolders = [@"\temp\", @"\tmp\", @"\downloads\", @"\users\public\", @"\$recycle.bin\", @"\perflogs\"];
    private static readonly string[] UserFolders = [@"\appdata\"];

    public enum PathKind { Normal, UserProfile, HighRisk }

    public static PathKind ClassifyPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return PathKind.Normal;
        var p = Environment.ExpandEnvironmentVariables(path).Replace('/', '\\').ToLowerInvariant();
        if (HighRiskFolders.Any(p.Contains)) return PathKind.HighRisk;
        if (UserFolders.Any(p.Contains)) return PathKind.UserProfile;
        return PathKind.Normal;
    }

    /// <summary>Regras para uma conexão de rede já enriquecida com o processo.</summary>
    public static IEnumerable<RiskFinding> ForConnection(ConnectionInfo c)
    {
        var external = c.Scope == IpScope.Externo;
        var unsignedOrBad = c.Signature.Status is SignatureStatus.NaoAssinado or SignatureStatus.NaoConfiavel or SignatureStatus.Invalida;

        if (external)
        {
            switch (ClassifyPath(c.ProcessPath))
            {
                case PathKind.HighRisk:
                    yield return new(RiskLevel.Alto, "Conexão externa de programa em pasta temporária/Downloads/Pública");
                    break;
                case PathKind.UserProfile when unsignedOrBad:
                    yield return new(RiskLevel.Alto, "Conexão externa de programa não assinado em AppData");
                    break;
                case PathKind.UserProfile:
                    yield return new(RiskLevel.Baixo, "Programa executado a partir de AppData");
                    break;
            }

            if (c.Signature.Status == SignatureStatus.Invalida)
                yield return new(RiskLevel.Alto, "Assinatura digital inválida");
            else if (c.Signature.Status == SignatureStatus.NaoConfiavel)
                yield return new(RiskLevel.Medio, "Programa com certificado não confiável e conexão externa");
            else if (c.Signature.Status == SignatureStatus.NaoAssinado)
                yield return new(RiskLevel.Medio, "Programa não assinado com conexão externa");

            if (c.ProcessPath is null && c.Pid > 4)
                yield return new(RiskLevel.Baixo, "Não foi possível identificar o executável");
        }

        if (c.ExposedListener && unsignedOrBad)
            yield return new(RiskLevel.Medio, "Programa não assinado escutando em todas as interfaces");
        else if (c.ExposedListener && ClassifyPath(c.ProcessPath) == PathKind.HighRisk)
            yield return new(RiskLevel.Alto, "Programa em pasta temporária escutando na rede");
    }

    /// <summary>Regras para um executável (processo, serviço, tarefa, inicialização).</summary>
    public static IEnumerable<RiskFinding> ForExecutable(string? path, SignatureInfo signature)
    {
        var kind = ClassifyPath(path);
        var unsignedOrBad = signature.Status is SignatureStatus.NaoAssinado or SignatureStatus.NaoConfiavel or SignatureStatus.Invalida;

        if (path is not null && Path.IsPathFullyQualified(path) && !File.Exists(path))
            yield return new(RiskLevel.Baixo, "Arquivo apontado não existe (entrada órfã)");

        if (kind == PathKind.HighRisk)
            yield return new(RiskLevel.Alto, "Executável em pasta temporária/Downloads/Pública");
        else if (kind == PathKind.UserProfile && unsignedOrBad)
            yield return new(RiskLevel.Medio, "Executável sem assinatura confiável em AppData");

        if (signature.Status == SignatureStatus.Invalida)
            yield return new(RiskLevel.Alto, "Assinatura digital inválida");
        else if (signature.Status == SignatureStatus.NaoConfiavel)
            yield return new(RiskLevel.Medio, "Certificado de assinatura não confiável (autoassinado?)");
        else if (signature.Status == SignatureStatus.NaoAssinado && kind == PathKind.Normal)
            yield return new(RiskLevel.Baixo, "Executável não assinado");
    }

    /// <summary>Regras para a linha de comando completa (tarefas, inicialização, serviços, processos).</summary>
    public static IEnumerable<RiskFinding> ForCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) yield break;
        var cmd = commandLine.ToLowerInvariant();

        if (IsPowerShell(cmd))
        {
            if (EncodedCommand().IsMatch(cmd))
                yield return new(RiskLevel.Alto, "PowerShell com comando codificado (-EncodedCommand)");
            if (cmd.Contains("downloadstring") || cmd.Contains("downloadfile") || cmd.Contains("invoke-webrequest") ||
                cmd.Contains("iwr ") || cmd.Contains("net.webclient") || cmd.Contains("start-bitstransfer"))
                yield return new(RiskLevel.Alto, "PowerShell baixando conteúdo da internet");
            if (Regex.IsMatch(cmd, @"\biex\b") || cmd.Contains("invoke-expression"))
                yield return new(RiskLevel.Alto, "PowerShell executando código dinâmico (IEX)");
            if (HiddenWindow().IsMatch(cmd))
                yield return new(RiskLevel.Medio, "PowerShell com janela oculta");
            if (cmd.Contains("-executionpolicy bypass") || cmd.Contains("-ep bypass") || cmd.Contains("-exec bypass"))
                yield return new(RiskLevel.Medio, "PowerShell ignorando política de execução");
        }

        if (Exe(cmd, "mshta"))
            yield return new(RiskLevel.Alto, "Uso de mshta.exe (frequente em malware)");
        if (Exe(cmd, "rundll32") && (cmd.Contains("javascript:") || cmd.Contains("http") || ClassifyPath(cmd) != PathKind.Normal))
            yield return new(RiskLevel.Alto, "rundll32 carregando script ou DLL de pasta do usuário");
        if (Exe(cmd, "regsvr32") && (cmd.Contains("/i:http") || cmd.Contains("scrobj.dll")))
            yield return new(RiskLevel.Alto, "regsvr32 carregando script remoto");
        if (Exe(cmd, "certutil") && (cmd.Contains("-urlcache") || cmd.Contains("-decode")))
            yield return new(RiskLevel.Alto, "certutil usado para baixar/decodificar arquivo");
        if (Exe(cmd, "bitsadmin") && cmd.Contains("/transfer"))
            yield return new(RiskLevel.Alto, "bitsadmin baixando arquivo");
        if (Exe(cmd, "wscript") || Exe(cmd, "cscript"))
            yield return new(ClassifyPath(cmd) == PathKind.Normal ? RiskLevel.Medio : RiskLevel.Alto, "Execução de script via Windows Script Host");
        if (cmd.Contains("http://") || cmd.Contains("https://"))
            if (!IsPowerShell(cmd) && (Exe(cmd, "cmd") || cmd.EndsWith(".ps1") || cmd.Contains(".vbs")))
                yield return new(RiskLevel.Medio, "Linha de comando contém URL");
    }

    public static IEnumerable<RiskFinding> ForSession(SessionInfo s)
    {
        if (string.IsNullOrWhiteSpace(s.ClientAddress)) yield break;
        if (!System.Net.IPAddress.TryParse(s.ClientAddress, out var ip)) yield break;
        var scope = Net.IpClassifier.Classify(ip);
        if (scope == IpScope.Externo)
            yield return new(RiskLevel.Alto, $"Sessão {s.Type} vinda de IP externo");
        else if (s.Type == "RDP")
            yield return new(RiskLevel.Baixo, "Sessão de área de trabalho remota ativa");
    }

    public static IEnumerable<RiskFinding> ForUser(UserAccountInfo u)
    {
        if (!u.Enabled) yield break;
        if (u.Sid.EndsWith("-501"))
            yield return new(RiskLevel.Alto, "Conta Convidado ativada");
        if (u.Sid.EndsWith("-500"))
            yield return new(RiskLevel.Medio, "Conta Administrador interna ativada");
        if (u.PasswordNotRequired)
            yield return new(RiskLevel.Alto, "Conta ativa que não exige senha");
        if (u.IsAdmin && u.PasswordNeverExpires)
            yield return new(RiskLevel.Baixo, "Administrador com senha que nunca expira");
        if (u.IsAdmin && u.LastLogon is null)
            yield return new(RiskLevel.Baixo, "Administrador que nunca fez logon");
    }

    private static bool IsPowerShell(string cmd) => Exe(cmd, "powershell") || Exe(cmd, "pwsh");

    private static bool Exe(string cmd, string name) =>
        Regex.IsMatch(cmd, $@"(^|[\\/\s""']){Regex.Escape(name)}(\.exe)?([\s""']|$)");

    [GeneratedRegex(@"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[a-z0-9+/=]{16,}")]
    private static partial Regex EncodedCommand();

    [GeneratedRegex(@"\s-(w|wi|win|wind|windo|window|windows|windowst|windowsty|windowstyl|windowstyle)\s+(h|hidden|1)\b")]
    private static partial Regex HiddenWindow();
}
