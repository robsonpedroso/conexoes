using System.Net;

namespace Conexoes.Core.Models;

public enum IpScope
{
    Indefinido,
    Loopback,
    Privado,
    Multicast,
    Externo,
}

public sealed class ConnectionInfo : InspectionItem
{
    private string _state = "";
    private string? _remoteHost;

    public required string Protocol { get; init; }
    public required IPAddress LocalAddress { get; init; }
    public required int LocalPort { get; init; }
    public IPAddress? RemoteAddress { get; init; }
    public int? RemotePort { get; init; }
    public required int Pid { get; init; }
    public IpScope Scope { get; init; }

    /// <summary>Escutando em 0.0.0.0 / :: , ou seja, acessível pela rede.</summary>
    public bool ExposedListener { get; init; }

    public string ProcessName { get; set; } = "";
    public string? ProcessPath { get; set; }
    public SignatureInfo Signature { get; set; } = SignatureInfo.Unknown;

    public string State
    {
        get => _state;
        set => SetField(ref _state, value);
    }

    public string? RemoteHost
    {
        get => _remoteHost;
        set => SetField(ref _remoteHost, value);
    }

    public string Local => $"{FormatIp(LocalAddress)}:{LocalPort}";
    public string Remote => RemoteAddress is null ? "" : $"{FormatIp(RemoteAddress)}:{RemotePort}";
    public string ScopeLabel => Scope.ToString();
    public string SignatureLabel => Signature.StatusLabel;
    public string? Publisher => Signature.Publisher;

    /// <summary>Chave estável da conexão, usada para atualizar a lista sem recriá-la.</summary>
    public string Key => $"{Protocol}|{Local}|{Remote}|{Pid}";

    public override string DisplayName => $"{ProcessName} ({Pid}) {Protocol} {Local} → {Remote}";

    public override string SearchText =>
        Join(Protocol, Local, Remote, RemoteHost, State, Pid, ProcessName, ProcessPath, Publisher, ScopeLabel, RiskText);

    private static string FormatIp(IPAddress ip) =>
        ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{ip}]" : ip.ToString();
}

public sealed class ProcessInfo : InspectionItem
{
    public required int Pid { get; init; }
    public required string Name { get; init; }
    public int ParentPid { get; init; }
    public string ParentName { get; set; } = "";
    public string? Path { get; init; }
    public string? CommandLine { get; init; }
    public string? User { get; init; }
    public DateTime? StartTime { get; init; }
    public SignatureInfo Signature { get; set; } = SignatureInfo.Unknown;
    public int Connections { get; set; }
    public int ExternalConnections { get; set; }

    public string SignatureLabel => Signature.StatusLabel;
    public string? Publisher => Signature.Publisher;

    public override string DisplayName => $"{Name} ({Pid})";

    public override string SearchText =>
        Join(Pid, Name, ParentPid, ParentName, Path, CommandLine, User, Publisher, RiskText);
}

public sealed class SessionInfo : InspectionItem
{
    public required string Type { get; init; }
    public string? Id { get; init; }
    public required string User { get; init; }
    public string State { get; init; } = "";
    public string? Station { get; init; }
    public string? ClientName { get; init; }
    public string? ClientAddress { get; init; }
    public DateTime? LogonTime { get; init; }
    public TimeSpan? Idle { get; init; }

    public string IdleLabel => Idle is { } t
        ? (t.TotalDays >= 1 ? $"{(int)t.TotalDays}d {t.Hours}h" : $"{t.Hours:00}:{t.Minutes:00}")
        : "";

    public override string DisplayName => $"{Type} {User} {ClientAddress}".Trim();

    public override string SearchText =>
        Join(Type, Id, User, State, Station, ClientName, ClientAddress, RiskText);
}

public sealed class UserAccountInfo : InspectionItem
{
    public required string Name { get; init; }
    public string? FullName { get; init; }
    public string? Description { get; init; }
    public bool Enabled { get; init; }
    public bool IsAdmin { get; set; }
    public DateTime? LastLogon { get; init; }
    public DateTime? PasswordLastSet { get; init; }
    public bool PasswordNeverExpires { get; init; }
    public bool PasswordNotRequired { get; init; }
    public bool LockedOut { get; init; }
    public required string Sid { get; init; }

    public string EnabledLabel => Enabled ? "Sim" : "Não";
    public string AdminLabel => IsAdmin ? "Sim" : "";

    public override string DisplayName => Name;

    public override string SearchText => Join(Name, FullName, Description, Sid, RiskText);
}

public sealed class GroupMemberInfo : InspectionItem
{
    public required string Name { get; init; }
    public required string Type { get; init; }
    public required string Sid { get; init; }
    public bool IsLocal { get; init; }
    public bool? Enabled { get; set; }

    public string LocalLabel => IsLocal ? "Local" : "Domínio/Microsoft";
    public string EnabledLabel => Enabled switch { true => "Sim", false => "Não", _ => "" };

    public override string DisplayName => Name;

    public override string SearchText => Join(Name, Type, Sid, LocalLabel, RiskText);
}

public sealed class ScheduledTaskInfo : InspectionItem
{
    public required string Name { get; init; }
    public required string Path { get; init; }
    public string State { get; init; } = "";
    public bool Enabled { get; init; }
    public string? Author { get; init; }
    public string? RunAs { get; init; }
    public bool HighestPrivileges { get; init; }
    public string Actions { get; init; } = "";
    public string Triggers { get; init; } = "";
    public DateTime? LastRun { get; init; }
    public DateTime? NextRun { get; init; }
    public string? LastResult { get; init; }
    public string? ExecutablePath { get; init; }
    public SignatureInfo Signature { get; set; } = SignatureInfo.Unknown;
    public bool IsMicrosoftFolder => Path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);

    public string SignatureLabel => Signature.StatusLabel;
    public string? Publisher => Signature.Publisher;
    public string PrivilegeLabel => HighestPrivileges ? "Elevado" : "";

    public override string DisplayName => Path;

    public override string SearchText =>
        Join(Name, Path, State, Author, RunAs, Actions, Triggers, Publisher, RiskText);
}

public sealed class StartupEntryInfo : InspectionItem
{
    public required string Location { get; init; }
    public required string Name { get; init; }
    public required string Command { get; init; }
    public string? ExecutablePath { get; init; }
    /// <summary>Chave completa do registro de onde veio (ex.: HKEY_CURRENT_USER\Software\...\Run).</summary>
    public string? RegistryKey { get; init; }
    /// <summary>Arquivo na pasta Inicializar de onde veio.</summary>
    public string? FilePath { get; init; }
    public SignatureInfo Signature { get; set; } = SignatureInfo.Unknown;

    public string SignatureLabel => Signature.StatusLabel;
    public string? Publisher => Signature.Publisher;

    public override string DisplayName => $"{Name} ({Location})";

    public override string SearchText => Join(Location, Name, Command, Publisher, RiskText);
}

public sealed class ServiceInfo : InspectionItem
{
    public required string Name { get; init; }
    public string? DisplayNameText { get; init; }
    public string? State { get; init; }
    public string? StartMode { get; init; }
    public string? PathName { get; init; }
    public string? Account { get; init; }
    public int Pid { get; init; }
    public string? Description { get; init; }
    public string? ExecutablePath { get; init; }
    public SignatureInfo Signature { get; set; } = SignatureInfo.Unknown;

    public string SignatureLabel => Signature.StatusLabel;
    public string? Publisher => Signature.Publisher;

    public bool IsMicrosoft =>
        Signature.Publisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true;

    public override string DisplayName => $"{Name} ({DisplayNameText})";

    public override string SearchText =>
        Join(Name, DisplayNameText, State, StartMode, PathName, Account, Publisher, RiskText);
}

public sealed class ShareInfo : InspectionItem
{
    public required string Name { get; init; }
    public string? Path { get; init; }
    public string? Description { get; init; }
    public required string Type { get; init; }
    public bool IsAdministrative { get; init; }

    public override string DisplayName => Name;

    public override string SearchText => Join(Name, Path, Description, Type, RiskText);
}
