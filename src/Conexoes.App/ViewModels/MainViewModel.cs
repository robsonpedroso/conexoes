using System.Collections.ObjectModel;
using System.Security.Principal;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Conexoes.Core.Collectors;
using Conexoes.Core.Models;
using Conexoes.Core.Reporting;

namespace Conexoes.App.ViewModels;

/// <summary>Linha do resumo: um programa e suas conexões externas agregadas.</summary>
public sealed record ExternalProgram(
    string ProcessName, string Pids, string? Path, int Connections, int RemoteAddresses,
    string RemoteHosts, string Signature, string? Publisher, RiskLevel Risk, string RiskLabel);

public partial class MainViewModel : ObservableObject
{
    private List<GroupMemberInfo>? _lastAdmins;

    public MainViewModel()
    {
        Connections = new ConnectionsViewModel();
        Processes = new ListTabViewModel<ProcessInfo>(CollectProcesses);
        Sessions = new ListTabViewModel<SessionInfo>(SessionCollector.Collect);
        Admins = new ListTabViewModel<GroupMemberInfo>(() => _lastAdmins = AccountCollector.CollectAdministrators());
        Users = new ListTabViewModel<UserAccountInfo>(() => AccountCollector.CollectUsers(_lastAdmins));
        Tasks = new MicrosoftFilteredTabViewModel<ScheduledTaskInfo>(ScheduledTaskCollector.Collect, t => t.IsMicrosoftFolder);
        Startup = new ListTabViewModel<StartupEntryInfo>(StartupCollector.Collect);
        Services = new MicrosoftFilteredTabViewModel<ServiceInfo>(ServiceAndShareCollector.CollectServices, s => s.IsMicrosoft);
        Shares = new ListTabViewModel<ShareInfo>(ServiceAndShareCollector.CollectShares);

        foreach (var tab in new IInspectionTab[] { Connections, Processes, Sessions, Admins, Users, Tasks, Startup, Services, Shares })
            tab.Updated += BuildSummary;

        using var identity = WindowsIdentity.GetCurrent();
        IsAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        CurrentUser = identity.Name;
    }

    public ConnectionsViewModel Connections { get; }
    public ListTabViewModel<ProcessInfo> Processes { get; }
    public ListTabViewModel<SessionInfo> Sessions { get; }
    public ListTabViewModel<UserAccountInfo> Users { get; }
    public ListTabViewModel<GroupMemberInfo> Admins { get; }
    public MicrosoftFilteredTabViewModel<ScheduledTaskInfo> Tasks { get; }
    public ListTabViewModel<StartupEntryInfo> Startup { get; }
    public MicrosoftFilteredTabViewModel<ServiceInfo> Services { get; }
    public ListTabViewModel<ShareInfo> Shares { get; }

    public bool IsAdmin { get; }
    public string CurrentUser { get; }
    public string MachineName => Environment.MachineName;

    public ObservableCollection<Alert> Alerts { get; } = [];
    public ObservableCollection<ExternalProgram> ExternalPrograms { get; } = [];

    [ObservableProperty] private bool _isAnalyzing;
    [ObservableProperty] private int _externalConnectionCount;
    [ObservableProperty] private int _externalProgramCount;
    [ObservableProperty] private int _sessionCount;
    [ObservableProperty] private int _activeAdminCount;
    [ObservableProperty] private int _nonMicrosoftTaskCount;
    [ObservableProperty] private int _startupCount;
    [ObservableProperty] private int _highAlerts;
    [ObservableProperty] private int _mediumAlerts;
    [ObservableProperty] private int _lowAlerts;
    [ObservableProperty] private string _lastAnalysis = "";

    [RelayCommand]
    public async Task AnalyzeAllAsync()
    {
        if (IsAnalyzing) return;
        IsAnalyzing = true;
        try
        {
            // Conexões primeiro (processos usam a contagem); administradores antes de usuários.
            await Connections.RefreshAsync();
            await Admins.RefreshAsync();
            await Task.WhenAll(
                Processes.RefreshAsync(), Sessions.RefreshAsync(), Users.RefreshAsync(), Tasks.RefreshAsync(),
                Startup.RefreshAsync(), Services.RefreshAsync(), Shares.RefreshAsync());
            LastAnalysis = $"Última análise completa: {DateTime.Now:dd/MM/yyyy HH:mm:ss}";
        }
        finally
        {
            IsAnalyzing = false;
            BuildSummary();
        }
    }

    private List<ProcessInfo> CollectProcesses()
    {
        var list = ProcessCollector.Collect();
        var snapshot = Connections.LastSnapshot;
        var byPid = snapshot.GroupBy(c => c.Pid).ToDictionary(g => g.Key, g => g.ToList());
        foreach (var p in list)
        {
            if (!byPid.TryGetValue(p.Pid, out var conns)) continue;
            p.Connections = conns.Count;
            p.ExternalConnections = conns.Count(c => c.Scope == IpScope.Externo);
        }
        return list;
    }

    private void BuildSummary()
    {
        if (IsAnalyzing) return; // evita recalcular a cada aba durante a análise completa

        // PID 0 só aparece em conexões já encerradas (TIME_WAIT), sem programa dono.
        var external = Connections.LastSnapshot.Where(c => c.Scope == IpScope.Externo && c.Pid != 0).ToList();
        ExternalConnectionCount = external.Count;

        ExternalPrograms.Clear();
        foreach (var g in external.GroupBy(c => c.ProcessPath ?? c.ProcessName, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(g => g.Max(c => c.Risk)).ThenByDescending(g => g.Count()))
        {
            var first = g.First();
            var risk = g.Max(c => c.Risk);
            var hosts = g.Select(c => c.RemoteHost).Where(h => !string.IsNullOrEmpty(h)).Distinct().Take(5);
            ExternalPrograms.Add(new ExternalProgram(
                first.ProcessName,
                string.Join(", ", g.Select(c => c.Pid).Distinct().OrderBy(p => p)),
                first.ProcessPath,
                g.Count(),
                g.Select(c => c.RemoteAddress).Distinct().Count(),
                string.Join(", ", hosts),
                first.SignatureLabel,
                first.Publisher,
                risk,
                g.OrderByDescending(c => c.Risk).First().RiskLabel));
        }
        ExternalProgramCount = ExternalPrograms.Count;

        SessionCount = Sessions.Items.Count;
        ActiveAdminCount = Admins.Items.Count(a => a.Enabled != false);
        NonMicrosoftTaskCount = Tasks.Items.Count(t => !t.IsMicrosoftFolder);
        StartupCount = Startup.Items.Count;

        var alerts = new List<Alert>();
        alerts.AddRange(AlertBuilder.FromItems("Conexões", Connections.LastSnapshot.DistinctBy(c => (c.ProcessPath, c.Risk, c.RiskText))));
        alerts.AddRange(AlertBuilder.FromItems("Processos", Processes.Items));
        alerts.AddRange(AlertBuilder.FromItems("Sessões", Sessions.Items));
        alerts.AddRange(AlertBuilder.FromItems("Usuários", Users.Items));
        alerts.AddRange(AlertBuilder.FromItems("Administradores", Admins.Items));
        alerts.AddRange(AlertBuilder.FromItems("Tarefas", Tasks.Items));
        alerts.AddRange(AlertBuilder.FromItems("Inicialização", Startup.Items));
        alerts.AddRange(AlertBuilder.FromItems("Serviços", Services.Items));
        alerts.AddRange(AlertBuilder.FromItems("Compartilhamentos", Shares.Items));
        alerts.AddRange(AlertBuilder.Global(Admins.Items));

        Alerts.Clear();
        foreach (var a in AlertBuilder.Sort(alerts)) Alerts.Add(a);
        HighAlerts = alerts.Count(a => a.Level == RiskLevel.Alto);
        MediumAlerts = alerts.Count(a => a.Level == RiskLevel.Medio);
        LowAlerts = alerts.Count(a => a.Level == RiskLevel.Baixo);
    }
}
