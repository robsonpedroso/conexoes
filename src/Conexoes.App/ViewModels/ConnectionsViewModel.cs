using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using Conexoes.Core.Collectors;
using Conexoes.Core.Models;
using Conexoes.Core.Net;

namespace Conexoes.App.ViewModels;

/// <summary>
/// Aba de conexões: atualização automática que preserva ordenação e seleção (atualiza a lista
/// por diferença em vez de recriá-la) e DNS reverso assíncrono para IPs externos.
/// </summary>
public partial class ConnectionsViewModel : ListTabViewModel<ConnectionInfo>
{
    private readonly DispatcherTimer _timer = new();
    private readonly ReverseDnsCache _dns = new();

    public ConnectionsViewModel() : base(ConnectionCollector.Collect)
    {
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Interval = TimeSpan.FromSeconds(IntervalSeconds);
        _timer.Start();
    }

    public int[] Intervals { get; } = [2, 5, 10, 30, 60];

    /// <summary>Última coleta completa (sem filtro), usada para contar conexões por processo.</summary>
    public IReadOnlyList<ConnectionInfo> LastSnapshot { get; private set; } = [];

    [ObservableProperty] private bool _onlyExternal = true;
    [ObservableProperty] private bool _hideUdp;
    [ObservableProperty] private bool _onlyEstablished;
    [ObservableProperty] private bool _autoRefresh = true;
    [ObservableProperty] private int _intervalSeconds = 5;
    [ObservableProperty] private bool _resolveDns = true;

    partial void OnOnlyExternalChanged(bool value) => RefreshView();
    partial void OnHideUdpChanged(bool value) => RefreshView();
    partial void OnOnlyEstablishedChanged(bool value) => RefreshView();

    partial void OnAutoRefreshChanged(bool value)
    {
        if (value) _timer.Start(); else _timer.Stop();
    }

    partial void OnIntervalSecondsChanged(int value) => _timer.Interval = TimeSpan.FromSeconds(Math.Max(1, value));

    partial void OnResolveDnsChanged(bool value)
    {
        if (value) foreach (var c in Items) Resolve(c);
    }

    protected override bool ExtraFilter(ConnectionInfo c) =>
        (!OnlyExternal || c.Scope == IpScope.Externo || c.Risk > RiskLevel.Nenhum) &&
        (!HideUdp || !c.Protocol.StartsWith("UDP")) &&
        (!OnlyEstablished || c.State == "ESTABLISHED");

    protected override void Apply(List<ConnectionInfo> list)
    {
        LastSnapshot = list;
        var incoming = new Dictionary<string, ConnectionInfo>();
        foreach (var c in list) incoming.TryAdd(c.Key, c);

        // remove as que sumiram
        for (var i = Items.Count - 1; i >= 0; i--)
            if (!incoming.ContainsKey(Items[i].Key)) Items.RemoveAt(i);

        var existing = Items.ToDictionary(c => c.Key);
        foreach (var (key, c) in incoming)
        {
            if (existing.TryGetValue(key, out var old))
            {
                old.State = c.State;
            }
            else
            {
                Items.Add(c);
                Resolve(c);
            }
        }
        View.Refresh();
    }

    private void Resolve(ConnectionInfo c)
    {
        if (!ResolveDns || c.RemoteAddress is null || c.Scope != IpScope.Externo || c.RemoteHost is not null) return;
        if (_dns.TryGetCached(c.RemoteAddress, out var cached))
        {
            c.RemoteHost = cached;
            return;
        }
        var dispatcher = Dispatcher.CurrentDispatcher;
        _ = _dns.ResolveAsync(c.RemoteAddress).ContinueWith(t =>
        {
            if (t.IsCompletedSuccessfully) dispatcher.BeginInvoke(() => c.RemoteHost = t.Result);
        }, TaskScheduler.Default);
    }
}
