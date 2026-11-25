using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Conexoes.Core.Models;

namespace Conexoes.App.ViewModels;

public interface IInspectionTab
{
    event Action? Updated;
    Task RefreshAsync();
}

/// <summary>Aba genérica: coleta em segundo plano, busca de texto, filtro "só com risco" e status.</summary>
public partial class ListTabViewModel<T> : ObservableObject, IInspectionTab where T : InspectionItem
{
    private readonly Func<List<T>> _collector;

    public ListTabViewModel(Func<List<T>> collector)
    {
        _collector = collector;
        View = CollectionViewSource.GetDefaultView(Items);
        View.Filter = o => o is T item && Matches(item);
    }

    public ObservableCollection<T> Items { get; } = [];

    public ICollectionView View { get; }

    /// <summary>Disparado na thread da interface sempre que a lista é atualizada.</summary>
    public event Action? Updated;

    [ObservableProperty] private string _filterText = "";
    [ObservableProperty] private bool _onlyRisk;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _status = "Ainda não carregado";
    [ObservableProperty] private string? _error;

    partial void OnFilterTextChanged(string value) => RefreshView();
    partial void OnOnlyRiskChanged(bool value) => RefreshView();

    protected void RefreshView()
    {
        View.Refresh();
        UpdateStatus();
    }

    private bool Matches(T item) =>
        (!OnlyRisk || item.Risk > RiskLevel.Nenhum) &&
        (string.IsNullOrWhiteSpace(FilterText) || item.SearchText.Contains(FilterText.Trim(), StringComparison.OrdinalIgnoreCase)) &&
        ExtraFilter(item);

    protected virtual bool ExtraFilter(T item) => true;

    [RelayCommand]
    public async Task RefreshAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        Error = null;
        try
        {
            var list = await Task.Run(_collector);
            Apply(list);
            LastUpdated = DateTime.Now;
            UpdateStatus();
            Updated?.Invoke();
        }
        catch (Exception ex)
        {
            Error = $"Falha ao coletar: {ex.Message}";
            Status = "Erro";
        }
        finally
        {
            IsBusy = false;
        }
    }

    public DateTime? LastUpdated { get; private set; }

    protected virtual void Apply(List<T> list)
    {
        // Não usar View.DeferRefresh() aqui: alterar a coleção durante o adiamento lança exceção no WPF.
        Items.Clear();
        foreach (var item in list) Items.Add(item);
    }

    protected void UpdateStatus()
    {
        if (LastUpdated is null) return;
        var shown = View.Cast<object>().Count();
        var risky = Items.Count(i => i.Risk > RiskLevel.Nenhum);
        Status = $"{shown} de {Items.Count} itens · {risky} com alerta · atualizado às {LastUpdated:HH:mm:ss}";
    }
}

/// <summary>Abas com opção de ocultar itens da Microsoft (sempre mostrando os que têm alerta).</summary>
public partial class MicrosoftFilteredTabViewModel<T>(Func<List<T>> collector, Func<T, bool> isMicrosoft)
    : ListTabViewModel<T>(collector) where T : InspectionItem
{
    [ObservableProperty] private bool _hideMicrosoft = true;

    partial void OnHideMicrosoftChanged(bool value) => RefreshView();

    protected override bool ExtraFilter(T item) =>
        !HideMicrosoft || item.Risk > RiskLevel.Nenhum || !isMicrosoft(item);
}
