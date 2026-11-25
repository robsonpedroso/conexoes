using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Conexoes.Core.Models;

public enum RiskLevel
{
    Nenhum = 0,
    Baixo = 1,
    Medio = 2,
    Alto = 3,
}

public enum SignatureStatus
{
    Desconhecido,
    Valida,
    NaoAssinado,
    /// <summary>Assinado, mas a cadeia termina numa raiz não confiável (ex.: certificado autoassinado).</summary>
    NaoConfiavel,
    /// <summary>Assinatura adulterada, revogada ou com hash divergente.</summary>
    Invalida,
}

/// <summary>Base para todas as linhas exibidas: carrega o nível de risco e os motivos.</summary>
public abstract class InspectionItem : INotifyPropertyChanged
{
    private readonly List<string> _reasons = [];

    public RiskLevel Risk { get; private set; }

    public IReadOnlyList<string> RiskReasons => _reasons;

    public string RiskText => string.Join("; ", _reasons);

    public string RiskLabel => Risk switch
    {
        RiskLevel.Alto => "Alto",
        RiskLevel.Medio => "Médio",
        RiskLevel.Baixo => "Baixo",
        _ => "",
    };

    /// <summary>Texto usado pela busca da interface.</summary>
    public abstract string SearchText { get; }

    /// <summary>Nome curto usado no resumo de alertas.</summary>
    public abstract string DisplayName { get; }

    public void AddRisk(RiskLevel level, string reason)
    {
        if (level == RiskLevel.Nenhum) return;
        if (!_reasons.Contains(reason)) _reasons.Add(reason);
        if (level > Risk) Risk = level;
        OnPropertyChanged(nameof(Risk));
        OnPropertyChanged(nameof(RiskText));
        OnPropertyChanged(nameof(RiskLabel));
    }

    public void AddRisks(IEnumerable<RiskFinding> findings)
    {
        foreach (var f in findings) AddRisk(f.Level, f.Reason);
    }

    public void ClearRisk()
    {
        _reasons.Clear();
        Risk = RiskLevel.Nenhum;
        OnPropertyChanged(nameof(Risk));
        OnPropertyChanged(nameof(RiskText));
        OnPropertyChanged(nameof(RiskLabel));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }

    protected static string Join(params object?[] parts) =>
        string.Join(' ', parts.Where(p => p is not null).Select(p => p!.ToString()));
}

public readonly record struct RiskFinding(RiskLevel Level, string Reason);

/// <param name="Source">Item que gerou o alerta (nulo para verificações globais).</param>
public sealed record Alert(string Category, string Item, RiskLevel Level, string Reason, InspectionItem? Source = null)
{
    public string LevelLabel => Level switch
    {
        RiskLevel.Alto => "Alto",
        RiskLevel.Medio => "Médio",
        RiskLevel.Baixo => "Baixo",
        _ => "",
    };
}

public sealed record SignatureInfo(SignatureStatus Status, string? Publisher)
{
    public static readonly SignatureInfo Unknown = new(SignatureStatus.Desconhecido, null);

    public string StatusLabel => Status switch
    {
        SignatureStatus.Valida => "Assinado",
        SignatureStatus.NaoAssinado => "Não assinado",
        SignatureStatus.NaoConfiavel => "Raiz não confiável",
        SignatureStatus.Invalida => "Assinatura inválida",
        _ => "?",
    };
}
