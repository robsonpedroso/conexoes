using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Windows.Controls;
using System.Windows.Data;
using Conexoes.App.ViewModels;
using Conexoes.Core.Models;
using Conexoes.Core.Reporting;

namespace Conexoes.App.Services;

/// <summary>Converte um DataGrid (colunas visíveis + linhas filtradas/ordenadas) em ReportTable.</summary>
public static class GridExporter
{
    public static ReportTable ToTable(DataGrid grid, string title)
    {
        var columns = grid.Columns
            .OfType<DataGridBoundColumn>()
            .Where(c => c.Visibility == System.Windows.Visibility.Visible && c.Binding is Binding)
            .OrderBy(c => c.DisplayIndex)
            .Select(c => (Header: c.Header?.ToString() ?? "", Binding: (Binding)c.Binding))
            .ToList();

        var source = (IEnumerable?)grid.ItemsSource ?? grid.Items;
        var rows = new List<IReadOnlyList<string>>();
        var risks = new List<RiskLevel>();
        foreach (var item in source)
        {
            if (item is null) continue;
            rows.Add(columns.Select(c => Format(GetValue(item, c.Binding.Path.Path), c.Binding.StringFormat)).ToList());
            risks.Add(item switch
            {
                InspectionItem i => i.Risk,
                Alert a => a.Level,
                ExternalProgram p => p.Risk,
                _ => RiskLevel.Nenhum,
            });
        }
        return new ReportTable(title, columns.Select(c => c.Header).ToList(), rows, risks);
    }

    /// <summary>Pares "coluna: valor" de uma linha, para o diálogo de detalhes e a cópia.</summary>
    public static IEnumerable<(string Header, string Value)> RowValues(DataGrid grid, object item) =>
        grid.Columns.OfType<DataGridBoundColumn>()
            .Where(c => c.Binding is Binding)
            .OrderBy(c => c.DisplayIndex)
            .Select(c => (c.Header?.ToString() ?? "", Format(GetValue(item, ((Binding)c.Binding).Path.Path), ((Binding)c.Binding).StringFormat)));

    public static object? GetValue(object item, string path)
    {
        object? current = item;
        foreach (var part in path.Split('.'))
        {
            if (current is null) return null;
            current = current.GetType().GetProperty(part, BindingFlags.Public | BindingFlags.Instance)?.GetValue(current);
        }
        return current;
    }

    private static string Format(object? value, string? format) => value switch
    {
        null => "",
        bool b => b ? "Sim" : "Não",
        DateTime d => d.ToString(format is { Length: > 0 } ? StripBraces(format) : "dd/MM/yyyy HH:mm:ss", CultureInfo.CurrentCulture),
        IFormattable f when format is { Length: > 0 } => string.Format(CultureInfo.CurrentCulture, format, f),
        _ => value.ToString() ?? "",
    };

    // StringFormat do WPF pode vir como "{0:dd/MM/yyyy}"
    private static string StripBraces(string format) =>
        format.StartsWith("{0:") && format.EndsWith('}') ? format[3..^1] : format;
}
