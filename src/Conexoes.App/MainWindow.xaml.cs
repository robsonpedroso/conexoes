using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Conexoes.App.Services;
using Conexoes.App.ViewModels;
using Conexoes.Core.Models;
using Conexoes.Core.Reporting;
using Microsoft.Win32;

namespace Conexoes.App;

public partial class MainWindow : Window
{
    public MainWindow() => InitializeComponent();

    private MainViewModel Vm => (MainViewModel)DataContext;

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        await Vm.AnalyzeAllAsync();

        // Modo automático: Conexoes.App.exe --relatorio C:\caminho\relatorio.html
        var args = Environment.GetCommandLineArgs();
        var idx = Array.FindIndex(args, a => a.Equals("--relatorio", StringComparison.OrdinalIgnoreCase));
        if (idx >= 0 && idx + 1 < args.Length)
        {
            Vm.Connections.OnlyExternal = false; // relatório automático leva todas as conexões
            WriteHtmlReport(Path.GetFullPath(args[idx + 1]));
            Close();
        }
    }

    // ---------- exportação ----------

    private DataGrid? CurrentGrid() =>
        Tabs.SelectedItem is TabItem { Content: DependencyObject content } ? FindGrid(content) : null;

    private static DataGrid? FindGrid(DependencyObject root)
    {
        if (root is DataGrid g) return g;
        foreach (var child in LogicalTreeHelper.GetChildren(root).OfType<DependencyObject>())
            if (FindGrid(child) is { } found) return found;
        return null;
    }

    private void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        var grid = CurrentGrid();
        if (grid is null) return;
        var title = grid.Tag?.ToString() ?? "dados";
        var dialog = new SaveFileDialog
        {
            Filter = "CSV (separado por ponto e vírgula)|*.csv",
            FileName = $"{Sanitize(title)}_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmm}.csv",
        };
        if (dialog.ShowDialog(this) != true) return;
        File.WriteAllText(dialog.FileName, Exporters.ToCsv(GridExporter.ToTable(grid, title)), new UTF8Encoding(true));
    }

    private void ExportHtml_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Filter = "Página HTML|*.html",
            FileName = $"relatorio_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmm}.html",
        };
        if (dialog.ShowDialog(this) != true) return;
        WriteHtmlReport(dialog.FileName);

        if (MessageBox.Show(this, "Relatório salvo. Abrir agora?", "Relatório", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
            Process.Start(new ProcessStartInfo(dialog.FileName) { UseShellExecute = true });
    }

    private void WriteHtmlReport(string path)
    {
        // Ordem do relatório: resumo primeiro, depois cada aba (com os filtros atuais de cada uma).
        DataGrid[] grids =
        [
            GridAlerts, GridExternalPrograms, GridConnections, GridProcesses, GridSessions, GridUsers,
            GridAdmins, GridTasks, GridStartup, GridServices, GridShares,
        ];
        var tables = grids.Select(g => GridExporter.ToTable(g, g.Tag?.ToString() ?? "")).ToList();
        File.WriteAllText(path, Exporters.ToHtml($"Relatório de segurança: {Environment.MachineName}", tables), new UTF8Encoding(false));
    }

    private static string Sanitize(string name) =>
        string.Concat(name.Select(c => Path.GetInvalidFileNameChars().Contains(c) || c == ' ' ? '_' : c));

    // ---------- menu de contexto ----------

    private static DataGrid? GridFromMenu(object sender) =>
        sender is MenuItem { Parent: ContextMenu { PlacementTarget: DataGrid g } } ? g : null;

    private static string? PathOf(object item)
    {
        foreach (var prop in new[] { "ProcessPath", "ExecutablePath", "Path" })
            if (GridExporter.GetValue(item, prop) is string s && File.Exists(s)) return s;
        return null;
    }

    private static int? PidOf(object item) => GridExporter.GetValue(item, "Pid") as int?;

    private void ShowDetails(DataGrid grid, object item)
    {
        var text = string.Join(Environment.NewLine,
            GridExporter.RowValues(grid, item).Where(v => v.Value.Length > 0).Select(v => $"{v.Header}: {v.Value}"));
        MessageBox.Show(this, text, "Detalhes", MessageBoxButton.OK, MessageBoxImage.None);
    }

    private void Details_Click(object sender, RoutedEventArgs e)
    {
        if (GridFromMenu(sender) is { SelectedItem: { } item } grid) ShowDetails(grid, item);
    }

    private void Grid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        // só quando o clique foi numa linha (não no cabeçalho)
        var dep = e.OriginalSource as DependencyObject;
        while (dep is not null and not DataGridRow) dep = VisualTreeHelper.GetParent(dep);
        if (dep is DataGridRow row && sender is DataGrid grid) ShowDetails(grid, row.Item);
    }

    private void OpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (GridFromMenu(sender)?.SelectedItem is not { } item) return;
        var path = PathOf(item);
        if (path is null)
        {
            MessageBox.Show(this, "Caminho do arquivo indisponível para este item.", "Abrir local", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        Process.Start("explorer.exe", $"/select,\"{path}\"");
    }

    private void CopyPath_Click(object sender, RoutedEventArgs e)
    {
        if (GridFromMenu(sender)?.SelectedItem is { } item && PathOf(item) is { } path) Clipboard.SetText(path);
    }

    private void CopyRows_Click(object sender, RoutedEventArgs e)
    {
        if (GridFromMenu(sender) is not { } grid || grid.SelectedItems.Count == 0) return;
        var sb = new StringBuilder();
        sb.AppendLine(string.Join('\t', GridExporter.RowValues(grid, grid.SelectedItems[0]!).Select(v => v.Header)));
        foreach (var item in grid.SelectedItems)
            sb.AppendLine(string.Join('\t', GridExporter.RowValues(grid, item).Select(v => v.Value)));
        Clipboard.SetText(sb.ToString());
    }

    private void OpenStartupLocation_Click(object sender, RoutedEventArgs e)
    {
        if (GridFromMenu(sender)?.SelectedItem is not StartupEntryInfo entry) return;
        if (entry.RegistryKey is { } key)
        {
            if (!LocationOpener.OpenRegistryKey(key))
                MessageBox.Show(this, "O Editor do Registro não foi aberto (permissão negada ou cancelada).", "Abrir local", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else if (entry.FilePath is { } file)
            LocationOpener.OpenFolderSelecting(file);
        else
            MessageBox.Show(this, "Local indisponível para este item.", "Abrir local", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void OpenTaskScheduler_Click(object sender, RoutedEventArgs e)
    {
        if (GridFromMenu(sender)?.SelectedItem is not ScheduledTaskInfo task) return;
        Clipboard.SetText(task.Path);
        if (!LocationOpener.OpenTaskScheduler())
            MessageBox.Show(this, $"Não foi possível abrir o Agendador de Tarefas.\nCaminho da tarefa (copiado): {task.Path}", "Agendador de Tarefas", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private DataGrid? GridForCategory(string category) => category switch
    {
        "Conexões" => GridConnections,
        "Processos" => GridProcesses,
        "Sessões" => GridSessions,
        "Usuários" => GridUsers,
        "Administradores" => GridAdmins,
        "Tarefas" => GridTasks,
        "Inicialização" => GridStartup,
        "Serviços" => GridServices,
        "Compartilhamentos" => GridShares,
        _ => null,
    };

    private void GoToTab_Click(object sender, RoutedEventArgs e)
    {
        if (GridFromMenu(sender)?.SelectedItem is not Alert alert || GridForCategory(alert.Category) is not { } grid) return;

        DependencyObject? dep = grid;
        while (dep is not null and not TabItem) dep = LogicalTreeHelper.GetParent(dep);
        if (dep is not TabItem tab) return;
        Tabs.SelectedItem = tab;

        // Seleciona a linha de origem depois que a aba for exibida. A lista pode ter sido
        // recriada desde a análise (ex.: conexões), então cai para comparação pelo nome exibido.
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () =>
        {
            var target = alert.Source is { } src && grid.Items.Contains(src)
                ? src
                : grid.Items.OfType<InspectionItem>().FirstOrDefault(i => i.DisplayName == alert.Item);
            if (target is null) return;
            grid.SelectedItem = target;
            grid.ScrollIntoView(target);
            grid.Focus();
        });
    }

    private async void KillProcess_Click(object sender, RoutedEventArgs e)
    {
        if (GridFromMenu(sender)?.SelectedItem is not { } item || PidOf(item) is not { } pid || pid <= 4)
        {
            MessageBox.Show(this, "Selecione uma linha com um processo (PID) válido.", "Finalizar processo", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string name;
        try
        {
            using var p = Process.GetProcessById(pid);
            name = p.ProcessName;
        }
        catch (ArgumentException)
        {
            MessageBox.Show(this, $"O processo {pid} não está mais em execução.", "Finalizar processo", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var answer = MessageBox.Show(this,
            $"Finalizar o processo \"{name}\" (PID {pid})?\n\nDados não salvos nesse programa serão perdidos. Finalizar processos do sistema pode travar o Windows.",
            "Confirmar", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        try
        {
            using var p = Process.GetProcessById(pid);
            p.Kill();
            p.WaitForExit(3000);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Não foi possível finalizar: {ex.Message}", "Finalizar processo", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        await Vm.Connections.RefreshAsync();
        await Vm.Processes.RefreshAsync();
    }
}
