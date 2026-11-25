using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace Conexoes.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnUnhandled;
#if DEBUG
        // Erros de binding vão para %TEMP%\conexoes-binding.log (ajuda a depurar a interface).
        var log = Path.Combine(Path.GetTempPath(), "conexoes-binding.log");
        PresentationTraceSources.DataBindingSource.Listeners.Add(new TextWriterTraceListener(log));
        PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Error;
        Trace.AutoFlush = true;
#endif
        base.OnStartup(e);
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(e.Exception.Message, "Erro inesperado", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
