using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using Microsoft.Win32;

namespace Conexoes.App.Services;

/// <summary>Abre no Explorer ou no Regedit o local de onde um item foi lido.</summary>
public static class LocationOpener
{
    private const string RegeditApplet = @"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit";

    /// <summary>Abre a pasta do arquivo com ele selecionado (ou só a pasta, se o arquivo não existir mais).</summary>
    public static void OpenFolderSelecting(string file)
    {
        if (File.Exists(file))
            Process.Start("explorer.exe", $"/select,\"{file}\"");
        else if (Path.GetDirectoryName(file) is { } dir && Directory.Exists(dir))
            Process.Start("explorer.exe", $"\"{dir}\"");
    }

    /// <summary>
    /// Abre o Regedit posicionado na chave. O Regedit não aceita a chave por argumento: ele reabre na
    /// última chave visitada (valor LastKey), então gravamos esse valor antes de iniciá-lo.
    /// </summary>
    /// <returns>false se o usuário cancelou o UAC.</returns>
    public static bool OpenRegistryKey(string key)
    {
        using (var applet = Registry.CurrentUser.CreateSubKey(RegeditApplet))
        {
            applet.SetValue("LastKey", $@"{RootName(applet.GetValue("LastKey") as string)}\{key}", RegistryValueKind.String);
        }

        try
        {
            // -m: nova instância; sem isso uma janela já aberta só recebe foco e não navega.
            Process.Start(new ProcessStartInfo("regedit.exe", "-m") { UseShellExecute = true });
            return true;
        }
        catch (Win32Exception)
        {
            return false;
        }
    }

    /// <summary>Abre o Agendador de Tarefas (ele não aceita abrir direto numa tarefa).</summary>
    /// <returns>false se não foi possível abrir (ex.: UAC cancelado).</returns>
    public static bool OpenTaskScheduler()
    {
        try
        {
            Process.Start(new ProcessStartInfo("taskschd.msc") { UseShellExecute = true });
            return true;
        }
        catch (Win32Exception)
        {
            return false;
        }
    }

    /// <summary>Nome localizado da raiz da árvore ("Computador", "Computer"...).</summary>
    private static string RootName(string? lastKey)
    {
        var first = lastKey?.Split('\\', 2)[0];
        if (!string.IsNullOrEmpty(first) && !first.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase))
            return first;
        return CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "pt" ? "Computador" : "Computer";
    }
}
