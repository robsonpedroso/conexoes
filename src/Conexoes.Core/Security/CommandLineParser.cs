namespace Conexoes.Core.Security;

public static class CommandLineParser
{
    private static readonly string[] Extensions = [".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll", ".scr", ".hta"];

    /// <summary>
    /// Extrai o caminho do executável de uma linha de comando como
    /// <c>"C:\Program Files\App\app.exe" /arg</c> ou <c>C:\Windows\system32\svchost.exe -k netsvcs</c>.
    /// Expande variáveis de ambiente e procura no PATH quando só o nome é informado.
    /// </summary>
    public static string? ExtractExecutable(string? commandLine, bool resolve = true)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var cmd = Environment.ExpandEnvironmentVariables(commandLine.Trim());

        string candidate;
        if (cmd.StartsWith('"'))
        {
            var end = cmd.IndexOf('"', 1);
            candidate = end > 1 ? cmd[1..end] : cmd.Trim('"');
        }
        else
        {
            candidate = cmd;
            var lower = cmd.ToLowerInvariant();
            var best = -1;
            foreach (var ext in Extensions)
            {
                var idx = lower.IndexOf(ext, StringComparison.Ordinal);
                while (idx >= 0)
                {
                    var after = idx + ext.Length;
                    if (after == lower.Length || lower[after] is ' ' or ',' or '\t')
                    {
                        if (best < 0 || after < best) best = after;
                        break;
                    }
                    idx = lower.IndexOf(ext, idx + 1, StringComparison.Ordinal);
                }
            }
            if (best > 0) candidate = cmd[..best];
            else
            {
                var space = cmd.IndexOf(' ');
                if (space > 0) candidate = cmd[..space];
            }
        }

        candidate = candidate.Trim();
        if (candidate.StartsWith(@"\??\", StringComparison.Ordinal)) candidate = candidate[4..];
        if (candidate.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            candidate = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), candidate[12..]);
        if (candidate.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase))
            candidate = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), candidate);

        if (!resolve) return candidate;
        return Resolve(candidate);
    }

    private static string Resolve(string candidate)
    {
        try
        {
            if (Path.IsPathFullyQualified(candidate))
            {
                if (File.Exists(candidate)) return candidate;
                if (!Path.HasExtension(candidate) && File.Exists(candidate + ".exe")) return candidate + ".exe";
                return candidate;
            }

            var names = Path.HasExtension(candidate) ? [candidate] : new[] { candidate + ".exe", candidate };
            var dirs = new List<string> { Environment.SystemDirectory, Environment.GetFolderPath(Environment.SpecialFolder.Windows) };
            dirs.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries));
            foreach (var dir in dirs)
                foreach (var name in names)
                {
                    var full = Path.Combine(dir.Trim(), name);
                    if (File.Exists(full)) return full;
                }
        }
        catch
        {
            // caminho inválido: devolve como veio
        }
        return candidate;
    }

    /// <summary>Caminho de serviço com espaços e sem aspas (vulnerabilidade "unquoted service path").</summary>
    public static bool IsUnquotedPathWithSpaces(string? pathName)
    {
        if (string.IsNullOrWhiteSpace(pathName)) return false;
        var p = pathName.Trim();
        if (p.StartsWith('"')) return false;
        var exe = ExtractExecutable(p, resolve: false);
        return exe is not null && exe.Contains(' ') && Path.IsPathFullyQualified(exe);
    }
}
