using System.Net;
using System.Text;
using Conexoes.Core.Models;

namespace Conexoes.Core.Reporting;

/// <summary>Uma tabela já convertida em texto: cabeçalhos + linhas.</summary>
public sealed record ReportTable(string Title, IReadOnlyList<string> Headers, IReadOnlyList<IReadOnlyList<string>> Rows,
    IReadOnlyList<RiskLevel>? RowRisk = null);

public static class Exporters
{
    public static string ToCsv(ReportTable table)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(';', table.Headers.Select(Csv)));
        foreach (var row in table.Rows)
            sb.AppendLine(string.Join(';', row.Select(Csv)));
        return sb.ToString();
    }

    private static string Csv(string? v)
    {
        v ??= "";
        // evita injeção de fórmula ao abrir no Excel
        if (v.Length > 0 && v[0] is '=' or '+' or '-' or '@') v = "'" + v;
        return v.Contains(';') || v.Contains('"') || v.Contains('\n') || v.Contains('\r')
            ? "\"" + v.Replace("\"", "\"\"") + "\""
            : v;
    }

    public static string ToHtml(string title, IEnumerable<ReportTable> tables)
    {
        Func<string?, string?> e = WebUtility.HtmlEncode;
        var sb = new StringBuilder();
        sb.Append($$"""
            <!doctype html>
            <html lang="pt-BR"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{{e(title)}}</title>
            <style>
              body { font-family: Segoe UI, system-ui, sans-serif; margin: 24px; color: #1b1b1b; }
              h1 { font-size: 22px; margin-bottom: 4px; } h2 { font-size: 17px; margin-top: 32px; }
              .meta { color: #555; font-size: 13px; }
              table { border-collapse: collapse; width: 100%; font-size: 12px; }
              th, td { border: 1px solid #ddd; padding: 4px 6px; text-align: left; vertical-align: top; word-break: break-word; }
              th { background: #f2f2f2; position: sticky; top: 0; }
              tr.r3 td { background: #fde2e2; } tr.r2 td { background: #fff1d6; } tr.r1 td { background: #fffbe6; }
              nav a { margin-right: 12px; font-size: 13px; }
            </style></head><body>
            <h1>{{e(title)}}</h1>
            <div class="meta">Computador: {{e(Environment.MachineName)}} · Gerado em {{DateTime.Now:dd/MM/yyyy HH:mm:ss}} · Usuário: {{e(Environment.UserDomainName)}}\{{e(Environment.UserName)}}</div>
            <nav>
            """);
        var list = tables.ToList();
        for (var i = 0; i < list.Count; i++)
            sb.Append($"<a href=\"#t{i}\">{e(list[i].Title)} ({list[i].Rows.Count})</a>");
        sb.Append("</nav>");

        for (var i = 0; i < list.Count; i++)
        {
            var t = list[i];
            sb.Append($"<h2 id=\"t{i}\">{e(t.Title)} ({t.Rows.Count})</h2><table><thead><tr>");
            foreach (var h in t.Headers) sb.Append($"<th>{e(h)}</th>");
            sb.Append("</tr></thead><tbody>");
            for (var r = 0; r < t.Rows.Count; r++)
            {
                var risk = t.RowRisk is not null && r < t.RowRisk.Count ? (int)t.RowRisk[r] : 0;
                sb.Append(risk > 0 ? $"<tr class=\"r{risk}\">" : "<tr>");
                foreach (var c in t.Rows[r]) sb.Append($"<td>{e(c)}</td>");
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table>");
        }
        sb.Append("</body></html>");
        return sb.ToString();
    }
}
