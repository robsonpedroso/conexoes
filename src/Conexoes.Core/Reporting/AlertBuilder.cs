using Conexoes.Core.Models;

namespace Conexoes.Core.Reporting;

public static class AlertBuilder
{
    public static List<Alert> FromItems(string category, IEnumerable<InspectionItem>? items)
    {
        if (items is null) return [];
        return items.Where(i => i.Risk > RiskLevel.Nenhum)
            .Select(i => new Alert(category, i.DisplayName, i.Risk, i.RiskText, i))
            .ToList();
    }

    /// <summary>Verificações que olham o conjunto, não um item isolado.</summary>
    public static List<Alert> Global(IReadOnlyCollection<GroupMemberInfo>? admins)
    {
        var alerts = new List<Alert>();
        if (admins is not null)
        {
            var active = admins.Count(a => a.Type == "Usuário" && a.Enabled != false);
            if (active > 2)
                alerts.Add(new Alert("Administradores", $"{active} contas", RiskLevel.Medio,
                    $"{active} contas de usuário ativas com privilégio de administrador; confira se todas são esperadas"));
        }
        return alerts;
    }

    public static IEnumerable<Alert> Sort(IEnumerable<Alert> alerts) =>
        alerts.OrderByDescending(a => a.Level).ThenBy(a => a.Category).ThenBy(a => a.Item);
}
