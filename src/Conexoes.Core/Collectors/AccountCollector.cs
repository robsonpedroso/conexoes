using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Conexoes.Core.Models;
using Conexoes.Core.Security;

namespace Conexoes.Core.Collectors;

/// <summary>Equivalente a <c>net user</c> e <c>net localgroup Administradores</c>.</summary>
public static class AccountCollector
{
    public const string AdministratorsSid = "S-1-5-32-544";

    public static List<UserAccountInfo> CollectUsers(IReadOnlyCollection<GroupMemberInfo>? admins = null)
    {
        admins ??= CollectAdministrators();
        var adminSids = admins.Select(a => a.Sid).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var list = new List<UserAccountInfo>();
        using var ctx = new PrincipalContext(ContextType.Machine);
        using var searcher = new PrincipalSearcher(new UserPrincipal(ctx));
        foreach (var result in searcher.FindAll())
        {
            if (result is not UserPrincipal u) continue;
            using (u)
            {
                try
                {
                    var sid = u.Sid?.Value ?? "";
                    var info = new UserAccountInfo
                    {
                        Name = u.SamAccountName ?? u.Name ?? "?",
                        FullName = u.DisplayName,
                        Description = u.Description,
                        Enabled = u.Enabled ?? false,
                        LastLogon = u.LastLogon?.ToLocalTime(),
                        PasswordLastSet = u.LastPasswordSet?.ToLocalTime(),
                        PasswordNeverExpires = u.PasswordNeverExpires,
                        PasswordNotRequired = u.PasswordNotRequired,
                        LockedOut = SafeIsLocked(u),
                        Sid = sid,
                        IsAdmin = adminSids.Contains(sid),
                    };
                    info.AddRisks(RiskRules.ForUser(info));
                    list.Add(info);
                }
                catch (PrincipalException)
                {
                    // conta inconsistente: ignora
                }
            }
        }

        // marca estado ativo/inativo dos administradores locais
        var bySid = list.ToDictionary(u => u.Sid, StringComparer.OrdinalIgnoreCase);
        foreach (var a in admins)
            if (bySid.TryGetValue(a.Sid, out var u)) a.Enabled = u.Enabled;

        return list;
    }

    private static bool SafeIsLocked(UserPrincipal u)
    {
        try { return u.IsAccountLockedOut(); } catch { return false; }
    }

    /// <summary>
    /// Membros do grupo Administradores pelo SID S-1-5-32-544 (funciona em qualquer idioma).
    /// Usa NetLocalGroupGetMembers, que também lida com contas Microsoft/Entra ID e SIDs órfãos.
    /// </summary>
    public static List<GroupMemberInfo> CollectAdministrators()
    {
        var groupName = new SecurityIdentifier(AdministratorsSid).Translate(typeof(NTAccount)).Value;
        groupName = groupName[(groupName.IndexOf('\\') + 1)..];

        var list = new List<GroupMemberInfo>();
        IntPtr resume = IntPtr.Zero;
        uint status;
        do
        {
            status = NetLocalGroupGetMembers(null, groupName, 2, out var buffer, -1, out var read, out _, ref resume);
            if (status != 0 && status != ERROR_MORE_DATA) throw new System.ComponentModel.Win32Exception((int)status);
            try
            {
                var size = Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_2>();
                for (var i = 0; i < read; i++)
                {
                    var m = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_2>(buffer + i * size);
                    var sid = new SecurityIdentifier(m.lgrmi2_sid).Value;
                    var name = m.lgrmi2_domainandname ?? sid;
                    var member = new GroupMemberInfo
                    {
                        Name = name,
                        Sid = sid,
                        Type = SidTypeName(m.lgrmi2_sidusage),
                        IsLocal = name.StartsWith(Environment.MachineName + "\\", StringComparison.OrdinalIgnoreCase),
                    };
                    if (m.lgrmi2_sidusage is SidTypeDeletedAccount or SidTypeUnknown)
                        member.AddRisk(RiskLevel.Medio, "SID órfão (conta excluída) no grupo Administradores");
                    if (sid.EndsWith("-501"))
                        member.AddRisk(RiskLevel.Alto, "Conta Convidado é administradora");
                    list.Add(member);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
        } while (status == ERROR_MORE_DATA);

        return list;
    }

    private const uint ERROR_MORE_DATA = 234;
    private const int SidTypeUser = 1;
    private const int SidTypeGroup = 2;
    private const int SidTypeWellKnownGroup = 5;
    private const int SidTypeDeletedAccount = 6;
    private const int SidTypeUnknown = 8;

    private static string SidTypeName(int usage) => usage switch
    {
        SidTypeUser => "Usuário",
        SidTypeGroup => "Grupo",
        4 => "Alias",
        SidTypeWellKnownGroup => "Grupo interno",
        SidTypeDeletedAccount => "Conta excluída",
        SidTypeUnknown => "Desconhecido",
        _ => usage.ToString(),
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LOCALGROUP_MEMBERS_INFO_2
    {
        public IntPtr lgrmi2_sid;
        public int lgrmi2_sidusage;
        public string? lgrmi2_domainandname;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetLocalGroupGetMembers(string? server, string groupName, int level, out IntPtr buffer,
        int prefMaxLen, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr buffer);
}
