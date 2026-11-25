using System.Runtime.InteropServices;
using Conexoes.Core.Models;
using Conexoes.Core.Security;

namespace Conexoes.Core.Collectors;

/// <summary>Equivalente a <c>schtasks /query /v</c>, usando a API COM do Agendador de Tarefas.</summary>
public static class ScheduledTaskCollector
{
    private const int TASK_ENUM_HIDDEN = 1;
    private const int TASK_ACTION_EXEC = 0;
    private const int TASK_ACTION_COM_HANDLER = 5;
    private const int TASK_RUNLEVEL_HIGHEST = 1;

    public static List<ScheduledTaskInfo> Collect()
    {
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new InvalidOperationException("Agendador de Tarefas indisponível.");
        dynamic service = Activator.CreateInstance(type)!;
        try
        {
            service.Connect();
            var list = new List<ScheduledTaskInfo>();
            Walk(service.GetFolder("\\"), list);

            Parallel.ForEach(list, t =>
            {
                t.Signature = SignatureVerifier.Verify(t.ExecutablePath);
                t.AddRisks(RiskRules.ForExecutable(t.ExecutablePath, t.Signature));
                t.AddRisks(RiskRules.ForCommandLine(t.Actions));
                if (t.HighestPrivileges && RiskRules.ClassifyPath(t.ExecutablePath) != RiskRules.PathKind.Normal)
                    t.AddRisk(RiskLevel.Alto, "Tarefa com privilégio elevado executando de pasta do usuário");
            });
            return list;
        }
        finally
        {
            Marshal.ReleaseComObject(service);
        }
    }

    private static void Walk(dynamic folder, List<ScheduledTaskInfo> list)
    {
        try
        {
            foreach (dynamic task in folder.GetTasks(TASK_ENUM_HIDDEN))
            {
                try
                {
                    list.Add(Read(task));
                }
                catch (COMException) { }
                catch (Microsoft.CSharp.RuntimeBinder.RuntimeBinderException) { }
            }
            foreach (dynamic sub in folder.GetFolders(0))
                Walk(sub, list);
        }
        catch (UnauthorizedAccessException) { }
        catch (COMException) { }
    }

    private static ScheduledTaskInfo Read(dynamic task)
    {
        dynamic def = task.Definition;
        var actions = new List<string>();
        string? exe = null;
        foreach (dynamic a in def.Actions)
        {
            int actionType = a.Type;
            if (actionType == TASK_ACTION_EXEC)
            {
                string path = a.Path ?? "";
                string args = a.Arguments ?? "";
                actions.Add(string.IsNullOrEmpty(args) ? path : $"{path} {args}");
                exe ??= CommandLineParser.ExtractExecutable(path.StartsWith('"') ? path : $"\"{path.Trim('"')}\"");
            }
            else if (actionType == TASK_ACTION_COM_HANDLER)
            {
                actions.Add($"COM {a.ClassId}");
            }
            else
            {
                actions.Add($"Ação tipo {actionType}");
            }
        }

        var triggers = new List<string>();
        foreach (dynamic tr in def.Triggers)
        {
            int trType = tr.Type;
            bool trEnabled = tr.Enabled;
            triggers.Add(TriggerName(trType) + (trEnabled ? "" : " (desativado)"));
        }

        int state = task.State;
        int lastResult = task.LastTaskResult;
        string? runAs = null;
        int runLevel = 0;
        try
        {
            runAs = def.Principal.UserId;
            if (string.IsNullOrEmpty(runAs)) runAs = def.Principal.GroupId;
            runLevel = def.Principal.RunLevel;
        }
        catch (COMException) { }

        return new ScheduledTaskInfo
        {
            Name = task.Name,
            Path = task.Path,
            State = StateName(state),
            Enabled = task.Enabled,
            Author = def.RegistrationInfo.Author,
            RunAs = runAs,
            HighestPrivileges = runLevel == TASK_RUNLEVEL_HIGHEST,
            Actions = string.Join(" | ", actions),
            Triggers = string.Join(", ", triggers),
            LastRun = ValidDate((DateTime)task.LastRunTime),
            NextRun = ValidDate((DateTime)task.NextRunTime),
            LastResult = lastResult == 0 ? "OK" : $"0x{lastResult:X8}",
            ExecutablePath = exe,
        };
    }

    private static DateTime? ValidDate(DateTime d) => d.Year < 2000 ? null : d;

    private static string StateName(int s) => s switch
    {
        1 => "Desativada",
        2 => "Na fila",
        3 => "Pronta",
        4 => "Executando",
        _ => "Desconhecido",
    };

    private static string TriggerName(int t) => t switch
    {
        0 => "Evento",
        1 => "Uma vez",
        2 => "Diário",
        3 => "Semanal",
        4 => "Mensal",
        5 => "Mensal (dia da semana)",
        6 => "Ocioso",
        7 => "Ao registrar",
        8 => "Na inicialização",
        9 => "No logon",
        11 => "Mudança de sessão",
        12 => "Personalizado",
        _ => $"Tipo {t}",
    };
}
