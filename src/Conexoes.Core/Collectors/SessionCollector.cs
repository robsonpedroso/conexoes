using System.Management;
using System.Runtime.InteropServices;
using Conexoes.Core.Models;
using Conexoes.Core.Security;

namespace Conexoes.Core.Collectors;

/// <summary>Equivalente a <c>query user</c> (sessões locais/RDP) e <c>net session</c> (acessos SMB).</summary>
public static class SessionCollector
{
    public static List<SessionInfo> Collect()
    {
        var list = new List<SessionInfo>();
        list.AddRange(TerminalSessions());
        list.AddRange(SmbSessions());
        foreach (var s in list) s.AddRisks(RiskRules.ForSession(s));
        return list;
    }

    private static IEnumerable<SessionInfo> TerminalSessions()
    {
        var result = new List<SessionInfo>();
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var pSessions, out var count)) return result;
        try
        {
            var size = Marshal.SizeOf<WTS_SESSION_INFO>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(pSessions + i * size);
                var user = QueryString(info.SessionId, WTS_INFO_CLASS.WTSUserName);
                if (string.IsNullOrEmpty(user)) continue; // sessão 0 de serviços, "Services", listeners
                var domain = QueryString(info.SessionId, WTS_INFO_CLASS.WTSDomainName);
                var station = Marshal.PtrToStringUni(info.pWinStationName) ?? "";
                var client = QueryString(info.SessionId, WTS_INFO_CLASS.WTSClientName);
                var protocol = QueryUShort(info.SessionId, WTS_INFO_CLASS.WTSClientProtocolType);
                var (logon, idle) = QueryTimes(info.SessionId);

                result.Add(new SessionInfo
                {
                    Type = protocol == 2 || station.StartsWith("RDP", StringComparison.OrdinalIgnoreCase) ? "RDP" : "Console",
                    Id = info.SessionId.ToString(),
                    User = string.IsNullOrEmpty(domain) ? user : $@"{domain}\{user}",
                    State = StateName(info.State),
                    Station = station,
                    ClientName = string.IsNullOrEmpty(client) ? null : client,
                    ClientAddress = protocol == 2 ? QueryClientAddress(info.SessionId) : null,
                    LogonTime = logon,
                    Idle = idle,
                });
            }
        }
        finally
        {
            WTSFreeMemory(pSessions);
        }
        return result;
    }

    private static IEnumerable<SessionInfo> SmbSessions()
    {
        var result = new List<SessionInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ComputerName, UserName, ActiveTime, IdleTime, ClientType FROM Win32_ServerSession");
            foreach (ManagementObject mo in searcher.Get())
                using (mo)
                {
                    var active = Convert.ToInt64(mo["ActiveTime"] ?? 0L);
                    result.Add(new SessionInfo
                    {
                        Type = "SMB",
                        User = mo["UserName"] as string ?? "",
                        State = "Conectado",
                        ClientAddress = mo["ComputerName"] as string,
                        ClientName = mo["ClientType"] as string,
                        LogonTime = DateTime.Now.AddSeconds(-active),
                        Idle = TimeSpan.FromSeconds(Convert.ToInt64(mo["IdleTime"] ?? 0L)),
                    });
                }
        }
        catch (ManagementException)
        {
            // serviço "Servidor" (LanmanServer) desativado
        }
        return result;
    }

    private static string StateName(int state) => state switch
    {
        0 => "Ativo",
        1 => "Conectado",
        2 => "Consultando",
        3 => "Sombreado",
        4 => "Desconectado",
        5 => "Ocioso",
        6 => "Escutando",
        7 => "Reiniciando",
        8 => "Inativo",
        9 => "Iniciando",
        _ => state.ToString(),
    };

    private static string? QueryString(int sessionId, WTS_INFO_CLASS cls)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, cls, out var buf, out _)) return null;
        try { return Marshal.PtrToStringUni(buf); }
        finally { WTSFreeMemory(buf); }
    }

    private static ushort QueryUShort(int sessionId, WTS_INFO_CLASS cls)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, cls, out var buf, out _)) return 0;
        try { return (ushort)Marshal.ReadInt16(buf); }
        finally { WTSFreeMemory(buf); }
    }

    private static string? QueryClientAddress(int sessionId)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WTS_INFO_CLASS.WTSClientAddress, out var buf, out _)) return null;
        try
        {
            var family = Marshal.ReadInt32(buf);
            var bytes = new byte[20];
            Marshal.Copy(buf + 4, bytes, 0, 20);
            return family == 2 ? $"{bytes[2]}.{bytes[3]}.{bytes[4]}.{bytes[5]}" : family == 23 ? "IPv6" : null;
        }
        finally
        {
            WTSFreeMemory(buf);
        }
    }

    private static (DateTime? Logon, TimeSpan? Idle) QueryTimes(int sessionId)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WTS_INFO_CLASS.WTSSessionInfo, out var buf, out _)) return (null, null);
        try
        {
            var info = Marshal.PtrToStructure<WTSINFO>(buf);
            DateTime? logon = info.LogonTime > 0 ? DateTime.FromFileTime(info.LogonTime) : null;
            TimeSpan? idle = info.LastInputTime > 0 && info.CurrentTime > info.LastInputTime
                ? TimeSpan.FromTicks(info.CurrentTime - info.LastInputTime)
                : null;
            return (logon, idle);
        }
        finally
        {
            WTSFreeMemory(buf);
        }
    }

    private enum WTS_INFO_CLASS
    {
        WTSUserName = 5,
        WTSDomainName = 7,
        WTSClientName = 10,
        WTSClientAddress = 14,
        WTSClientProtocolType = 16,
        WTSSessionInfo = 24,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WTSINFO
    {
        public int State;
        public int SessionId;
        public int IncomingBytes;
        public int OutgoingBytes;
        public int IncomingFrames;
        public int OutgoingFrames;
        public int IncomingCompressedBytes;
        public int OutgoingCompressedBytes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string WinStationName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string Domain;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string UserName;
        public long ConnectTime;
        public long DisconnectTime;
        public long LastInputTime;
        public long LogonTime;
        public long CurrentTime;
    }

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr hServer, int reserved, int version, out IntPtr ppSessionInfo, out int count);

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}
