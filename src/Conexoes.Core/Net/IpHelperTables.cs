using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace Conexoes.Core.Net;

/// <summary>Linha crua da tabela de conexões (equivalente a uma linha do netstat -ano).</summary>
public readonly record struct RawConnection(
    string Protocol,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress? RemoteAddress,
    int? RemotePort,
    string State,
    int Pid);

/// <summary>Lê as tabelas TCP/UDP do Windows via GetExtendedTcpTable/GetExtendedUdpTable (iphlpapi).</summary>
public static class IpHelperTables
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    internal const int Tcp4RowSize = 24;
    internal const int Tcp6RowSize = 56;
    internal const int Udp4RowSize = 12;
    internal const int Udp6RowSize = 28;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    public static List<RawConnection> GetAll()
    {
        var list = new List<RawConnection>();
        list.AddRange(ParseTcp4(Fetch(tcp: true, AF_INET)));
        list.AddRange(ParseTcp6(Fetch(tcp: true, AF_INET6)));
        list.AddRange(ParseUdp4(Fetch(tcp: false, AF_INET)));
        list.AddRange(ParseUdp6(Fetch(tcp: false, AF_INET6)));
        return list;
    }

    private static byte[] Fetch(bool tcp, int family)
    {
        // A tabela pode crescer entre as chamadas; tenta algumas vezes.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var size = 0;
            Call(IntPtr.Zero, ref size);
            size += 4096;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var result = Call(buffer, ref size);
                if (result == 0)
                {
                    var bytes = new byte[size];
                    Marshal.Copy(buffer, bytes, 0, size);
                    return bytes;
                }
                if (result != ERROR_INSUFFICIENT_BUFFER) throw new Win32Exception((int)result);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        throw new InvalidOperationException("Não foi possível ler a tabela de conexões.");

        uint Call(IntPtr buf, ref int sz) => tcp
            ? GetExtendedTcpTable(buf, ref sz, true, family, TCP_TABLE_OWNER_PID_ALL, 0)
            : GetExtendedUdpTable(buf, ref sz, true, family, UDP_TABLE_OWNER_PID, 0);
    }

    /// <summary>As portas vêm em network byte order nos 16 bits baixos de um DWORD.</summary>
    internal static int NetworkPortToHost(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    internal static string TcpStateName(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => $"?({state})",
    };

    private static uint U32(ReadOnlySpan<byte> s, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(s[offset..]);

    private static List<RawConnection> ParseTable(byte[] table, int rowSize, Func<byte[], int, RawConnection> parseRow)
    {
        var list = new List<RawConnection>();
        if (table.Length < 4) return list;
        var count = BinaryPrimitives.ReadUInt32LittleEndian(table);
        for (var i = 0; i < count; i++)
        {
            var offset = 4 + i * rowSize;
            if (offset + rowSize > table.Length) break;
            list.Add(parseRow(table, offset));
        }
        return list;
    }

    // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid
    internal static List<RawConnection> ParseTcp4(byte[] table) => ParseTable(table, Tcp4RowSize, (t, o) =>
    {
        var r = t.AsSpan(o, Tcp4RowSize);
        var state = TcpStateName(U32(r, 0));
        var listening = state == "LISTEN";
        return new RawConnection("TCP",
            new IPAddress(r.Slice(4, 4)), NetworkPortToHost(U32(r, 8)),
            listening ? null : new IPAddress(r.Slice(12, 4)), listening ? null : NetworkPortToHost(U32(r, 16)),
            state, (int)U32(r, 20));
    });

    // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid
    internal static List<RawConnection> ParseTcp6(byte[] table) => ParseTable(table, Tcp6RowSize, (t, o) =>
    {
        var r = t.AsSpan(o, Tcp6RowSize);
        var state = TcpStateName(U32(r, 48));
        var listening = state == "LISTEN";
        return new RawConnection("TCP",
            new IPAddress(r.Slice(0, 16), U32(r, 16)), NetworkPortToHost(U32(r, 20)),
            listening ? null : new IPAddress(r.Slice(24, 16), U32(r, 40)), listening ? null : NetworkPortToHost(U32(r, 44)),
            state, (int)U32(r, 52));
    });

    // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid
    internal static List<RawConnection> ParseUdp4(byte[] table) => ParseTable(table, Udp4RowSize, (t, o) =>
    {
        var r = t.AsSpan(o, Udp4RowSize);
        return new RawConnection("UDP", new IPAddress(r.Slice(0, 4)), NetworkPortToHost(U32(r, 4)), null, null, "", (int)U32(r, 8));
    });

    // MIB_UDP6ROW_OWNER_PID: localAddr[16], localScope, localPort, pid
    internal static List<RawConnection> ParseUdp6(byte[] table) => ParseTable(table, Udp6RowSize, (t, o) =>
    {
        var r = t.AsSpan(o, Udp6RowSize);
        return new RawConnection("UDP", new IPAddress(r.Slice(0, 16), U32(r, 16)), NetworkPortToHost(U32(r, 20)), null, null, "", (int)U32(r, 24));
    });
}