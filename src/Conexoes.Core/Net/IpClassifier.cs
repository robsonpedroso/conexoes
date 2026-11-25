using System.Net;
using System.Net.Sockets;
using Conexoes.Core.Models;

namespace Conexoes.Core.Net;

public static class IpClassifier
{
    public static IpScope Classify(IPAddress? ip)
    {
        if (ip is null) return IpScope.Indefinido;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return IpScope.Indefinido;
        if (IPAddress.IsLoopback(ip)) return IpScope.Loopback;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 10) return IpScope.Privado;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return IpScope.Privado;
            if (b[0] == 192 && b[1] == 168) return IpScope.Privado;
            if (b[0] == 169 && b[1] == 254) return IpScope.Privado;       // link-local
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return IpScope.Privado; // CGNAT
            if (b[0] >= 224 && b[0] <= 239) return IpScope.Multicast;
            if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return IpScope.Multicast;
            if (b[0] == 0) return IpScope.Indefinido;
            return IpScope.Externo;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6Multicast) return IpScope.Multicast;
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal) return IpScope.Privado;
            return IpScope.Externo;
        }

        return IpScope.Indefinido;
    }

    public static bool IsUnspecified(IPAddress ip) =>
        ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any);
}
