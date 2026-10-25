using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace EvidenceCollector.Core;

public static class NetUtil
{
#pragma warning disable SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.
    private static readonly Regex HostNameRegex = new(
        @"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
#pragma warning restore SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.

    /// <summary>True for addresses that are not routable on the public Internet.</summary>
    public static bool IsNonPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)   // carrier-grade NAT
                || b[0] == 0
                || b[0] >= 224;                                  // multicast / reserved
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte[] b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC                         // fc00::/7 unique local
                || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)       // fe80::/10 link local
                || b[0] == 0xFF;                                 // multicast
        }
        return true;
    }

    /// <summary>Syntactic DNS host-name check (no IP literals).</summary>
    public static bool IsValidDnsName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        if (IPAddress.TryParse(name, out _)) return false;
        return HostNameRegex.IsMatch(name);
    }

    /// <summary>Removes credentials from proxy or URL strings before they are logged.</summary>
    public static string RedactCredentials(string value) =>
        Regex.Replace(value, @"(?<=://)[^/@\s]+@", "***@");
}
