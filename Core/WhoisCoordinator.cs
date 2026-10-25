using System.Net;
using System.Text;

namespace EvidenceCollector.Core;

/// <summary>
/// Runs the domain (WHOIS/RDAP) and server-IP lookups for a URL and stores each answer as evidence.
/// A lookup is not repeated for the same domain / IP within a session unless the operator forces it.
/// </summary>
public sealed class WhoisCoordinator(SessionContext ctx)
{
    private const int MaxIpLookupsPerCall = 2;

    private readonly SessionContext _ctx = ctx;
    private readonly WhoisClient _client = new(ctx.Config.Whois);
#pragma warning disable IDE0028 // Simplify collection initialization
    private readonly HashSet<string> _done = new(StringComparer.OrdinalIgnoreCase);
#pragma warning restore IDE0028 // Simplify collection initialization
    private readonly Lock _gate = new();

    public async Task<List<WhoisResult>> LookupForUrlAsync(string url, IEnumerable<string>? serverIps, bool force, CancellationToken ct)
    {
        var results = new List<WhoisResult>();
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) || string.IsNullOrEmpty(uri.Host)) return results;

        string host = uri.IdnHost;
        var ips = new List<IPAddress>();

        if (IPAddress.TryParse(host.Trim('[', ']'), out IPAddress? hostIp))
        {
            ips.Add(hostIp);
        }
        else if (Claim("domain:" + host, force))
        {
            WhoisResult r = await _client.LookupDomainAsync(host, ct).ConfigureAwait(false);
            PhaseReports.SaveWhois(_ctx, r, "domain", url);
            results.Add(r);
        }

        if (serverIps != null)
            foreach (string s in serverIps)
                if (IPAddress.TryParse(s.Trim('[', ']'), out IPAddress? ip) && !ips.Contains(ip)) ips.Add(ip);

        foreach (IPAddress ip in ips.Take(MaxIpLookupsPerCall))
        {
            if (NetUtil.IsNonPublic(ip)) continue;
            if (!Claim("ip:" + ip, force)) continue;
            ct.ThrowIfCancellationRequested();
            WhoisResult r = await _client.LookupIpAsync(ip, ct).ConfigureAwait(false);
            PhaseReports.SaveWhois(_ctx, r, "ip", url);
            results.Add(r);
        }
        return results;
    }

    /// <summary>Looks up an address on its own (used for the workstation's public IP in Phase 2).</summary>
    public async Task<WhoisResult?> LookupIpAsync(IPAddress ip, string? reason, bool force, CancellationToken ct)
    {
        if (NetUtil.IsNonPublic(ip) || !Claim("ip:" + ip, force)) return null;
        WhoisResult r = await _client.LookupIpAsync(ip, ct).ConfigureAwait(false);
        PhaseReports.SaveWhois(_ctx, r, "ip", reason);
        return r;
    }

    /// <summary>Returns true when the lookup should run now (not done yet, or forced).</summary>
    private bool Claim(string key, bool force)
    {
        lock (_gate) return _done.Add(key) || force;
    }

    public static string Describe(IEnumerable<WhoisResult> results)
    {
        var sb = new StringBuilder();
        foreach (WhoisResult r in results)
        {
            sb.AppendLine($"[{r.Source}] {r.Subject} - {(r.Found ? "record found" : "no record: " + (r.Error ?? "unknown"))}");
            foreach (string line in r.Summary.Take(12)) sb.AppendLine("  " + line);
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
