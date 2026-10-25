using EvidenceCollector.Config;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace EvidenceCollector.Core;

public sealed class WhoisStep
{
    public string Server { get; set; } = "";
    public string Query { get; set; } = "";
    public string QueriedUtc { get; set; } = "";
    public string Response { get; set; } = "";
    public string? Error { get; set; }
}

public sealed class WhoisResult
{
    public string Subject { get; set; } = "";
    public string Source { get; set; } = "";          // "WHOIS" or "RDAP"
    public bool Found { get; set; }
    public string? Error { get; set; }
    public string StartedUtc { get; set; } = "";
    public List<WhoisStep> Steps { get; set; } = [];
    public List<string> Summary { get; set; } = [];

    public string RenderText()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{Source} RECORD FOR: {Subject}");
        sb.AppendLine($"Started (system UTC): {StartedUtc}");
        sb.AppendLine($"Result: {(Found ? "record found" : "no record found")}{(Error != null ? "  (" + Error + ")" : "")}");
        if (Summary.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Summary extracted from the response:");
            foreach (string line in Summary) sb.AppendLine("  " + line);
        }
        foreach (WhoisStep step in Steps)
        {
            sb.AppendLine();
            sb.AppendLine($"----- server: {step.Server}   query: {step.Query}   at {step.QueriedUtc} -----");
            if (step.Error != null) sb.AppendLine($"[error] {step.Error}");
            sb.AppendLine(step.Response.TrimEnd());
        }
        return sb.ToString();
    }
}

/// <summary>
/// RFC 3912 WHOIS client with IANA referral chasing, plus an RDAP fallback (RFC 7480 family)
/// because many registries now redact or disable port-43 data. Server names learned from referrals are
/// untrusted: they are syntax-checked, resolved and refused when they point at non-public addresses.
/// </summary>
public sealed class WhoisClient
{
#pragma warning disable SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.
    private static readonly Regex ReferRegex = new(@"^\s*(?:refer|whois)\s*:\s*(\S+)\s*$", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant);
#pragma warning restore SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.
#pragma warning disable SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.
    private static readonly Regex RegistrarServerRegex = new(@"^\s*Registrar WHOIS Server\s*:\s*(\S+)\s*$", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant);
#pragma warning restore SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.
#pragma warning disable SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.
    private static readonly Regex NoMatchRegex = new(
        @"no match|not found|no entries found|no data found|no object found|status:\s*(free|available)|domain is free|is available for registration|nothing found",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
#pragma warning restore SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.

    private readonly WhoisConfig _cfg;

    public WhoisClient(WhoisConfig cfg) { _cfg = cfg; }

    // ------------------------------------------------------------------ public API

    public async Task<WhoisResult> LookupDomainAsync(string host, CancellationToken ct)
    {
        var result = new WhoisResult { Subject = host, Source = "WHOIS", StartedUtc = TrustedClock.FormatIso(DateTime.UtcNow) };
        try
        {
            string tld = host.Split('.').Last();
            WhoisStep iana = await QueryAsync(_cfg.IanaServer, tld, ct).ConfigureAwait(false);
            result.Steps.Add(iana);
            string? registry = ParseReferral(iana.Response);

            if (registry == null)
            {
                result.Error = "IANA returned no WHOIS server for this top-level domain.";
            }
            else
            {
                foreach (string candidate in DomainCandidates(host))
                {
                    WhoisStep step = await QueryAsync(registry, candidate, ct).ConfigureAwait(false);
                    result.Steps.Add(step);
                    if (step.Error != null || LooksLikeNoMatch(step.Response)) continue;

                    result.Found = true;
                    result.Subject = candidate;
                    await FollowRegistrarAsync(result, step.Response, candidate, ct).ConfigureAwait(false);
                    break;
                }
                if (!result.Found && result.Error == null) result.Error = "The registry has no record for this name.";
            }
        }
        catch (Exception ex) when (ex is SocketException or IOException or TimeoutException or InvalidOperationException)
        {
            result.Error = ex.Message;
        }

        if (!result.Found && _cfg.UseRdapFallback)
        {
            foreach (string candidate in DomainCandidates(host).Take(4))
            {
                WhoisResult rdap = await LookupRdapAsync("domain", candidate, candidate, ct).ConfigureAwait(false);
                if (rdap.Found)
                {
                    rdap.Steps.InsertRange(0, result.Steps);
                    return rdap;
                }
                result.Steps.AddRange(rdap.Steps);
            }
        }

        ExtractSummary(result);
        return result;
    }

    public async Task<WhoisResult> LookupIpAsync(IPAddress ip, CancellationToken ct)
    {
        var result = new WhoisResult { Subject = ip.ToString(), Source = "WHOIS", StartedUtc = TrustedClock.FormatIso(DateTime.UtcNow) };
        try
        {
            WhoisStep iana = await QueryAsync(_cfg.IanaServer, ip.ToString(), ct).ConfigureAwait(false);
            result.Steps.Add(iana);
            string? rir = ParseReferral(iana.Response);
            if (rir == null) result.Error = "IANA returned no regional registry for this address.";
            else
            {
                WhoisStep step = await QueryAsync(rir, ip.ToString(), ct).ConfigureAwait(false);
                result.Steps.Add(step);
                result.Found = step.Error == null && !LooksLikeNoMatch(step.Response) && step.Response.Length > 0;
            }
        }
        catch (Exception ex) when (ex is SocketException or IOException or TimeoutException or InvalidOperationException)
        {
            result.Error = ex.Message;
        }

        if (!result.Found && _cfg.UseRdapFallback)
        {
            WhoisResult rdap = await LookupRdapAsync("ip", ip.ToString(), ip.ToString(), ct).ConfigureAwait(false);
            if (rdap.Found) { rdap.Steps.InsertRange(0, result.Steps); return rdap; }
            result.Steps.AddRange(rdap.Steps);
        }

        ExtractSummary(result);
        return result;
    }

    // ------------------------------------------------------------------ helpers (internal for tests)

    /// <summary>Longest-first list of names to try at the registry: a.b.example.co.uk, b.example.co.uk, example.co.uk, co.uk.</summary>
    internal static List<string> DomainCandidates(string host)
    {
        string[] labels = host.Trim('.').ToLowerInvariant().Split('.', StringSplitOptions.RemoveEmptyEntries);
        var list = new List<string>();
        for (int i = 0; i <= labels.Length - 2 && list.Count < 5; i++)
            list.Add(string.Join('.', labels.Skip(i)));
        if (list.Count == 0) list.Add(string.Join('.', labels));
        return list;
    }

    internal static string? ParseReferral(string text)
    {
        Match m = ReferRegex.Match(text);
        if (!m.Success) return null;
        string server = m.Groups[1].Value.Trim().TrimEnd('.').ToLowerInvariant();
        return NetUtil.IsValidDnsName(server) ? server : null;
    }

    internal static bool LooksLikeNoMatch(string text) => text.Length < 8 || NoMatchRegex.IsMatch(text);

    private async Task FollowRegistrarAsync(WhoisResult result, string registryResponse, string query, CancellationToken ct)
    {
        string current = registryResponse;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { result.Steps.Last().Server };
        for (int depth = 0; depth < 2; depth++)
        {
            Match m = RegistrarServerRegex.Match(current);
            if (!m.Success) return;
            string server = m.Groups[1].Value.Trim().TrimEnd('.').ToLowerInvariant();
            if (server.StartsWith("http", StringComparison.Ordinal)) return;             // web form, not a WHOIS server
            if (!NetUtil.IsValidDnsName(server) || !seen.Add(server)) return;

            WhoisStep step = await QueryAsync(server, query, ct).ConfigureAwait(false);
            result.Steps.Add(step);
            if (step.Error != null) return;
            current = step.Response;
        }
    }

    private async Task<WhoisStep> QueryAsync(string server, string query, CancellationToken ct)
    {
        var step = new WhoisStep { Server = server, Query = query, QueriedUtc = TrustedClock.FormatIso(DateTime.UtcNow) };
        try
        {
            if (!NetUtil.IsValidDnsName(server)) throw new InvalidOperationException($"refused WHOIS server name \"{server}\"");
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(server, ct).ConfigureAwait(false);
            IPAddress? address = addresses.FirstOrDefault(a => !NetUtil.IsNonPublic(a));
            if (address == null) throw new InvalidOperationException($"WHOIS server {server} does not resolve to a public address");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(_cfg.TimeoutSeconds));

            using var tcp = new TcpClient(address.AddressFamily);
            await tcp.ConnectAsync(address, _cfg.Port, cts.Token).ConfigureAwait(false);
            await using NetworkStream stream = tcp.GetStream();

            byte[] request = Encoding.ASCII.GetBytes(query + "\r\n");
            await stream.WriteAsync(request, cts.Token).ConfigureAwait(false);

            int max = _cfg.MaxResponseKb * 1024;
            var ms = new MemoryStream();
            var buffer = new byte[8192];
            int read;
            while (ms.Length < max && (read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cts.Token).ConfigureAwait(false)) > 0)
                ms.Write(buffer, 0, read);

            step.Response = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            step.Error = "timeout";
        }
        catch (Exception ex) when (ex is SocketException or IOException or InvalidOperationException)
        {
            step.Error = ex.Message;
        }
        return step;
    }

    // ------------------------------------------------------------------ RDAP fallback

    private async Task<WhoisResult> LookupRdapAsync(string kind, string subject, string display, CancellationToken ct)
    {
        var result = new WhoisResult { Subject = display, Source = "RDAP", StartedUtc = TrustedClock.FormatIso(DateTime.UtcNow) };
        string url = $"{_cfg.RdapBaseUrl.TrimEnd('/')}/{kind}/{Uri.EscapeDataString(subject)}";
        var step = new WhoisStep { Server = _cfg.RdapBaseUrl, Query = url, QueriedUtc = TrustedClock.FormatIso(DateTime.UtcNow) };
        result.Steps.Add(step);

        try
        {
            if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("RDAP base URL must use HTTPS");
            using var handler = new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = true, MaxAutomaticRedirections = 4 };
            using var client = new HttpClient(handler, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(_cfg.TimeoutSeconds) };
            client.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json");
            client.DefaultRequestHeaders.UserAgent.ParseAdd("EvidenceCollector/1.0");

            using HttpResponseMessage response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                step.Error = $"HTTP {(int)response.StatusCode}";
                result.Error = step.Error;
                return result;
            }

            await using Stream s = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            var ms = new MemoryStream();
            var buffer = new byte[8192];
            int max = _cfg.MaxResponseKb * 1024;
            int read;
            while (ms.Length < max && (read = await s.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false)) > 0)
                ms.Write(buffer, 0, read);

            string json = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
            step.Server = response.RequestMessage?.RequestUri?.ToString() ?? step.Server;
            step.Response = PrettyJson(json);
            result.Found = true;
            SummarizeRdap(json, result.Summary);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or InvalidOperationException or JsonException)
        {
            step.Error = ex.Message;
            result.Error = ex.Message;
        }
        return result;
    }

    private static string PrettyJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (JsonException) { return json; }
    }

    private static void SummarizeRdap(string json, List<string> summary)
    {
        using var doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;
        if (root.TryGetProperty("ldhName", out JsonElement name)) summary.Add($"Domain: {name.GetString()}");
        if (root.TryGetProperty("handle", out JsonElement handle)) summary.Add($"Handle: {handle.GetString()}");
        if (root.TryGetProperty("name", out JsonElement netName)) summary.Add($"Name: {netName.GetString()}");
        if (root.TryGetProperty("country", out JsonElement country)) summary.Add($"Country: {country.GetString()}");
        if (root.TryGetProperty("status", out JsonElement status) && status.ValueKind == JsonValueKind.Array)
            summary.Add("Status: " + string.Join(", ", status.EnumerateArray().Select(x => x.GetString())));
        if (root.TryGetProperty("events", out JsonElement events) && events.ValueKind == JsonValueKind.Array)
            foreach (JsonElement ev in events.EnumerateArray())
                if (ev.TryGetProperty("eventAction", out JsonElement act) && ev.TryGetProperty("eventDate", out JsonElement date))
                    summary.Add($"Event: {act.GetString()} = {date.GetString()}");
        if (root.TryGetProperty("entities", out JsonElement entities) && entities.ValueKind == JsonValueKind.Array)
            foreach (JsonElement ent in entities.EnumerateArray())
            {
                string roles = ent.TryGetProperty("roles", out JsonElement r) && r.ValueKind == JsonValueKind.Array
                    ? string.Join("/", r.EnumerateArray().Select(x => x.GetString())) : "entity";
                string? fn = ExtractVcardName(ent);
                summary.Add($"Entity ({roles}): {fn ?? ent.GetProperty("handle").GetString() ?? "(redacted)"}");
            }
    }

    private static string? ExtractVcardName(JsonElement entity)
    {
        if (!entity.TryGetProperty("vcardArray", out JsonElement vcard) || vcard.ValueKind != JsonValueKind.Array || vcard.GetArrayLength() < 2) return null;
        foreach (JsonElement prop in vcard[1].EnumerateArray())
            if (prop.ValueKind == JsonValueKind.Array && prop.GetArrayLength() >= 4 && prop[0].GetString() == "fn")
                return prop[3].GetString();
        return null;
    }

    /// <summary>Pulls the lines bailiffs usually transcribe (registrar, dates, registrant) from raw WHOIS text.</summary>
    private static void ExtractSummary(WhoisResult result)
    {
        if (result.Summary.Count > 0 || result.Steps.Count == 0) return;
        string[] keys =
        {
            "Domain Name", "Registrar", "Registrar URL", "Creation Date", "Created", "Registry Expiry Date", "Expiry Date",
            "Updated Date", "Name Server", "Registrant Organization", "Registrant Name", "Registrant Country", "NetName", "OrgName",
            "Organization", "organisation", "Country", "inetnum", "NetRange", "CIDR", "descr", "role", "address"
        };
        string text = result.Steps.LastOrDefault(s => s.Response.Length > 0)?.Response ?? string.Empty;
        foreach (string line in text.Split('\n'))
        {
            string trimmed = line.Trim();
            int colon = trimmed.IndexOf(':');
            if (colon <= 0) continue;
            string key = trimmed[..colon].Trim();
            if (keys.Any(k => string.Equals(k, key, StringComparison.OrdinalIgnoreCase)) && result.Summary.Count < 40)
                result.Summary.Add(trimmed);
        }
    }
}
