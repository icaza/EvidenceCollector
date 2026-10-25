using EvidenceCollector.Config;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Serialization;

namespace EvidenceCollector.Core;

public sealed class PublicIpResult
{
    public string Endpoint { get; set; } = "";
    public bool Ok { get; set; }
    public string? Ip { get; set; }
    public string? Error { get; set; }
    public string RawResponse { get; set; } = "";
    public string QueriedUtc { get; set; } = "";
    public double DurationMs { get; set; }
}

public sealed class InterfaceInfo
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Type { get; set; } = "";
    public string Status { get; set; } = "";
    public string MacAddress { get; set; } = "";
    public long SpeedMbps { get; set; }
    public bool DhcpEnabled { get; set; }
    public string DnsSuffix { get; set; } = "";
    public List<string> IPv4 { get; set; } = [];
    public List<string> IPv6 { get; set; } = [];
    public List<string> Gateways { get; set; } = [];
    public List<string> DhcpServers { get; set; } = [];
    public List<string> DnsServers { get; set; } = [];
}

public sealed class NetworkSnapshot
{
    public string CollectedUtc { get; set; } = "";
    public string MachineName { get; set; } = "";
    public string UserName { get; set; } = "";
    public string OsDescription { get; set; } = "";
    public string? PublicIp { get; set; }
    public string PublicIpNote { get; set; } = "";
    public List<PublicIpResult> PublicIpResults { get; set; } = [];
    public List<InterfaceInfo> Interfaces { get; set; } = [];
    public List<string> DnsServers { get; set; } = [];
    public List<string> Gateways { get; set; } = [];
    /// <summary>Literal output of ipconfig / netsh. Stored as separate evidence files, so it is not repeated in the JSON report.</summary>
    [JsonIgnore] public Dictionary<string, string> RawCommandOutputs { get; set; } = new();
    public NtpSyncResult? Ntp { get; set; }
}

/// <summary>Phase 2 telemetry: public IP, local IP configuration (ipconfig equivalent), DNS servers.</summary>
public static class NetworkDiagnostics
{
    // ------------------------------------------------------------------ public IP

    public static async Task<List<PublicIpResult>> LookupPublicIpAsync(NetworkConfig cfg, CancellationToken ct)
    {
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,                                   // evidence requires a direct connection
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 3,
            ConnectTimeout = TimeSpan.FromSeconds(cfg.RequestTimeoutSeconds),
            AutomaticDecompression = DecompressionMethods.All
        };
        using var client = new HttpClient(handler, disposeHandler: false)
        {
            Timeout = TimeSpan.FromSeconds(cfg.RequestTimeoutSeconds)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("EvidenceCollector/1.0");

        var tasks = cfg.PublicIpEndpoints.Select(url => QueryEndpointAsync(client, url, ct)).ToList();
        PublicIpResult[] results = await Task.WhenAll(tasks).ConfigureAwait(false);
        return results.ToList();
    }

    private static async Task<PublicIpResult> QueryEndpointAsync(HttpClient client, string url, CancellationToken ct)
    {
        var r = new PublicIpResult { Endpoint = url, QueriedUtc = TrustedClock.FormatIso(DateTime.UtcNow) };
        var sw = Stopwatch.StartNew();
        try
        {
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            await using Stream s = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            var buffer = new byte[512];
            int n = await s.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
            string text = Encoding.UTF8.GetString(buffer, 0, n).Trim();
            r.RawResponse = text.Length > 200 ? text[..200] : text;
            if (IPAddress.TryParse(text, out IPAddress? ip)) { r.Ip = ip.ToString(); r.Ok = true; }
            else r.Error = "response is not an IP address";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { r.Error = ex.Message; }
        sw.Stop();
        r.DurationMs = Math.Round(sw.Elapsed.TotalMilliseconds, 1);
        return r;
    }

    /// <summary>Returns the IP reported by at least <paramref name="minAgree"/> endpoints.</summary>
    public static (string? Ip, string Note) Consensus(IReadOnlyList<PublicIpResult> results, int minAgree)
    {
        var ok = results.Where(r => r.Ok && r.Ip != null).ToList();
        if (ok.Count == 0) return (null, "No endpoint returned a public IP address.");

        var groups = ok.GroupBy(r => r.Ip!).OrderByDescending(g => g.Count()).ToList();
        var top = groups[0];
        if (groups.Count > 1)
            return (top.Count() >= minAgree ? top.Key : null,
                $"Endpoints disagree: {string.Join(", ", groups.Select(g => $"{g.Key} x{g.Count()}"))}.");
        if (top.Count() < minAgree)
            return (null, $"Only {top.Count()} endpoint(s) answered; {minAgree} required for confirmation.");
        return (top.Key, $"{top.Count()} endpoint(s) agree.");
    }

    // ------------------------------------------------------------------ local IP configuration

    public static List<InterfaceInfo> CollectInterfaces()
    {
        var list = new List<InterfaceInfo>();
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            var info = new InterfaceInfo
            {
                Name = nic.Name,
                Description = nic.Description,
                Type = nic.NetworkInterfaceType.ToString(),
                Status = nic.OperationalStatus.ToString(),
                MacAddress = FormatMac(nic.GetPhysicalAddress()),
                SpeedMbps = nic.Speed > 0 ? nic.Speed / 1_000_000 : 0
            };

            try
            {
                IPInterfaceProperties props = nic.GetIPProperties();
                info.DnsSuffix = props.DnsSuffix ?? "";
                foreach (UnicastIPAddressInformation u in props.UnicastAddresses)
                {
                    if (u.Address.AddressFamily == AddressFamily.InterNetwork)
                        info.IPv4.Add($"{u.Address} / {(u.IPv4Mask?.ToString() ?? "?")}");
                    else if (u.Address.AddressFamily == AddressFamily.InterNetworkV6)
                        info.IPv6.Add($"{u.Address} /{u.PrefixLength}");
                }
                info.Gateways.AddRange(props.GatewayAddresses.Select(g => g.Address.ToString()));
                info.DhcpServers.AddRange(props.DhcpServerAddresses.Select(d => d.ToString()));
                info.DnsServers.AddRange(props.DnsAddresses.Select(d => d.ToString()));
                try { info.DhcpEnabled = props.GetIPv4Properties().IsDhcpEnabled; }
                catch (NetworkInformationException) { /* IPv4 not enabled on this adapter */ }
            }
            catch (NetworkInformationException) { /* adapter vanished while enumerating */ }

            list.Add(info);
        }
        return list;
    }

    public static NetworkSnapshot BuildSnapshot(List<InterfaceInfo> interfaces)
    {
        var active = interfaces.Where(i => i.Status == "Up").ToList();
        return new NetworkSnapshot
        {
            CollectedUtc = TrustedClock.FormatIso(DateTime.UtcNow),
            MachineName = Environment.MachineName,
            UserName = Environment.UserName,
            OsDescription = RuntimeInformation.OSDescription,
            Interfaces = interfaces,
            DnsServers = active.SelectMany(i => i.DnsServers).Distinct().ToList(),
            Gateways = active.SelectMany(i => i.Gateways).Distinct().ToList()
        };
    }

    // ------------------------------------------------------------------ raw command output (fixed allow-list)

    /// <summary>
    /// Captures the literal output of the operating-system tools that bailiffs traditionally paste into a report.
    /// The command list is hard-coded on purpose: configuration can switch it on or off but never extend it.
    /// </summary>
    public static async Task<Dictionary<string, string>> CollectRawOutputsAsync(CancellationToken ct)
    {
        var result = new Dictionary<string, string>();
        if (!OperatingSystem.IsWindows()) return result;

        result["ipconfig_all"] = await RunSystemToolAsync("ipconfig.exe", "/all", ct).ConfigureAwait(false);
        result["netsh_winhttp_show_proxy"] = await RunSystemToolAsync("netsh.exe", "winhttp show proxy", ct).ConfigureAwait(false);
        return result;
    }

    private static async Task<string> RunSystemToolAsync(string exeName, string arguments, CancellationToken ct)
    {
        string exe = Path.Combine(Environment.SystemDirectory, exeName);
        if (!File.Exists(exe)) return $"(tool not found: {exeName})";

        Encoding encoding = Encoding.UTF8;
        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            int oem = CultureInfo.CurrentCulture.TextInfo.OEMCodePage;
            if (oem > 0) encoding = Encoding.GetEncoding(oem);
        }
        catch (Exception) { /* keep UTF-8 */ }

        var psi = new ProcessStartInfo(exe, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = encoding,
            StandardErrorEncoding = encoding,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            using var process = Process.Start(psi);
            if (process == null) return $"(could not start {exeName})";
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            Task<string> stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            Task<string> stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            string text = await stdout.ConfigureAwait(false);
            string err = await stderr.ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(err) ? text : text + "\n[stderr]\n" + err;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return $"(timed out: {exeName} {arguments})";
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return $"(failed: {ex.Message})";
        }
    }

    // ------------------------------------------------------------------ rendering

    public static string RenderText(NetworkSnapshot s)
    {
        var sb = new StringBuilder();
        sb.AppendLine("NETWORK DIAGNOSTICS");
        sb.AppendLine("===================");
        sb.AppendLine($"Collected (system UTC): {s.CollectedUtc}");
        sb.AppendLine($"Machine / user        : {s.MachineName} / {s.UserName}");
        sb.AppendLine($"Operating system      : {s.OsDescription}");
        sb.AppendLine();
        sb.AppendLine($"Public IP address     : {s.PublicIp ?? "(not confirmed)"}");
        sb.AppendLine($"Public IP note        : {s.PublicIpNote}");
        foreach (PublicIpResult p in s.PublicIpResults)
            sb.AppendLine($"  - {p.Endpoint,-36} {(p.Ok ? p.Ip : "ERROR: " + p.Error),-40} {p.DurationMs,7:0.0} ms  @ {p.QueriedUtc}");
        sb.AppendLine();
        sb.AppendLine($"DNS servers (active)  : {(s.DnsServers.Count == 0 ? "(none)" : string.Join(", ", s.DnsServers))}");
        sb.AppendLine($"Default gateways      : {(s.Gateways.Count == 0 ? "(none)" : string.Join(", ", s.Gateways))}");
        sb.AppendLine();
        sb.AppendLine("NETWORK ADAPTERS");
        sb.AppendLine("----------------");
        foreach (InterfaceInfo i in s.Interfaces)
        {
            sb.AppendLine($"{i.Name}  [{i.Status}]  {i.Type}");
            sb.AppendLine($"    Description : {i.Description}");
            sb.AppendLine($"    MAC         : {i.MacAddress}    Speed: {i.SpeedMbps} Mbit/s    DHCP: {(i.DhcpEnabled ? "yes" : "no")}");
            if (!string.IsNullOrEmpty(i.DnsSuffix)) sb.AppendLine($"    DNS suffix  : {i.DnsSuffix}");
            foreach (string a in i.IPv4) sb.AppendLine($"    IPv4        : {a}");
            foreach (string a in i.IPv6) sb.AppendLine($"    IPv6        : {a}");
            foreach (string a in i.Gateways) sb.AppendLine($"    Gateway     : {a}");
            foreach (string a in i.DhcpServers) sb.AppendLine($"    DHCP server : {a}");
            foreach (string a in i.DnsServers) sb.AppendLine($"    DNS server  : {a}");
            sb.AppendLine();
        }
        if (s.Ntp != null)
        {
            sb.AppendLine("NTP REFERENCE TIME");
            sb.AppendLine("------------------");
            sb.AppendLine(s.Ntp.Summary);
            sb.AppendLine($"System UTC at sync : {s.Ntp.SystemUtcAtSync}");
            sb.AppendLine($"Reference UTC      : {s.Ntp.ReferenceUtc}");
            foreach (NtpSample n in s.Ntp.Samples)
                sb.AppendLine($"  - {n.Server,-24} {n.Address,-40} stratum {n.Stratum}  offset {n.OffsetMs,10:+0.000;-0.000} ms  rtt {n.RoundTripMs,8:0.000} ms  ref {n.ReferenceId}");
            foreach (string f in s.Ntp.Failures) sb.AppendLine($"  ! {f}");
            sb.AppendLine();
        }
        foreach (var kv in s.RawCommandOutputs)
        {
            sb.AppendLine($"RAW OUTPUT: {kv.Key}");
            sb.AppendLine(new string('-', 10 + kv.Key.Length));
            sb.AppendLine(kv.Value.TrimEnd());
            sb.AppendLine();
        }
        return sb.ToString();
    }

    private static string FormatMac(PhysicalAddress mac)
    {
        byte[] b = mac.GetAddressBytes();
        return b.Length == 0 ? "" : string.Join("-", b.Select(x => x.ToString("X2", CultureInfo.InvariantCulture)));
    }
}
