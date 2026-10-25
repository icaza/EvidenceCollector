using EvidenceCollector.Config;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EvidenceCollector.Core;

public sealed class ResolvedAddress
{
    public string Ip { get; set; } = "";
    public string Family { get; set; } = "";
    public string? ReverseDns { get; set; }
}

public sealed class TlsInfo
{
    public bool Attempted { get; set; }
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public string ConnectedAddress { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string CipherSuite { get; set; } = "";
    public string PolicyErrors { get; set; } = "";
    public string Subject { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string NotBefore { get; set; } = "";
    public string NotAfter { get; set; } = "";
    public string SerialNumber { get; set; } = "";
    public string Sha256Fingerprint { get; set; } = "";
    public string SubjectAlternativeNames { get; set; } = "";
    /// <summary>The server (leaf) certificate in PEM form, so it can be examined with any tool.</summary>
    public string LeafCertificatePem { get; set; } = "";
    public List<string> ChainSubjects { get; set; } = [];
    public List<string> ChainStatus { get; set; } = [];
}

public sealed class TracerouteHop
{
    public int Ttl { get; set; }
    public string Address { get; set; } = "*";
    public long? RoundTripMs { get; set; }
    public string Status { get; set; } = "";
}

public sealed class TargetReport
{
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string CollectedUtc { get; set; } = "";
    public List<ResolvedAddress> Addresses { get; set; } = [];
    public string? DnsError { get; set; }
    public TlsInfo? Tls { get; set; }
    public List<TracerouteHop>? Traceroute { get; set; }
}

/// <summary>
/// Out-of-band record of the target host: DNS resolution, TLS certificate and optional ICMP route.
/// The TLS probe performs a handshake only (no HTTP request is sent) and accepts any certificate
/// so that invalid certificates are recorded rather than hidden; it never transmits user data.
/// </summary>
public static class TargetDiagnostics
{
    public static async Task<TargetReport> CollectAsync(string host, int port, bool tls, bool dns, bool traceroute,
        NetworkConfig cfg, CancellationToken ct)
    {
        var report = new TargetReport { Host = host, Port = port, CollectedUtc = TrustedClock.FormatIso(DateTime.UtcNow) };

        IPAddress[] addresses = [];
        if (IPAddress.TryParse(host.Trim('[', ']'), out IPAddress? literal)) addresses = new[] { literal };
        else
        {
            try { addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is SocketException or ArgumentException) { report.DnsError = ex.Message; }
        }

        if (dns)
        {
            foreach (IPAddress a in addresses.Take(8))
            {
                var item = new ResolvedAddress { Ip = a.ToString(), Family = a.AddressFamily == AddressFamily.InterNetwork ? "A" : "AAAA" };
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(TimeSpan.FromSeconds(4));
                    IPHostEntry entry = await Dns.GetHostEntryAsync(a.ToString(), cts.Token).ConfigureAwait(false);
                    item.ReverseDns = entry.HostName;
                }
                catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException) { item.ReverseDns = null; }
                report.Addresses.Add(item);
            }
        }

        IPAddress? first = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault();

        if (tls && first != null)
            report.Tls = await ProbeTlsAsync(host, first, port, ct).ConfigureAwait(false);

        if (traceroute && first != null)
            report.Traceroute = await TraceRouteAsync(first, cfg.TracerouteMaxHops, cfg.TracerouteTimeoutMs, ct).ConfigureAwait(false);

        return report;
    }

    public static async Task<TlsInfo> ProbeTlsAsync(string host, IPAddress address, int port, CancellationToken ct)
    {
        var info = new TlsInfo { Attempted = true, ConnectedAddress = address.ToString() };
        var chainSubjects = new List<string>();
        var chainStatus = new List<string>();
        SslPolicyErrors policy = SslPolicyErrors.None;

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));

            using var tcp = new TcpClient(address.AddressFamily);
            await tcp.ConnectAsync(address, port, cts.Token).ConfigureAwait(false);

            await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.None,    // let the operating system choose
                // Inspection only: the callback records the outcome and accepts the handshake so that
                // an invalid certificate is documented instead of aborting the probe. No payload is sent.
                RemoteCertificateValidationCallback = (_, _, chain, errors) =>
                {
                    policy = errors;
                    if (chain != null)
                    {
                        foreach (X509ChainElement el in chain.ChainElements)
                            chainSubjects.Add(el.Certificate.Subject);
                        foreach (X509ChainStatus st in chain.ChainStatus)
                            chainStatus.Add($"{st.Status}: {st.StatusInformation.Trim()}");
                    }
                    return true;
                }
            };
            await ssl.AuthenticateAsClientAsync(options, cts.Token).ConfigureAwait(false);

            info.Protocol = ssl.SslProtocol.ToString();
            info.CipherSuite = ssl.NegotiatedCipherSuite.ToString();
            info.PolicyErrors = policy == SslPolicyErrors.None ? "None (certificate chain and name validated)" : policy.ToString();

            if (ssl.RemoteCertificate != null)
            {
                using var cert = new X509Certificate2(ssl.RemoteCertificate);
                info.Subject = cert.Subject;
                info.Issuer = cert.Issuer;
                info.NotBefore = TrustedClock.FormatIso(cert.NotBefore);
                info.NotAfter = TrustedClock.FormatIso(cert.NotAfter);
                info.SerialNumber = cert.SerialNumber;
                info.LeafCertificatePem = cert.ExportCertificatePem();
                info.Sha256Fingerprint = HashEngine.ToHex(cert.GetCertHash(HashAlgorithmName.SHA256));
                X509Extension? san = cert.Extensions.Cast<X509Extension>().FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");
                if (san != null) info.SubjectAlternativeNames = san.Format(false);
            }
            info.ChainSubjects = chainSubjects;
            info.ChainStatus = chainStatus;
            info.Ok = true;
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException or InvalidOperationException)
        {
            info.Error = ex.Message;
            info.PolicyErrors = policy.ToString();
        }
        return info;
    }

    /// <summary>ICMP traceroute using TTL-limited echo requests. Many networks filter ICMP; gaps are expected.</summary>
    public static async Task<List<TracerouteHop>> TraceRouteAsync(IPAddress target, int maxHops, int timeoutMs, CancellationToken ct)
    {
        var hops = new List<TracerouteHop>();
        using var ping = new Ping();
        byte[] payload = Encoding.ASCII.GetBytes("EvidenceCollector-trace");

        for (int ttl = 1; ttl <= maxHops; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            var hop = new TracerouteHop { Ttl = ttl };
            try
            {
                PingReply reply = await ping.SendPingAsync(target, timeoutMs, payload, new PingOptions(ttl, true)).ConfigureAwait(false);
                hop.Status = reply.Status.ToString();
                if (reply.Status is IPStatus.Success or IPStatus.TtlExpired)
                {
                    hop.Address = reply.Address?.ToString() ?? "*";
                    hop.RoundTripMs = reply.RoundtripTime;
                }
                hops.Add(hop);
                if (reply.Status == IPStatus.Success) break;
            }
            catch (PingException ex)
            {
                hop.Status = "Error: " + (ex.InnerException?.Message ?? ex.Message);
                hops.Add(hop);
                break;
            }
        }
        return hops;
    }

    public static string RenderText(TargetReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"TARGET RECORD: {r.Host}:{r.Port}");
        sb.AppendLine($"Collected (system UTC): {r.CollectedUtc}");
        sb.AppendLine();
        sb.AppendLine("DNS resolution (system resolver)");
        if (r.DnsError != null) sb.AppendLine($"  ERROR: {r.DnsError}");
        foreach (ResolvedAddress a in r.Addresses)
            sb.AppendLine($"  {a.Family,-4} {a.Ip,-40} reverse DNS: {a.ReverseDns ?? "(none)"}");
        if (r.Tls != null)
        {
            sb.AppendLine();
            sb.AppendLine("TLS certificate (separate handshake from the tool, not from the browser)");
            if (!r.Tls.Ok) sb.AppendLine($"  ERROR: {r.Tls.Error}");
            else
            {
                sb.AppendLine($"  Connected to : {r.Tls.ConnectedAddress}");
                sb.AppendLine($"  Protocol     : {r.Tls.Protocol}    Cipher: {r.Tls.CipherSuite}");
                sb.AppendLine($"  Validation   : {r.Tls.PolicyErrors}");
                sb.AppendLine($"  Subject      : {r.Tls.Subject}");
                sb.AppendLine($"  Issuer       : {r.Tls.Issuer}");
                sb.AppendLine($"  Valid        : {r.Tls.NotBefore}  ->  {r.Tls.NotAfter}");
                sb.AppendLine($"  Serial       : {r.Tls.SerialNumber}");
                sb.AppendLine($"  SHA-256 fp   : {r.Tls.Sha256Fingerprint}");
                if (r.Tls.SubjectAlternativeNames.Length > 0) sb.AppendLine($"  SAN          : {r.Tls.SubjectAlternativeNames}");
                foreach (string c in r.Tls.ChainSubjects) sb.AppendLine($"  Chain        : {c}");
                foreach (string c in r.Tls.ChainStatus) sb.AppendLine($"  Chain status : {c}");
            }
        }
        if (r.Traceroute != null)
        {
            sb.AppendLine();
            sb.AppendLine("Traceroute (ICMP)");
            foreach (TracerouteHop h in r.Traceroute)
                sb.AppendLine($"  {h.Ttl,3}  {h.Address,-40} {(h.RoundTripMs.HasValue ? h.RoundTripMs + " ms" : "*"),8}  {h.Status}");
        }
        return sb.ToString();
    }
}
