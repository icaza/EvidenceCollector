using EvidenceCollector.Config;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace EvidenceCollector.Core;

public sealed class NtpSample
{
    public string Server { get; set; } = "";
    public string Address { get; set; } = "";
    public int Stratum { get; set; }
    public int Version { get; set; }
    public string ReferenceId { get; set; } = "";
    public double OffsetMs { get; set; }
    public double RoundTripMs { get; set; }
    public string ServerTimeUtc { get; set; } = "";
}

public sealed class NtpSyncResult
{
    public bool Success { get; set; }
    public bool WithinTolerance { get; set; }
    public double MedianOffsetMs { get; set; }
    public double SpreadMs { get; set; }
    /// <summary>Conservative uncertainty of the reference time: the larger of half the spread and half the smallest round trip.</summary>
    public double UncertaintyMs { get; set; }
    public string ReferenceUtc { get; set; } = "";
    public string SystemUtcAtSync { get; set; } = "";
    public List<NtpSample> Samples { get; set; } = [];
    public List<string> Failures { get; set; } = [];
    public string Summary { get; set; } = "";
}

/// <summary>
/// Minimal SNTPv4 (RFC 4330) client. Responses are validated (mode, stratum, leap indicator,
/// originate-timestamp echo, source address) and several independent servers are combined by median.
/// Note: plain NTP is unauthenticated; it is a consistency reference, not a cryptographic timestamp.
/// </summary>
public static class NtpClient
{
    private static readonly DateTime NtpEpoch = new(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private const double MaxSpreadBetweenServersMs = 500;

    // ------------------------------------------------------------------ packet helpers (unit-testable)

    public static ulong ToNtpTimestamp(DateTime utc)
    {
        long ticks = (utc.ToUniversalTime() - NtpEpoch).Ticks;
        ulong seconds = (ulong)(ticks / TimeSpan.TicksPerSecond) & 0xFFFFFFFFUL;
        double fraction = (ticks % TimeSpan.TicksPerSecond) * 4294967296.0 / TimeSpan.TicksPerSecond;
        return (seconds << 32) | (uint)fraction;
    }

    public static DateTime FromNtpTimestamp(ulong ts)
    {
        ulong seconds = ts >> 32;
        double fraction = (ts & 0xFFFFFFFFUL) / 4294967296.0;
        // Era handling: when the MSB is clear the value belongs to era 1 (after 2036-02-07).
        if ((seconds & 0x80000000UL) == 0) seconds += 1UL << 32;
        return NtpEpoch.AddSeconds(seconds + fraction);
    }

    public static byte[] BuildRequest(DateTime utcNow, out ulong transmitTimestamp)
    {
        var packet = new byte[48];
        packet[0] = 0x23; // LI = 0, VN = 4, Mode = 3 (client)
        transmitTimestamp = ToNtpTimestamp(utcNow);
        WriteUInt64BigEndian(packet, 40, transmitTimestamp);
        return packet;
    }

    /// <summary>Validates a server reply and computes offset and delay. Returns null and a reason on failure.</summary>
    public static NtpSample? ParseResponse(byte[] buffer, int length, ulong expectedOrigin,
        DateTime clientSendUtc, double roundTripClientMs, out string? error)
    {
        error = null;
        if (length < 48) { error = "short packet"; return null; }

        int li = buffer[0] >> 6;
        int vn = (buffer[0] >> 3) & 0x7;
        int mode = buffer[0] & 0x7;
        int stratum = buffer[1];

        if (mode != 4) { error = $"unexpected mode {mode}"; return null; }
        if (vn is < 3 or > 4) { error = $"unsupported version {vn}"; return null; }
        if (li == 3) { error = "server clock unsynchronized (leap indicator 3)"; return null; }
        if (stratum == 0) { error = "kiss-o'-death or unspecified stratum"; return null; }
        if (stratum > 15) { error = $"invalid stratum {stratum}"; return null; }

        ulong origin = ReadUInt64BigEndian(buffer, 24);
        ulong receive = ReadUInt64BigEndian(buffer, 32);
        ulong transmit = ReadUInt64BigEndian(buffer, 40);

        if (origin != expectedOrigin) { error = "originate timestamp mismatch (possible spoofed reply)"; return null; }
        if (receive == 0 || transmit == 0) { error = "server timestamps missing"; return null; }

        DateTime t1 = clientSendUtc;
        DateTime t2 = FromNtpTimestamp(receive);
        DateTime t3 = FromNtpTimestamp(transmit);
        DateTime t4 = t1.AddMilliseconds(roundTripClientMs);

        if (t3 < t2) { error = "server transmit time precedes receive time"; return null; }

        double offset = ((t2 - t1).TotalMilliseconds + (t3 - t4).TotalMilliseconds) / 2.0;
        double delay = (t4 - t1).TotalMilliseconds - (t3 - t2).TotalMilliseconds;
        if (delay < 0) delay = 0;

        string refId = stratum == 1
            ? System.Text.Encoding.ASCII.GetString(buffer, 12, 4).TrimEnd('\0')
            : $"{buffer[12]}.{buffer[13]}.{buffer[14]}.{buffer[15]}";

        return new NtpSample
        {
            Stratum = stratum,
            Version = vn,
            ReferenceId = refId,
            OffsetMs = Math.Round(offset, 3),
            RoundTripMs = Math.Round(delay, 3),
            ServerTimeUtc = TrustedClock.FormatIso(t3)
        };
    }

    // ------------------------------------------------------------------ network

    public static async Task<NtpSample> QueryOnceAsync(string server, int timeoutMs, CancellationToken ct)
    {
        IPAddress[] addresses = await Dns.GetHostAddressesAsync(server, ct).ConfigureAwait(false);
        IPAddress? address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                             ?? addresses.FirstOrDefault();
        if (address == null) throw new InvalidOperationException("no address resolved");

        using var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(timeoutMs);

        var endpoint = new IPEndPoint(address, 123);
        DateTime sendUtc = DateTime.UtcNow;
        byte[] request = BuildRequest(sendUtc, out ulong transmit);

        var sw = Stopwatch.StartNew();
        await socket.SendToAsync(request, SocketFlags.None, endpoint, timeout.Token).ConfigureAwait(false);

        var buffer = new byte[128];
        EndPoint remote = new IPEndPoint(address.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
        SocketReceiveFromResult received;
        try
        {
            received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, remote, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException($"no reply within {timeoutMs} ms");
        }
        sw.Stop();

        if (received.RemoteEndPoint is IPEndPoint ep && !ep.Address.Equals(address))
            throw new InvalidOperationException($"reply came from unexpected address {ep.Address}");

        NtpSample? sample = ParseResponse(buffer, received.ReceivedBytes, transmit, sendUtc, sw.Elapsed.TotalMilliseconds, out string? error);
        if (sample == null) throw new InvalidOperationException(error ?? "invalid reply");

        sample.Server = server;
        sample.Address = address.ToString();
        return sample;
    }

    /// <summary>Queries one server several times and keeps the sample with the smallest round-trip delay.</summary>
    private static async Task<NtpSample> QueryBestAsync(string server, NtpConfig cfg, CancellationToken ct)
    {
        NtpSample? best = null;
        Exception? last = null;
        for (int i = 0; i < cfg.SamplesPerServer; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                NtpSample s = await QueryOnceAsync(server, cfg.TimeoutMs, ct).ConfigureAwait(false);
                if (best == null || s.RoundTripMs < best.RoundTripMs) best = s;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { last = ex; }
            if (i + 1 < cfg.SamplesPerServer) await Task.Delay(150, ct).ConfigureAwait(false);
        }
        return best ?? throw (last ?? new InvalidOperationException("no sample"));
    }

    public static async Task<NtpSyncResult> SyncAsync(NtpConfig cfg, CancellationToken ct = default)
    {
        var result = new NtpSyncResult();
        var tasks = cfg.Servers.Select(async server =>
        {
            try { return (server, sample: await QueryBestAsync(server, cfg, ct).ConfigureAwait(false), error: (string?)null); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { return (server, sample: (NtpSample?)null, error: ex.Message); }
        }).ToList();

        var outcomes = await Task.WhenAll(tasks).ConfigureAwait(false);
        foreach (var o in outcomes)
        {
            if (o.sample != null) result.Samples.Add(o.sample);
            else result.Failures.Add($"{o.server}: {o.error}");
        }

        DateTime nowSystem = DateTime.UtcNow;
        result.SystemUtcAtSync = TrustedClock.FormatIso(nowSystem);

        if (result.Samples.Count == 0)
        {
            result.Summary = "No NTP server answered. UDP port 123 may be blocked.";
            return result;
        }

        var offsets = result.Samples.Select(s => s.OffsetMs).OrderBy(x => x).ToList();
        result.MedianOffsetMs = Median(offsets);
        result.SpreadMs = offsets[^1] - offsets[0];
        result.UncertaintyMs = Math.Round(Math.Max(result.SpreadMs / 2.0, result.Samples.Min(x => x.RoundTripMs) / 2.0), 3);
        result.ReferenceUtc = TrustedClock.FormatIso(nowSystem.AddMilliseconds(result.MedianOffsetMs));
        result.WithinTolerance = Math.Abs(result.MedianOffsetMs) <= cfg.MaxAllowedOffsetMs;

        bool enough = result.Samples.Count >= cfg.MinimumResponses;
        bool consistent = result.SpreadMs <= MaxSpreadBetweenServersMs;
        result.Success = enough && consistent;

        result.Summary = result.Success
            ? $"{result.Samples.Count} server(s) agree; system clock offset {result.MedianOffsetMs:+0.0;-0.0} ms (spread {result.SpreadMs:0.0} ms)."
            : !enough
                ? $"Only {result.Samples.Count} of {cfg.Servers.Count} server(s) answered; {cfg.MinimumResponses} required."
                : $"Servers disagree by {result.SpreadMs:0.0} ms (limit {MaxSpreadBetweenServersMs:0} ms); reference time rejected.";
        return result;
    }

    public static double Median(IReadOnlyList<double> sorted)
    {
        int n = sorted.Count;
        if (n == 0) return 0;
        return n % 2 == 1 ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
    }

    private static void WriteUInt64BigEndian(byte[] buf, int offset, ulong value)
    {
        for (int i = 7; i >= 0; i--) { buf[offset + i] = (byte)(value & 0xFF); value >>= 8; }
    }

    private static ulong ReadUInt64BigEndian(byte[] buf, int offset)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | buf[offset + i];
        return v;
    }
}
