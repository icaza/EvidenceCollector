using EvidenceCollector.Config;
using System.Net;
using System.Text;

namespace EvidenceCollector.Core;

/// <summary>Outcome of one run of a phase that is made of a checklist (Phase 1 and Phase 2).</summary>
public class PhaseResult
{
    public int Run { get; init; }
    public List<CheckResult> Checks { get; } = [];
    public PhaseStatus Status { get; set; }
    public bool HasWarnings => Checks.Any(c => c.Status == CheckStatus.Warn);
    public bool HasFailures => Checks.Any(c => c.Status == CheckStatus.Fail);

    public PhaseStatus Evaluate() =>
        Status = HasFailures ? PhaseStatus.Failed : HasWarnings ? PhaseStatus.PassedWithWarnings : PhaseStatus.Passed;
}

public sealed class PreparationResult : PhaseResult
{
    public BrowserCleanReport? Clean { get; set; }
}

public sealed class NetworkPhaseResult : PhaseResult
{
    public NetworkSnapshot? Snapshot { get; set; }
}

/// <summary>
/// Phase 2 - technical network configuration and diagnostics. Captures, before any evidence is gathered:
/// local IP configuration (the "ipconfig" data), active DNS servers, the public IP address (confirmed by several
/// independent endpoints), the literal output of ipconfig / netsh, the NTP reference time and the registry holder of
/// the public address. Everything is written to the audit log and to 02_network/ as fingerprinted evidence files.
/// </summary>
public static class NetworkPhaseRunner
{
    public static async Task<NetworkPhaseResult> RunAsync(SessionContext ctx, int run, WhoisCoordinator? whois,
        IProgress<string>? progress, CancellationToken ct)
    {
        AppConfig cfg = ctx.Config;
        var result = new NetworkPhaseResult { Run = run };
        ctx.SetPhase(2, PhaseStatus.Running, $"run {run}");

        void Add(CheckResult c)
        {
            result.Checks.Add(c);
            AuditLevel level = c.Status switch { CheckStatus.Fail => AuditLevel.Error, CheckStatus.Warn => AuditLevel.Warn, _ => AuditLevel.Info };
            ctx.Audit.TryAppend(level, 2, "net.check", $"{c.Title}: {c.Status.ToString().ToUpperInvariant()}",
                new Dictionary<string, object?> { ["id"] = c.Id, ["details"] = c.Details });
        }

        try
        {
            // ---------------------------------------------------------- local IP configuration and DNS
            progress?.Report("Collecting the local IP configuration…");
            List<InterfaceInfo> interfaces = await Task.Run(NetworkDiagnostics.CollectInterfaces, ct).ConfigureAwait(false);
            NetworkSnapshot snap = NetworkDiagnostics.BuildSnapshot(interfaces);
            Add(CheckAdapters(snap));
            Add(CheckDns(snap));

            // ---------------------------------------------------------- public IP
            progress?.Report("Looking up the public IP address…");
            snap.PublicIpResults = await NetworkDiagnostics.LookupPublicIpAsync(cfg.Network, ct).ConfigureAwait(false);
            (string? ip, string note) = NetworkDiagnostics.Consensus(snap.PublicIpResults, cfg.Network.MinimumAgreeingEndpoints);
            snap.PublicIp = ip;
            snap.PublicIpNote = note;
            Add(CheckPublicIp(snap, cfg));

            // ---------------------------------------------------------- literal command output
            if (cfg.Network.CollectRawCommandOutput)
            {
                progress?.Report("Recording the output of ipconfig /all and netsh winhttp show proxy…");
                snap.RawCommandOutputs = await NetworkDiagnostics.CollectRawOutputsAsync(ct).ConfigureAwait(false);
                Add(snap.RawCommandOutputs.Count > 0
                    ? CheckResult.Info("raw", "Operating-system command output",
                        "Recorded verbatim: " + string.Join(", ", snap.RawCommandOutputs.Keys))
                    : CheckResult.Info("raw", "Operating-system command output", "Not available on this platform."));
            }

            // ---------------------------------------------------------- reference time
            progress?.Report("Synchronising the clock (NTP)…");
            NtpSyncResult ntp = await TimeSync.SyncAsync(cfg.Ntp, ct).ConfigureAwait(false);
            snap.Ntp = ntp;
            ctx.StartTimeSync ??= ntp;
            Add(ClockCheck.FromSync(ntp, cfg));
            ctx.Audit.TryAppend(ntp.Success ? AuditLevel.Info : AuditLevel.Warn, 2, "net.ntp", ntp.Summary,
                new Dictionary<string, object?> { ["offsetMs"] = ntp.MedianOffsetMs, ["spreadMs"] = ntp.SpreadMs, ["servers"] = ntp.Samples.Count });

            // ---------------------------------------------------------- holder of the public address
            if (whois != null && ip != null && cfg.Capture.DomainRecord.IncludeWhois && IPAddress.TryParse(ip, out IPAddress? parsed))
            {
                progress?.Report("Looking up the holder of the public IP address (WHOIS / RDAP)…");
                WhoisResult? owner = await whois.LookupIpAsync(parsed, "Phase 2 - public IP of the workstation", run > 1, ct).ConfigureAwait(false);
                if (owner != null)
                    Add(owner.Found
                        ? CheckResult.Info("owner", "Public IP holder (WHOIS / RDAP)", string.Join("\n", owner.Summary.Take(10)))
                        : CheckResult.Warn("owner", "Public IP holder (WHOIS / RDAP)", "No record could be retrieved: " + (owner.Error ?? "unknown reason")));
            }

            ctx.Network = snap;
            result.Snapshot = snap;
        }
        catch (OperationCanceledException)
        {
            ctx.SetPhase(2, PhaseStatus.Failed, "cancelled");
            throw;
        }

        result.Evaluate();
        ctx.NetworkChecks.Clear();
        ctx.NetworkChecks.AddRange(result.Checks);

        progress?.Report("Recording the Phase 2 results…");
        await Task.Run(() => PhaseReports.SaveNetwork(ctx, run, result.Snapshot!, result.Checks), ct).ConfigureAwait(false);
        ctx.SetPhase(2, result.Status, result.Status == PhaseStatus.Failed ? "blocking check(s) failed" : null);
        return result;
    }

    // ------------------------------------------------------------------ individual checks

    private static CheckResult CheckAdapters(NetworkSnapshot snap)
    {
        var up = snap.Interfaces.Where(i => i.Status == "Up").ToList();
        if (up.Count == 0)
            return CheckResult.Fail("adapters", "Local IP configuration", "No active network adapter was found.");

        var sb = new StringBuilder();
        foreach (InterfaceInfo i in up)
        {
            sb.AppendLine($"{i.Name} ({i.Type}) MAC {i.MacAddress}");
            foreach (string a in i.IPv4) sb.AppendLine($"    IPv4 {a}");
            foreach (string a in i.IPv6.Take(2)) sb.AppendLine($"    IPv6 {a}");
            foreach (string a in i.Gateways) sb.AppendLine($"    gateway {a}");
        }
        return CheckResult.Pass("adapters", "Local IP configuration", $"{up.Count} active adapter(s)\n{sb.ToString().TrimEnd()}");
    }

    private static CheckResult CheckDns(NetworkSnapshot snap) =>
        snap.DnsServers.Count == 0
            ? CheckResult.Warn("dns", "DNS servers", "No DNS server is configured on the active adapters.")
            : CheckResult.Pass("dns", "DNS servers", string.Join(", ", snap.DnsServers));

    private static CheckResult CheckPublicIp(NetworkSnapshot snap, AppConfig cfg)
    {
        var sb = new StringBuilder();
        sb.AppendLine(snap.PublicIp != null ? $"Public IP address: {snap.PublicIp}" : "The public IP address could not be confirmed.");
        sb.AppendLine(snap.PublicIpNote);
        foreach (PublicIpResult r in snap.PublicIpResults)
            sb.AppendLine($"  {r.Endpoint}: {(r.Ok ? r.Ip : "error - " + r.Error)}");
        string details = sb.ToString().TrimEnd();

        var data = new Dictionary<string, object?> { ["publicIp"] = snap.PublicIp };
        if (snap.PublicIp != null) return CheckResult.Pass("publicip", "Public IP address", details, data);
        return new CheckResult
        {
            Id = "publicip",
            Title = "Public IP address",
            Details = details,
            Data = data,
            Status = cfg.Workflow.RequirePublicIp ? CheckStatus.Fail : CheckStatus.Warn
        };
    }
}
