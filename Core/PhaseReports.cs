using System.Text;

namespace EvidenceCollector.Core;

/// <summary>
/// Writes the per-phase result files into the session folder and registers (fingerprints) each of them.
/// Files are never overwritten: a repeated run of a phase gets a new run number (r01, r02, ...).
/// </summary>
public static class PhaseReports
{
    // ------------------------------------------------------------------ NTP

    public static EvidenceItem SaveNtp(SessionContext ctx, string absolutePath, NtpSyncResult result, int phase, string description)
    {
        JsonUtil.WriteFile(absolutePath, result);
        return ctx.Registry.Add(absolutePath, EvidenceCategory.Session, phase, description);
    }

    // ------------------------------------------------------------------ check lists

    public static string FormatChecks(IEnumerable<CheckResult> checks)
    {
        var sb = new StringBuilder();
        foreach (CheckResult c in checks)
        {
            sb.Append('[').Append(c.Status.ToString().ToUpperInvariant().PadRight(4)).Append("] ").AppendLine(c.Title);
            foreach (string line in c.Details.Split('\n'))
                sb.Append("       ").AppendLine(line.TrimEnd('\r'));
            sb.AppendLine();
        }
        return sb.ToString();
    }

    public static string FormatCleanReport(BrowserCleanReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("BROWSER DATA NEUTRALISATION");
        sb.AppendLine($"Cleaned (UTC)        : {r.CleanedUtc}");
        sb.AppendLine($"WebView2 runtime     : {r.WebView2Version ?? "unknown"}");
        sb.AppendLine($"Profile folder       : {r.UserDataFolder}");
        sb.AppendLine($"Profile API used     : {(r.ProfileApiUsed ? "yes (CoreWebView2Profile.ClearBrowsingDataAsync)" : "no (DevTools fallback only)")}");
        sb.AppendLine($"Cookies before/after : {r.CookiesBefore} / {r.CookiesAfter}");
        sb.AppendLine($"Profile bytes b/a    : {r.ProfileBytesBefore} / {r.ProfileBytesAfter}");
        sb.AppendLine($"Result               : {(r.Success ? "CLEAN" : "NOT CLEAN")}");
        sb.AppendLine();
        sb.AppendLine("Steps:");
        foreach (string s in r.Steps) sb.AppendLine("  - " + s);
        if (r.Errors.Count > 0)
        {
            sb.AppendLine("Errors:");
            foreach (string e in r.Errors) sb.AppendLine("  ! " + e);
        }
        return sb.ToString();
    }

    // ------------------------------------------------------------------ phase 1

    public static void SavePreparation(SessionContext ctx, int run, IReadOnlyList<CheckResult> checks, BrowserCleanReport? clean)
    {
        string p = $"prep_r{run:D2}";
        string stamp = TrustedClock.FormatIso(TrustedClock.UtcNow);

        string json = Path.Combine(ctx.PreparationDir, p + "_checks.json");
        JsonUtil.WriteFile(json, new { run, generatedUtc = stamp, clockSynced = TrustedClock.IsSynchronized, checks });
        ctx.Registry.Add(json, EvidenceCategory.Preparation, 1, $"Phase 1 system status checks (run {run}), structured");

        string txt = Path.Combine(ctx.PreparationDir, p + "_checks.txt");
        JsonUtil.WriteText(txt, $"ENVIRONMENT PREPARATION - run {run} - {stamp}\n\n" + FormatChecks(checks));
        ctx.Registry.Add(txt, EvidenceCategory.Preparation, 1, $"Phase 1 system status checks (run {run}), readable");

        if (clean != null)
        {
            string cj = Path.Combine(ctx.PreparationDir, p + "_browser_clean.json");
            JsonUtil.WriteFile(cj, clean);
            ctx.Registry.Add(cj, EvidenceCategory.Preparation, 1, $"Browser data neutralisation report (run {run}), structured");
            string ct = Path.Combine(ctx.PreparationDir, p + "_browser_clean.txt");
            JsonUtil.WriteText(ct, FormatCleanReport(clean));
            ctx.Registry.Add(ct, EvidenceCategory.Preparation, 1, $"Browser data neutralisation report (run {run}), readable");
        }
    }

    // ------------------------------------------------------------------ phase 2

    public static void SaveNetwork(SessionContext ctx, int run, NetworkSnapshot snapshot, IReadOnlyList<CheckResult> checks)
    {
        string p = $"net_r{run:D2}";

        string json = Path.Combine(ctx.NetworkDir, p + "_report.json");
        JsonUtil.WriteFile(json, new { run, checks, snapshot });
        ctx.Registry.Add(json, EvidenceCategory.Network, 2, $"Network diagnostics (run {run}), structured");

        string txt = Path.Combine(ctx.NetworkDir, p + "_report.txt");
        JsonUtil.WriteText(txt, FormatChecks(checks) + "\n" + NetworkDiagnostics.RenderText(snapshot));
        ctx.Registry.Add(txt, EvidenceCategory.Network, 2, $"Network diagnostics (run {run}), readable");

        // The literal command output, byte for byte as the tool returned it.
        foreach (KeyValuePair<string, string> raw in snapshot.RawCommandOutputs)
        {
            string f = Path.Combine(ctx.NetworkDir, $"{p}_{JsonUtil.SafeName(raw.Key, 40)}.txt");
            JsonUtil.WriteText(f, raw.Value);
            ctx.Registry.Add(f, EvidenceCategory.Network, 2, $"Raw output of '{raw.Key}' (run {run})");
        }
    }

    // ------------------------------------------------------------------ WHOIS / RDAP

    /// <summary>
    /// Stores one WHOIS/RDAP lookup: a readable record (every server answer verbatim) and the structured form.
    /// A failed lookup is stored too: the attempt itself is part of the record.
    /// </summary>
    public static List<EvidenceItem> SaveWhois(SessionContext ctx, WhoisResult result, string kind, string? triggeredByUrl)
    {
        int n;
        lock (ctx.Whois) { ctx.Whois.Add(result); n = ctx.Whois.Count; }

        var items = new List<EvidenceItem>();
        string baseName = $"whois_{n:D3}_{JsonUtil.SafeName(kind, 16)}_{JsonUtil.SafeName(result.Subject, 48)}";

        var sb = new StringBuilder();
        sb.AppendLine($"Lookup type : {kind}");
        sb.AppendLine($"Retrieved   : {result.StartedUtc} (system UTC; NTP offset {(TrustedClock.OffsetMs is { } o ? o.ToString("+0.0;-0.0;0.0", System.Globalization.CultureInfo.InvariantCulture) + " ms" : "not synchronised")})");
        if (!string.IsNullOrWhiteSpace(triggeredByUrl)) sb.AppendLine($"Triggered by: {triggeredByUrl}");
        sb.AppendLine();
        sb.Append(result.RenderText());

        string txt = Path.Combine(ctx.WhoisDir, baseName + ".txt");
        JsonUtil.WriteText(txt, sb.ToString());
        items.Add(ctx.Registry.Add(txt, EvidenceCategory.Whois, 3,
            $"{result.Source} record for '{result.Subject}' ({kind}); server answers reproduced verbatim", triggeredByUrl));

        string js = Path.Combine(ctx.WhoisDir, baseName + ".json");
        JsonUtil.WriteFile(js, new { schemaVersion = 1, kind, triggeredByUrl, result });
        items.Add(ctx.Registry.Add(js, EvidenceCategory.Whois, 3, $"Structured form of the {result.Source} lookup for '{result.Subject}'", triggeredByUrl));

        ctx.Audit.TryAppend(result.Found ? AuditLevel.Info : AuditLevel.Warn, 3, "whois.lookup",
            $"{kind} lookup for '{result.Subject}' via {result.Source}: {(result.Found ? "record found" : result.Error ?? "no record")}",
            new Dictionary<string, object?> { ["files"] = items.Select(i => i.RelativePath).ToList() });
        return items;
    }
}
