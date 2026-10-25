using EvidenceCollector.Core;
using System.Globalization;
using System.Net;
using System.Text;

namespace EvidenceCollector.Sealing;

/// <summary>
/// Builds the self-contained, print-friendly HTML report that accompanies the evidence package
/// (the technical annex of the official record). Every value is HTML-encoded: page titles and URLs are untrusted text.
/// </summary>
public static class ReportGenerator
{
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
    private static string Utc(DateTime? d) => d.HasValue ? d.Value.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture) + " UTC" : "-";
    private static string Href(string rel) => string.Join('/', rel.Split('/').Select(Uri.EscapeDataString));
    private static string Size(long b) => b < 1024 ? $"{b} B" : b < 1024 * 1024 ? $"{b / 1024.0:0.0} KB" : $"{b / 1048576.0:0.0} MB";
    private static string Short(string h) => h.Length > 16 ? h[..16] + "…" : h;

    public static string BuildHtml(SessionContext ctx, IReadOnlyList<AuditEntry> audit, IReadOnlyList<EvidenceItem> items,
        NtpSyncResult? sealSync, DateTime sealedUtc)
    {
        var info = ctx.Info;
        var sealing = ctx.Config.Sealing;
        var sb = new StringBuilder(64 * 1024);

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.AppendLine($"<title>{E(sealing.ReportTitle)} - {E(info.CaseReference)}</title>");
        sb.AppendLine(Css);
        sb.AppendLine("</head><body>");

        // ---------------------------------------------------------------- header
        sb.AppendLine("<header>");
        sb.AppendLine($"<h1>{E(sealing.ReportTitle)}</h1>");
        if (!string.IsNullOrWhiteSpace(sealing.Organization)) sb.AppendLine($"<p class=\"sub\">{E(sealing.Organization)}</p>");
        sb.AppendLine($"<p class=\"sub\">Technical annex · {E(AppInfo.Name)} {E(AppInfo.Version)} · workflow: {E(AppInfo.Standard)}</p>");
        sb.AppendLine($"<p class=\"note\">{E(AppInfo.Disclaimer)}</p>");
        sb.AppendLine("</header>");

        // ---------------------------------------------------------------- 1 session
        sb.AppendLine("<h2>1. Session</h2>");
        sb.AppendLine("<table class=\"kv\">");
        Row(sb, "Case reference", info.CaseReference);
        Row(sb, "Requester", info.Requester);
        Row(sb, "Operator", info.OperatorName);
        Row(sb, "Capacity", info.OperatorTitle);
        Row(sb, "Office", info.Office);
        Row(sb, "Location of the operation", info.Location);
        Row(sb, "Purpose", info.Purpose);
        Row(sb, "Session id", info.SessionId);
        Row(sb, "Session started", Utc(info.CreatedUtc));
        Row(sb, "Session sealed", Utc(sealedUtc));
        Row(sb, "Tool", $"{AppInfo.Name} {AppInfo.Version}");
        Row(sb, "Configuration (config.json) SHA-256", ctx.ConfigSha256, mono: true);
        Row(sb, "Browser engine", ctx.WebView2Version == null ? "-" : "Microsoft Edge WebView2 " + ctx.WebView2Version);
        sb.AppendLine("</table>");

        // ---------------------------------------------------------------- 2 time
        sb.AppendLine("<h2>2. Time reference</h2>");
        sb.AppendLine("<p>Every timestamp in this package is UTC, taken from the workstation clock corrected by the offset measured against several NTP servers. " +
                      "The offset and its uncertainty are recorded below and in each audit-log line.</p>");
        sb.AppendLine("<table class=\"grid\"><tr><th>Moment</th><th>Result</th><th>Offset (NTP - PC)</th><th>Spread</th><th>Uncertainty</th><th>Servers (answering / configured)</th></tr>");
        TimeRow(sb, "Session start", ctx.StartTimeSync, ctx.Config.Ntp.Servers.Count);
        TimeRow(sb, "Sealing", sealSync, ctx.Config.Ntp.Servers.Count);
        sb.AppendLine("</table>");
        foreach (var (label, sync) in new[] { ("Session start", ctx.StartTimeSync), ("Sealing", sealSync) })
        {
            if (sync == null || sync.Samples.Count == 0) continue;
            sb.AppendLine($"<details><summary>NTP exchanges - {E(label)}</summary><table class=\"grid\"><tr><th>Server</th><th>Address</th><th>Stratum</th><th>Offset ms</th><th>Round trip ms</th><th>Server time (UTC)</th></tr>");
            foreach (var s in sync.Samples)
                sb.AppendLine($"<tr><td>{E(s.Server)}</td><td>{E(s.Address)}</td><td>{s.Stratum.ToString(CultureInfo.InvariantCulture)}</td>" +
                              $"<td>{s.OffsetMs.ToString("+0.0;-0.0;0.0", CultureInfo.InvariantCulture)}</td><td>{s.RoundTripMs.ToString("0.0", CultureInfo.InvariantCulture)}</td>" +
                              $"<td>{E(s.ServerTimeUtc)}</td></tr>");
            foreach (var failure in sync.Failures)
                sb.AppendLine($"<tr><td colspan=\"6\">no answer: {E(failure)}</td></tr>");
            sb.AppendLine("</table></details>");
        }

        // ---------------------------------------------------------------- 3 phase 1
        sb.AppendLine("<h2>3. Phase 1 - Environment preparation and neutralisation</h2>");
        sb.AppendLine($"<p>Status: <b>{E(ctx.Phases[1].ToString())}</b> · {Utc(ctx.PhaseStartedUtc[1])} → {Utc(ctx.PhaseFinishedUtc[1])}</p>");
        if (ctx.PreparationChecks.Count > 0)
        {
            sb.AppendLine("<table class=\"grid\"><tr><th>Check</th><th>Status</th><th>Detail</th></tr>");
            foreach (var c in ctx.PreparationChecks)
                sb.AppendLine($"<tr><td>{E(c.Title)}</td><td class=\"st-{c.Status.ToString().ToLowerInvariant()}\">{E(c.Status.ToString().ToUpperInvariant())}</td><td class=\"pre\">{E(c.Details)}</td></tr>");
            sb.AppendLine("</table>");
        }
        if (ctx.CleanReport != null)
            sb.AppendLine($"<h3>Browser data neutralisation</h3><pre>{E(PhaseReports.FormatCleanReport(ctx.CleanReport))}</pre>");

        // ---------------------------------------------------------------- 4 phase 2
        sb.AppendLine("<h2>4. Phase 2 - Network configuration and diagnostics</h2>");
        sb.AppendLine($"<p>Status: <b>{E(ctx.Phases[2].ToString())}</b> · {Utc(ctx.PhaseStartedUtc[2])} → {Utc(ctx.PhaseFinishedUtc[2])}</p>");
        if (ctx.NetworkChecks.Count > 0)
        {
            sb.AppendLine("<table class=\"grid\"><tr><th>Check</th><th>Status</th><th>Detail</th></tr>");
            foreach (var c in ctx.NetworkChecks)
                sb.AppendLine($"<tr><td>{E(c.Title)}</td><td class=\"st-{c.Status.ToString().ToLowerInvariant()}\">{E(c.Status.ToString().ToUpperInvariant())}</td><td class=\"pre\">{E(c.Details)}</td></tr>");
            sb.AppendLine("</table>");
        }
        if (ctx.Network != null) sb.AppendLine($"<pre>{E(NetworkDiagnostics.RenderText(ctx.Network))}</pre>");
        else sb.AppendLine("<p>No network diagnostics were recorded.</p>");

        // ---------------------------------------------------------------- 5 phase 3
        sb.AppendLine("<h2>5. Phase 3 - Controlled navigation and evidence capture</h2>");
        sb.AppendLine($"<p>Status: <b>{E(ctx.Phases[3].ToString())}</b> · {ctx.Captures.Count} capture set(s)</p>");
        List<CaptureSet> captures;
        lock (ctx.Captures) captures = ctx.Captures.OrderBy(c => c.Seq).ToList();
        foreach (var cap in captures)
        {
            sb.AppendLine($"<h3>Capture #{cap.Seq:D4} - {E(string.IsNullOrWhiteSpace(cap.Label) ? "capture" : cap.Label)}</h3>");
            sb.AppendLine("<table class=\"kv\">");
            Row(sb, "URL", cap.Url);
            Row(sb, "Page title", cap.Title);
            Row(sb, "Started", Utc(cap.StartedUtc));
            Row(sb, "Finished", Utc(cap.FinishedUtc));
            Row(sb, "Folder", cap.RelativeFolder, mono: true);
            if (!string.IsNullOrWhiteSpace(cap.OperatorNote)) Row(sb, "Operator note", cap.OperatorNote);
            sb.AppendLine("</table>");
            if (cap.Notes.Count > 0)
            {
                sb.AppendLine("<p><b>Remarks recorded during the capture</b></p><ul>");
                foreach (var n in cap.Notes) sb.AppendLine($"<li>{E(n)}</li>");
                sb.AppendLine("</ul>");
            }
            var files = items.Where(i => i.CaptureSeq == cap.Seq).OrderBy(i => i.RelativePath, StringComparer.Ordinal).ToList();
            if (sealing.IncludeThumbnails)
                foreach (var shot in files.Where(i => i.Category == EvidenceCategory.Screenshot && i.RelativePath.EndsWith(".png", StringComparison.OrdinalIgnoreCase)
                                                      && !i.RelativePath.EndsWith("_raw.png", StringComparison.OrdinalIgnoreCase)).Take(12))
                    sb.AppendLine($"<a href=\"../{Href(shot.RelativePath)}\"><img class=\"shot\" loading=\"lazy\" style=\"max-width:{Math.Max(100, sealing.ThumbnailMaxWidthPx)}px\" src=\"../{Href(shot.RelativePath)}\" alt=\"{E(shot.RelativePath)}\"></a>");
            sb.AppendLine("<table class=\"grid\"><tr><th>File</th><th>Description</th><th>Size</th><th>SHA-256</th></tr>");
            foreach (var f in files)
                sb.AppendLine($"<tr><td><a href=\"../{Href(f.RelativePath)}\">{E(Path.GetFileName(f.RelativePath))}</a></td><td>{E(f.Description)}</td><td>{Size(f.SizeBytes)}</td><td class=\"mono\">{E(f.Sha256)}</td></tr>");
            sb.AppendLine("</table>");
        }

        List<NavigationTrailEntry> trail;
        lock (ctx.NavigationTrail) trail = ctx.NavigationTrail.ToList();
        if (trail.Count > 0)
        {
            const int maxRows = 500;
            sb.AppendLine($"<h3>Navigation trail ({trail.Count} event(s))</h3>");
            sb.AppendLine("<details><summary>Every navigation made in the evidence browser, in order</summary><table class=\"grid log\"><tr><th>#</th><th>UTC</th><th>Event</th><th>By</th><th>URL</th><th>Status</th></tr>");
            foreach (var t in trail.Take(maxRows))
                sb.AppendLine($"<tr><td>{t.Seq}</td><td>{E(t.TimeUtc)}</td><td>{E(t.Kind)}{(t.Redirected ? " (redirect)" : "")}</td><td>{(t.UserInitiated ? "operator" : "page")}</td>" +
                              $"<td class=\"mono\">{E(t.Url)}</td><td>{E(t.HttpStatus?.ToString(CultureInfo.InvariantCulture) ?? t.Status)}</td></tr>");
            if (trail.Count > maxRows) sb.AppendLine($"<tr><td colspan=\"6\">… {trail.Count - maxRows} more event(s) in 00_session/navigation_trail.json</td></tr>");
            sb.AppendLine("</table></details>");
        }

        List<WhoisResult> whois;
        lock (ctx.Whois) whois = ctx.Whois.ToList();
        if (whois.Count > 0)
        {
            sb.AppendLine("<h3>Domain and IP ownership lookups (WHOIS / RDAP)</h3>");
            foreach (var w in whois)
                sb.AppendLine($"<details><summary>{E(w.Source)} - {E(w.Subject)} - {(w.Found ? "record found" : "no record: " + E(w.Error))}</summary><pre>{E(w.RenderText())}</pre></details>");
        }

        // ---------------------------------------------------------------- 6 phase 4
        sb.AppendLine("<h2>6. Phase 4 - Closing, integrity and archiving</h2>");
        sb.AppendLine("<p>Each file below was fingerprinted (SHA-256" + (ctx.Registry.IncludesSha512 ? " and SHA-512" : "") + ") when it was created, and re-hashed at sealing; " +
                      "the audit log is a hash chain (each line contains the SHA-256 of the previous one). " +
                      "<b>manifest.json</b> lists every file with its fingerprints; its own SHA-256 is written in SEAL_RECEIPT.txt and must be reported in the official record.</p>");
        sb.AppendLine("<table class=\"grid\"><tr><th>#</th><th>File</th><th>Phase</th><th>Category</th><th>Size</th><th>SHA-256</th><th>Registered (UTC)</th></tr>");
        foreach (var i in items.OrderBy(x => x.Id))
            sb.AppendLine($"<tr><td>{i.Id}</td><td><a href=\"../{Href(i.RelativePath)}\">{E(i.RelativePath)}</a></td><td>{i.Phase}</td><td>{E(i.Category.ToString())}</td>" +
                          $"<td>{Size(i.SizeBytes)}</td><td class=\"mono\" title=\"{E(i.Sha256)}\">{E(i.Sha256)}</td><td>{Utc(i.RegisteredUtc)}{(i.ClockSynced ? "" : " (clock not synced)")}</td></tr>");
        sb.AppendLine("</table>");

        // ---------------------------------------------------------------- 7 audit log
        sb.AppendLine("<h2>7. Chronological audit log</h2>");
        sb.AppendLine($"<p>{audit.Count} entries up to the start of sealing. The authoritative record is <b>audit/audit.jsonl</b> (hash-chained); the final head hash is in manifest.json.</p>");
        sb.AppendLine("<table class=\"grid log\"><tr><th>#</th><th>UTC</th><th>Lvl</th><th>Ph</th><th>Event</th><th>Message</th><th>Hash</th></tr>");
        foreach (var e in audit)
            sb.AppendLine($"<tr class=\"lv-{e.Level.ToString().ToLowerInvariant()}\"><td>{e.Seq}</td><td>{E(e.Utc)}</td>" +
                          $"<td>{e.Level.ToString().ToUpperInvariant()}</td><td>{(e.Phase == 0 ? "S" : e.Phase.ToString(CultureInfo.InvariantCulture))}</td><td>{E(e.Event)}</td><td>{E(e.Message)}</td><td class=\"mono\">{E(Short(e.Hash))}</td></tr>");
        sb.AppendLine("</table>");

        // ---------------------------------------------------------------- 8 verification
        sb.AppendLine("<h2>8. How to verify this package</h2>");
        sb.AppendLine("<ol>");
        sb.AppendLine("<li>Compare the SHA-256 of <code>05_sealing/manifest.json</code> with the value written in the official record " +
                      "(Windows: <code>certutil -hashfile manifest.json SHA256</code> · Linux/macOS: <code>sha256sum manifest.json</code>).</li>");
        sb.AppendLine("<li>From the session folder, check every file: <code>sha256sum -c 05_sealing/manifest.sha256</code>, or use <i>Verify sealed package…</i> in Evidence Collector, which also checks that no file was added and that the audit log chain is intact.</li>");
        sb.AppendLine("<li>The audit log chain: every line of <code>audit/audit.jsonl</code> carries <code>prevHash</code> (the hash of the preceding line) and <code>hash</code> = SHA-256 of the UTF-8 text " +
                      "<code>seq, utc, clockOffsetUs, level, phase, event, length:message, data, prevHash</code> (one per line, <code>null</code> when absent). " +
                      "The first line chains to <code>SHA-256(\"EVC-AUDIT-GENESIS|&lt;session id&gt;\")</code>; the last <code>hash</code> is the <code>headHash</code> sealed in manifest.json.</li>");
        sb.AppendLine("</ol>");
        sb.AppendLine($"<p class=\"small\">Generated by {E(AppInfo.Name)} {E(AppInfo.Version)}-alpha1 at {Utc(sealedUtc)}.</p>");
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    private static void Row(StringBuilder sb, string key, string? value, bool mono = false)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        sb.AppendLine($"<tr><th>{E(key)}</th><td{(mono ? " class=\"mono\"" : "")}>{E(value)}</td></tr>");
    }

    private static void TimeRow(StringBuilder sb, string label, NtpSyncResult? s, int configuredServers)
    {
        if (s == null) { sb.AppendLine($"<tr><td>{E(label)}</td><td colspan=\"5\">not available</td></tr>"); return; }
        sb.AppendLine($"<tr><td>{E(label)}</td><td class=\"{(s.Success ? "st-pass" : "st-fail")}\">{(s.Success ? (s.WithinTolerance ? "SYNCHRONISED" : "SYNCHRONISED (PC clock off)") : "NOT SYNCHRONISED")}</td>" +
                      $"<td>{s.MedianOffsetMs.ToString("+0.0;-0.0;0.0", CultureInfo.InvariantCulture)} ms</td><td>{s.SpreadMs.ToString("0.0", CultureInfo.InvariantCulture)} ms</td>" +
                      $"<td>±{s.UncertaintyMs.ToString("0.0", CultureInfo.InvariantCulture)} ms</td><td>{s.Samples.Select(x => x.Server).Distinct().Count()} / {configuredServers}</td></tr>");
    }

    private const string Css = @"<style>
:root{--ink:#1b2430;--muted:#5b6675;--line:#d5dbe3;--bg:#ffffff;--soft:#f4f6f9;--accent:#1f4e9c}
*{box-sizing:border-box}
body{font:14px/1.5 'Segoe UI',system-ui,Arial,sans-serif;color:var(--ink);background:var(--bg);max-width:1100px;margin:0 auto;padding:28px 24px 60px}
header{border-bottom:3px solid var(--accent);margin-bottom:8px;padding-bottom:6px}
h1{font-size:26px;margin:0}h2{font-size:18px;margin:34px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px;color:var(--accent)}h3{font-size:15px;margin:22px 0 6px}
.sub{color:var(--muted);margin:2px 0}.note{background:var(--soft);border-left:3px solid var(--accent);padding:8px 12px;font-size:12.5px;color:var(--muted)}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
th{background:var(--soft)}.kv th{width:240px}.mono,code,pre{font-family:Consolas,'Cascadia Mono',monospace;font-size:12px}.mono{word-break:break-all}
pre{background:var(--soft);border:1px solid var(--line);padding:10px;white-space:pre-wrap;word-break:break-word}.pre{white-space:pre-wrap;font-size:12px}
.st-pass{color:#18794e;font-weight:600}.st-warn{color:#a15c00;font-weight:600}.st-fail{color:#b42318;font-weight:600}.st-info{color:#175cd3;font-weight:600}
.lv-warn td{background:#fff7e6}.lv-error td{background:#fdecea}.log td{font-size:11.5px}.small{font-size:12px;color:var(--muted)}
img.shot{max-width:100%;max-height:420px;border:1px solid var(--line);margin:6px 6px 6px 0}details{margin:6px 0}summary{cursor:pointer}
@media print{body{max-width:none;padding:0}img.shot{max-height:300px}details{display:block}a{color:inherit;text-decoration:none}h2{break-after:avoid}tr{break-inside:avoid}}
</style>";
}
