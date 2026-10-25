using EvidenceCollector.Browser;
using EvidenceCollector.Config;
using EvidenceCollector.Core;
using Microsoft.Web.WebView2.Core;
using System.Text;
using System.Text.Json;

namespace EvidenceCollector.Capture;

/// <summary>What a capture trigger collects. Each flag maps to one button of the Phase 3 toolbar.</summary>
[Flags]
public enum CaptureParts
{
    None = 0,
    ViewportScreenshot = 1,
    FullPageScreenshot = 2,
    /// <summary>Raw HTTP response body, rendered DOM, visible text, style sheets.</summary>
    Source = 4,
    /// <summary>Single-file MHTML snapshot and PDF rendering.</summary>
    Archive = 8,
    /// <summary>DNS answer, TLS certificate chain, cookies, network log and request table.</summary>
    Connection = 16,
    /// <summary>WHOIS / RDAP of the domain and of the server address.</summary>
    Whois = 32,
    Full = ViewportScreenshot | FullPageScreenshot | Source | Archive | Connection | Whois
}

public sealed record CaptureOutcome(CaptureSet Set, IReadOnlyList<string> Warnings, int FilesRegistered);

/// <summary>
/// Phase 3 - one evidence capture of the page currently shown in the evidence browser.
/// Everything is written to its own folder under 03_captures/ and fingerprinted (SHA-256, optional SHA-512) the moment
/// it is written. The page is locked against navigation while the capture runs. A part that fails is recorded as a
/// warning and does not stop the other parts: a partial capture is better evidence than none, provided the gap is visible.
/// Must be called on the UI thread (it drives the WebView2 control); CPU-heavy work runs on the thread pool.
/// </summary>
public sealed class CaptureService(SessionContext session, EvidenceBrowser browser, WhoisCoordinator whois)
{
    private readonly SessionContext _s = session;
    private readonly EvidenceBrowser _browser = browser;
    private readonly WhoisCoordinator _whois = whois;

    private AppConfig Cfg => _s.Config;

    public static bool IsCapturableUrl(string? url) =>
        !string.IsNullOrWhiteSpace(url)
        && !url.Equals("about:blank", StringComparison.OrdinalIgnoreCase)
        && !url.StartsWith("chrome-error:", StringComparison.OrdinalIgnoreCase)
        && Uri.TryCreate(url, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps);

    public async Task<CaptureOutcome> RunAsync(CaptureParts parts, string label, string? operatorNote,
        IProgress<string>? progress, CancellationToken ct)
    {
        if (!_browser.IsReady) throw new InvalidOperationException("The evidence browser is not ready.");
        if (!IsCapturableUrl(_browser.CurrentUrl)) throw new InvalidOperationException("Load a web page first: there is nothing to capture.");

        var warnings = new List<string>();
        CaptureSet? set = null;
        var cancelled = false;
        var files = 0;

        try
        {
            progress?.Report("Waiting for the page to finish loading…");
            var complete = await _browser.WaitForCompleteAsync(Cfg.Capture.WaitForPageCompleteMs, ct);

            // From here on the page cannot navigate away: the capture describes one single state.
            _browser.Locked = true;
            var url = _browser.CurrentUrl;
            set = _s.BeginCaptureSet(label, url);
            set.Title = _browser.CurrentTitle;
            set.OperatorNote = string.IsNullOrWhiteSpace(operatorNote) ? null : operatorNote.Trim();
            if (!complete) Warn(set, warnings, $"The page did not report document.readyState = \"complete\" within {Cfg.Capture.WaitForPageCompleteMs} ms; the capture continued with the page as it was.");
            if (set.OperatorNote != null) _s.Audit.Info(3, "capture.note", "Operator note for this capture: " + set.OperatorNote);

            await Part(set, warnings, "Page information", () => SavePageInfoAsync(set), ct);

            if (parts.HasFlag(CaptureParts.ViewportScreenshot))
                await Part(set, warnings, "Viewport screenshot", () => ViewportShotAsync(set, progress, ct), ct);

            if (parts.HasFlag(CaptureParts.FullPageScreenshot))
                await Part(set, warnings, "Full-page screenshot", () => FullPageShotAsync(set, warnings, progress, ct), ct);

            if (parts.HasFlag(CaptureParts.Source))
                await Part(set, warnings, "Page source", () => SourceAsync(set, warnings, progress), ct);

            if (parts.HasFlag(CaptureParts.Archive))
                await Part(set, warnings, "Archive (MHTML / PDF)", () => ArchiveAsync(set, warnings, progress), ct);

            if (parts.HasFlag(CaptureParts.Connection))
                await Part(set, warnings, "Connection data", () => ConnectionAsync(set, warnings, progress, ct), ct);

            if (parts.HasFlag(CaptureParts.Whois))
                await Part(set, warnings, "WHOIS / RDAP", () => WhoisAsync(set, progress, ct), ct);

            if (!string.Equals(NetworkRecorder.StripFragment(_browser.CurrentUrl), NetworkRecorder.StripFragment(url), StringComparison.OrdinalIgnoreCase))
                Warn(set, warnings, $"The page URL changed while the capture was running (now {_browser.CurrentUrl}). The files describe the page at {url}.");
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
            if (set != null) Warn(set, warnings, "The capture was cancelled before it finished: the files below are incomplete.");
        }
        finally
        {
            _browser.Locked = false;
        }

        if (set == null) throw new OperationCanceledException(ct);

        progress?.Report("Recording the capture…");
        files = await FinishAsync(set, parts, warnings);
        if (cancelled) throw new OperationCanceledException("Capture cancelled.");
        return new CaptureOutcome(set, warnings, files);
    }

    // ---------------------------------------------------------------------------------------------- bookkeeping

    private async Task Part(CaptureSet set, List<string> warnings, string name, Func<Task> action, CancellationToken ct)
    {
        try { await action(); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { Warn(set, warnings, $"{name} failed: {ex.Message}"); }
    }

    private void Warn(CaptureSet set, List<string> warnings, string text)
    {
        warnings.Add(text);
        lock (set.Notes) set.Notes.Add("WARNING: " + text);
        _s.Audit.Warn(3, "capture.warning", text, new Dictionary<string, object?> { ["capture"] = set.Seq });
    }

    private void Note(CaptureSet set, string text)
    {
        lock (set.Notes) set.Notes.Add(text);
        _s.Audit.Info(3, "capture.note", text, new Dictionary<string, object?> { ["capture"] = set.Seq });
    }

    private Task<EvidenceItem> SaveAsync(CaptureSet set, string name, byte[] bytes, EvidenceCategory category, string description) =>
        Task.Run(() =>
        {
            var path = Path.Combine(set.Folder, name.Replace('/', Path.DirectorySeparatorChar));
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            using (var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                fs.Write(bytes, 0, bytes.Length);
            var item = _s.Registry.Add(path, category, 3, description, set.Url, set.Seq);
            lock (set.EvidenceIds) set.EvidenceIds.Add(item.Id);
            return item;
        });

    private Task<EvidenceItem> SaveTextAsync(CaptureSet set, string name, string text, EvidenceCategory category, string description) =>
        SaveAsync(set, name, new UTF8Encoding(false).GetBytes(text), category, description);

    private Task<EvidenceItem> SaveJsonAsync<T>(CaptureSet set, string name, T value, EvidenceCategory category, string description) =>
        SaveTextAsync(set, name, JsonUtil.ToJson(value) + "\n", category, description);

    // ---------------------------------------------------------------------------------------------- page information

    private async Task SavePageInfoAsync(CaptureSet set)
    {
        string? pageJson = null;
        try { pageJson = await _browser.EvalStringAsync(PageScripts.PageInfo); }
        catch { /* the document is reported as unavailable below */ }

        JsonElement? page = null;
        if (!string.IsNullOrEmpty(pageJson))
        {
            using var doc = JsonDocument.Parse(pageJson);
            page = doc.RootElement.Clone();
        }

        await SaveJsonAsync(set, "page_info.json", new
        {
            schemaVersion = 1,
            capturedUtc = TrustedClock.UtcNow,
            systemUtc = TrustedClock.SystemUtcNow,
            clockSynchronised = TrustedClock.IsSynchronized,
            clockOffsetMs = TrustedClock.OffsetMs is { } off ? Math.Round(off, 1) : (double?)null,
            url = set.Url,
            title = set.Title,
            webView2Runtime = _browser.RuntimeVersion,
            userAgent = _browser.UserAgent,
            page
        }, EvidenceCategory.Other, "Facts about the page and the browser at the moment of the capture (document state, sizes, language, user agent)");
    }

    // ---------------------------------------------------------------------------------------------- screenshots

    private StampInfo Stamp(CaptureSet set, string kind, string? part) => new()
    {
        Url = set.Url,
        Title = set.Title,
        Kind = kind,
        CaseReference = _s.Info.CaseReference,
        OperatorName = _s.Info.OperatorName,
        SessionShortId = _s.Info.ShortId,
        CaptureSeq = set.Seq,
        CapturedUtc = TrustedClock.UtcNow,
        ClockSynced = TrustedClock.IsSynchronized,
        ClockOffsetMs = TrustedClock.OffsetMs ?? 0.0,
        PartLabel = part
    };

    /// <summary>Saves a screenshot: stamped copy (when the overlay is enabled) and/or the untouched PNG.</summary>
    private async Task SaveScreenshotAsync(CaptureSet set, string baseName, byte[] rawPng, StampInfo stamp, string description)
    {
        var overlay = Cfg.Capture.Screenshot.Overlay;
        if (overlay.Enabled)
        {
            var stamped = await Task.Run(() => ScreenshotStamper.Stamp(rawPng, stamp, overlay));
            await SaveAsync(set, baseName + ".png", stamped, EvidenceCategory.Screenshot,
                description + " - with the information band (URL, UTC time, case) and watermark");
            if (Cfg.Capture.Screenshot.KeepRawImage)
                await SaveAsync(set, baseName + "_raw.png", rawPng, EvidenceCategory.Screenshot, description + " - unmodified browser image");
        }
        else
        {
            await SaveAsync(set, baseName + ".png", rawPng, EvidenceCategory.Screenshot, description + " - unmodified browser image");
        }
    }

    private async Task ViewportShotAsync(CaptureSet set, IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Capturing the viewport…");
        ct.ThrowIfCancellationRequested();
        byte[] png;
        using (var ms = new MemoryStream())
        {
            await _browser.WebCore.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, ms);
            png = ms.ToArray();
        }
        var stamp = Stamp(set, "Viewport screenshot", null);
        await SaveScreenshotAsync(set, "screenshot_viewport", png, stamp, "Screenshot of the visible part of the page (viewport)");
    }

    private async Task FullPageShotAsync(CaptureSet set, List<string> warnings, IProgress<string>? progress, CancellationToken ct)
    {
        var cap = Cfg.Capture.Screenshot;

        if (cap.AutoScrollBeforeFullPage)
        {
            progress?.Report("Scrolling through the page so lazy-loaded content is requested…");
            try
            {
                var scroll = await _browser.EvalAsyncStringAsync(PageScripts.AutoScroll(cap.AutoScrollStepDelayMs, cap.AutoScrollMaxDurationMs));
                Note(set, "Automatic scrolling before the full-page capture (content below the fold is requested by the page): " + (scroll ?? "no result"));
                await Task.Delay(400, ct);
                await _browser.WaitForCompleteAsync(5000, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Warn(set, warnings, "Automatic scrolling failed: " + ex.Message);
            }
        }

        // Size of the whole document, in CSS pixels.
        double width, height;
        using (var doc = JsonDocument.Parse(await _browser.CdpAsync("Page.getLayoutMetrics")))
        {
            var root = doc.RootElement;
            var size = root.TryGetProperty("cssContentSize", out var cs) ? cs : root.GetProperty("contentSize");
            width = size.GetProperty("width").GetDouble();
            height = size.GetProperty("height").GetDouble();
        }

        var pageWidth = (int)Math.Clamp(Math.Ceiling(width), 1, 16000);
        var fullHeight = (int)Math.Max(1, Math.Ceiling(height));
        var pageHeight = Math.Min(fullHeight, cap.FullPageMaxTotalHeightPx);
        if (width > pageWidth) Warn(set, warnings, $"The page is {Math.Ceiling(width)} px wide; the capture is limited to {pageWidth} px.");
        if (fullHeight > pageHeight) Warn(set, warnings, $"The page is {fullHeight} px high; the full-page capture stops at capture.screenshot.fullPageMaxTotalHeightPx = {pageHeight} px.");

        var segment = cap.FullPageMaxTileHeightPx;
        var count = (int)Math.Ceiling(pageHeight / (double)segment);
        Note(set, $"Full-page capture: document {pageWidth} x {fullHeight} CSS px, saved as {count} part(s) of at most {segment} px.");

        for (var i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var y = i * segment;
            var h = Math.Min(segment, pageHeight - y);
            progress?.Report($"Capturing the full page… part {i + 1} of {count}");

            var request = JsonSerializer.Serialize(new
            {
                format = "png",
                fromSurface = true,
                captureBeyondViewport = true,
                clip = new { x = 0, y, width = pageWidth, height = h, scale = 1 }
            });
            string base64;
            using (var doc = JsonDocument.Parse(await _browser.CdpAsync("Page.captureScreenshot", request)))
                base64 = doc.RootElement.GetProperty("data").GetString() ?? throw new InvalidOperationException("The browser returned no image data.");
            var png = Convert.FromBase64String(base64);

            var part = $"Part {i + 1} of {count}  |  pixel rows {y}-{y + h - 1} of {fullHeight}" + (fullHeight > pageHeight ? " (page truncated)" : "");
            var stamp = Stamp(set, "Full-page screenshot", part);
            await SaveScreenshotAsync(set, $"screenshot_fullpage_p{i + 1:D2}", png, stamp,
                $"Full-page screenshot, part {i + 1} of {count} (pixel rows {y}-{y + h - 1})");
        }
    }

    // ---------------------------------------------------------------------------------------------- source

    private async Task SourceAsync(CaptureSet set, List<string> warnings, IProgress<string>? progress)
    {
        progress?.Report("Saving the page source…");
        var cap = Cfg.Capture.Source;
        var recorder = _browser.Recorder;
        var bodies = recorder?.Bodies() ?? Array.Empty<RecordedBody>();

        // 1. exactly what the server sent (after transfer decoding)
        RecordedBody? main = null;
        if (cap.SaveRawResponseBody)
        {
            main = recorder?.MainDocumentBody();
            if (main != null)
            {
                await SaveAsync(set, "source_raw_response.html", main.Bytes, EvidenceCategory.Source,
                    $"Raw HTML response body exactly as received from the server (HTTP {main.Status}, {main.ContentType})");
            }
            else
            {
                Warn(set, warnings, "The raw response body of the main document is not available (it may have been served from a cache or exceeded capture.source.maxCachedBodyMb). The rendered DOM is saved instead.");
            }
        }

        if (cap.SaveResponseHeaders)
        {
            var doc = recorder?.MainDocument();
            if (doc != null)
                await SaveTextAsync(set, "source_main_response_headers.txt", FormatMainResponse(doc), EvidenceCategory.Source,
                    "HTTP status, redirect chain and response headers of the main document as seen by the browser");
        }

        // 2. what the browser built from it
        if (cap.SaveRenderedDom)
        {
            var dom = await _browser.EvalStringAsync(PageScripts.RenderedDom);
            if (dom != null)
                await SaveTextAsync(set, "source_rendered_dom.html", dom, EvidenceCategory.Source, "Rendered DOM (HTML after scripts ran) at the moment of the capture");
        }
        if (cap.SavePlainText)
        {
            var text = await _browser.EvalStringAsync(PageScripts.VisibleText);
            if (text != null)
                await SaveTextAsync(set, "source_visible_text.txt", text, EvidenceCategory.Source, "Visible text of the page (document.body.innerText) with its title");
        }

        // 3. style sheets: the files as received, plus what the browser exposes (inline and adopted sheets)
        if (cap.SaveStylesheets)
        {
            var index = new List<object>();
            var cssBodies = bodies.Where(b => b.IsCss).ToList();
            if (cssBodies.Count > cap.MaxStylesheetCount)
                Warn(set, warnings, $"The page loaded {cssBodies.Count} style sheets; only the first {cap.MaxStylesheetCount} are saved (capture.source.maxStylesheetCount).");
            foreach (var b in cssBodies.Take(cap.MaxStylesheetCount))
            {
                if (b.Length > cap.MaxStylesheetBytes)
                {
                    Warn(set, warnings, $"Style sheet not saved (larger than capture.source.maxStylesheetBytes): {b.Url} ({b.Length} bytes, SHA-256 {b.Sha256}).");
                    continue;
                }
                var name = $"css/{b.Order:D3}_{JsonUtil.SafeName(LastSegment(b.Url), 60)}";
                if (!name.EndsWith(".css", StringComparison.OrdinalIgnoreCase)) name += ".css";
                await SaveAsync(set, name, b.Bytes, EvidenceCategory.Stylesheet, $"Style sheet as received: {b.Url}");
                index.Add(new { file = name, b.Url, b.Status, b.ContentType, b.Sha256, b.Length });
            }
            foreach (var b in bodies.Where(b => b.IsHtml && !ReferenceEquals(b, main)))
            {
                var name = $"html_frames/{b.Order:D3}_{JsonUtil.SafeName(LastSegment(b.Url), 60)}.html";
                await SaveAsync(set, name, b.Bytes, EvidenceCategory.Source, $"HTML document loaded by the page (frame or sub-document) as received: {b.Url}");
                index.Add(new { file = name, b.Url, b.Status, b.ContentType, b.Sha256, b.Length });
            }
            if (index.Count > 0)
                await SaveJsonAsync(set, "source_bodies_index.json", index, EvidenceCategory.Source, "Index of the HTML / CSS bodies saved above");

            var cssom = await _browser.EvalStringAsync(PageScripts.StyleSheets);
            if (cssom != null)
                await SaveTextAsync(set, "stylesheets_cssom.json", PrettyJson(cssom), EvidenceCategory.Stylesheet,
                    "Every style sheet of the document as exposed by the browser (external, inline, adopted); cross-origin sheets report an access error");
        }
    }

    private static string FormatMainResponse(NetResource r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Request          : {r.Method} {r.Url}");
        sb.AppendLine($"Final URL        : {r.ResponseUrl ?? r.Url}");
        sb.AppendLine($"Status           : {r.Status} {r.StatusText}");
        sb.AppendLine($"Protocol         : {r.Protocol}");
        sb.AppendLine($"Server address   : {r.RemoteIp}:{r.RemotePort}");
        sb.AppendLine($"MIME type        : {r.MimeType}");
        sb.AppendLine($"Served from cache: {(r.FromCache ? "yes" : "no")}");
        if (r.Redirects.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Redirect chain:");
            foreach (var step in r.Redirects)
                sb.AppendLine($"  {step.Status}  {step.Url}  ->  {step.Location}");
        }
        sb.AppendLine();
        sb.AppendLine("Response headers:");
        foreach (var h in r.ResponseHeaders.OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase))
            sb.AppendLine($"  {h.Key}: {h.Value.Replace("\n", "\n    ")}");
        return sb.ToString();
    }

    private static string LastSegment(string url)
    {
        try
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out var u))
            {
                var seg = u.Segments.LastOrDefault()?.Trim('/');
                return string.IsNullOrEmpty(seg) ? u.IdnHost : seg;
            }
        }
        catch { /* use the fallback */ }
        return "resource";
    }

    private static string PrettyJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return JsonSerializer.Serialize(doc.RootElement, JsonUtil.Options) + "\n";
        }
        catch { return json; }
    }

    // ---------------------------------------------------------------------------------------------- archive

    private async Task ArchiveAsync(CaptureSet set, List<string> warnings, IProgress<string>? progress)
    {
        var cap = Cfg.Capture.Archive;

        if (cap.SaveMhtml)
        {
            progress?.Report("Creating the MHTML snapshot…");
            try
            {
                using var doc = JsonDocument.Parse(await _browser.CdpAsync("Page.captureSnapshot", "{\"format\":\"mhtml\"}"));
                var data = doc.RootElement.GetProperty("data").GetString();
                if (!string.IsNullOrEmpty(data))
                    await SaveTextAsync(set, "page_snapshot.mhtml", data, EvidenceCategory.Archive,
                        "Single-file MHTML snapshot of the page and its sub-resources (images, style sheets, scripts)");
            }
            catch (Exception ex) { Warn(set, warnings, "The MHTML snapshot could not be created: " + ex.Message); }
        }

        if (cap.SavePdf)
        {
            progress?.Report("Creating the PDF rendering…");
            try
            {
                var settings = _browser.WebCore.Environment.CreatePrintSettings();
                settings.ShouldPrintBackgrounds = true;
                settings.ShouldPrintHeaderAndFooter = false;
                var letter = string.Equals(cap.PdfPaperSize, "Letter", StringComparison.OrdinalIgnoreCase);
                settings.PageWidth = letter ? 8.5 : 8.27;
                settings.PageHeight = letter ? 11.0 : 11.69;

                byte[] pdf;
                using (var stream = await _browser.WebCore.PrintToPdfStreamAsync(settings))
                using (var ms = new MemoryStream())
                {
                    await stream.CopyToAsync(ms);
                    pdf = ms.ToArray();
                }
                await SaveAsync(set, "page_print.pdf", pdf, EvidenceCategory.Archive, $"PDF rendering of the page ({cap.PdfPaperSize}, print layout)");
            }
            catch (Exception ex) { Warn(set, warnings, "The PDF rendering could not be created: " + ex.Message); }
        }
    }

    // ---------------------------------------------------------------------------------------------- connection data

    private async Task ConnectionAsync(CaptureSet set, List<string> warnings, IProgress<string>? progress, CancellationToken ct)
    {
        var rec = Cfg.Capture.DomainRecord;
        var recorder = _browser.Recorder;
        var main = recorder?.MainDocument();

        if ((rec.IncludeDns || rec.IncludeTls || rec.IncludeTraceroute) && Uri.TryCreate(set.Url, UriKind.Absolute, out var uri))
        {
            progress?.Report("Recording DNS and TLS information…");
            var host = uri.IdnHost.Trim('[', ']');
            var useTls = rec.IncludeTls && uri.Scheme == Uri.UriSchemeHttps;
            var target = await TargetDiagnostics.CollectAsync(host, uri.Port, useTls, rec.IncludeDns, rec.IncludeTraceroute, Cfg.Network, ct);

            await SaveJsonAsync(set, "connection.json", new
            {
                schemaVersion = 1,
                host,
                note = "The DNS answer and the TLS handshake below were obtained by this workstation, independently of the browser. " +
                       "'observedByBrowser' is what the browser reported for the main document.",
                resolvedAndProbedByWorkstation = target,
                observedByBrowser = main == null ? null : new
                {
                    main.RemoteIp,
                    main.RemotePort,
                    main.Protocol,
                    main.Status,
                    securityDetails = main.SecurityDetails
                }
            }, EvidenceCategory.Connection, "DNS resolution, TLS handshake and certificate obtained by the workstation, and the server address seen by the browser");

            await SaveTextAsync(set, "connection.txt", TargetDiagnostics.RenderText(target), EvidenceCategory.Connection,
                "Readable form of the DNS / TLS / route record of the target host");

            if (target.Tls is { Ok: true } tls && !string.IsNullOrWhiteSpace(tls.LeafCertificatePem))
            {
                var pem = new StringBuilder();
                pem.AppendLine($"# Subject : {tls.Subject}");
                pem.AppendLine($"# Issuer  : {tls.Issuer}");
                pem.AppendLine($"# Valid   : {tls.NotBefore} - {tls.NotAfter}");
                pem.AppendLine($"# SHA-256 : {tls.Sha256Fingerprint}");
                pem.AppendLine(tls.LeafCertificatePem.Trim());
                await SaveTextAsync(set, "tls_server_certificate.pem", pem.ToString() + "\n", EvidenceCategory.Connection,
                    "TLS server certificate presented to the workstation (PEM, with subject / issuer / validity / SHA-256 fingerprint)");
            }
            else if (target.Tls is { Ok: false } failed)
            {
                Warn(set, warnings, "The TLS handshake of the workstation failed: " + failed.Error);
            }
            if (target.DnsError != null) Warn(set, warnings, "DNS resolution by the workstation failed: " + target.DnsError);
        }

        var cookieCfg = Cfg.Capture.Cookies;
        if (cookieCfg.SaveCookieList)
        {
            progress?.Report("Recording cookies…");
            var cookies = await _browser.WebCore.CookieManager.GetCookiesAsync(null);
            var rows = cookies.Select(c => new
            {
                c.Name,
                c.Domain,
                c.Path,
                expires = c.IsSession ? null : (DateTime?)c.Expires.ToUniversalTime(),
                c.IsSession,
                c.IsHttpOnly,
                c.IsSecure,
                sameSite = c.SameSite.ToString(),
                valueLength = c.Value.Length,
                valueSha256 = HashEngine.Sha256HexOfString(c.Value),
                value = cookieCfg.StoreCookieValues ? c.Value : null
            }).ToList();
            await SaveJsonAsync(set, "cookies.json", new
            {
                schemaVersion = 1,
                note = cookieCfg.StoreCookieValues
                    ? "Cookie values are stored (capture.cookies.storeCookieValues = true): treat this file as confidential."
                    : "Cookie values are NOT stored (capture.cookies.storeCookieValues = false): only name, attributes, value length and SHA-256 of the value.",
                count = rows.Count,
                cookies = rows
            }, EvidenceCategory.Connection, $"Cookies held by the browser after loading the page ({rows.Count})");
        }

        if (Cfg.Capture.Source.SaveResourceJournal && recorder != null)
        {
            progress?.Report("Saving the network log…");
            var resources = recorder.Resources();
            await SaveJsonAsync(set, "network_resources.json", new
            {
                schemaVersion = 1,
                pageUrl = recorder.PageUrl,
                pageStartedUtc = recorder.PageStartedUtc,
                count = resources.Count,
                resources
            }, EvidenceCategory.Log, $"Every request made by the page and the response seen by the browser (URL, status, MIME type, server address, protocol, TLS details): {resources.Count} entries");

            var logPath = Path.Combine(set.Folder, "network_log.jsonl");
            var written = await Task.Run(() => recorder.CopyPageLogTo(logPath));
            if (written > 0)
            {
                var item = await Task.Run(() => _s.Registry.Add(logPath, EvidenceCategory.Log, 3,
                    "Raw browser network events of this page (JSON lines, NTP-corrected timestamps; cookie values and credentials masked)", set.Url, set.Seq));
                lock (set.EvidenceIds) set.EvidenceIds.Add(item.Id);
            }
            else File.Delete(logPath);
        }
    }

    // ---------------------------------------------------------------------------------------------- whois

    private async Task WhoisAsync(CaptureSet set, IProgress<string>? progress, CancellationToken ct)
    {
        if (!Cfg.Capture.DomainRecord.IncludeWhois) { Note(set, "WHOIS / RDAP lookups are disabled in config.json (capture.domainRecord.includeWhois)."); return; }
        progress?.Report("Looking up the domain and server ownership (WHOIS / RDAP)…");
        var results = await _whois.LookupForUrlAsync(set.Url, ServerAddresses(set.Url), force: false, ct);
        Note(set, results.Count == 0
            ? "WHOIS / RDAP: nothing new to look up (already recorded earlier in this session)."
            : $"WHOIS / RDAP: {results.Count} lookup(s) recorded in 04_whois ({string.Join(", ", results.Select(r => $"{r.Source} {r.Subject}" + (r.Found ? "" : " (no record)")))}).");
    }

    /// <summary>Addresses of the server as seen by the browser for the current page.</summary>
    public IEnumerable<string> ServerAddresses(string url)
    {
        var ips = new List<string>();
        var ip = _browser.Recorder?.MainDocument()?.RemoteIp;
        if (!string.IsNullOrWhiteSpace(ip)) ips.Add(ip.Trim('[', ']'));
        return ips.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------------------------------------- closing

    private async Task<int> FinishAsync(CaptureSet set, CaptureParts parts, List<string> warnings)
    {
        set.FinishedUtc = TrustedClock.UtcNow;

        List<EvidenceItem> items;
        lock (set.EvidenceIds)
        {
            var ids = new HashSet<long>(set.EvidenceIds);
            items = _s.Registry.Items.Where(i => ids.Contains(i.Id)).OrderBy(i => i.RelativePath, StringComparer.Ordinal).ToList();
        }

        var summary = new
        {
            schemaVersion = 1,
            set.Seq,
            set.Label,
            set.Url,
            set.Title,
            set.StartedUtc,
            set.FinishedUtc,
            parts = parts.ToString(),
            clockSynchronised = TrustedClock.IsSynchronized,
            clockOffsetMs = TrustedClock.OffsetMs is { } off ? Math.Round(off, 1) : (double?)null,
            operatorNote = set.OperatorNote,
            notes = set.Notes.ToList(),
            warnings,
            files = items.Select(i => new { path = i.RelativePath, i.Category, i.SizeBytes, i.Sha256, i.Description }).ToList()
        };
        try
        {
            await SaveJsonAsync(set, "capture.json", summary, EvidenceCategory.Other, "Summary of this capture: parts, notes, warnings and the list of files with their SHA-256");
        }
        catch (Exception ex)
        {
            _s.Audit.Error(3, "capture.summary", "capture.json could not be written: " + ex.Message);
        }

        _s.Audit.Log(warnings.Count == 0 ? AuditLevel.Info : AuditLevel.Warn, 3, "capture.end",
            $"Capture #{set.Seq:D4} finished: {items.Count} file(s), {warnings.Count} warning(s)",
            new Dictionary<string, object?> { ["capture"] = set.Seq, ["folder"] = set.RelativeFolder, ["files"] = items.Count, ["warnings"] = warnings.Count });
        return items.Count + 1;
    }
}
