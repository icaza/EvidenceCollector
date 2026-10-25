using EvidenceCollector.Config;
using EvidenceCollector.Core;
using Microsoft.Web.WebView2.Core;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace EvidenceCollector.Browser;

public sealed class RedirectStep
{
    public string Url { get; set; } = "";
    public int Status { get; set; }
    public string? Location { get; set; }
}

/// <summary>What the browser itself observed for one request (Chrome DevTools "Network" domain).</summary>
public sealed class NetResource
{
    public string RequestId { get; set; } = "";
    public string Url { get; set; } = "";
    public string Method { get; set; } = "";
    public string Type { get; set; } = "";
    public string FrameId { get; set; } = "";
    public DateTime StartedUtc { get; set; }
    public int Status { get; set; }
    public string? StatusText { get; set; }
    public string? ResponseUrl { get; set; }
    public string? MimeType { get; set; }
    public string? RemoteIp { get; set; }
    public int RemotePort { get; set; }
    public string? Protocol { get; set; }
    public bool FromCache { get; set; }
    public bool Finished { get; set; }
    public bool Failed { get; set; }
    public string? Error { get; set; }
    public long EncodedBytes { get; set; }
    public List<RedirectStep> Redirects { get; } = [];
    public Dictionary<string, string> ResponseHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>TLS details as reported by the browser (protocol, cipher, issuer, validity, SCTs…).</summary>
    public JsonElement? SecurityDetails { get; set; }
}

/// <summary>An HTML or CSS response body exactly as the browser received it (after transfer decoding).</summary>
public sealed class RecordedBody
{
    public int Order { get; set; }
    public string Url { get; set; } = "";
    public int Status { get; set; }
    public string ContentType { get; set; } = "";
    public bool IsHtml { get; set; }
    public bool IsCss { get; set; }
    public DateTime ReceivedUtc { get; set; }
    public string Sha256 { get; set; } = "";
    [JsonIgnore] public byte[] Bytes { get; set; } = [];
    public long Length => Bytes.LongLength;
}

/// <summary>
/// Records the network activity of the page in the evidence browser:
///  - every DevTools Network event is appended, with an NTP-corrected timestamp, to a private temp file (JSON lines);
///    a capture copies the part that belongs to the current page;
///  - a table of requests/responses (URL, status, MIME type, server IP, protocol, TLS details, redirects);
///  - the raw HTML and CSS response bodies (bounded by capture.maxCachedBodyMb).
/// Secrets (Authorization, cookie values unless capture.storeCookieValues is true) are masked in the log.
/// </summary>
public sealed class NetworkRecorder : IDisposable
{
    private static readonly JsonSerializerOptions NodeJson = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static readonly string[] Events =
    {
        "Network.requestWillBeSent", "Network.requestWillBeSentExtraInfo", "Network.responseReceived",
        "Network.responseReceivedExtraInfo", "Network.loadingFinished", "Network.loadingFailed", "Network.requestServedFromCache"
    };

    private readonly CoreWebView2 _core;
    private readonly AppConfig _cfg;
    private readonly AuditLog? _audit;
    private readonly Func<int> _phase;
    private readonly object _gate = new();
    private readonly Dictionary<string, NetResource> _resources = [];
    private readonly List<string> _order = [];
    private readonly List<RecordedBody> _bodies = [];
    private readonly List<CoreWebView2DevToolsProtocolEventReceiver> _receivers = [];
    private readonly string _livePath;
    private readonly bool _redactCookies;
    private StreamWriter? _writer;
    private long _written;
    private long _pageStart;
    private long _bodyBytes;
    private int _bodyOrder;
    private bool _bodyCapWarned;
    private bool _journalCapWarned;
    private int _cssCount;
    private string _mainFrameId = "";
    private string? _mainDocRequestId;
    private bool _started;
    private bool _disposed;

    public NetworkRecorder(CoreWebView2 core, AppConfig cfg, string workFolder, AuditLog? audit, Func<int> phase)
    {
        _core = core;
        _cfg = cfg;
        _audit = audit;
        _phase = phase;
        _redactCookies = !cfg.Capture.Cookies.StoreCookieValues;
        Directory.CreateDirectory(workFolder);
        _livePath = Path.Combine(workFolder, Guid.NewGuid().ToString("N") + ".jsonl");
        _writer = new StreamWriter(new FileStream(_livePath, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite, 64 * 1024),
            new UTF8Encoding(false))
        { NewLine = "\n", AutoFlush = false };
    }

    public string? PageUrl { get; private set; }
    public DateTime PageStartedUtc { get; private set; }
    public int EventCount { get; private set; }

    public async Task StartAsync()
    {
        if (_started) return;
        _started = true;
        foreach (var name in Events)
        {
            var receiver = _core.GetDevToolsProtocolEventReceiver(name);
            var evt = name;
            receiver.DevToolsProtocolEventReceived += (_, e) => OnEvent(evt, e.ParameterObjectAsJson);
            _receivers.Add(receiver);
        }
        await _core.CallDevToolsProtocolMethodAsync("Network.enable", "{}");
        if (_cfg.WebView.DisableCache)
            await _core.CallDevToolsProtocolMethodAsync("Network.setCacheDisabled", "{\"cacheDisabled\":true}");
        await RefreshMainFrameAsync();
        _core.WebResourceResponseReceived += OnWebResourceResponseReceived;
    }

    private async Task RefreshMainFrameAsync()
    {
        try
        {
            var json = await _core.CallDevToolsProtocolMethodAsync("Page.getFrameTree", "{}");
            using var doc = JsonDocument.Parse(json);
            _mainFrameId = doc.RootElement.GetProperty("frameTree").GetProperty("frame").GetProperty("id").GetString() ?? "";
        }
        catch { /* the main document is then recognised by its type only */ }
    }

    /// <summary>Called when the main frame starts a navigation to another document: the per-page tables restart.</summary>
    public void BeginPage(string url)
    {
        lock (_gate)
        {
            _writer?.Flush();
            _pageStart = _written;
            _resources.Clear();
            _order.Clear();
            _bodies.Clear();
            _bodyBytes = 0;
            _bodyOrder = 0;
            _bodyCapWarned = false;
            _journalCapWarned = false;
            _cssCount = 0;
            _mainDocRequestId = null;
            PageUrl = url;
            PageStartedUtc = TrustedClock.UtcNow;
        }
        _ = RefreshMainFrameAsync();
    }

    // ------------------------------------------------------------------------ DevTools events

    private void OnEvent(string method, string json)
    {
        if (_disposed) return;
        try
        {
            var line = Redactor.Apply(json, _redactCookies);
            lock (_gate)
            {
                if (_writer == null) return;
                var text = $"{{\"t\":\"{TrustedClock.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture)}\",\"m\":\"{method}\",\"p\":{line}}}";
                _writer.Write(text);
                _writer.Write('\n');
                _written += Encoding.UTF8.GetByteCount(text) + 1;
                EventCount++;
            }
            Track(method, json);
        }
        catch (Exception ex)
        {
            Warn("network.record", "A network event could not be recorded: " + ex.Message);
        }
    }

    private void Track(string method, string json)
    {
        using var doc = JsonDocument.Parse(json);
        var p = doc.RootElement;
        var id = Str(p, "requestId");
        if (id == null) return;

        lock (_gate)
        {
            switch (method)
            {
                case "Network.requestWillBeSent":
                    {
                        if (!_resources.TryGetValue(id, out var r))
                        {
                            if (_resources.Count >= _cfg.WebView.NetworkJournalMaxEntries)
                            {
                                if (!_journalCapWarned)
                                {
                                    _journalCapWarned = true;
                                    Warn("network.journal-cap", $"More than {_cfg.WebView.NetworkJournalMaxEntries} requests for this page (webView.networkJournalMaxEntries): the request table stops growing; the raw event log keeps everything.");
                                }
                                break;
                            }
                            r = new NetResource { RequestId = id, StartedUtc = TrustedClock.UtcNow };
                            _resources[id] = r;
                            _order.Add(id);
                        }
                        if (p.TryGetProperty("redirectResponse", out var rr) && rr.ValueKind == JsonValueKind.Object)
                        {
                            string? loc = null;
                            if (rr.TryGetProperty("headers", out var hs) && hs.ValueKind == JsonValueKind.Object)
                                foreach (var h in hs.EnumerateObject())
                                    if (h.Name.Equals("location", StringComparison.OrdinalIgnoreCase)) loc = h.Value.GetString();
                            r.Redirects.Add(new RedirectStep { Url = Str(rr, "url") ?? "", Status = Int(rr, "status"), Location = loc });
                        }
                        if (p.TryGetProperty("request", out var req))
                        {
                            r.Url = Str(req, "url") ?? r.Url;
                            r.Method = Str(req, "method") ?? r.Method;
                        }
                        r.Type = Str(p, "type") ?? r.Type;
                        r.FrameId = Str(p, "frameId") ?? r.FrameId;
                        if (r.Type == "Document" && (r.FrameId == _mainFrameId || _mainFrameId.Length == 0))
                            _mainDocRequestId = id;
                        break;
                    }
                case "Network.responseReceived":
                    {
                        if (!_resources.TryGetValue(id, out var r)) break;
                        r.Type = Str(p, "type") ?? r.Type;
                        if (!p.TryGetProperty("response", out var resp)) break;
                        r.ResponseUrl = Str(resp, "url");
                        r.Status = Int(resp, "status");
                        r.StatusText = Str(resp, "statusText");
                        r.MimeType = Str(resp, "mimeType");
                        r.RemoteIp = Str(resp, "remoteIPAddress");
                        r.RemotePort = Int(resp, "remotePort");
                        r.Protocol = Str(resp, "protocol");
                        r.FromCache = Bool(resp, "fromDiskCache") || Bool(resp, "fromPrefetchCache") || Bool(resp, "fromServiceWorker");
                        if (resp.TryGetProperty("securityDetails", out var sd) && sd.ValueKind == JsonValueKind.Object) r.SecurityDetails = sd.Clone();
                        if (resp.TryGetProperty("headers", out var hdrs) && hdrs.ValueKind == JsonValueKind.Object)
                            foreach (var h in hdrs.EnumerateObject())
                            {
                                var name = h.Name;
                                var value = h.Value.ValueKind == JsonValueKind.String ? h.Value.GetString() ?? "" : h.Value.ToString();
                                if (name.Equals("set-cookie", StringComparison.OrdinalIgnoreCase) && _redactCookies) value = Redactor.MaskSetCookie(value);
                                r.ResponseHeaders[name] = value;
                            }
                        break;
                    }
                case "Network.loadingFinished":
                    if (_resources.TryGetValue(id, out var fin)) { fin.Finished = true; fin.EncodedBytes = (long)Dbl(p, "encodedDataLength"); }
                    break;
                case "Network.loadingFailed":
                    if (_resources.TryGetValue(id, out var bad))
                    {
                        bad.Failed = true;
                        bad.Error = Str(p, "errorText") + (Str(p, "blockedReason") is { } br ? " (blocked: " + br + ")" : "");
                    }
                    break;
            }
        }
    }

    // ------------------------------------------------------------------------ bodies

    private async void OnWebResourceResponseReceived(object? sender, CoreWebView2WebResourceResponseReceivedEventArgs e)
    {
        try
        {
            if (_disposed) return;
            var status = e.Response.StatusCode;
            if (status is >= 300 and < 400 or 204 or 304) return;

            string contentType = "";
            long declared = -1;
            foreach (var h in e.Response.Headers)
            {
                if (h.Key.Equals("content-type", StringComparison.OrdinalIgnoreCase)) contentType = h.Value;
                else if (h.Key.Equals("content-length", StringComparison.OrdinalIgnoreCase)) long.TryParse(h.Value, out declared);
            }
            var lower = contentType.ToLowerInvariant();
            var isHtml = lower.Contains("text/html") || lower.Contains("application/xhtml");
            var isCss = lower.Contains("text/css");
            if (!isHtml && !isCss) return;
            var src = _cfg.Capture.Source;
            if (isCss && !src.SaveStylesheets) return;
            if (isHtml && !src.SaveRawResponseBody) return;

            var cap = src.MaxCachedBodyMb * 1024L * 1024L;
            var url = e.Request.Uri;
            if (declared > 0 && Interlocked.Read(ref _bodyBytes) + declared > cap) { WarnCap(url); return; }

            using var stream = await e.Response.GetContentAsync();
            if (stream == null) return;
            using var ms = new MemoryStream();
            var buffer = new byte[64 * 1024];
            int n;
            while ((n = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, n);
                if (Interlocked.Read(ref _bodyBytes) + ms.Length > cap) { WarnCap(url); return; }
            }
            var bytes = ms.ToArray();
            lock (_gate)
            {
                if (isCss && (bytes.Length > src.MaxStylesheetBytes || _cssCount >= src.MaxStylesheetCount))
                {
                    Warn("network.css-cap", $"Style sheet not kept (capture.source.maxStylesheetBytes / maxStylesheetCount): {url}");
                    return;
                }
                if (isCss) _cssCount++;
                _bodyBytes += bytes.Length;
                _bodies.Add(new RecordedBody
                {
                    Order = ++_bodyOrder,
                    Url = url,
                    Status = status,
                    ContentType = contentType,
                    IsHtml = isHtml,
                    IsCss = isCss,
                    ReceivedUtc = TrustedClock.UtcNow,
                    Bytes = bytes,
                    Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()
                });
            }
        }
        catch
        {
            // A body that cannot be read (served from cache, aborted, …) is simply not available; the rendered DOM is saved anyway.
        }
    }

    private void WarnCap(string url)
    {
        if (_bodyCapWarned) return;
        _bodyCapWarned = true;
        Warn("network.body-cap", $"Response bodies exceed capture.source.maxCachedBodyMb ({_cfg.Capture.Source.MaxCachedBodyMb} MB): '{url}' and later HTML/CSS bodies are not kept.");
    }

    private void Warn(string code, string message) => _audit?.TryAppend(AuditLevel.Warn, _phase(), code, message);

    // ------------------------------------------------------------------------ results

    public IReadOnlyList<NetResource> Resources()
    {
        lock (_gate) return [.. _order.Select(i => _resources[i])];
    }

    public IReadOnlyList<RecordedBody> Bodies()
    {
        lock (_gate) return _bodies.ToList();
    }

    public NetResource? MainDocument()
    {
        lock (_gate)
        {
            if (_mainDocRequestId != null && _resources.TryGetValue(_mainDocRequestId, out var r)) return r;
            return _order.Select(i => _resources[i]).LastOrDefault(r => r.Type == "Document" && r.Status > 0);
        }
    }

    /// <summary>The raw HTML body of the main document: the body recorded for the final URL of the main request.</summary>
    public RecordedBody? MainDocumentBody()
    {
        var main = MainDocument();
        lock (_gate)
        {
            if (main != null)
            {
                var wanted = StripFragment(main.ResponseUrl ?? main.Url);
                var match = _bodies.LastOrDefault(b => b.IsHtml && StripFragment(b.Url).Equals(wanted, StringComparison.OrdinalIgnoreCase));
                if (match != null) return match;
            }
            return null;
        }
    }

    /// <summary>Copies the log lines of the current page (since its main navigation started) to <paramref name="destination"/>.</summary>
    public long CopyPageLogTo(string destination)
    {
        long start, end;
        lock (_gate)
        {
            _writer?.Flush();
            start = _pageStart;
            end = _written;
        }
        using var src = new FileStream(_livePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var dst = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        src.Seek(start, SeekOrigin.Begin);
        var buffer = new byte[64 * 1024];
        var left = end - start;
        while (left > 0)
        {
            var n = src.Read(buffer, 0, (int)Math.Min(buffer.Length, left));
            if (n <= 0) break;
            dst.Write(buffer, 0, n);
            left -= n;
        }
        return end - start - left;
    }

    public static string StripFragment(string url)
    {
        var i = url.IndexOf('#');
        return i < 0 ? url : url[..i];
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static int Int(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : 0;

    private static double Dbl(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0;

    private static bool Bool(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _core.WebResourceResponseReceived -= OnWebResourceResponseReceived; } catch { /* browser already gone */ }
        lock (_gate)
        {
            try { _writer?.Flush(); _writer?.Dispose(); } catch { /* ignore */ }
            _writer = null;
        }
    }

    // ------------------------------------------------------------------------ redaction

    internal static class Redactor
    {
        public static string Apply(string json, bool maskCookies)
        {
            if (json.IndexOf("cookie", StringComparison.Ordinal) < 0 && json.IndexOf("authorization", StringComparison.OrdinalIgnoreCase) < 0)
                return json;
            try
            {
                var node = JsonNode.Parse(json);
                Walk(node, maskCookies);
                return node?.ToJsonString(NodeJson) ?? "null";
            }
            catch
            {
                return "{\"redactionError\":true}"; // never write an event that could not be screened
            }
        }

        private static void Walk(JsonNode? n, bool maskCookies)
        {
            switch (n)
            {
                case JsonObject o:
                    foreach (var kv in o.ToList())
                    {
                        if (kv.Value is JsonValue v && v.TryGetValue<string>(out var s))
                        {
                            if (kv.Key.Equals("authorization", StringComparison.OrdinalIgnoreCase) || kv.Key.Equals("proxy-authorization", StringComparison.OrdinalIgnoreCase))
                                o[kv.Key] = MaskAuthorization(s);
                            else if (maskCookies && kv.Key.Equals("cookie", StringComparison.OrdinalIgnoreCase))
                                o[kv.Key] = MaskCookieHeader(s);
                            else if (maskCookies && kv.Key.Equals("set-cookie", StringComparison.OrdinalIgnoreCase))
                                o[kv.Key] = MaskSetCookie(s);
                        }
                        else Walk(kv.Value, maskCookies);
                    }
                    // CDP cookie objects: { name, value, domain, path, … }
                    if (maskCookies && o.ContainsKey("name") && o.ContainsKey("value") && (o.ContainsKey("domain") || o.ContainsKey("path")) &&
                        o["value"] is JsonValue cv && cv.TryGetValue<string>(out var cval))
                        o["value"] = Mask(cval);
                    break;
                case JsonArray a:
                    foreach (var item in a) Walk(item, maskCookies);
                    break;
            }
        }

        public static string Mask(string value) =>
            $"[masked len={value.Length} sha256={Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant()[..16]}]";

        private static string MaskAuthorization(string value)
        {
            var sp = value.IndexOf(' ');
            return sp > 0 ? value[..sp] + " " + Mask(value[(sp + 1)..]) : Mask(value);
        }

        /// <summary>"a=1; b=2" → "a=[masked…]; b=[masked…]" (cookie names stay visible, values do not).</summary>
        private static string MaskCookieHeader(string value) =>
            string.Join("; ", value.Split(';', StringSplitOptions.RemoveEmptyEntries).Select(pair =>
            {
                var t = pair.Trim();
                var eq = t.IndexOf('=');
                return eq > 0 ? t[..(eq + 1)] + Mask(t[(eq + 1)..]) : t;
            }));

        /// <summary>One Set-Cookie header per line: the value is masked, the name and attributes are kept.</summary>
        public static string MaskSetCookie(string value) =>
            string.Join("\n", value.Split('\n').Select(line =>
            {
                var semi = line.IndexOf(';');
                var first = semi < 0 ? line : line[..semi];
                var rest = semi < 0 ? "" : line[semi..];
                var eq = first.IndexOf('=');
                return eq > 0 ? first[..(eq + 1)] + Mask(first[(eq + 1)..]) + rest : line;
            }));
    }
}
