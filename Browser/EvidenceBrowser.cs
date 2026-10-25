using EvidenceCollector.Config;
using EvidenceCollector.Core;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using System.Text.Json;

namespace EvidenceCollector.Browser;

/// <summary>
/// The controlled browser. Wraps the WebView2 control with the settings an evidence collection needs:
/// private profile in a temporary folder (InPrivate by default), direct connection, no cache, no autofill,
/// no downloads, no permission grants, restricted URL schemes, one single window, and a complete audit trail
/// of navigation. All members must be called on the UI thread.
/// </summary>
public sealed class EvidenceBrowser(WebView2 view, SessionContext session) : IDisposable
{
    private readonly WebView2 _view = view;
    private readonly SessionContext _session = session;
    private TaskCompletionSource<bool>? _navigationTcs;
    private bool _disposed;

    private AppConfig Cfg => _session.Config;
    private WebViewConfig Web => _session.Config.WebView;

    public NetworkRecorder? Recorder { get; private set; }
    public string UserDataFolder { get; private set; } = "";
    public string? RuntimeVersion { get; private set; }
    public string UserAgent { get; private set; } = "";

    /// <summary>Phase number written into audit entries produced by browser events (the form updates it when the phase changes).</summary>
    public int AuditPhase { get; set; } = 1;
    public bool IsReady { get; private set; }
    public bool IsNavigating { get; private set; }

    /// <summary>While true every navigation is refused (set during a capture so it describes one single page state).</summary>
    public bool Locked { get; set; }

    public CoreWebView2 WebCore => _view.CoreWebView2 ?? throw new InvalidOperationException("The browser is not initialised.");
    public string CurrentUrl => _view.CoreWebView2?.Source ?? "";
    public string CurrentTitle => _view.CoreWebView2?.DocumentTitle ?? "";
    public bool CanGoBack => _view.CoreWebView2?.CanGoBack ?? false;
    public bool CanGoForward => _view.CoreWebView2?.CanGoForward ?? false;

    /// <summary>Raised when the URL, title, loading state or history changed (UI thread).</summary>
    public event EventHandler? StateChanged;

    /// <summary>Raised for events the operator should see immediately (blocked navigation, refused download...).</summary>
    public event Action<string>? Notice;

    /// <summary>Raised on the UI thread each time a page finished loading successfully.</summary>
    public event Action<string>? PageLoaded;

    private void Log(AuditLevel level, string code, string message, object? data = null) =>
        _session.Audit.TryAppend(level, AuditPhase, code, message, data);

    // ------------------------------------------------------------------------ start-up

    public async Task InitializeAsync()
    {
        if (IsReady) return;

        try { RuntimeVersion = CoreWebView2Environment.GetAvailableBrowserVersionString(NullIfEmpty(Cfg.Paths.WebViewRuntimeFolder)); }
        catch (WebView2RuntimeNotFoundException)
        {
            throw new InvalidOperationException(
                "The Microsoft Edge WebView2 Runtime is not installed. Install the Evergreen runtime from " +
                "https://developer.microsoft.com/microsoft-edge/webview2/ and start the application again.");
        }
        _session.WebView2Version = RuntimeVersion;

        UserDataFolder = SecureTemp.CreateSessionFolder(AppConfig.ResolvePath(Cfg.Paths.TempRoot), _session.Info.SessionId);

        var options = new CoreWebView2EnvironmentOptions
        {
            AdditionalBrowserArguments = BuildArguments(),
            AllowSingleSignOnUsingOSPrimaryAccount = false // never present the Windows account to a visited site
        };
        if (!string.IsNullOrWhiteSpace(Web.Language)) options.Language = Web.Language.Trim();

        string? runtime = NullIfEmpty(Cfg.Paths.WebViewRuntimeFolder);
        CoreWebView2Environment env = await CoreWebView2Environment.CreateAsync(runtime, UserDataFolder, options);

        CoreWebView2ControllerOptions? controller = null;
        if (Web.InPrivateMode)
        {
            controller = env.CreateCoreWebView2ControllerOptions();
            controller.IsInPrivateModeEnabled = true;
        }

        // The control must have a window handle before it can host the browser, even when its tab page is not shown yet.
        _ = _view.Handle;
        await _view.EnsureCoreWebView2Async(env, controller);

        ConfigureSettings();
        HookEvents();
        UserAgent = WebCore.Settings.UserAgent;

        Recorder = new NetworkRecorder(WebCore, Cfg, SecureTemp.WorkFolder(UserDataFolder), _session.Audit, () => AuditPhase);
        await Recorder.StartAsync();

        IsReady = true;
        Log(AuditLevel.Info, "browser.ready", $"Evidence browser started (WebView2 runtime {RuntimeVersion})",
            new Dictionary<string, object?>
            {
                ["userDataFolder"] = UserDataFolder,
                ["inPrivate"] = Web.InPrivateMode,
                ["arguments"] = options.AdditionalBrowserArguments,
                ["userAgent"] = UserAgent,
                ["cacheDisabled"] = Web.DisableCache
            });
    }

    private static string? NullIfEmpty(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        return AppConfig.ResolvePath(s);
    }

    private string BuildArguments()
    {
        var args = new List<string>();
        if (Web.ForceDirectConnection) args.Add("--no-proxy-server");
        if (!string.IsNullOrWhiteSpace(Web.AdditionalBrowserArguments)) args.Add(Web.AdditionalBrowserArguments.Trim());
        return string.Join(" ", args);
    }

    private void ConfigureSettings()
    {
        CoreWebView2Settings s = WebCore.Settings;
        s.AreDevToolsEnabled = !Web.DisableDevTools;
        s.AreDefaultContextMenusEnabled = !Web.DisableContextMenu;
        s.IsPasswordAutosaveEnabled = false;
        s.IsGeneralAutofillEnabled = false;
        s.IsZoomControlEnabled = false; // a fixed 100% zoom keeps screenshots reproducible
        s.IsPinchZoomEnabled = false;
        s.IsSwipeNavigationEnabled = false;
        s.IsStatusBarEnabled = true;    // shows the target URL of a link under the pointer
        s.IsBuiltInErrorPageEnabled = true;
        s.AreHostObjectsAllowed = false;
        s.IsWebMessageEnabled = false;
        if (!string.IsNullOrWhiteSpace(Web.UserAgentOverride)) s.UserAgent = Web.UserAgentOverride.Trim();
        _view.ZoomFactor = 1.0;
    }

    /// <summary>Lets the runtime trim its memory while the window is minimised (config: webView.lowMemoryWhenMinimized).</summary>
    public void SetLowMemory(bool low)
    {
        if (!IsReady) return;
        try { WebCore.MemoryUsageTargetLevel = low ? CoreWebView2MemoryUsageTargetLevel.Low : CoreWebView2MemoryUsageTargetLevel.Normal; }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException or NotImplementedException) { /* older runtime */ }
    }

    private void HookEvents()
    {
        CoreWebView2 core = WebCore;

        core.NavigationStarting += (_, e) =>
        {
            if (Locked) { e.Cancel = true; return; }
            if (!IsAllowedTarget(e.Uri))
            {
                e.Cancel = true;
                Log(AuditLevel.Warn, "nav.blocked", $"Navigation blocked (scheme not allowed): {e.Uri}");
                _session.RecordNavigation("blocked", e.Uri, e.IsUserInitiated, e.IsRedirected, "scheme not allowed");
                Notice?.Invoke("Navigation blocked: only " + string.Join(", ", Web.AllowedSchemes) + " pages are allowed.");
                return;
            }
            IsNavigating = true;
            if (!e.IsRedirected && !IsSameDocument(CurrentUrl, e.Uri)) Recorder?.BeginPage(e.Uri);
            Log(AuditLevel.Info, "nav.start", $"Navigation started: {e.Uri}",
                new Dictionary<string, object?> { ["userInitiated"] = e.IsUserInitiated, ["redirect"] = e.IsRedirected, ["navigationId"] = e.NavigationId });
            _session.RecordNavigation("start", e.Uri, e.IsUserInitiated, e.IsRedirected);
            StateChanged?.Invoke(this, EventArgs.Empty);
        };

        core.NavigationCompleted += (_, e) =>
        {
            IsNavigating = false;
            bool ok = e.IsSuccess;
            Log(ok ? AuditLevel.Info : AuditLevel.Warn, "nav.complete",
                ok ? $"Page loaded: {core.Source}" : $"Navigation failed ({e.WebErrorStatus}): {core.Source}",
                new Dictionary<string, object?> { ["httpStatus"] = e.HttpStatusCode, ["title"] = core.DocumentTitle, ["webErrorStatus"] = e.WebErrorStatus.ToString() });
            _session.RecordNavigation(ok ? "complete" : "failed", core.Source, false, false, e.WebErrorStatus.ToString(), e.HttpStatusCode, core.DocumentTitle);
            _navigationTcs?.TrySetResult(ok);
            StateChanged?.Invoke(this, EventArgs.Empty);
            if (ok) PageLoaded?.Invoke(core.Source);
        };

        core.SourceChanged += (_, _) => StateChanged?.Invoke(this, EventArgs.Empty);
        core.DocumentTitleChanged += (_, _) => StateChanged?.Invoke(this, EventArgs.Empty);
        core.HistoryChanged += (_, _) => StateChanged?.Invoke(this, EventArgs.Empty);

        // One window only: a link that opens a new window loads in the same view (user gesture) or is refused (script).
        core.NewWindowRequested += (_, e) =>
        {
            e.Handled = true;
            if (Locked) return;
            if (e.IsUserInitiated || !Web.BlockPopupsWithoutUserGesture)
            {
                if (IsAllowedTarget(e.Uri))
                {
                    Log(AuditLevel.Info, "nav.newwindow", $"New-window request opened in the same view: {e.Uri}");
                    core.Navigate(e.Uri);
                }
                else Log(AuditLevel.Warn, "nav.blocked", $"New-window request blocked (scheme not allowed): {e.Uri}");
            }
            else
            {
                Log(AuditLevel.Warn, "nav.popup-blocked", $"Pop-up without user gesture blocked: {e.Uri}");
                Notice?.Invoke("A pop-up opened by the page without a user action was blocked.");
            }
        };

        core.DownloadStarting += (_, e) =>
        {
            if (Web.AllowDownloads)
            {
                Log(AuditLevel.Warn, "download.allowed", $"Download allowed by configuration (not part of the evidence package): {e.DownloadOperation.Uri}");
                return;
            }
            e.Cancel = true;
            e.Handled = true;
            Log(AuditLevel.Warn, "download.blocked", $"Download refused by the evidence browser: {e.DownloadOperation.Uri}");
            Notice?.Invoke("A download was refused. Files are not downloaded in the evidence browser.");
        };

        core.PermissionRequested += (_, e) =>
        {
            e.State = CoreWebView2PermissionState.Deny;
            Log(AuditLevel.Info, "permission.denied", $"Permission '{e.PermissionKind}' requested by {e.Uri} was denied",
                new Dictionary<string, object?> { ["userInitiated"] = e.IsUserInitiated });
        };

        core.ServerCertificateErrorDetected += (_, e) =>
        {
            // Default action is kept (the browser shows its warning page); the error is part of the record.
            Log(AuditLevel.Warn, "tls.error", $"Server certificate error ({e.ErrorStatus}) for {e.RequestUri}",
                new Dictionary<string, object?>
                {
                    ["subject"] = e.ServerCertificate?.Subject,
                    ["issuer"] = e.ServerCertificate?.Issuer,
                    ["validFrom"] = e.ServerCertificate?.ValidFrom.ToString("o"),
                    ["validTo"] = e.ServerCertificate?.ValidTo.ToString("o")
                });
        };

        core.ScriptDialogOpening += (_, e) =>
            Log(AuditLevel.Info, "page.dialog", $"The page opened a {e.Kind} dialog: {Truncate(e.Message, 300)}");

        core.ProcessFailed += (_, e) =>
            Log(AuditLevel.Error, "browser.process-failed", $"Browser process failed: {e.ProcessFailedKind} ({e.Reason})");
    }

    private bool IsAllowedTarget(string uri)
    {
        if (string.Equals(uri, "about:blank", StringComparison.OrdinalIgnoreCase)) return true;
        if (uri.StartsWith("chrome-error://chromewebdata", StringComparison.OrdinalIgnoreCase)) return true; // the browser's own error page
        return UrlValidator.IsNavigationAllowed(uri, Web, out _);
    }

    private static bool IsSameDocument(string current, string target) =>
        !string.IsNullOrEmpty(current) && NetworkRecorder.StripFragment(current).Equals(NetworkRecorder.StripFragment(target), StringComparison.OrdinalIgnoreCase)
        && target.Contains('#');

    // ------------------------------------------------------------------------ navigation

    public void Navigate(string url)
    {
        if (!IsReady) throw new InvalidOperationException("The browser is not ready.");
        WebCore.Navigate(url);
    }

    public void GoBack() { if (CanGoBack) WebCore.GoBack(); }
    public void GoForward() { if (CanGoForward) WebCore.GoForward(); }
    public void Reload() => WebCore.Reload();
    public void Stop() => WebCore.Stop();

    /// <summary>Navigates and waits until the navigation completed (or the timeout elapsed).</summary>
    public async Task<bool> NavigateAndWaitAsync(string url, int timeoutMs)
    {
        _navigationTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Navigate(url);
        Task done = await Task.WhenAny(_navigationTcs.Task, Task.Delay(timeoutMs));
        return done == _navigationTcs.Task && _navigationTcs.Task.Result;
    }

    /// <summary>Waits for <c>document.readyState == "complete"</c>; returns false when the timeout elapsed first.</summary>
    public async Task<bool> WaitForCompleteAsync(int timeoutMs, CancellationToken ct)
    {
        long deadline = Environment.TickCount64 + timeoutMs;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string? state = await EvalStringAsync(PageScripts.ReadyState);
                if (state == "complete" && !IsNavigating) return true;
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException or JsonException)
            { /* the page is between documents */ }
            if (Environment.TickCount64 >= deadline) return false;
            await Task.Delay(200, ct);
        }
    }

    // ------------------------------------------------------------------------ script / DevTools helpers

    /// <summary>Evaluates a script that returns a string; null when it returned null/undefined.</summary>
    public async Task<string?> EvalStringAsync(string script)
    {
        string json = await WebCore.ExecuteScriptAsync(script);
        if (string.IsNullOrEmpty(json) || json == "null") return null;
        return JsonSerializer.Deserialize<string>(json);
    }

    public Task<string> CdpAsync(string method, string parametersJson = "{}") =>
        WebCore.CallDevToolsProtocolMethodAsync(method, parametersJson);

    /// <summary>Evaluates an async script through DevTools (awaits its promise) and returns the string value.</summary>
    public async Task<string?> EvalAsyncStringAsync(string expression)
    {
        string p = JsonSerializer.Serialize(new { expression, awaitPromise = true, returnByValue = true });
        string json = await CdpAsync("Runtime.evaluate", p);
        using JsonDocument doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("exceptionDetails", out JsonElement ex))
            throw new InvalidOperationException("Script error: " + (ex.TryGetProperty("text", out JsonElement t) ? t.GetString() : "unknown"));
        JsonElement result = doc.RootElement.GetProperty("result");
        return result.TryGetProperty("value", out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    // ------------------------------------------------------------------------ Phase 1: neutralisation

    /// <summary>
    /// Clears every kind of browsing data of the profile (cache, cookies, local/session storage, IndexedDB, history,
    /// autofill, service workers...), resets the navigation history, and verifies the result.
    /// </summary>
    public async Task<BrowserCleanReport> CleanAsync(CancellationToken ct)
    {
        CoreWebView2 core = WebCore;
        var r = new BrowserCleanReport
        {
            UserDataFolder = UserDataFolder,
            WebView2Version = RuntimeVersion,
            ProfileBytesBefore = SecureTemp.GetFolderSize(UserDataFolder)
        };
        try { r.CookiesBefore = (await core.CookieManager.GetCookiesAsync(null)).Count; }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException)
        { r.Errors.Add("Cookies could not be counted before cleaning: " + ex.Message); }

        // 1. leave any page: nothing is left running that could write data while it is being deleted
        try
        {
            if (!string.Equals(core.Source, "about:blank", StringComparison.OrdinalIgnoreCase))
            {
                await NavigateAndWaitAsync("about:blank", 8000);
                r.Steps.Add("Navigated to about:blank (no page is running while the data is deleted).");
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException)
        { r.Errors.Add("Navigation to about:blank failed: " + ex.Message); }
        ct.ThrowIfCancellationRequested();

        // 2. profile API: the kinds of browsing data selected in config.json (all of them by default)
        NeutralizationConfig n = Cfg.Neutralization;
        r.CookiesExpectedEmpty = n.ClearCookies;
        try
        {
            CoreWebView2BrowsingDataKinds kinds;
            string described;
            if (n.ClearCache && n.ClearCookies && n.ClearLocalStorage && n.ClearHistory)
            {
                kinds = CoreWebView2BrowsingDataKinds.AllProfile;
                described = "AllProfile: cache, cookies, local and session storage, IndexedDB, service workers, history, autofill, passwords, settings.";
            }
            else
            {
                kinds = default;
                var parts = new List<string>();
                if (n.ClearCache) { kinds |= CoreWebView2BrowsingDataKinds.DiskCache | CoreWebView2BrowsingDataKinds.CacheStorage; parts.Add("cache"); }
                if (n.ClearCookies) { kinds |= CoreWebView2BrowsingDataKinds.Cookies; parts.Add("cookies"); }
                if (n.ClearLocalStorage) { kinds |= CoreWebView2BrowsingDataKinds.AllDomStorage; parts.Add("local/session storage, IndexedDB, service workers"); }
                if (n.ClearHistory) { kinds |= CoreWebView2BrowsingDataKinds.BrowsingHistory | CoreWebView2BrowsingDataKinds.DownloadHistory; parts.Add("history"); }
                described = "selected kinds only (config.json neutralization): " + (parts.Count == 0 ? "none" : string.Join(", ", parts)) + ".";
            }
            if (kinds != default)
            {
                await core.Profile.ClearBrowsingDataAsync(kinds);
                r.ProfileApiUsed = true;
                r.Steps.Add("CoreWebView2Profile.ClearBrowsingDataAsync(" + described);
            }
            else r.Steps.Add("No browsing-data kind is selected for clearing in config.json (neutralization.*).");
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException)
        { r.Errors.Add("Profile.ClearBrowsingDataAsync failed: " + ex.Message); }

        // 3. cookie manager (explicit)
        if (n.ClearCookies)
        {
            try
            {
                core.CookieManager.DeleteAllCookies();
                r.Steps.Add("CookieManager.DeleteAllCookies().");
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException)
            { r.Errors.Add("DeleteAllCookies failed: " + ex.Message); }
        }

        // 4. DevTools: HTTP cache, cookies, navigation history (complements the profile API)
        var cdpSteps = new List<(string, string)>();
        if (n.ClearCache) cdpSteps.Add(("Network.clearBrowserCache", "HTTP cache cleared (DevTools)."));
        if (n.ClearCookies) cdpSteps.Add(("Network.clearBrowserCookies", "Cookies cleared (DevTools)."));
        if (n.ClearHistory) cdpSteps.Add(("Page.resetNavigationHistory", "Back/forward history reset (DevTools)."));
        foreach ((string method, string label) in cdpSteps)
        {
            try { await CdpAsync(method); r.Steps.Add(label); }
            catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException or ArgumentException)
            { r.Steps.Add($"{method} not available: {ex.Message}"); }
        }

        if (Web.DisableCache) r.Steps.Add("HTTP cache is disabled for the whole session (Network.setCacheDisabled): every resource is fetched from the network.");
        if (Web.InPrivateMode) r.Steps.Add("InPrivate profile in use: the browser never writes cookies, cache or storage to disk.");
        if (Web.ForceDirectConnection) r.Steps.Add("Browser started with --no-proxy-server (direct connection).");

        // 5. verification
        try { r.CookiesAfter = (await core.CookieManager.GetCookiesAsync(null)).Count; }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException)
        { r.Errors.Add("Cookies could not be counted after cleaning: " + ex.Message); r.CookiesAfter = -1; }
        r.ProfileBytesAfter = SecureTemp.GetFolderSize(UserDataFolder);
        r.CleanedUtc = TrustedClock.FormatIso(TrustedClock.UtcNow);
        if (n.ClearCookies && r.CookiesAfter > 0) r.Errors.Add($"{r.CookiesAfter} cookie(s) are still present after cleaning.");

        Log(r.Success ? AuditLevel.Info : AuditLevel.Error, "browser.clean",
            r.Success ? "Browser data neutralised and verified" : "Browser data neutralisation FAILED",
            new Dictionary<string, object?> { ["cookiesBefore"] = r.CookiesBefore, ["cookiesAfter"] = r.CookiesAfter, ["errors"] = r.Errors });
        StateChanged?.Invoke(this, EventArgs.Empty);
        return r;
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "...";

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { Recorder?.Dispose(); } catch (Exception) { /* browser already gone */ }
        try { _view.Dispose(); } catch (Exception) { /* ignore */ }
    }
}
