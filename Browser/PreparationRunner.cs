using EvidenceCollector.Config;
using EvidenceCollector.Core;

namespace EvidenceCollector.Browser;

/// <summary>
/// Phase 1 - environment preparation and neutralisation.
/// Verifies the workstation (clock, disk, proxy, VPN, hosts file, browser profile), then clears every kind of
/// browsing data of the evidence browser and verifies the result. Every check is written to the audit log and,
/// at the end, to 01_preparation/ as structured and readable files that are fingerprinted like any other evidence.
/// </summary>
public static class PreparationRunner
{
    public static async Task<PreparationResult> RunAsync(SessionContext ctx, EvidenceBrowser browser, int run,
        IProgress<string>? progress, CancellationToken ct)
    {
        AppConfig cfg = ctx.Config;
        var res = new PreparationResult { Run = run };
        ctx.SetPhase(1, PhaseStatus.Running, $"run {run}");

        void Add(CheckResult c)
        {
            res.Checks.Add(c);
            AuditLevel level = c.Status switch { CheckStatus.Fail => AuditLevel.Error, CheckStatus.Warn => AuditLevel.Warn, _ => AuditLevel.Info };
            ctx.Audit.TryAppend(level, 1, "prep.check", $"{c.Title}: {c.Status.ToString().ToUpperInvariant()}",
                new Dictionary<string, object?> { ["id"] = c.Id, ["details"] = c.Details });
        }

        try
        {
            // ---------------------------------------------------------- workstation and tool
            progress?.Report("Checking the workstation…");
            Add(EnvironmentChecker.CheckSystem());
            Add(EnvironmentChecker.CheckConfig(ctx.ConfigManager));
            Add(await EnvironmentChecker.CheckToolIntegrityAsync(cfg.Hashing.BufferSizeKb, ct));
            Add(CheckBrowserEngine(browser));
            Add(CheckBrowserProfile(cfg, browser));
            Add(CheckTemp(cfg, browser));
            Add(EnvironmentChecker.CheckDisk(cfg.Paths.OutputRoot, cfg.Workflow.MinimumFreeDiskMb));

            // ---------------------------------------------------------- clock (first: every later timestamp is corrected with it)
            progress?.Report("Synchronising the clock (NTP)…");
            NtpSyncResult sync = await TimeSync.SyncAsync(cfg.Ntp, ct);
            ctx.StartTimeSync = sync;
            Add(ClockCheck.FromSync(sync, cfg));
            try
            {
                await Task.Run(() => PhaseReports.SaveNtp(ctx, Path.Combine(ctx.PreparationDir, $"prep_r{run:D2}_ntp.json"), sync, 1,
                    $"NTP synchronisation during Phase 1 (run {run})"), ct);
            }
            catch (Exception ex) when (ex is IOException or InvalidOperationException)
            {
                ctx.Audit.TryAppend(AuditLevel.Warn, 1, "prep.ntp-save", "The NTP result could not be stored: " + ex.Message);
            }

            // ---------------------------------------------------------- direct connection
            progress?.Report("Checking for a system proxy…");
            Add(await EnvironmentChecker.CheckProxyAsync(cfg, ct));
            progress?.Report("Checking for VPN / tunnel adapters…");
            Add(await Task.Run(() => EnvironmentChecker.CheckVpn(cfg), ct));
            progress?.Report("Checking the hosts file…");
            string? hostsRaw = null;
            Add(await Task.Run(() => EnvironmentChecker.CheckHostsFile(cfg, out hostsRaw), ct));
            if (!string.IsNullOrEmpty(hostsRaw))
            {
                string hostsPath = Path.Combine(ctx.PreparationDir, $"prep_r{run:D2}_hosts_file.txt");
                await Task.Run(() =>
                {
                    JsonUtil.WriteText(hostsPath, hostsRaw);
                    ctx.Registry.Add(hostsPath, EvidenceCategory.Preparation, 1, "Content of the system hosts file when the session was prepared");
                }, ct);
            }

            // ---------------------------------------------------------- neutralisation of the browser
            progress?.Report("Clearing cache, cookies, storage and history of the evidence browser…");
            res.Clean = await browser.CleanAsync(ct);
            Add(CleanCheck(res.Clean));
        }
        catch (OperationCanceledException)
        {
            ctx.SetPhase(1, PhaseStatus.Failed, "cancelled");
            throw;
        }

        res.Evaluate();
        ctx.PreparationChecks.Clear();
        ctx.PreparationChecks.AddRange(res.Checks);
        ctx.CleanReport = res.Clean;

        progress?.Report("Recording the Phase 1 results…");
        await Task.Run(() => PhaseReports.SavePreparation(ctx, run, res.Checks, res.Clean), ct);
        ctx.SetPhase(1, res.Status, res.Status == PhaseStatus.Failed ? "blocking check(s) failed" : null);
        return res;
    }

    /// <summary>Re-neutralises the browser between two sites during Phase 3 and records the result as a Phase 1 run.</summary>
    public static async Task<PreparationResult> CleanOnlyAsync(SessionContext ctx, EvidenceBrowser browser, int run, CancellationToken ct)
    {
        var res = new PreparationResult { Run = run };
        res.Clean = await browser.CleanAsync(ct);
        res.Checks.Add(CleanCheck(res.Clean));
        res.Evaluate();
        await Task.Run(() => PhaseReports.SavePreparation(ctx, run, res.Checks, res.Clean), ct);
        return res;
    }

    // ------------------------------------------------------------------ individual checks

    private static CheckResult CheckBrowserEngine(EvidenceBrowser browser) =>
        string.IsNullOrEmpty(browser.RuntimeVersion)
            ? CheckResult.Fail("webview2", "Browser engine (WebView2)", "The Microsoft Edge WebView2 runtime is not available.")
            : CheckResult.Pass("webview2", "Browser engine (WebView2)",
                $"Microsoft Edge WebView2 runtime {browser.RuntimeVersion}\nUser agent: {browser.UserAgent}");

    private static CheckResult CheckBrowserProfile(AppConfig cfg, EvidenceBrowser browser)
    {
        WebViewConfig b = cfg.WebView;
        var lines = new List<string>
        {
            $"Profile folder (private temporary folder): {browser.UserDataFolder}",
            $"InPrivate profile (nothing written to disk by the browser): {(b.InPrivateMode ? "yes" : "no")}",
            $"HTTP cache disabled for the whole session: {(b.DisableCache ? "yes" : "no")}",
            $"Direct connection (--no-proxy-server): {(b.ForceDirectConnection ? "yes" : "no")}",
            $"Allowed schemes: {string.Join(", ", b.AllowedSchemes)}",
            $"Downloads: {(b.AllowDownloads ? "allowed by configuration" : "refused")}; permissions denied; autofill and password saving off; single window; fixed 100% zoom."
        };
        bool weak = !b.InPrivateMode || !b.DisableCache || !b.ForceDirectConnection || b.AllowDownloads;
        string text = (weak ? "One or more isolation options are relaxed in config.json.\n" : "") + string.Join("\n", lines);
        return weak
            ? CheckResult.Warn("profile", "Browser profile settings", text)
            : CheckResult.Pass("profile", "Browser profile settings", text);
    }

    private static CheckResult CheckTemp(AppConfig cfg, EvidenceBrowser browser)
    {
        CheckResult location = EnvironmentChecker.CheckTempLocation(cfg.Paths.TempRoot);
        try
        {
            string probe = Path.Combine(SecureTemp.WorkFolder(browser.UserDataFolder), "probe_" + Guid.NewGuid().ToString("N") + ".tmp");
            File.WriteAllText(probe, "probe");
            File.Delete(probe);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return CheckResult.Fail("temp", "Temporary files", "The temporary folder is not writable: " + ex.Message);
        }
        string wipe = cfg.Neutralization.SecureWipeTemp
            ? $"Files up to {cfg.Neutralization.SecureWipeMaxFileMb} MB are overwritten before deletion when the session ends (best effort; not guaranteed on SSD)."
            : "Temporary files are deleted (not overwritten) when the session ends.";
        return new CheckResult
        {
            Id = location.Id,
            Title = location.Title,
            Status = location.Status,
            Data = location.Data,
            Details = location.Details + "\n" + wipe
        };
    }

    private static CheckResult CleanCheck(BrowserCleanReport r)
    {
        string detail = $"Cookies before / after: {r.CookiesBefore} / {r.CookiesAfter}\n" +
                        $"Profile size before / after: {r.ProfileBytesBefore / 1024} KB / {r.ProfileBytesAfter / 1024} KB\n" +
                        string.Join("\n", r.Steps.Select(s => "- " + s));
        if (r.Errors.Count > 0) detail += "\nProblems:\n" + string.Join("\n", r.Errors.Select(e => "! " + e));
        return r.Success
            ? CheckResult.Pass("clean", "Browser data neutralisation", detail)
            : CheckResult.Fail("clean", "Browser data neutralisation", detail);
    }
}
