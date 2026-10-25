using EvidenceCollector.Config;
using Microsoft.Win32;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace EvidenceCollector.Core;

/// <summary>Phase 1 pre-checks. Each method is side-effect free and returns a displayable result.</summary>
public static class EnvironmentChecker
{
    // ------------------------------------------------------------------ system status

    public static CheckResult CheckSystem()
    {
        bool elevated = false;
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using WindowsIdentity id = WindowsIdentity.GetCurrent();
                elevated = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception) { /* informational only */ }
        }

        string tz = TimeZoneInfo.Local.Id + " (UTC" + (TimeZoneInfo.Local.GetUtcOffset(DateTime.Now) >= TimeSpan.Zero ? "+" : "-")
                    + TimeZoneInfo.Local.GetUtcOffset(DateTime.Now).ToString(@"hh\:mm") + ")";
        string details = $"{RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture}); {RuntimeInformation.FrameworkDescription}; " +
                         $"machine {Environment.MachineName}; user {Environment.UserName}{(elevated ? " (administrator)" : "")}; " +
                         $"time zone {tz}; culture {CultureInfo.CurrentCulture.Name}";

        return CheckResult.Info("system", "System status", details, new Dictionary<string, object?>
        {
            ["os"] = RuntimeInformation.OSDescription,
            ["architecture"] = RuntimeInformation.OSArchitecture.ToString(),
            ["framework"] = RuntimeInformation.FrameworkDescription,
            ["machine"] = Environment.MachineName,
            ["user"] = Environment.UserName,
            ["elevated"] = elevated,
            ["timeZone"] = TimeZoneInfo.Local.Id,
            ["culture"] = CultureInfo.CurrentCulture.Name,
            ["systemUtcAtCheck"] = TrustedClock.FormatIso(DateTime.UtcNow)
        });
    }

    public static CheckResult CheckDisk(string outputRoot, int minimumFreeMb)
    {
        try
        {
            string full = AppConfig.ResolvePath(outputRoot);
            string? root = Path.GetPathRoot(full);
            if (string.IsNullOrEmpty(root)) return CheckResult.Info("disk", "Output storage", $"Output folder: {full}");
            var drive = new DriveInfo(root);
            long freeMb = drive.AvailableFreeSpace / (1024 * 1024);
            var data = new Dictionary<string, object?> { ["outputRoot"] = full, ["freeMb"] = freeMb };
            return freeMb < minimumFreeMb
                ? CheckResult.Warn("disk", "Output storage", $"Only {freeMb} MB free on {root} (minimum {minimumFreeMb} MB). Output: {full}", data)
                : CheckResult.Pass("disk", "Output storage", $"{freeMb:N0} MB free on {root}. Output: {full}", data);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException or NotSupportedException)
        {
            return CheckResult.Info("disk", "Output storage", $"Free space could not be determined ({ex.Message}).");
        }
    }

    public static CheckResult CheckTempLocation(string tempRoot)
    {
        string full = AppConfig.ResolvePath(tempRoot);
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        bool inProfile = !string.IsNullOrEmpty(profile) && full.StartsWith(profile, StringComparison.OrdinalIgnoreCase);
        return inProfile
            ? CheckResult.Pass("temp", "Temporary files", $"Isolated browser profile is stored in the user profile ({full}) and wiped when the session ends.")
            : CheckResult.Warn("temp", "Temporary files", $"The temporary folder {full} is outside the user profile. Make sure only the current user can read it.");
    }

    public static async Task<CheckResult> CheckToolIntegrityAsync(int bufferSizeKb, CancellationToken ct)
    {
        var files = new List<string>();
        string? exe = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(exe) && File.Exists(exe)) files.Add(exe);
        //string dll = typeof(EnvironmentChecker).Assembly.Location;
        string dll = AppContext.BaseDirectory;
        if (!string.IsNullOrEmpty(dll) && File.Exists(dll) && !files.Contains(dll, StringComparer.OrdinalIgnoreCase)) files.Add(dll);

        var data = new Dictionary<string, object?>
        {
            ["version"] = typeof(EnvironmentChecker).Assembly.GetName().Version?.ToString() ?? "unknown"
        };
        var lines = new List<string>();
        foreach (string f in files)
        {
            FileDigest d = await HashEngine.ComputeFileAsync(f, includeSha512: false, bufferSizeKb * 1024, ct).ConfigureAwait(false);
            data[Path.GetFileName(f)] = d.Sha256;
            lines.Add($"{Path.GetFileName(f)} SHA-256 {d.Sha256}");
        }
        return CheckResult.Info("tool", "Tool integrity", $"Evidence Collector {data["version"]}; " + (lines.Count == 0 ? "binary hash unavailable" : string.Join("; ", lines)), data);
    }

    public static CheckResult CheckConfig(ConfigManager mgr)
    {
        var data = new Dictionary<string, object?> { ["path"] = mgr.FilePath, ["sha256"] = mgr.Sha256 };
        if (mgr.Warnings.Count > 0)
            return CheckResult.Warn("config", "Configuration", $"{mgr.FilePath} (SHA-256 {mgr.Sha256}). {string.Join(" ", mgr.Warnings)}", data);
        return CheckResult.Info("config", "Configuration", $"{mgr.FilePath} (SHA-256 {mgr.Sha256})", data);
    }

    // ------------------------------------------------------------------ proxy

    public static async Task<CheckResult> CheckProxyAsync(AppConfig cfg, CancellationToken ct)
    {
        var findings = new List<string>();
        var info = new List<string>();

        foreach (string name in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy" })
        {
            string? v = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrWhiteSpace(v)) findings.Add($"environment variable {name} = {NetUtil.RedactCredentials(v)}");
        }

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                if (key != null)
                {
                    if (key.GetValue("ProxyEnable") is int enabled && enabled == 1)
                        findings.Add($"system proxy enabled: {NetUtil.RedactCredentials(key.GetValue("ProxyServer") as string ?? "(server not set)")}");
                    if (key.GetValue("AutoConfigURL") is string pac && !string.IsNullOrWhiteSpace(pac))
                        findings.Add($"automatic configuration script (PAC): {NetUtil.RedactCredentials(pac)}");
                    if (key.GetValue("AutoDetect") is int auto && auto == 1)
                        info.Add("automatic proxy detection (WPAD) is enabled");
                }
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                info.Add("proxy registry settings could not be read");
            }
        }

        // Effective proxy for a test URL (resolves PAC/WPAD; may block, so it runs with a timeout).
        string? effective = null;
        try
        {
            if (Uri.TryCreate(cfg.Network.ProxyTestUrl, UriKind.Absolute, out Uri? test))
            {
                Task<Uri?> probe = Task.Run(() => HttpClientProxyFor(test), ct);
                Task finished = await Task.WhenAny(probe, Task.Delay(TimeSpan.FromSeconds(8), ct)).ConfigureAwait(false);
                if (finished == probe) effective = probe.Result?.ToString();
                else info.Add("effective proxy lookup timed out");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { info.Add("effective proxy lookup failed: " + ex.Message); }

        if (effective != null) findings.Add($"effective proxy for {cfg.Network.ProxyTestUrl}: {NetUtil.RedactCredentials(effective)}");

        var data = new Dictionary<string, object?> { ["findings"] = findings, ["notes"] = info, ["effectiveProxy"] = effective };
        string forced = cfg.WebView.ForceDirectConnection ? " The isolated browser is started with --no-proxy-server (direct connection)." : "";

        if (findings.Count == 0)
            return CheckResult.Pass("proxy", "Proxy detection", "No system or environment proxy detected." + (info.Count > 0 ? " Notes: " + string.Join("; ", info) + "." : "") + forced, data);

        CheckStatus status = CheckResult.FromPolicy(cfg.Workflow.ProxyPolicy);
        return new CheckResult
        {
            Id = "proxy",
            Title = "Proxy detection",
            Status = status,
            Data = data,
            Details = "Proxy configuration found: " + string.Join("; ", findings) + "." + forced
        };
    }

    private static Uri? HttpClientProxyFor(Uri target)
    {
        IWebProxy proxy = HttpClient.DefaultProxy;
        Uri? p = proxy.GetProxy(target);
        return p != null && !p.Equals(target) ? p : null;
    }

    // ------------------------------------------------------------------ VPN

    public static CheckResult CheckVpn(AppConfig cfg)
    {
        var suspects = new List<string>();
        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback) continue;

                string text = (nic.Name + " " + nic.Description).ToLowerInvariant();
                if (cfg.Network.NonVpnTunnelKeywords.Any(k => text.Contains(k, StringComparison.InvariantCultureIgnoreCase))) continue;

                bool typeHit = nic.NetworkInterfaceType is NetworkInterfaceType.Ppp or NetworkInterfaceType.Tunnel || (int)nic.NetworkInterfaceType == 53;
                string? keyword = cfg.Network.VpnInterfaceKeywords.FirstOrDefault(k => k.Length > 0 && text.Contains(k, StringComparison.InvariantCultureIgnoreCase));
                if (typeHit || keyword != null)
                    suspects.Add($"{nic.Name} ({nic.Description}; {nic.NetworkInterfaceType}{(keyword != null ? "; matches \"" + keyword + "\"" : "")})");
            }
        }
        catch (NetworkInformationException ex)
        {
            return CheckResult.Info("vpn", "VPN detection", "Network adapters could not be enumerated: " + ex.Message);
        }

        var data = new Dictionary<string, object?> { ["suspectInterfaces"] = suspects };
        if (suspects.Count == 0)
            return CheckResult.Pass("vpn", "VPN detection", "No active VPN or tunnel adapter detected.", data);

        return new CheckResult
        {
            Id = "vpn",
            Title = "VPN detection",
            Status = CheckResult.FromPolicy(cfg.Workflow.VpnPolicy),
            Data = data,
            Details = "Active VPN/tunnel adapter(s): " + string.Join("; ", suspects) + ". A VPN changes the apparent origin of the connection."
        };
    }

    // ------------------------------------------------------------------ hosts file

    public static CheckResult CheckHostsFile(AppConfig cfg, out string? rawContent)
    {
        rawContent = null;
        string path = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
        if (!OperatingSystem.IsWindows() || !File.Exists(path))
            return CheckResult.Info("hosts", "Hosts file", "The system hosts file is not available on this platform.");

        try
        {
            rawContent = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return CheckResult.Info("hosts", "Hosts file", "The hosts file could not be read: " + ex.Message);
        }

        var entries = ParseHostsEntries(rawContent);
        var data = new Dictionary<string, object?> { ["path"] = path, ["customEntries"] = entries };
        if (entries.Count == 0)
            return CheckResult.Pass("hosts", "Hosts file", "No custom entries (only default localhost mappings).", data);

        return new CheckResult
        {
            Id = "hosts",
            Title = "Hosts file",
            Status = CheckResult.FromPolicy(cfg.Workflow.HostsFilePolicy),
            Data = data,
            Details = $"{entries.Count} custom entr{(entries.Count == 1 ? "y" : "ies")} can redirect names locally: {string.Join("; ", entries.Take(5))}{(entries.Count > 5 ? "; …" : "")}"
        };
    }

    internal static List<string> ParseHostsEntries(string content)
    {
        var entries = new List<string>();
        foreach (string raw in content.Split('\n'))
        {
            string line = raw;
            int hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            line = line.Trim();
            if (line.Length == 0) continue;

            string[] parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            bool defaultLocalhost = (parts[0] == "127.0.0.1" || parts[0] == "::1") && parts.Skip(1).All(h => h.Equals("localhost", StringComparison.OrdinalIgnoreCase));
            if (!defaultLocalhost) entries.Add(string.Join(' ', parts));
        }
        return entries;
    }
}
