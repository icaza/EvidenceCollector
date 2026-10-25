using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace EvidenceCollector.Config;

/// <summary>
/// Loads, validates and saves config.json. The file is looked up next to the executable
/// (or at --config &lt;path&gt;); if that folder is not writable a copy is created under %LOCALAPPDATA%.
/// A malformed file is never overwritten: defaults are used and saving is disabled until it is fixed.
/// </summary>
public sealed class ConfigManager
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() }
    };

    public string FilePath { get; private set; } = string.Empty;
    public AppConfig Config { get; private set; } = new();

    /// <summary>SHA-256 of the config file bytes as read at load time (recorded in the audit log).</summary>
    public string Sha256 { get; private set; } = string.Empty;

    /// <summary>Non-null when the file could not be parsed or values were adjusted.</summary>
    public List<string> Warnings { get; } = [];

    public bool SaveDisabled { get; private set; }

    private ConfigManager() { }

    public static ConfigManager Load(string? explicitPath = null)
    {
        var mgr = new ConfigManager();
        string path = explicitPath ?? Path.Combine(AppContext.BaseDirectory, "config.json");

        if (!File.Exists(path))
        {
            if (!TryWriteDefault(path))
            {
                string fallback = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "EvidenceCollector", "config.json");
                path = fallback;
                if (!File.Exists(path)) TryWriteDefault(path);
            }
        }

        mgr.FilePath = path;

        if (File.Exists(path))
        {
            try
            {
                byte[] bytes = File.ReadAllBytes(path);
                mgr.Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                var cfg = JsonSerializer.Deserialize<AppConfig>(bytes, JsonOptions);
                mgr.Config = cfg ?? new AppConfig();
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                mgr.Config = new AppConfig();
                mgr.SaveDisabled = true;
                mgr.Warnings.Add($"config.json could not be read ({ex.Message}). Built-in defaults are in use and the file will not be overwritten.");
            }
        }
        else
        {
            mgr.Warnings.Add("config.json could not be created; built-in defaults are in use.");
            mgr.SaveDisabled = true;
        }

        Normalize(mgr.Config, mgr.Warnings);
        return mgr;
    }

    /// <summary>Atomic save (temp file + replace). Used only for UI preferences such as the theme.</summary>
    public bool TrySave()
    {
        if (SaveDisabled || string.IsNullOrEmpty(FilePath)) return false;
        try
        {
            string json = JsonSerializer.Serialize(Config, JsonOptions);
            string tmp = FilePath + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, FilePath, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Warnings.Add($"config.json could not be saved: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Updates only the "theme" value in place so the user's comments and layout survive (a full re-serialisation
    /// would drop them). Best effort: returns false when the file cannot be patched.
    /// </summary>
    public bool TrySaveTheme(ThemeMode theme)
    {
        Config.Ui.Theme = theme;
        if (SaveDisabled || string.IsNullOrEmpty(FilePath) || !File.Exists(FilePath)) return false;
        try
        {
            string text = File.ReadAllText(FilePath);
            var rx = new System.Text.RegularExpressions.Regex("(\"theme\"\\s*:\\s*\")(?:Dark|Light)(\")",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (!rx.IsMatch(text)) return TrySave();
            string patched = rx.Replace(text, "${1}" + theme + "${2}", 1);
            if (patched != text)
            {
                string tmp = FilePath + ".tmp";
                File.WriteAllText(tmp, patched, new System.Text.UTF8Encoding(false));
                File.Move(tmp, FilePath, overwrite: true);
            }
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Warnings.Add($"config.json could not be saved: {ex.Message}");
            return false;
        }
    }

    private static bool TryWriteDefault(string path)
    {
        try
        {
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(path, JsonSerializer.Serialize(new AppConfig(), JsonOptions));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Clamps values to safe ranges and records every adjustment.</summary>
    public static void Normalize(AppConfig c, List<string> warnings)
    {
        static int Clamp(int v, int min, int max) => Math.Min(max, Math.Max(min, v));

        void Fix(string name, int value, int min, int max, Action<int> set)
        {
            int clamped = Clamp(value, min, max);
            if (clamped != value)
            {
                set(clamped);
                warnings.Add($"{name} was {value}; adjusted to {clamped} (allowed {min}-{max}).");
            }
        }

        Fix("ntp.timeoutMs", c.Ntp.TimeoutMs, 500, 30000, v => c.Ntp.TimeoutMs = v);
        Fix("ntp.samplesPerServer", c.Ntp.SamplesPerServer, 1, 8, v => c.Ntp.SamplesPerServer = v);
        Fix("ntp.minimumResponses", c.Ntp.MinimumResponses, 1, 10, v => c.Ntp.MinimumResponses = v);
        Fix("ntp.maxAllowedOffsetMs", c.Ntp.MaxAllowedOffsetMs, 10, 600000, v => c.Ntp.MaxAllowedOffsetMs = v);
        Fix("network.requestTimeoutSeconds", c.Network.RequestTimeoutSeconds, 2, 120, v => c.Network.RequestTimeoutSeconds = v);
        Fix("network.minimumAgreeingEndpoints", c.Network.MinimumAgreeingEndpoints, 1, 10, v => c.Network.MinimumAgreeingEndpoints = v);
        Fix("network.tracerouteMaxHops", c.Network.TracerouteMaxHops, 1, 64, v => c.Network.TracerouteMaxHops = v);
        Fix("network.tracerouteTimeoutMs", c.Network.TracerouteTimeoutMs, 200, 10000, v => c.Network.TracerouteTimeoutMs = v);
        Fix("hashing.bufferSizeKb", c.Hashing.BufferSizeKb, 16, 8192, v => c.Hashing.BufferSizeKb = v);
        Fix("hashing.maxParallelism", c.Hashing.MaxParallelism, 1, 16, v => c.Hashing.MaxParallelism = v);
        Fix("capture.screenshot.fullPageMaxTileHeightPx", c.Capture.Screenshot.FullPageMaxTileHeightPx, 500, 12000, v => c.Capture.Screenshot.FullPageMaxTileHeightPx = v);
        Fix("capture.screenshot.fullPageMaxTotalHeightPx", c.Capture.Screenshot.FullPageMaxTotalHeightPx, 1000, 400000, v => c.Capture.Screenshot.FullPageMaxTotalHeightPx = v);
        Fix("capture.screenshot.autoScrollStepDelayMs", c.Capture.Screenshot.AutoScrollStepDelayMs, 50, 5000, v => c.Capture.Screenshot.AutoScrollStepDelayMs = v);
        Fix("capture.screenshot.autoScrollMaxDurationMs", c.Capture.Screenshot.AutoScrollMaxDurationMs, 1000, 120000, v => c.Capture.Screenshot.AutoScrollMaxDurationMs = v);
        Fix("capture.screenshot.overlay.watermarkOpacityPercent", c.Capture.Screenshot.Overlay.WatermarkOpacityPercent, 0, 60, v => c.Capture.Screenshot.Overlay.WatermarkOpacityPercent = v);
        Fix("capture.autoCapture.delayAfterLoadMs", c.Capture.AutoCapture.DelayAfterLoadMs, 0, 60000, v => c.Capture.AutoCapture.DelayAfterLoadMs = v);
        Fix("capture.source.maxStylesheetCount", c.Capture.Source.MaxStylesheetCount, 0, 500, v => c.Capture.Source.MaxStylesheetCount = v);
        Fix("capture.source.maxStylesheetBytes", c.Capture.Source.MaxStylesheetBytes, 1024, 50 * 1024 * 1024, v => c.Capture.Source.MaxStylesheetBytes = v);
        Fix("whois.timeoutSeconds", c.Whois.TimeoutSeconds, 2, 60, v => c.Whois.TimeoutSeconds = v);
        Fix("whois.maxResponseKb", c.Whois.MaxResponseKb, 4, 4096, v => c.Whois.MaxResponseKb = v);
        Fix("whois.port", c.Whois.Port, 1, 65535, v => c.Whois.Port = v);
        Fix("webView.networkJournalMaxEntries", c.WebView.NetworkJournalMaxEntries, 100, 100000, v => c.WebView.NetworkJournalMaxEntries = v);
        Fix("logging.uiMaxEntries", c.Logging.UiMaxEntries, 200, 100000, v => c.Logging.UiMaxEntries = v);
        Fix("workflow.minimumFreeDiskMb", c.Workflow.MinimumFreeDiskMb, 0, 10_000_000, v => c.Workflow.MinimumFreeDiskMb = v);
        Fix("capture.waitForPageCompleteMs", c.Capture.WaitForPageCompleteMs, 0, 120000, v => c.Capture.WaitForPageCompleteMs = v);
        Fix("capture.source.maxCachedBodyMb", c.Capture.Source.MaxCachedBodyMb, 1, 512, v => c.Capture.Source.MaxCachedBodyMb = v);
        Fix("neutralization.secureWipeMaxFileMb", c.Neutralization.SecureWipeMaxFileMb, 0, 4096, v => c.Neutralization.SecureWipeMaxFileMb = v);

        if (c.Ntp.Servers.Count == 0)
        {
            c.Ntp.Servers = new AppConfig().Ntp.Servers;
            warnings.Add("ntp.servers was empty; defaults restored.");
        }
        if (c.Network.PublicIpEndpoints.Count == 0)
        {
            c.Network.PublicIpEndpoints = new AppConfig().Network.PublicIpEndpoints;
            warnings.Add("network.publicIpEndpoints was empty; defaults restored.");
        }

        // Only https endpoints are accepted for public-IP lookups (integrity of the answer).
        int before = c.Network.PublicIpEndpoints.Count;
        c.Network.PublicIpEndpoints = [.. c.Network.PublicIpEndpoints.Where(u => Uri.TryCreate(u, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps)];
        if (c.Network.PublicIpEndpoints.Count != before)
            warnings.Add("Non-HTTPS entries were removed from network.publicIpEndpoints.");
        if (c.Network.PublicIpEndpoints.Count == 0)
            c.Network.PublicIpEndpoints = new AppConfig().Network.PublicIpEndpoints;

        c.WebView.AllowedSchemes = [.. c.WebView.AllowedSchemes
            .Select(s => s.Trim().ToLowerInvariant())
            .Where(s => s is "http" or "https")
            .Distinct()];
        if (c.WebView.AllowedSchemes.Count == 0)
        {
            c.WebView.AllowedSchemes = new List<string> { "http", "https" };
            warnings.Add("webView.allowedSchemes may only contain http and/or https; defaults restored.");
        }
        if (c.WebView.DefaultScheme is not ("http" or "https")) c.WebView.DefaultScheme = "https";

        // SHA-256 is mandatory; anything unknown is dropped.
        var algos = c.Hashing.Algorithms
            .Select(a => a.Replace("-", "").Trim().ToUpperInvariant())
            .Where(a => a is "SHA256" or "SHA512")
            .Distinct()
            .ToList();
        if (!algos.Contains("SHA256")) algos.Insert(0, "SHA256");
        c.Hashing.Algorithms = algos;

        if (!string.Equals(c.Capture.Archive.PdfPaperSize, "A4", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(c.Capture.Archive.PdfPaperSize, "Letter", StringComparison.OrdinalIgnoreCase))
        {
            c.Capture.Archive.PdfPaperSize = "A4";
            warnings.Add("capture.archive.pdfPaperSize must be \"A4\" or \"Letter\"; \"A4\" is used.");
        }

        if (!string.IsNullOrWhiteSpace(c.Capture.Screenshot.Overlay.LocalTimeZoneId))
        {
            try { TimeZoneInfo.FindSystemTimeZoneById(c.Capture.Screenshot.Overlay.LocalTimeZoneId.Trim()); }
            catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
            {
                warnings.Add($"capture.screenshot.overlay.localTimeZoneId \"{c.Capture.Screenshot.Overlay.LocalTimeZoneId}\" is unknown; this PC's time zone is used.");
                c.Capture.Screenshot.Overlay.LocalTimeZoneId = "";
            }
        }

        c.Session.SessionIdPrefix = new string((c.Session.SessionIdPrefix ?? "EVC")
            .Where(ch => char.IsAsciiLetterOrDigit(ch)).Take(8).ToArray());
        if (c.Session.SessionIdPrefix.Length == 0) c.Session.SessionIdPrefix = "EVC";
    }
}
