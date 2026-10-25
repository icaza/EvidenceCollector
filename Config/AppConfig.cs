namespace EvidenceCollector.Config;

public enum ThemeMode { Dark, Light }

public enum CheckPolicy { Ignore, Warn, Block }

public enum OverlayMode { Band, Overlay }

public enum OverlayPosition { Top, Bottom }

/// <summary>Root of config.json. Every property has a safe default so a partial file is valid.</summary>
public sealed class AppConfig
{
    public int SchemaVersion { get; set; } = 1;
    public UiConfig Ui { get; set; } = new();
    public PathsConfig Paths { get; set; } = new();
    public SessionConfig Session { get; set; } = new();
    public WorkflowConfig Workflow { get; set; } = new();
    public NeutralizationConfig Neutralization { get; set; } = new();
    public NetworkConfig Network { get; set; } = new();
    public NtpConfig Ntp { get; set; } = new();
    public WebViewConfig WebView { get; set; } = new();
    public CaptureConfig Capture { get; set; } = new();
    public WhoisConfig Whois { get; set; } = new();
    public HashingConfig Hashing { get; set; } = new();
    public SealingConfig Sealing { get; set; } = new();
    public LoggingConfig Logging { get; set; } = new();

    /// <summary>Expands environment variables and returns an absolute path.</summary>
    public static string ResolvePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        return Path.GetFullPath(Environment.ExpandEnvironmentVariables(path.Trim()));
    }
}

public sealed class UiConfig
{
    public ThemeMode Theme { get; set; } = ThemeMode.Dark;
    public bool ShowAuditPanel { get; set; } = true;
}

public sealed class PathsConfig
{
    public string OutputRoot { get; set; } = "%USERPROFILE%/Documents/EvidenceCollector/Sessions";
    public string TempRoot { get; set; } = "%LOCALAPPDATA%/EvidenceCollector/Temp";
    public string WebViewRuntimeFolder { get; set; } = "";
}

public sealed class SessionConfig
{
    public string SessionIdPrefix { get; set; } = "EVC";
    public string CaseReference { get; set; } = "";
    public string OperatorName { get; set; } = "";
    public string OperatorTitle { get; set; } = "";
    public string Office { get; set; } = "";
    public string Location { get; set; } = "";
    public bool RequireCaseReference { get; set; } = true;
    public bool RequireOperatorName { get; set; } = true;
}

public sealed class WorkflowConfig
{
    public bool EnforcePhaseOrder { get; set; } = true;
    public CheckPolicy ProxyPolicy { get; set; } = CheckPolicy.Warn;
    public CheckPolicy VpnPolicy { get; set; } = CheckPolicy.Warn;
    public CheckPolicy HostsFilePolicy { get; set; } = CheckPolicy.Warn;
    public bool RequirePublicIp { get; set; } = true;
    public bool RequireNtpSync { get; set; } = true;
    public int MinimumFreeDiskMb { get; set; } = 500;
}

public sealed class NeutralizationConfig
{
    public bool ClearCache { get; set; } = true;
    public bool ClearCookies { get; set; } = true;
    public bool ClearLocalStorage { get; set; } = true;
    public bool ClearHistory { get; set; } = true;
    public bool SecureWipeTemp { get; set; } = true;
    public int SecureWipeMaxFileMb { get; set; } = 256;
}

public sealed class NetworkConfig
{
    public List<string> PublicIpEndpoints { get; set; } = new()
    {
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com"
    };
    public int MinimumAgreeingEndpoints { get; set; } = 2;
    public int RequestTimeoutSeconds { get; set; } = 10;
    public bool CollectRawCommandOutput { get; set; } = true;
    public string ProxyTestUrl { get; set; } = "https://example.com/";
    public List<string> VpnInterfaceKeywords { get; set; } =
    [
        "vpn", "tap-windows", "tap0901", "wireguard", "wintun", "openvpn", "nordlynx", "tailscale",
        "zerotier", "anyconnect", "globalprotect", "fortinet", "forticlient", "proton", "mullvad",
        "warp", "pulse secure", "sonicwall", "checkpoint", "l2tp", "pptp", "sstp", "ikev2"
    ];
    public List<string> NonVpnTunnelKeywords { get; set; } =
    [
        "teredo", "isatap", "6to4", "microsoft ip-https"
    ];
    public int TracerouteMaxHops { get; set; } = 30;
    public int TracerouteTimeoutMs { get; set; } = 1500;
}

public sealed class NtpConfig
{
    public List<string> Servers { get; set; } =
    [
        "ntp-p1.obspm.fr", "time.cloudflare.com", "time.google.com", "time.windows.com", "pool.ntp.org"
    ];
    public int TimeoutMs { get; set; } = 3000;
    public int SamplesPerServer { get; set; } = 3;
    public int MinimumResponses { get; set; } = 2;
    public int MaxAllowedOffsetMs { get; set; } = 1000;
}

public sealed class WebViewConfig
{
    public bool ForceDirectConnection { get; set; } = true;
    /// <summary>InPrivate profile: the browser never writes cookies, cache or storage to disk.</summary>
    public bool InPrivateMode { get; set; } = true;
    /// <summary>Disables the HTTP cache for the whole session so every resource is fetched from the network.</summary>
    public bool DisableCache { get; set; } = true;
    /// <summary>Browser UI language (BCP-47, e.g. "en-US"); empty = runtime default.</summary>
    public string Language { get; set; } = "";
    public bool BlockPopupsWithoutUserGesture { get; set; } = true;
    public string AdditionalBrowserArguments { get; set; } = "--disable-background-networking --disable-sync";
    public string StartPage { get; set; } = "about:blank";
    public string DefaultScheme { get; set; } = "https";
    public List<string> AllowedSchemes { get; set; } = ["http", "https"];
    public bool BlockPrivateAddresses { get; set; } = false;
    public bool AllowDownloads { get; set; } = false;
    public bool DisableDevTools { get; set; } = true;
    public bool DisableContextMenu { get; set; } = true;
    public string UserAgentOverride { get; set; } = "";
    public int NetworkJournalMaxEntries { get; set; } = 4000;
    public bool LowMemoryWhenMinimized { get; set; } = true;
}

public sealed class CaptureConfig
{
    /// <summary>How long a capture waits for document.readyState = "complete" before it continues anyway.</summary>
    public int WaitForPageCompleteMs { get; set; } = 30000;
    public ScreenshotConfig Screenshot { get; set; } = new();
    public SourceConfig Source { get; set; } = new();
    public ArchiveConfig Archive { get; set; } = new();
    public CookieConfig Cookies { get; set; } = new();
    public AutoCaptureConfig AutoCapture { get; set; } = new();
    public DomainRecordConfig DomainRecord { get; set; } = new();
}

public sealed class ArchiveConfig
{
    public bool SaveMhtml { get; set; } = true;
    public bool SavePdf { get; set; } = true;
    /// <summary>"A4" or "Letter".</summary>
    public string PdfPaperSize { get; set; } = "A4";
}

public sealed class CookieConfig
{
    public bool SaveCookieList { get; set; } = true;
    /// <summary>false = only names, attributes, value length and SHA-256 of the value are stored (values are never written).</summary>
    public bool StoreCookieValues { get; set; } = false;
}

public sealed class ScreenshotConfig
{
    public bool KeepRawImage { get; set; } = true;
    public int FullPageMaxTileHeightPx { get; set; } = 6000;
    public int FullPageMaxTotalHeightPx { get; set; } = 60000;
    public bool AutoScrollBeforeFullPage { get; set; } = true;
    public int AutoScrollStepDelayMs { get; set; } = 250;
    public int AutoScrollMaxDurationMs { get; set; } = 20000;
    public OverlayConfig Overlay { get; set; } = new();
}

public sealed class OverlayConfig
{
    public bool Enabled { get; set; } = true;
    public OverlayMode Mode { get; set; } = OverlayMode.Band;
    public OverlayPosition Position { get; set; } = OverlayPosition.Bottom;
    public bool DiagonalWatermark { get; set; } = true;
    public int WatermarkOpacityPercent { get; set; } = 12;
    public string FontFamily { get; set; } = "Segoe UI";
    /// <summary>IANA or Windows time-zone id for the local time printed on screenshots; empty = this PC's zone.</summary>
    public string LocalTimeZoneId { get; set; } = "";
    public string BandBackground { get; set; } = "#101820";
    public string BandForeground { get; set; } = "#FFFFFF";
}

public sealed class SourceConfig
{
    public bool SaveRenderedDom { get; set; } = true;
    public bool SaveRawResponseBody { get; set; } = true;
    public bool SavePlainText { get; set; } = true;
    public bool SaveResponseHeaders { get; set; } = true;
    public bool SaveStylesheets { get; set; } = true;
    public int MaxStylesheetCount { get; set; } = 60;
    public int MaxStylesheetBytes { get; set; } = 5 * 1024 * 1024;
    public bool SaveResourceJournal { get; set; } = true;
    /// <summary>Upper bound of HTML/CSS response bodies kept in memory per page.</summary>
    public int MaxCachedBodyMb { get; set; } = 64;
}

public sealed class AutoCaptureConfig
{
    public bool Enabled { get; set; } = false;
    public int DelayAfterLoadMs { get; set; } = 2000;
    public bool FullPageScreenshot { get; set; } = true;
    public bool Source { get; set; } = true;
    public bool DomainRecord { get; set; } = true;
}

public sealed class DomainRecordConfig
{
    public bool IncludeWhois { get; set; } = true;
    public bool IncludeDns { get; set; } = true;
    public bool IncludeTls { get; set; } = true;
    public bool IncludeTraceroute { get; set; } = false;
}

public sealed class WhoisConfig
{
    public string IanaServer { get; set; } = "whois.iana.org";
    public int Port { get; set; } = 43;
    public int TimeoutSeconds { get; set; } = 10;
    public int MaxResponseKb { get; set; } = 256;
    public bool UseRdapFallback { get; set; } = true;
    public string RdapBaseUrl { get; set; } = "https://rdap.org";
}

public sealed class HashingConfig
{
    /// <summary>SHA256 is always computed. "SHA512" may be added as a second digest.</summary>
    public List<string> Algorithms { get; set; } = ["SHA256"];
    public int BufferSizeKb { get; set; } = 512;
    public int MaxParallelism { get; set; } = 2;
}

public sealed class SealingConfig
{
    public bool CreateZipArchive { get; set; } = true;
    /// <summary>Re-verifies the sealed package against its manifest straight after sealing.</summary>
    public bool VerifyAfterSeal { get; set; } = true;
    public bool MarkFilesReadOnly { get; set; } = true;
    public string ReportTitle { get; set; } = "Internet Evidence Collection Report";
    public string Organization { get; set; } = "";
    public bool IncludeThumbnails { get; set; } = true;
    public int ThumbnailMaxWidthPx { get; set; } = 420;
}

public sealed class LoggingConfig
{
    public bool FlushEveryEntry { get; set; } = true;
    public bool WriteTextLog { get; set; } = true;
    public int UiMaxEntries { get; set; } = 5000;
}
