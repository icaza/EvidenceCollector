using EvidenceCollector.Config;
using System.Net;

namespace EvidenceCollector.Core;

public sealed class UrlValidationResult
{
    public bool IsValid { get; set; }
    public Uri? Uri { get; set; }
    public string Normalized { get; set; } = "";
    public string? Error { get; set; }
    public List<string> Warnings { get; } = [];
}

/// <summary>Validates and normalizes the URL typed by the operator before any navigation takes place.</summary>
public static class UrlValidator
{
    private const int MaxLength = 2048;

    private static readonly string[] KnownNonWebSchemes =
        { "javascript:", "data:", "file:", "vbscript:", "blob:", "mailto:", "ftp:", "ws:", "wss:", "edge:", "chrome:", "view-source:", "about:" };

    public static UrlValidationResult Validate(string? input, WebViewConfig cfg)
    {
        var r = new UrlValidationResult();
        string text = (input ?? string.Empty).Trim();

        if (text.Length == 0) return Fail(r, "Enter a web address.");
        if (text.Length > MaxLength) return Fail(r, $"The address is longer than {MaxLength} characters.");
        if (text.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)))
            return Fail(r, "The address must not contain spaces or control characters.");

        if (!text.Contains("://"))
        {
            string lower = text.ToLowerInvariant();
            string? blocked = KnownNonWebSchemes.FirstOrDefault(s => lower.StartsWith(s, StringComparison.Ordinal));
            if (blocked != null) return Fail(r, $"The scheme \"{blocked.TrimEnd(':')}\" is not allowed. Only {string.Join(" and ", cfg.AllowedSchemes)} are permitted.");
            if (text.StartsWith("//")) text = text.TrimStart('/');
            text = cfg.DefaultScheme + "://" + text;
            r.Warnings.Add($"No scheme was given; {cfg.DefaultScheme}:// was assumed.");
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) || uri == null)
            return Fail(r, "The address is not a valid URL.");

        string scheme = uri.Scheme.ToLowerInvariant();
        if (!cfg.AllowedSchemes.Contains(scheme))
            return Fail(r, $"The scheme \"{scheme}\" is not allowed. Only {string.Join(" and ", cfg.AllowedSchemes)} are permitted.");

        if (!string.IsNullOrEmpty(uri.UserInfo))
            return Fail(r, "Credentials inside the URL (user:password@host) are not allowed.");

        if (string.IsNullOrEmpty(uri.Host))
            return Fail(r, "The address has no host name.");

        UriHostNameType hostType = uri.HostNameType;
        if (hostType is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6))
            return Fail(r, "The host name is not valid.");

        if (hostType == UriHostNameType.Dns && Uri.CheckHostName(uri.IdnHost) != UriHostNameType.Dns)
            return Fail(r, "The host name contains invalid characters.");

        bool nonPublic = false;
        if (IPAddress.TryParse(uri.Host.Trim('[', ']'), out IPAddress? ip)) nonPublic = NetUtil.IsNonPublic(ip);
        else
        {
            string h = uri.IdnHost.ToLowerInvariant();
            nonPublic = h == "localhost" || h.EndsWith(".localhost") || h.EndsWith(".local") || h.EndsWith(".internal")
                        || h.EndsWith(".lan") || !h.Contains('.');
        }

        if (nonPublic)
        {
            if (cfg.BlockPrivateAddresses) return Fail(r, "Local and private addresses are blocked by configuration (webView.blockPrivateAddresses).");
            r.Warnings.Add("The address is local or private; it is not a public Internet resource.");
        }

        if (scheme == "http") r.Warnings.Add("Unencrypted HTTP connection.");
        if (!uri.IsDefaultPort) r.Warnings.Add($"Non-standard port {uri.Port}.");
        if (!string.Equals(uri.Host, uri.IdnHost, StringComparison.OrdinalIgnoreCase))
            r.Warnings.Add($"Internationalized host name; punycode form: {uri.IdnHost}.");

        r.IsValid = true;
        r.Uri = uri;
        r.Normalized = uri.AbsoluteUri;
        return r;
    }

    /// <summary>Checks a navigation target requested by the page itself (redirects, links, scripts).</summary>
    public static bool IsNavigationAllowed(string? url, WebViewConfig cfg, out string reason)
    {
        reason = "";
        if (string.IsNullOrWhiteSpace(url)) { reason = "empty target"; return false; }
        if (string.Equals(url, "about:blank", StringComparison.OrdinalIgnoreCase)) return true;
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri)) { reason = "unparseable target"; return false; }
        if (!cfg.AllowedSchemes.Contains(uri.Scheme.ToLowerInvariant())) { reason = $"scheme \"{uri.Scheme}\" is not allowed"; return false; }
        if (!string.IsNullOrEmpty(uri.UserInfo)) { reason = "credentials in URL"; return false; }
        if (cfg.BlockPrivateAddresses && IPAddress.TryParse(uri.Host.Trim('[', ']'), out IPAddress? ip) && NetUtil.IsNonPublic(ip))
        { reason = "private address"; return false; }
        return true;
    }

    private static UrlValidationResult Fail(UrlValidationResult r, string error)
    {
        r.IsValid = false;
        r.Error = error;
        return r;
    }
}
