namespace EvidenceCollector.Core;

public enum CheckStatus { Pass, Warn, Fail, Info }

/// <summary>One line of the Phase 1 / Phase 2 verification checklists.</summary>
public sealed class CheckResult
{
    public string Id { get; init; } = "";
    public string Title { get; init; } = "";
    public CheckStatus Status { get; init; }
    public string Details { get; init; } = "";
    public Dictionary<string, object?>? Data { get; init; }

    public static CheckResult Pass(string id, string title, string details, Dictionary<string, object?>? data = null) =>
        new() { Id = id, Title = title, Status = CheckStatus.Pass, Details = details, Data = data };

    public static CheckResult Warn(string id, string title, string details, Dictionary<string, object?>? data = null) =>
        new() { Id = id, Title = title, Status = CheckStatus.Warn, Details = details, Data = data };

    public static CheckResult Fail(string id, string title, string details, Dictionary<string, object?>? data = null) =>
        new() { Id = id, Title = title, Status = CheckStatus.Fail, Details = details, Data = data };

    public static CheckResult Info(string id, string title, string details, Dictionary<string, object?>? data = null) =>
        new() { Id = id, Title = title, Status = CheckStatus.Info, Details = details, Data = data };

    /// <summary>Maps a policy to the status reported when a problem is found.</summary>
    public static CheckStatus FromPolicy(Config.CheckPolicy policy) => policy switch
    {
        Config.CheckPolicy.Block => CheckStatus.Fail,
        Config.CheckPolicy.Warn => CheckStatus.Warn,
        _ => CheckStatus.Info
    };
}

public sealed class ManifestEntry
{
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public string Sha256 { get; set; } = "";
    public string? Sha512 { get; set; }
    public string LastWriteUtc { get; set; } = "";
}

public sealed class NavigationTrailEntry
{
    public int Seq { get; set; }
    public string TimeUtc { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Url { get; set; } = "";
    public bool UserInitiated { get; set; }
    public bool Redirected { get; set; }
    public string? Status { get; set; }
    public int? HttpStatus { get; set; }
    public string? Title { get; set; }
}

/// <summary>Progress notification used by long operations (sealing, verification).</summary>
public readonly record struct StepProgress(string Message, int Percent);

/// <summary>Outcome of the Phase 1 browser-data neutralisation.</summary>
public sealed class BrowserCleanReport
{
    public string CleanedUtc { get; set; } = "";
    public string UserDataFolder { get; set; } = "";
    public string? WebView2Version { get; set; }
    public bool ProfileApiUsed { get; set; }
    public int CookiesBefore { get; set; }
    public int CookiesAfter { get; set; }
    public long ProfileBytesBefore { get; set; }
    public long ProfileBytesAfter { get; set; }
    public List<string> Steps { get; set; } = [];
    public List<string> Errors { get; set; } = [];
    /// <summary>False when cookie clearing is switched off in config.json (neutralization.clearCookies).</summary>
    public bool CookiesExpectedEmpty { get; set; } = true;
    public bool Success => (!CookiesExpectedEmpty || CookiesAfter == 0) && Errors.Count == 0;
}

/// <summary>One user-triggered capture (a folder under 03_captures).</summary>
public sealed class CaptureSet
{
    public int Seq { get; set; }
    public string Label { get; set; } = "";
    public string Folder { get; set; } = "";
    public string RelativeFolder { get; set; } = "";
    public string Url { get; set; } = "";
    public string Title { get; set; } = "";
    public DateTime StartedUtc { get; set; }
    public DateTime? FinishedUtc { get; set; }
    public List<long> EvidenceIds { get; } = [];
    public List<string> Notes { get; } = [];
    public string? OperatorNote { get; set; }
}
