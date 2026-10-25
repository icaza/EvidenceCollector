using EvidenceCollector.Config;
using System.Security.Cryptography;

namespace EvidenceCollector.Core;

public enum PhaseStatus { NotStarted, Running, Passed, PassedWithWarnings, Failed }

public enum EvidenceCategory
{
    Session, Preparation, Network, Screenshot, Source, Stylesheet, Archive, Connection, Whois, Log, Seal, Report, Other
}

/// <summary>Fixed relative paths inside a session folder (shared by the seal engine and the verifier).</summary>
public static class SessionLayout
{
    public const string AuditDir = "audit";
    public const string AuditJsonl = "audit/audit.jsonl";
    public const string AuditText = "audit/audit.log";

    public const string SealingDir = "05_sealing";
    public const string Manifest = "05_sealing/manifest.json";
    public const string ManifestList = "05_sealing/manifest.sha256";
    public const string Receipt = "05_sealing/SEAL_RECEIPT.txt";
    public const string Report = "05_sealing/report.html";

    public static readonly string[] SubFolders =
        { "00_session", "01_preparation", "02_network", "03_captures", "04_whois", "05_sealing" };
}

/// <summary>Case and operator information entered at the start of a session.</summary>
public sealed class SessionInfo
{
    public string SessionId { get; set; } = "";
    public string CaseReference { get; set; } = "";
    public string Requester { get; set; } = "";
    public string OperatorName { get; set; } = "";
    public string OperatorTitle { get; set; } = "";
    public string Office { get; set; } = "";
    public string Location { get; set; } = "";
    public string Purpose { get; set; } = "";
    public DateTime CreatedUtc { get; set; }

    /// <summary>Last segment of the session id (the random part), printed on screenshots.</summary>
    public string ShortId
    {
        get
        {
            int i = SessionId.LastIndexOf('-');
            return i >= 0 && i < SessionId.Length - 1 ? SessionId[(i + 1)..] : SessionId;
        }
    }

    public static string NewSessionId(string prefix, DateTime utc) =>
        $"{prefix}-{utc:yyyyMMdd-HHmmss}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(2)).ToLowerInvariant()}";
}

/// <summary>A file that belongs to the evidence package, fingerprinted at the moment it was created.</summary>
public sealed class EvidenceItem
{
    public long Id { get; set; }
    public string RelativePath { get; set; } = "";
    public EvidenceCategory Category { get; set; }
    public int Phase { get; set; }
    public string Description { get; set; } = "";
    public string? SourceUrl { get; set; }
    /// <summary>NTP-corrected UTC time when the file was registered.</summary>
    public DateTime RegisteredUtc { get; set; }
    /// <summary>Raw PC clock (UTC) at the same moment, so the correction can be audited.</summary>
    public DateTime SystemUtc { get; set; }
    public bool ClockSynced { get; set; }
    public double? ClockOffsetMs { get; set; }
    public long SizeBytes { get; set; }
    public string Sha256 { get; set; } = "";
    public string? Sha512 { get; set; }
    public int? CaptureSeq { get; set; }
}

/// <summary>
/// Registry of every evidence file. Each file is hashed when it is registered (SHA-256 and optionally SHA-512);
/// the seal step re-hashes everything and refuses to seal when a file changed in between.
/// </summary>
public sealed class EvidenceRegistry
{
    private readonly object _gate = new();
    private readonly List<EvidenceItem> _items = new();
    private readonly string _root;
    private readonly bool _sha512;
    private readonly int _bufferKb;
    private readonly AuditLog? _audit;
    private long _nextId;

    public EvidenceRegistry(string rootFolder, bool includeSha512, int bufferSizeKb, AuditLog? audit)
    {
        _root = Path.GetFullPath(rootFolder).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        _sha512 = includeSha512;
        _bufferKb = bufferSizeKb;
        _audit = audit;
    }

    public event Action<EvidenceItem>? ItemAdded;

    public bool IncludesSha512 => _sha512;

    public int Count { get { lock (_gate) return _items.Count; } }

    public IReadOnlyList<EvidenceItem> Items
    {
        get { lock (_gate) return _items.ToList(); }
    }

    public string ToRelative(string absolutePath)
    {
        string full = Path.GetFullPath(absolutePath);
        string prefix = _root + Path.DirectorySeparatorChar;
        if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Path is outside the session folder: {absolutePath}");
        return full[prefix.Length..].Replace('\\', '/');
    }

    public string ToAbsolute(string relativePath) =>
        Path.Combine(_root, relativePath.Replace('/', Path.DirectorySeparatorChar));

    /// <summary>Hashes the file now and records it. The file must already be completely written.</summary>
    public EvidenceItem Add(string absolutePath, EvidenceCategory category, int phase, string description,
        string? sourceUrl = null, int? captureSeq = null)
    {
        string rel = ToRelative(absolutePath);
        FileDigest hashes = HashEngine.ComputeFile(absolutePath, _sha512, _bufferKb);
        EvidenceItem item;
        lock (_gate)
        {
            if (_items.Any(i => string.Equals(i.RelativePath, rel, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException($"File already registered: {rel}");
            item = new EvidenceItem
            {
                Id = ++_nextId,
                RelativePath = rel,
                Category = category,
                Phase = phase,
                Description = description,
                SourceUrl = sourceUrl,
                RegisteredUtc = TrustedClock.UtcNow,
                SystemUtc = TrustedClock.SystemUtcNow,
                ClockSynced = TrustedClock.IsSynchronized,
                ClockOffsetMs = TrustedClock.OffsetMs is { } off ? Math.Round(off, 1) : null,
                SizeBytes = hashes.Length,
                Sha256 = hashes.Sha256,
                Sha512 = hashes.Sha512,
                CaptureSeq = captureSeq
            };
            _items.Add(item);
        }

        _audit?.TryAppend(AuditLevel.Info, phase, "evidence.registered", rel,
            new Dictionary<string, object?> { ["id"] = item.Id, ["sha256"] = item.Sha256, ["bytes"] = item.SizeBytes, ["category"] = category.ToString() });
        try { ItemAdded?.Invoke(item); }
        catch (Exception) { /* a faulty UI subscriber must never break evidence registration */ }
        return item;
    }

    public bool IsRegistered(string relativePath)
    {
        lock (_gate) return _items.Any(i => string.Equals(i.RelativePath, relativePath, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>All files currently on disk under the session folder (relative paths, '/' separators).</summary>
    public List<string> EnumerateDiskFiles() =>
        Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories)
            .Select(ToRelative)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();
}

/// <summary>Everything that belongs to one collection session.</summary>
public sealed class SessionContext : IDisposable
{
    public SessionInfo Info { get; }
    public AppConfig Config { get; }
    public ConfigManager ConfigManager { get; }
    public string ConfigPath { get; }
    public string ConfigSha256 { get; }
    public string Folder { get; }
    public AuditLog Audit { get; }
    public EvidenceRegistry Registry { get; }

    /// <summary>Index 1..4 = Phase 1..4 (index 0 unused).</summary>
    public PhaseStatus[] Phases { get; } = new PhaseStatus[5];
    public DateTime?[] PhaseStartedUtc { get; } = new DateTime?[5];
    public DateTime?[] PhaseFinishedUtc { get; } = new DateTime?[5];

    public List<CheckResult> PreparationChecks { get; } = new();
    public BrowserCleanReport? CleanReport { get; set; }
    public List<CheckResult> NetworkChecks { get; } = new();
    public NetworkSnapshot? Network { get; set; }
    public NtpSyncResult? StartTimeSync { get; set; }
    public NtpSyncResult? SealTimeSync { get; set; }
    public List<CaptureSet> Captures { get; } = new();
    public List<WhoisResult> Whois { get; } = new();
    public List<NavigationTrailEntry> NavigationTrail { get; } = new();
    public string? WebView2Version { get; set; }
    public bool IsSealed { get; set; }

    public string SessionDir => Path.Combine(Folder, "00_session");
    public string PreparationDir => Path.Combine(Folder, "01_preparation");
    public string NetworkDir => Path.Combine(Folder, "02_network");
    public string CapturesDir => Path.Combine(Folder, "03_captures");
    public string WhoisDir => Path.Combine(Folder, "04_whois");
    public string SealingDir => Path.Combine(Folder, SessionLayout.SealingDir);

    private int _captureSeq;
    private readonly object _seqGate = new();

    private SessionContext(SessionInfo info, ConfigManager manager, string folder)
    {
        AppConfig config = manager.Config;
        Info = info; Config = config; ConfigManager = manager; ConfigPath = manager.FilePath; ConfigSha256 = manager.Sha256; Folder = folder;
        Audit = new AuditLog(Path.Combine(folder, SessionLayout.AuditDir), info.SessionId,
            config.Logging.FlushEveryEntry, config.Logging.WriteTextLog);
        Registry = new EvidenceRegistry(folder, config.Hashing.Algorithms.Contains("SHA512"), config.Hashing.BufferSizeKb, Audit);
    }

    public static SessionContext Create(ConfigManager cfg, SessionInfo info)
    {
        AppConfig config = cfg.Config;
        string outRoot = AppConfig.ResolvePath(config.Paths.OutputRoot);
        Directory.CreateDirectory(outRoot);

        info.CreatedUtc = TrustedClock.UtcNow;
        if (string.IsNullOrWhiteSpace(info.SessionId))
            info.SessionId = SessionInfo.NewSessionId(config.Session.SessionIdPrefix, info.CreatedUtc);

        string folder = Path.Combine(outRoot, $"{info.SessionId}_{JsonUtil.SafeName(info.CaseReference, 32)}");
        if (Directory.Exists(folder)) throw new IOException($"Session folder already exists: {folder}");
        Directory.CreateDirectory(folder);
        foreach (string sub in SessionLayout.SubFolders) Directory.CreateDirectory(Path.Combine(folder, sub));

        var ctx = new SessionContext(info, cfg, folder);
        ctx.Audit.Info(0, "session.created", $"Session {info.SessionId} created",
            new Dictionary<string, object?>
            {
                ["tool"] = AppInfo.Name + " " + AppInfo.Version,
                ["case"] = info.CaseReference,
                ["operator"] = info.OperatorName,
                ["configSha256"] = cfg.Sha256,
                ["clockSynced"] = TrustedClock.IsSynchronized,
                ["clockOffsetMs"] = TrustedClock.OffsetMs is { } o ? Math.Round(o, 1) : null
            });

        // Immutable description of the session and of the configuration in force.
        string sessionJson = Path.Combine(ctx.SessionDir, "session.json");
        JsonUtil.WriteFile(sessionJson, new
        {
            schemaVersion = 1,
            tool = new { name = AppInfo.Name, version = AppInfo.Version, standard = AppInfo.Standard },
            session = info,
            configFile = new { path = cfg.FilePath, sha256 = cfg.Sha256 }
        });
        ctx.Registry.Add(sessionJson, EvidenceCategory.Session, 0, "Session, case and operator description");

        string effective = Path.Combine(ctx.SessionDir, "config_effective.json");
        JsonUtil.WriteText(effective, System.Text.Json.JsonSerializer.Serialize(config, ConfigManager.JsonOptions) + "\n");
        ctx.Registry.Add(effective, EvidenceCategory.Session, 0, "Configuration actually in force (after validation), as loaded by the application");

        if (File.Exists(cfg.FilePath))
        {
            string snap = Path.Combine(ctx.SessionDir, "config_snapshot.json");
            File.Copy(cfg.FilePath, snap, overwrite: false);
            string nowHash = HashEngine.ComputeFile(snap, false).Sha256;
            ctx.Registry.Add(snap, EvidenceCategory.Session, 0, "Copy of config.json taken when the session was created");
            if (!HashEngine.HexEquals(nowHash, cfg.Sha256))
                ctx.Audit.Warn(0, "config.changed", "config.json changed on disk after it was loaded; the application keeps using the loaded values (see config_effective.json).",
                    new Dictionary<string, object?> { ["loadedSha256"] = cfg.Sha256, ["currentSha256"] = nowHash });
        }
        return ctx;
    }

    /// <summary>Allocates the next capture set (folder) under 03_captures.</summary>
    public CaptureSet BeginCaptureSet(string label, string url)
    {
        int seq;
        lock (_seqGate) seq = ++_captureSeq;

        string host = "page";
        if (Uri.TryCreate(url, UriKind.Absolute, out Uri? u) && !string.IsNullOrEmpty(u.Host)) host = u.IdnHost;
        DateTime now = TrustedClock.UtcNow;
        string rel = $"03_captures/{seq:D4}_{JsonUtil.SafeName(host, 40)}_{now:yyyyMMdd'T'HHmmss'Z'}";
        string abs = Path.Combine(Folder, rel.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(abs);

        var set = new CaptureSet { Seq = seq, Label = label, Folder = abs, RelativeFolder = rel, Url = url, StartedUtc = now };
        lock (Captures) Captures.Add(set);
        Audit.Info(3, "capture.begin", $"Capture #{seq:D4} started: {label}",
            new Dictionary<string, object?> { ["url"] = url, ["folder"] = rel });
        return set;
    }

    public void SetPhase(int phase, PhaseStatus status, string? message = null)
    {
        Phases[phase] = status;
        DateTime now = TrustedClock.UtcNow;
        if (status == PhaseStatus.Running) PhaseStartedUtc[phase] ??= now;
        if (status is PhaseStatus.Passed or PhaseStatus.PassedWithWarnings or PhaseStatus.Failed) PhaseFinishedUtc[phase] = now;
        AuditLevel level = status == PhaseStatus.Failed ? AuditLevel.Error : status == PhaseStatus.PassedWithWarnings ? AuditLevel.Warn : AuditLevel.Info;
        Audit.TryAppend(level, phase, "phase.status", $"Phase {phase}: {status}" + (message != null ? " - " + message : ""));
    }

    public void RecordNavigation(string kind, string url, bool userInitiated, bool redirected, string? status = null, int? httpStatus = null, string? title = null)
    {
        lock (NavigationTrail)
        {
            NavigationTrail.Add(new NavigationTrailEntry
            {
                Seq = NavigationTrail.Count + 1,
                TimeUtc = TrustedClock.FormatIso(TrustedClock.UtcNow),
                Kind = kind,
                Url = url,
                UserInitiated = userInitiated,
                Redirected = redirected,
                Status = status,
                HttpStatus = httpStatus,
                Title = title
            });
        }
    }

    /// <summary>Writes the chronological list of pages visited during Phase 3 and registers it as evidence.</summary>
    public EvidenceItem? SaveNavigationTrail()
    {
        List<NavigationTrailEntry> trail;
        lock (NavigationTrail) trail = [.. NavigationTrail];
        if (trail.Count == 0) return null;
        string path = Path.Combine(SessionDir, "navigation_trail.json");
        if (File.Exists(path)) return null;
        JsonUtil.WriteFile(path, new { schemaVersion = 1, count = trail.Count, entries = trail });
        return Registry.Add(path, EvidenceCategory.Log, 3, "Chronological trail of every page navigation in the evidence browser");
    }

    public void Dispose() => Audit.Dispose();
}
