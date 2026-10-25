using System.Text;

namespace EvidenceCollector.Sealing;

public sealed class SealException : Exception
{
    public SealException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Outcome of sealing a session (Phase 4).</summary>
public sealed class SealResult
{
    public DateTime SealedUtc { get; set; }
    public bool ClockSynced { get; set; }
    public string SessionFolder { get; set; } = "";
    public string ManifestPath { get; set; } = "";
    public string ManifestSha256 { get; set; } = "";
    public string ManifestListPath { get; set; } = "";
    public string ManifestListSha256 { get; set; } = "";
    public string ReceiptPath { get; set; } = "";
    public string ReportPath { get; set; } = "";
    public string? ZipPath { get; set; }
    public string? ZipSha256 { get; set; }
    public string AuditHeadHash { get; set; } = "";
    public int AuditEntries { get; set; }
    public int FileCount { get; set; }
    public VerificationReport? Verification { get; set; }
    public List<string> Warnings { get; } = [];

    public string ToText()
    {
        var sb = new StringBuilder();
        sb.AppendLine("SESSION SEALED");
        sb.AppendLine($"Sealed (UTC)          : {SealedUtc:yyyy-MM-dd HH:mm:ss.fff}  ({(ClockSynced ? "NTP-synchronised clock" : "UNSYNCHRONISED clock")})");
        sb.AppendLine($"Files in manifest     : {FileCount}");
        sb.AppendLine($"Audit log             : {AuditEntries} entries, head hash {AuditHeadHash}");
        sb.AppendLine($"manifest.json SHA-256 : {ManifestSha256}");
        sb.AppendLine($"manifest.sha256 SHA-256: {ManifestListSha256}");
        if (ZipPath != null) sb.AppendLine($"ZIP archive           : {ZipPath}\n  SHA-256             : {ZipSha256}");
        sb.AppendLine($"Report                : {ReportPath}");
        if (Verification != null) sb.AppendLine($"Verification          : {(Verification.Ok ? "PASSED" : "FAILED")} ({Verification.FilesChecked} files re-hashed)");
        foreach (var w in Warnings) sb.AppendLine("Warning: " + w);
        sb.AppendLine();
        sb.AppendLine("Write the manifest.json SHA-256 above in the official record (procès-verbal): it fingerprints the whole package.");
        return sb.ToString();
    }
}

public enum IssueSeverity { Info, Warning, Error }

public sealed class VerificationIssue
{
    public IssueSeverity Severity { get; set; }
    public string Path { get; set; } = "";
    public string Message { get; set; } = "";
}

/// <summary>Result of re-verifying a sealed package against its manifest.</summary>
public sealed class VerificationReport
{
    public string Folder { get; set; } = "";
    public DateTime VerifiedUtc { get; set; } = DateTime.UtcNow;
    public int FilesChecked { get; set; }
    public int FilesOk { get; set; }
    public int AuditEntries { get; set; }
    public bool AuditChainOk { get; set; }
    public string? AuditHeadHash { get; set; }
    public string? ManifestSha256 { get; set; }
    public string? SessionId { get; set; }
    public string? CaseReference { get; set; }
    public string? SealedUtc { get; set; }
    public List<VerificationIssue> Issues { get; } = [];

    public bool Ok => !Issues.Any(i => i.Severity == IssueSeverity.Error);

    public void Add(IssueSeverity severity, string path, string message) =>
        Issues.Add(new VerificationIssue { Severity = severity, Path = path, Message = message });

    public string ToText()
    {
        var sb = new StringBuilder();
        sb.AppendLine(Ok ? "VERIFICATION PASSED - the package matches its manifest." : "VERIFICATION FAILED - the package does NOT match its manifest.");
        sb.AppendLine();
        sb.AppendLine($"Folder            : {Folder}");
        if (CaseReference != null) sb.AppendLine($"Case reference    : {CaseReference}");
        if (SessionId != null) sb.AppendLine($"Session id        : {SessionId}");
        if (SealedUtc != null) sb.AppendLine($"Sealed (UTC)      : {SealedUtc}");
        if (ManifestSha256 != null) sb.AppendLine($"manifest.json     : SHA-256 {ManifestSha256}");
        sb.AppendLine($"Files             : {FilesOk} of {FilesChecked} verified");
        sb.AppendLine($"Audit log chain   : {(AuditChainOk ? "intact" : "BROKEN")} ({AuditEntries} entries{(AuditHeadHash != null ? ", head " + AuditHeadHash : "")})");
        sb.AppendLine($"Verified (UTC)    : {VerifiedUtc:yyyy-MM-dd HH:mm:ss} (system clock)");
        if (Issues.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("FINDINGS");
            foreach (var i in Issues.OrderByDescending(x => x.Severity))
                sb.AppendLine($"  [{i.Severity.ToString().ToUpperInvariant()}] {(string.IsNullOrEmpty(i.Path) ? "" : i.Path + ": ")}{i.Message}");
        }
        return sb.ToString();
    }
}
