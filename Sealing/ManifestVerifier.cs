using EvidenceCollector.Core;
using System.Text.Json;

namespace EvidenceCollector.Sealing;

/// <summary>
/// Re-verifies a sealed session folder from its manifest alone (no running session is needed), so a court expert,
/// the opposing party or the operator can check integrity years later:
///   1. every file listed in manifest.json exists and still has the recorded size and SHA-256 / SHA-512;
///   2. no file was added to the folder after sealing;
///   3. manifest.sha256 (sha256sum format) agrees with manifest.json;
///   4. the audit log hash chain is intact and ends at the recorded head hash;
///   5. the SHA-256 written in SEAL_RECEIPT.txt matches manifest.json.
/// </summary>
public static class ManifestVerifier
{
    public const string ManifestRelPath = SessionLayout.Manifest;
    public const string ManifestListRelPath = SessionLayout.ManifestList;
    public const string ReceiptRelPath = SessionLayout.Receipt;
    public const string AuditRelPath = SessionLayout.AuditJsonl;

    private const int BufferKb = 512;

    public static async Task<VerificationReport> VerifyAsync(string sessionFolder, IProgress<(int Done, int Total)>? progress = null, CancellationToken ct = default)
    {
        var report = new VerificationReport { Folder = sessionFolder };
        var root = Path.GetFullPath(sessionFolder);
        var manifestPath = Path.Combine(root, ManifestRelPath.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(manifestPath))
        {
            report.Add(IssueSeverity.Error, ManifestRelPath, "manifest.json not found: this folder is not a sealed Evidence Collector package.");
            return report;
        }

        report.ManifestSha256 = HashEngine.ComputeFile(manifestPath, false, BufferKb, ct).Sha256;

        JsonDocument doc;
        try { doc = JsonDocument.Parse(File.ReadAllBytes(manifestPath)); }
        catch (Exception ex)
        {
            report.Add(IssueSeverity.Error, ManifestRelPath, "manifest.json is not valid JSON: " + ex.Message);
            return report;
        }

        using (doc)
        {
            var rootEl = doc.RootElement;
            try
            {
                if (rootEl.TryGetProperty("session", out var s))
                {
                    report.SessionId = Str(s, "sessionId");
                    report.CaseReference = Str(s, "caseReference");
                }
                report.SealedUtc = Str(rootEl, "sealedUtc");

                var expected = new Dictionary<string, (long Size, string Sha256, string? Sha512)>(StringComparer.OrdinalIgnoreCase);
                foreach (var f in rootEl.GetProperty("files").EnumerateArray())
                {
                    var rel = Str(f, "path") ?? "";
                    if (!IsSafeRelative(rel)) { report.Add(IssueSeverity.Error, rel, "unsafe path in manifest (absolute or '..'): entry ignored."); continue; }
                    expected[rel] = (f.GetProperty("size").GetInt64(), Str(f, "sha256") ?? "", Str(f, "sha512"));
                }

                // 1. listed files
                var anySha512 = expected.Values.Any(v => v.Sha512 != null);
                var existing = new List<string>();
                foreach (var rel in expected.Keys)
                {
                    var abs = Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar));
                    if (File.Exists(abs)) existing.Add(abs);
                    else report.Add(IssueSeverity.Error, rel, "file listed in the manifest is MISSING.");
                }
                report.FilesChecked = expected.Count;

                int total = existing.Count;
                IProgress<StepProgress>? hashProgress = progress == null
                    ? null
                    : new Progress<StepProgress>(p => progress.Report((p.Percent * total / 100, total)));
                var hashes = await HashEngine.ComputeManyAsync(existing, anySha512, BufferKb,
                    Math.Clamp(Environment.ProcessorCount, 1, 4), hashProgress, ct).ConfigureAwait(false);
                foreach (var (rel, exp) in expected)
                {
                    var abs = Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar));
                    if (!hashes.TryGetValue(abs, out var h)) continue; // already reported as missing
                    var ok = true;
                    if (h.Length != exp.Size) { report.Add(IssueSeverity.Error, rel, $"size differs (manifest {exp.Size}, disk {h.Length})."); ok = false; }
                    if (!HashEngine.HexEquals(h.Sha256, exp.Sha256)) { report.Add(IssueSeverity.Error, rel, "SHA-256 differs: the file was modified after sealing."); ok = false; }
                    if (exp.Sha512 != null && !HashEngine.HexEquals(h.Sha512, exp.Sha512)) { report.Add(IssueSeverity.Error, rel, "SHA-512 differs: the file was modified after sealing."); ok = false; }
                    if (ok) report.FilesOk++;
                }

                // 2. files added after sealing
                var allowedExtras = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ManifestListRelPath, ReceiptRelPath };
                foreach (var abs in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    var rel = Path.GetRelativePath(root, abs).Replace('\\', '/');
                    if (!expected.ContainsKey(rel) && !allowedExtras.Contains(rel) && !rel.Equals(ManifestRelPath, StringComparison.OrdinalIgnoreCase))
                        report.Add(IssueSeverity.Error, rel, "file is NOT listed in the manifest (added after sealing?).");
                }

                // 3. sha256sum-style list
                var listPath = Path.Combine(root, ManifestListRelPath.Replace('/', Path.DirectorySeparatorChar));
                if (!File.Exists(listPath)) report.Add(IssueSeverity.Warning, ManifestListRelPath, "manifest.sha256 not found.");
                else
                {
                    var listed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var line in File.ReadLines(listPath))
                    {
                        var t = line.TrimEnd('\r');
                        if (t.Length < 67) continue;
                        listed[t[66..]] = t[..64];
                    }
                    foreach (var (rel, exp) in expected)
                        if (!listed.TryGetValue(rel, out var h) || !HashEngine.HexEquals(h, exp.Sha256))
                            report.Add(IssueSeverity.Error, ManifestListRelPath, $"manifest.sha256 disagrees with manifest.json for '{rel}'.");
                    if (!listed.TryGetValue(ManifestRelPath, out var mh) || !HashEngine.HexEquals(mh, report.ManifestSha256))
                        report.Add(IssueSeverity.Error, ManifestListRelPath, "manifest.sha256 does not contain the correct hash of manifest.json.");
                }

                // 4. audit chain
                var auditPath = Path.Combine(root, AuditRelPath.Replace('/', Path.DirectorySeparatorChar));
                if (!File.Exists(auditPath)) report.Add(IssueSeverity.Error, AuditRelPath, "audit log not found.");
                else
                {
                    // The chain must start at the genesis value of THIS session, otherwise a log copied from another session would pass.
                    var av = AuditLog.Verify(auditPath, report.SessionId != null ? AuditLog.GenesisHash(report.SessionId) : null);
                    report.AuditChainOk = av.Ok;
                    report.AuditEntries = (int)av.Count;
                    report.AuditHeadHash = av.HeadHash;
                    if (!av.Ok) report.Add(IssueSeverity.Error, AuditRelPath, "audit log hash chain is broken: " + av.Message);
                    if (rootEl.TryGetProperty("audit", out var a))
                    {
                        var head = Str(a, "headHash");
                        if (av.Ok && head != null && !HashEngine.HexEquals(head, av.HeadHash))
                            report.Add(IssueSeverity.Error, AuditRelPath, "audit log head hash differs from the one sealed in the manifest (entries were appended or removed).");
                        if (a.TryGetProperty("entries", out var ne) && ne.TryGetInt32(out var n) && av.Ok && n != av.Count)
                            report.Add(IssueSeverity.Error, AuditRelPath, $"audit log has {av.Count} entries, the manifest recorded {n}.");
                    }
                }

                // 5. receipt
                var receipt = Path.Combine(root, ReceiptRelPath.Replace('/', Path.DirectorySeparatorChar));
                if (!File.Exists(receipt)) report.Add(IssueSeverity.Warning, ReceiptRelPath, "seal receipt not found.");
                else
                {
                    var line = File.ReadLines(receipt).FirstOrDefault(l => l.StartsWith("Manifest SHA-256", StringComparison.Ordinal));
                    var value = line?[(line.IndexOf(':') + 1)..].Trim();
                    if (value == null || !HashEngine.HexEquals(value, report.ManifestSha256))
                        report.Add(IssueSeverity.Error, ReceiptRelPath, "the manifest hash written in the receipt does not match manifest.json.");
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                report.Add(IssueSeverity.Error, ManifestRelPath, "manifest.json could not be interpreted: " + ex.Message);
            }
        }
        return report;
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool IsSafeRelative(string rel) =>
        rel.Length > 0 && !Path.IsPathRooted(rel) && !rel.Contains(':') &&
        !rel.Split('/', '\\').Any(p => p == "..");
}
