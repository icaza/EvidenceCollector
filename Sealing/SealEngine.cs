using EvidenceCollector.Core;
using System.IO.Compression;
using System.Text;

namespace EvidenceCollector.Sealing;

/// <summary>
/// Phase 4. Closing and sealing of a session, in this fixed order:
///  1. final NTP synchronisation (the official sealing time);
///  2. every registered file is re-hashed and compared with the fingerprint taken when it was created;
///     any unregistered file in the folder stops the seal;
///  3. the HTML report is written, then the audit log is closed (nothing can be appended afterwards);
///  4. manifest.json (all files, sizes, SHA-256/512, audit head hash), manifest.sha256 (sha256sum format) and the receipt;
///  5. optional ZIP archive + its SHA-256, files marked read-only, full re-verification.
/// </summary>
public static class SealEngine
{
    public static async Task<SealResult> SealAsync(SessionContext ctx, IProgress<string>? progress, CancellationToken ct)
    {
        void P(string m) => progress?.Report(m);
        var cfg = ctx.Config;
        var audit = ctx.Audit;
        var reg = ctx.Registry;

        if (ctx.IsSealed || audit.IsClosed) throw new SealException("This session is already sealed.");
        if (ctx.Captures.Count == 0) throw new SealException("Nothing to seal: no capture was made in Phase 3.");

        EnsureFreeSpace(ctx.Folder, Math.Max(cfg.Workflow.MinimumFreeDiskMb, 1));

        ctx.SetPhase(4, PhaseStatus.Running);
        audit.Info(4, "seal.begin", "Sealing started");

        // ---------------------------------------------------------------- 1. official time
        P("Final time synchronisation (NTP)…");
        NtpSyncResult sync = await TimeSync.SyncAsync(cfg.Ntp, ct).ConfigureAwait(false);
        ctx.SealTimeSync = sync;
        audit.Log(sync.Success ? AuditLevel.Info : AuditLevel.Warn, 4, "seal.ntp", sync.Summary,
            new Dictionary<string, object?>
            {
                ["offsetMs"] = Math.Round(sync.MedianOffsetMs, 1),
                ["spreadMs"] = Math.Round(sync.SpreadMs, 1),
                ["servers"] = sync.Samples.Count
            });
        if (!sync.Success && cfg.Workflow.RequireNtpSync)
        {
            ctx.SetPhase(4, PhaseStatus.Failed, "NTP synchronisation unavailable");
            throw new SealException("The session cannot be sealed without a valid NTP synchronisation (workflow.requireNtpSync = true).\n" + sync.Summary);
        }
        DateTime sealedUtc = TrustedClock.UtcNow;
        bool clockSynced = TrustedClock.IsSynchronized;
        PhaseReports.SaveNtp(ctx, UniquePath(ctx.SealingDir, "ntp_seal_sync", ".json"), sync, 4, "NTP synchronisation at sealing time");

        // ---------------------------------------------------------------- 2. integrity re-check
        P("Re-hashing every evidence file…");
        ctx.SaveNavigationTrail();
        IReadOnlyList<EvidenceItem> items = reg.Items;
        var abs = items.Select(i => reg.ToAbsolute(i.RelativePath)).ToList();
        Dictionary<string, FileDigest> rehash = await HashEngine.ComputeManyAsync(abs, reg.IncludesSha512,
            cfg.Hashing.BufferSizeKb, cfg.Hashing.MaxParallelism,
            new Progress<StepProgress>(p => P($"Re-hashing evidence files… {p.Percent}%")), ct).ConfigureAwait(false);

        var problems = new List<string>();
        foreach (EvidenceItem i in items)
        {
            string path = reg.ToAbsolute(i.RelativePath);
            if (!File.Exists(path) || !rehash.TryGetValue(path, out FileDigest? h)) { problems.Add($"{i.RelativePath}: file is missing"); continue; }
            if (!HashEngine.HexEquals(h.Sha256, i.Sha256) || h.Length != i.SizeBytes)
                problems.Add($"{i.RelativePath}: content changed since it was captured (registered {Short(i.Sha256)}, now {Short(h.Sha256)})");
            else if (i.Sha512 != null && !HashEngine.HexEquals(h.Sha512, i.Sha512))
                problems.Add($"{i.RelativePath}: SHA-512 differs from the value recorded when the file was captured");
        }
        var registered = new HashSet<string>(items.Select(i => i.RelativePath), StringComparer.OrdinalIgnoreCase);
        foreach (string f in reg.EnumerateDiskFiles())
        {
            // The audit log files are written continuously until the log is closed; they are sealed separately below.
            if (registered.Contains(f) || f.Equals(SessionLayout.AuditJsonl, StringComparison.OrdinalIgnoreCase) || f.Equals(SessionLayout.AuditText, StringComparison.OrdinalIgnoreCase))
                continue;
            problems.Add($"{f}: file exists in the session folder but was never registered as evidence");
        }

        if (problems.Count > 0)
        {
            foreach (string p in problems) audit.Error(4, "seal.integrity", p);
            ctx.SetPhase(4, PhaseStatus.Failed, $"{problems.Count} integrity problem(s)");
            throw new SealException("Sealing refused: the session folder is not in the state in which it was recorded.\n - " + string.Join("\n - ", problems));
        }
        audit.Info(4, "seal.integrity", $"{items.Count} evidence files re-hashed: all match their fingerprints");

        // ---------------------------------------------------------------- 3. report, close the audit log
        P("Writing the report…");
        ctx.SetPhase(4, PhaseStatus.Passed);
        string reportPath = Path.Combine(ctx.Folder, SessionLayout.Report.Replace('/', Path.DirectorySeparatorChar));
        File.WriteAllText(reportPath, ReportGenerator.BuildHtml(ctx, audit.Snapshot(), reg.Items, sync, sealedUtc), new UTF8Encoding(false));

        audit.Info(4, "seal.closing", "Audit log closed: manifest, receipt and archive follow (events after this line are shown on screen only)",
            new Dictionary<string, object?> { ["evidenceFiles"] = items.Count });
        string head = audit.CloseAndGetHead();
        ctx.IsSealed = true; // from here on the session can no longer be modified, whatever happens next

        try
        {
            return await FinishSealAsync(ctx, sync, sealedUtc, clockSynced, items, reportPath, head, P, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not SealException)
        {
            throw new SealException("Sealing was interrupted after the audit log had been closed, so the session folder is incomplete and cannot be sealed again: " + ex.Message, ex);
        }
    }

    private static async Task<SealResult> FinishSealAsync(SessionContext ctx, NtpSyncResult sync, DateTime sealedUtc, bool clockSynced,
        IReadOnlyList<EvidenceItem> items, string reportPath, string head, Action<string> P, CancellationToken ct)
    {
        var cfg = ctx.Config;
        var reg = ctx.Registry;
        bool sha512 = reg.IncludesSha512;
        int bufferKb = cfg.Hashing.BufferSizeKb;

        string auditJsonl = Path.Combine(ctx.Folder, SessionLayout.AuditJsonl.Replace('/', Path.DirectorySeparatorChar));
        string auditTxt = Path.Combine(ctx.Folder, SessionLayout.AuditText.Replace('/', Path.DirectorySeparatorChar));
        IReadOnlyList<AuditEntry> snapshot = ctx.Audit.Snapshot();
        if (!File.Exists(auditTxt)) File.WriteAllText(auditTxt, AuditLog.FormatText(snapshot), new UTF8Encoding(false));

        // ---------------------------------------------------------------- 4. manifest
        P("Writing the manifest…");
        var files = new List<SealedFile>();
        foreach (EvidenceItem i in items)
            files.Add(new SealedFile
            {
                Path = i.RelativePath,
                Size = i.SizeBytes,
                Sha256 = i.Sha256,
                Sha512 = i.Sha512,
                Category = i.Category.ToString(),
                Phase = i.Phase,
                RegisteredUtc = TrustedClock.FormatIso(i.RegisteredUtc),
                ClockSynced = i.ClockSynced,
                Description = i.Description,
                SourceUrl = i.SourceUrl
            });

        foreach ((string path, string cat, string desc) in new[]
                 {
                     (auditJsonl, "Log", "Hash-chained audit log (authoritative, JSON lines)"),
                     (auditTxt, "Log", "Human-readable copy of the audit log"),
                     (reportPath, "Report", "HTML report (technical annex)")
                 })
        {
            FileDigest h = HashEngine.ComputeFile(path, sha512, bufferKb, ct);
            files.Add(new SealedFile
            {
                Path = reg.ToRelative(path),
                Size = h.Length,
                Sha256 = h.Sha256,
                Sha512 = h.Sha512,
                Category = cat,
                Phase = 4,
                RegisteredUtc = TrustedClock.FormatIso(sealedUtc),
                ClockSynced = clockSynced,
                Description = desc
            });
        }
        files = files.OrderBy(f => f.Path, StringComparer.Ordinal).ToList();

        string manifestPath = Path.Combine(ctx.Folder, SessionLayout.Manifest.Replace('/', Path.DirectorySeparatorChar));
        JsonUtil.WriteFile(manifestPath, new
        {
            schemaVersion = 1,
            tool = new { name = AppInfo.Name, version = AppInfo.Version, standard = AppInfo.Standard },
            session = ctx.Info,
            sealedUtc = TrustedClock.FormatIso(sealedUtc),
            timeReference = new
            {
                clockSynchronised = clockSynced,
                offsetMs = TrustedClock.OffsetMs is { } o ? Math.Round(o, 1) : (double?)null,
                startSync = ctx.StartTimeSync?.Summary,
                sealSync = sync.Summary,
                sealUncertaintyMs = Math.Round(sync.UncertaintyMs, 1)
            },
            configSha256 = ctx.ConfigSha256,
            environment = new
            {
                machine = Environment.MachineName,
                os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                webView2 = ctx.WebView2Version
            },
            audit = new
            {
                file = SessionLayout.AuditJsonl,
                textCopy = SessionLayout.AuditText,
                entries = snapshot.Count,
                genesisHash = AuditLog.GenesisHash(ctx.Info.SessionId),
                headHash = head
            },
            algorithms = sha512 ? new[] { "SHA-256", "SHA-512" } : new[] { "SHA-256" },
            fileCount = files.Count,
            files
        });
        string manifestHash = HashEngine.ComputeFile(manifestPath, false, bufferKb, ct).Sha256;

        // sha256sum-compatible list (binary-mode marker '*'): "sha256sum -c 05_sealing/manifest.sha256" from the session folder.
        string listPath = Path.Combine(ctx.Folder, SessionLayout.ManifestList.Replace('/', Path.DirectorySeparatorChar));
        var list = new StringBuilder();
        foreach (SealedFile f in files.Append(new SealedFile { Path = SessionLayout.Manifest, Sha256 = manifestHash }).OrderBy(f => f.Path, StringComparer.Ordinal))
            list.Append(f.Sha256).Append(" *").Append(f.Path).Append('\n');
        File.WriteAllText(listPath, list.ToString(), new UTF8Encoding(false));
        string listHash = HashEngine.ComputeFile(listPath, false, bufferKb, ct).Sha256;

        string receiptPath = Path.Combine(ctx.Folder, SessionLayout.Receipt.Replace('/', Path.DirectorySeparatorChar));
        File.WriteAllText(receiptPath, BuildReceipt(ctx, sync, sealedUtc, manifestHash, listHash, head, snapshot.Count, files.Count), new UTF8Encoding(false));

        var result = new SealResult
        {
            SealedUtc = sealedUtc,
            ClockSynced = clockSynced,
            SessionFolder = ctx.Folder,
            ManifestPath = manifestPath,
            ManifestSha256 = manifestHash,
            ManifestListPath = listPath,
            ManifestListSha256 = listHash,
            ReceiptPath = receiptPath,
            ReportPath = reportPath,
            AuditHeadHash = head,
            AuditEntries = snapshot.Count,
            FileCount = files.Count
        };
        if (!sync.Success) result.Warnings.Add("The clock was NOT synchronised with NTP at sealing time: timestamps rely on the workstation clock.");

        // ---------------------------------------------------------------- 5. archive, read-only, verification
        if (cfg.Sealing.CreateZipArchive)
        {
            P("Creating the ZIP archive…");
            try
            {
                string zipPath = ctx.Folder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + ".zip";
                await Task.Run(() => CreateZip(ctx.Folder, zipPath, ct), ct).ConfigureAwait(false);
                string zh = HashEngine.ComputeFile(zipPath, false, bufferKb, ct).Sha256;
                File.WriteAllText(zipPath + ".sha256", $"{zh} *{Path.GetFileName(zipPath)}\n", new UTF8Encoding(false));
                result.ZipPath = zipPath;
                result.ZipSha256 = zh;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                result.Warnings.Add("The ZIP archive could not be created (the sealed folder itself is complete): " + ex.Message);
            }
        }

        if (cfg.Sealing.MarkFilesReadOnly)
        {
            P("Marking files read-only…");
            try
            {
                var targets = Directory.EnumerateFiles(ctx.Folder, "*", SearchOption.AllDirectories).ToList();
                if (result.ZipPath != null) { targets.Add(result.ZipPath); targets.Add(result.ZipPath + ".sha256"); }
                foreach (string f in targets)
                {
                    try { File.SetAttributes(f, File.GetAttributes(f) | FileAttributes.ReadOnly); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best effort */ }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                result.Warnings.Add("Files could not all be marked read-only: " + ex.Message);
            }
        }

        if (cfg.Sealing.VerifyAfterSeal)
        {
            P("Verifying the sealed package…");
            result.Verification = await ManifestVerifier.VerifyAsync(ctx.Folder,
                new Progress<(int Done, int Total)>(p => P($"Verifying the sealed package… {p.Done}/{p.Total} files")), ct).ConfigureAwait(false);
            if (!result.Verification.Ok)
                result.Warnings.Add("Post-seal verification reported problems: see the verification details.");
        }
        return result;
    }

    private static string BuildReceipt(SessionContext ctx, NtpSyncResult sync, DateTime sealedUtc, string manifestHash, string listHash,
        string head, int auditEntries, int fileCount)
    {
        var sb = new StringBuilder();
        sb.AppendLine("EVIDENCE COLLECTOR - SEAL RECEIPT");
        sb.AppendLine("=================================");
        sb.AppendLine($"Case reference        : {ctx.Info.CaseReference}");
        sb.AppendLine($"Operator              : {ctx.Info.OperatorName}");
        sb.AppendLine($"Session id            : {ctx.Info.SessionId}");
        sb.AppendLine($"Sealed (UTC)          : {sealedUtc:yyyy-MM-dd HH:mm:ss.fff}");
        sb.AppendLine($"Time reference        : {(sync.Success ? sync.Summary : "NOT SYNCHRONISED - " + sync.Summary)}");
        sb.AppendLine($"Files in the manifest : {fileCount}");
        sb.AppendLine($"Audit log             : {auditEntries} entries, head hash {head}");
        sb.AppendLine();
        sb.AppendLine($"Manifest SHA-256      : {manifestHash}");
        sb.AppendLine($"Manifest list SHA-256 : {listHash}   (manifest.sha256)");
        sb.AppendLine();
        sb.AppendLine("Report the 'Manifest SHA-256' value in the official record: it fingerprints the entire package.");
        sb.AppendLine("Verify: from the session folder run  sha256sum -c 05_sealing/manifest.sha256");
        sb.AppendLine("        or use 'Verify a sealed package' in Evidence Collector.");
        return sb.ToString();
    }

    private static void CreateZip(string folder, string zipPath, CancellationToken ct)
    {
        string rootName = Path.GetFileName(folder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        using var fs = new FileStream(zipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Create);
        foreach (string file in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            string rel = Path.GetRelativePath(folder, file).Replace('\\', '/');
            // PNG/PDF content is already compressed: storing it avoids wasted CPU.
            CompressionLevel level = rel.EndsWith(".png", StringComparison.OrdinalIgnoreCase) || rel.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase)
                ? CompressionLevel.NoCompression : CompressionLevel.Optimal;
            zip.CreateEntryFromFile(file, rootName + "/" + rel, level);
        }
    }

    private static void EnsureFreeSpace(string folder, int minMb)
    {
        try
        {
            string? root = Path.GetPathRoot(Path.GetFullPath(folder));
            if (string.IsNullOrEmpty(root)) return;
            long free = new DriveInfo(root).AvailableFreeSpace;
            if (free < minMb * 1024L * 1024L)
                throw new SealException($"Not enough free disk space to seal the session ({free / 1048576} MB available, {minMb} MB required).");
        }
        catch (SealException) { throw; }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException or NotSupportedException)
        {
            // free space cannot be determined (network share, ...): carry on
        }
    }

    /// <summary>A path that does not exist yet, so a repeated seal attempt never overwrites an earlier file.</summary>
    private static string UniquePath(string directory, string baseName, string extension)
    {
        string path = Path.Combine(directory, baseName + extension);
        for (int n = 2; File.Exists(path); n++) path = Path.Combine(directory, $"{baseName}_{n}{extension}");
        return path;
    }

    private static string Short(string hash) => hash.Length > 12 ? hash[..12] + "…" : hash;

    private sealed class SealedFile
    {
        public string Path { get; set; } = "";
        public long Size { get; set; }
        public string Sha256 { get; set; } = "";
        public string? Sha512 { get; set; }
        public string? Category { get; set; }
        public int Phase { get; set; }
        public string? RegisteredUtc { get; set; }
        public bool ClockSynced { get; set; }
        public string? Description { get; set; }
        public string? SourceUrl { get; set; }
    }
}
