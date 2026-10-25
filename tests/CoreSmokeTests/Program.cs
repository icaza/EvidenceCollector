// Platform-neutral smoke tests for the evidence engine. Run:  dotnet run --project tests/CoreSmokeTests
// They exercise the same source files as the application: hashing, audit chain, NTP maths, URL validation,
// and a complete session -> seal -> verify -> tamper cycle. Exit code 0 = all passed.
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EvidenceCollector.Config;
using EvidenceCollector.Core;
using EvidenceCollector.Sealing;

int passed = 0, failed = 0;

void Check(string name, bool ok, string? detail = null)
{
    if (ok) { passed++; Console.WriteLine($"  PASS  {name}"); }
    else { failed++; Console.WriteLine($"  FAIL  {name}{(detail != null ? "  -> " + detail : "")}"); }
}

void Section(string title) => Console.WriteLine($"\n== {title}");

string root = Path.Combine(Path.GetTempPath(), "evc-smoke-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(root);

static void MakeWritable(string path)
{
    if (File.Exists(path)) File.SetAttributes(path, FileAttributes.Normal);
}

static async Task<string> RunProcess(string file, string args, string workDir)
{
    var psi = new ProcessStartInfo(file, args) { WorkingDirectory = workDir, RedirectStandardOutput = true, RedirectStandardError = true };
    using Process p = Process.Start(psi)!;
    string output = await p.StandardOutput.ReadToEndAsync() + await p.StandardError.ReadToEndAsync();
    await p.WaitForExitAsync();
    return p.ExitCode + "|" + output;
}

try
{
    // ------------------------------------------------------------------------------------------ hashing
    Section("Hashing");
    Check("SHA-256 of 'abc' (FIPS 180 vector)", HashEngine.Sha256HexOfString("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    string abc = Path.Combine(root, "abc.txt");
    File.WriteAllText(abc, "abc");
    FileDigest d = HashEngine.ComputeFile(abc, includeSha512: true);
    Check("file SHA-256", d.Sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    Check("file SHA-512 (FIPS 180 vector)", d.Sha512 != null && d.Sha512.StartsWith("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"));
    Check("file length", d.Length == 3);
    Check("HexEquals is case-insensitive", HashEngine.HexEquals("ABCDEF", "abcdef"));

    // ------------------------------------------------------------------------------------------ NTP maths
    Section("NTP");
    DateTime now = DateTime.UtcNow;
    double roundTripErr = Math.Abs((NtpClient.FromNtpTimestamp(NtpClient.ToNtpTimestamp(now)) - now).TotalMilliseconds);
    Check("NTP timestamp round trip < 1 ms", roundTripErr < 1, roundTripErr.ToString("0.000"));

    DateTime sent = DateTime.UtcNow;
    byte[] req = NtpClient.BuildRequest(sent, out ulong origin);
    byte[] reply = FakeNtpReply(req, DateTime.UtcNow.AddMilliseconds(250));
    NtpSample? sample = NtpClient.ParseResponse(reply, 48, origin, sent, 20, out string? ntpErr);
    Check("reply parsed", sample != null, ntpErr);
    Check("offset of a server 250 ms ahead is about +250 ms", sample != null && Math.Abs(sample.OffsetMs - 250) < 30, sample?.OffsetMs.ToString("0.0"));
    byte[] spoofed = (byte[])reply.Clone(); spoofed[24] ^= 0xFF;
    Check("reply with a wrong originate timestamp is rejected", NtpClient.ParseResponse(spoofed, 48, origin, sent, 20, out _) == null);
    byte[] unsynced = (byte[])reply.Clone(); unsynced[0] |= 0xC0; // leap indicator 3
    Check("reply from an unsynchronised server is rejected", NtpClient.ParseResponse(unsynced, 48, origin, sent, 20, out _) == null);

    // ------------------------------------------------------------------------------------------ URL validation
    Section("URL validation");
    var web = new WebViewConfig();
    UrlValidationResult ok1 = UrlValidator.Validate("example.com/path?q=1", web);
    Check("bare host gets the default scheme", ok1.IsValid && ok1.Normalized.StartsWith("https://example.com/"), ok1.Normalized + " " + ok1.Error);
    foreach (string bad in new[] { "javascript:alert(1)", "file:///C:/Windows/win.ini", "data:text/html,<b>x</b>", "ftp://example.com/", "" })
        Check($"refused: '{bad}'", !UrlValidator.Validate(bad, web).IsValid);

    // ------------------------------------------------------------------------------------------ shipped configuration
    Section("Configuration");
    string shippedConfig = ShippedConfigPath();
    ConfigManager shipped = ConfigManager.Load(shippedConfig);
    Check("config.json of the project loads without warnings", shipped.Warnings.Count == 0 && !shipped.SaveDisabled, string.Join(" | ", shipped.Warnings));
    Check("config.json lists every setting at its built-in default",
        JsonSerializer.Serialize(shipped.Config, ConfigManager.JsonOptions) == JsonSerializer.Serialize(new AppConfig(), ConfigManager.JsonOptions));
    string brokenPath = Path.Combine(root, "broken-config.json");
    File.WriteAllText(brokenPath, "{ \"ui\": { \"theme\": ");
    ConfigManager broken = ConfigManager.Load(brokenPath);
    Check("a malformed config.json falls back to defaults and is never overwritten",
        broken.SaveDisabled && broken.Warnings.Count > 0 && File.ReadAllText(brokenPath).StartsWith("{ \"ui\""));
    string clampPath = Path.Combine(root, "clamp-config.json");
    File.WriteAllText(clampPath, "{ // comment\n \"ntp\": { \"timeoutMs\": 5, \"servers\": [] }, \"webView\": { \"allowedSchemes\": [\"ftp\"] }, }");
    ConfigManager clamped = ConfigManager.Load(clampPath);
    Check("comments and trailing commas are accepted; out-of-range values are clamped and reported",
        clamped.Config.Ntp.TimeoutMs == 500 && clamped.Config.Ntp.Servers.Count > 0 && clamped.Config.WebView.AllowedSchemes.SequenceEqual(new[] { "http", "https" }) && clamped.Warnings.Count >= 3,
        string.Join(" | ", clamped.Warnings));
    string themePath = Path.Combine(root, "theme-config.json");
    File.WriteAllText(themePath, "{\n  // my comment\n  \"ui\": { \"theme\": \"Dark\" }\n}\n");
    ConfigManager themed = ConfigManager.Load(themePath);
    themed.TrySaveTheme(ThemeMode.Light);
    string themedText = File.ReadAllText(themePath);
    Check("changing the theme patches the value in place and keeps the user's comments", themedText.Contains("// my comment") && themedText.Contains("\"Light\""), themedText);

    // ------------------------------------------------------------------------------------------ audit chain
    Section("Audit chain");
    string auditDir = Path.Combine(root, "audit-unit");
    string head;
    using (var log = new AuditLog(auditDir, "UNIT-1", flushEveryEntry: true, writeTextLog: true))
    {
        for (int i = 0; i < 6; i++) log.Info(i % 4, "test.event", $"message {i} with \"quotes\" and accents éà", new Dictionary<string, object?> { ["n"] = i });
        head = log.CloseAndGetHead();
    }
    string jsonl = Path.Combine(auditDir, "audit.jsonl");
    AuditVerifyResult av = AuditLog.Verify(jsonl, AuditLog.GenesisHash("UNIT-1"));
    Check("intact chain verifies", av.Ok && av.Count == 6 && av.HeadHash == head, av.Message);
    Check("a chain checked against another session's genesis fails", !AuditLog.Verify(jsonl, AuditLog.GenesisHash("OTHER")).Ok);

    // independent re-computation, written from the documentation in the report (not calling AuditLog.ComputeHash)
    string prev = HashEngine.Sha256HexOfString("EVC-AUDIT-GENESIS|UNIT-1");
    bool independent = true;
    foreach (string line in File.ReadLines(jsonl))
    {
        using JsonDocument doc = JsonDocument.Parse(line);
        JsonElement r = doc.RootElement;
        JsonElement off = r.GetProperty("clockOffsetUs");
        JsonElement data = r.GetProperty("data");
        string msg = r.GetProperty("message").GetString()!;
        string canonical = string.Join("\n",
            r.GetProperty("seq").GetInt64(), r.GetProperty("utc").GetString(),
            off.ValueKind == JsonValueKind.Null ? "null" : off.GetInt64().ToString(),
            r.GetProperty("level").GetString(), r.GetProperty("phase").GetInt32(), r.GetProperty("event").GetString(),
            msg.Length + ":" + msg, data.ValueKind == JsonValueKind.Null ? "null" : data.GetRawText(), prev);
        string h = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        if (h != r.GetProperty("hash").GetString() || r.GetProperty("prevHash").GetString() != prev) independent = false;
        prev = h;
    }
    Check("documented hash formula reproduces every entry hash", independent);

    string[] lines = File.ReadAllLines(jsonl);
    string backup = Path.Combine(root, "audit-backup.jsonl");
    File.Copy(jsonl, backup);
    File.WriteAllLines(jsonl, lines.Select((l, i) => i == 2 ? l.Replace("message 2", "message X") : l));
    Check("an edited entry is detected", !AuditLog.Verify(jsonl).Ok);
    File.WriteAllLines(jsonl, lines.Where((_, i) => i != 3));
    Check("a deleted entry is detected", !AuditLog.Verify(jsonl).Ok);
    File.WriteAllLines(jsonl, lines.Take(4));
    AuditVerifyResult truncated = AuditLog.Verify(jsonl);
    Check("truncation changes the head hash (caught by the manifest)", truncated.Ok && truncated.HeadHash != head);
    File.Copy(backup, jsonl, overwrite: true);
    Check("restored log verifies again", AuditLog.Verify(jsonl, AuditLog.GenesisHash("UNIT-1")).Ok);

    // ------------------------------------------------------------------------------------------ session -> seal -> verify
    Section("Session, sealing and verification");
    using UdpClient? ntpServer = TryStartFakeNtpServer();
    Check("fake NTP server on 127.0.0.1:123", ntpServer != null, "needs permission to bind UDP 123; NTP-dependent checks are skipped otherwise");

    string cfgPath = Path.Combine(root, "config.json");
    ConfigManager cfg = ConfigManager.Load(cfgPath);
    cfg.Config.Paths.OutputRoot = Path.Combine(root, "sessions");
    cfg.Config.Hashing.Algorithms = new List<string> { "SHA256", "SHA512" };
    cfg.Config.Ntp.Servers = new List<string> { "127.0.0.1" };
    cfg.Config.Ntp.TimeoutMs = 1000;
    cfg.Config.Ntp.SamplesPerServer = 1;
    cfg.Config.Ntp.MinimumResponses = 1;
    cfg.Config.Workflow.RequireNtpSync = ntpServer != null;
    cfg.Config.Workflow.MinimumFreeDiskMb = 1;

    if (ntpServer != null)
    {
        NtpSyncResult sync = await TimeSync.SyncAsync(cfg.Config.Ntp);
        Check("NTP synchronisation succeeded against the fake server", sync.Success && TrustedClock.IsSynchronized, sync.Summary);
    }

    SessionContext? ctx = null;
    SealResult? result = null;
    try
    {
        ctx = SessionContext.Create(cfg, new SessionInfo { CaseReference = "TEST/2026-001", OperatorName = "Smoke Test", Purpose = "automated test" });
        Check("session folder created with the standard sub-folders", SessionLayout.SubFolders.All(s => Directory.Exists(Path.Combine(ctx.Folder, s))));
        Check("session.json and the config snapshot are registered", ctx.Registry.IsRegistered("00_session/session.json") && ctx.Registry.IsRegistered("00_session/config_snapshot.json"));

        // sealing an empty session is refused
        try { await SealEngine.SealAsync(ctx, null, CancellationToken.None); Check("sealing without any capture is refused", false); }
        catch (SealException) { Check("sealing without any capture is refused", true); }

        ctx.SetPhase(1, PhaseStatus.Passed); ctx.SetPhase(2, PhaseStatus.Passed); ctx.SetPhase(3, PhaseStatus.Running);
        CaptureSet set = ctx.BeginCaptureSet("unit capture", "https://example.com/page");
        string htmlBytes = "<html><body>évidence</body></html>";
        string html = Path.Combine(set.Folder, "source_rendered_dom.html");
        File.WriteAllText(html, htmlBytes, new UTF8Encoding(false));
        EvidenceItem item = ctx.Registry.Add(html, EvidenceCategory.Source, 3, "rendered DOM", set.Url, set.Seq);
        string png = Path.Combine(set.Folder, "screenshot.png");
        File.WriteAllBytes(png, RandomNumberGenerator.GetBytes(4096));
        ctx.Registry.Add(png, EvidenceCategory.Screenshot, 3, "screenshot", set.Url, set.Seq);
        ctx.RecordNavigation("start", set.Url, true, false);
        ctx.RecordNavigation("complete", set.Url, false, false, "Success", 200, "Example");
        ctx.SetPhase(3, PhaseStatus.Passed);
        Check("registered files carry SHA-256 and SHA-512", item.Sha256.Length == 64 && item.Sha512?.Length == 128);

        // an unregistered file stops the seal
        string stray = Path.Combine(ctx.CapturesDir, "stray.txt");
        File.WriteAllText(stray, "not registered");
        try { await SealEngine.SealAsync(ctx, null, CancellationToken.None); Check("an unregistered file stops the seal", false); }
        catch (SealException ex) { Check("an unregistered file stops the seal", ex.Message.Contains("stray.txt")); }
        File.Delete(stray);

        // a registered file changed after capture stops the seal
        File.WriteAllText(html, "<html>changed</html>");
        try { await SealEngine.SealAsync(ctx, null, CancellationToken.None); Check("a file modified after capture stops the seal", false); }
        catch (SealException ex) { Check("a file modified after capture stops the seal", ex.Message.Contains("content changed")); }
        File.WriteAllText(html, htmlBytes, new UTF8Encoding(false));
        Check("Phase 4 shows Failed after a refused seal, and the audit log is still open", ctx.Phases[4] == PhaseStatus.Failed && !ctx.Audit.IsClosed);

        var steps = new List<string>();
        result = await SealEngine.SealAsync(ctx, new Progress<string>(steps.Add), CancellationToken.None);
        Check("sealing succeeded and the session is marked sealed", ctx.IsSealed && ctx.Audit.IsClosed);
        Check("post-seal verification passed", result.Verification is { Ok: true }, result.Verification?.ToText());
        Check("manifest hash in the result equals the SHA-256 of manifest.json", HashEngine.ComputeFile(result.ManifestPath, false).Sha256 == result.ManifestSha256);
        Check("receipt contains the manifest hash", File.ReadAllText(result.ReceiptPath).Contains(result.ManifestSha256));
        Check("ZIP archive and its SHA-256 file were created", result.ZipPath != null && File.Exists(result.ZipPath) && File.Exists(result.ZipPath + ".sha256"));
        Check("report.html exists and is HTML-encoded", File.Exists(result.ReportPath) && !File.ReadAllText(result.ReportPath).Contains("<script", StringComparison.OrdinalIgnoreCase));
        Check("no warnings on a clean seal", result.Warnings.Count == 0, string.Join("; ", result.Warnings));
        Check("progress was reported", steps.Count > 3);
        Check("a sealed session cannot be sealed twice", await ThrowsSeal(() => SealEngine.SealAsync(ctx!, null, CancellationToken.None)));

        string reportText = File.ReadAllText(result.ReportPath);
        Check("report mentions the case, the audit file and the navigation trail",
            reportText.Contains("TEST/2026-001") && reportText.Contains("audit/audit.jsonl") && reportText.Contains("Navigation trail"));

        // independent verification
        string folder = ctx.Folder;
        VerificationReport again = await ManifestVerifier.VerifyAsync(folder);
        Check("stand-alone verifier agrees", again.Ok && again.FilesChecked == again.FilesOk && again.AuditChainOk, again.ToText());
        if (OperatingSystem.IsLinux() && File.Exists("/usr/bin/sha256sum"))
        {
            string outp = await RunProcess("/usr/bin/sha256sum", "-c 05_sealing/manifest.sha256", folder);
            Check("manifest.sha256 is accepted by 'sha256sum -c'", outp.StartsWith("0|"), outp);
        }

        // ------------------------------------------------------------------------------------ tampering
        Section("Tamper detection on the sealed package");
        string target = Path.Combine(folder, "03_captures", Path.GetFileName(set.Folder), "source_rendered_dom.html");
        byte[] original = File.ReadAllBytes(target);
        MakeWritable(target);
        File.WriteAllText(target, "<html><body>évidence</body></html>" + " ");
        VerificationReport t1 = await ManifestVerifier.VerifyAsync(folder);
        Check("a modified evidence file is detected", !t1.Ok && t1.Issues.Any(i => i.Message.Contains("SHA-256 differs")), t1.ToText());
        File.WriteAllBytes(target, original);

        string extra = Path.Combine(folder, "03_captures", "added_later.txt");
        File.WriteAllText(extra, "x");
        VerificationReport t2 = await ManifestVerifier.VerifyAsync(folder);
        Check("a file added after sealing is detected", !t2.Ok && t2.Issues.Any(i => i.Message.Contains("NOT listed")));
        File.Delete(extra);

        string missing = Path.Combine(folder, "03_captures", Path.GetFileName(set.Folder), "screenshot.png");
        byte[] pngBytes = File.ReadAllBytes(missing);
        MakeWritable(missing); File.Delete(missing);
        VerificationReport t3 = await ManifestVerifier.VerifyAsync(folder);
        Check("a deleted evidence file is detected", !t3.Ok && t3.Issues.Any(i => i.Message.Contains("MISSING")));
        File.WriteAllBytes(missing, pngBytes);

        string auditFile = Path.Combine(folder, "audit", "audit.jsonl");
        string auditOriginal = File.ReadAllText(auditFile);
        MakeWritable(auditFile);
        File.WriteAllText(auditFile, auditOriginal.Replace("Sealing started", "Sealing begun"));
        VerificationReport t4 = await ManifestVerifier.VerifyAsync(folder);
        Check("an edited audit entry is detected", !t4.Ok && !t4.AuditChainOk);
        File.WriteAllText(auditFile, string.Join("\n", auditOriginal.TrimEnd('\n').Split('\n').SkipLast(2)) + "\n");
        VerificationReport t5 = await ManifestVerifier.VerifyAsync(folder);
        Check("removing the last audit entries is detected (head hash sealed in the manifest)", !t5.Ok);
        File.WriteAllText(auditFile, auditOriginal);

        string manifest = Path.Combine(folder, "05_sealing", "manifest.json");
        string manifestOriginal = File.ReadAllText(manifest);
        MakeWritable(manifest);
        File.WriteAllText(manifest, manifestOriginal.Replace("TEST/2026-001", "TEST/2026-002"));
        VerificationReport t6 = await ManifestVerifier.VerifyAsync(folder);
        Check("an edited manifest no longer matches manifest.sha256 / the receipt", !t6.Ok);
        File.WriteAllText(manifest, manifestOriginal);

        VerificationReport restored = await ManifestVerifier.VerifyAsync(folder);
        Check("after restoring every file the package verifies again", restored.Ok, restored.ToText());
        Check("a folder that is not a sealed package is reported as such", !(await ManifestVerifier.VerifyAsync(root)).Ok);
    }
    finally { ctx?.Dispose(); }
}
catch (Exception ex)
{
    failed++;
    Console.WriteLine("  FAIL  unexpected exception: " + ex);
}
finally
{
    try
    {
        foreach (string f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)) { try { File.SetAttributes(f, FileAttributes.Normal); } catch { } }
        Directory.Delete(root, recursive: true);
    }
    catch { /* temp folder cleanup is best effort */ }
}

Console.WriteLine($"\n{passed} passed, {failed} failed");
return failed == 0 ? 0 : 1;

// ---------------------------------------------------------------------------------------------- helpers

static async Task<bool> ThrowsSeal(Func<Task> action)
{
    try { await action(); return false; }
    catch (SealException) { return true; }
}

static byte[] FakeNtpReply(byte[] request, DateTime serverTimeUtc)
{
    var reply = new byte[48];
    reply[0] = 0x24;                                  // LI 0, VN 4, mode 4 (server)
    reply[1] = 2;                                     // stratum 2
    Array.Copy(request, 40, reply, 24, 8);            // originate = client's transmit
    ulong ts = NtpClient.ToNtpTimestamp(serverTimeUtc);
    for (int i = 0; i < 8; i++)
    {
        byte b = (byte)(ts >> (56 - 8 * i));
        reply[32 + i] = b;                            // receive
        reply[40 + i] = b;                            // transmit
    }
    return reply;
}

static UdpClient? TryStartFakeNtpServer()
{
    try
    {
        var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 123));
        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    UdpReceiveResult rx = await server.ReceiveAsync();
                    byte[] reply = FakeNtpReply(rx.Buffer, DateTime.UtcNow);
                    await server.SendAsync(reply, reply.Length, rx.RemoteEndPoint);
                }
            }
            catch (Exception) { /* socket closed at the end of the run */ }
        });
        return server;
    }
    catch (SocketException) { return null; }
}

static string ShippedConfigPath([System.Runtime.CompilerServices.CallerFilePath] string source = "") =>
    Path.GetFullPath(Path.Combine(Path.GetDirectoryName(source)!, "..", "..", "config.json"));
