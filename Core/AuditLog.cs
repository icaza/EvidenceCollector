using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace EvidenceCollector.Core;

public enum AuditLevel { Info, Warn, Error, Security }

public sealed class AuditEntry
{
    public long Seq { get; init; }
    public string Utc { get; init; } = "";
    public long? ClockOffsetUs { get; init; }
    public AuditLevel Level { get; init; }
    public int Phase { get; init; }
    public string Event { get; init; } = "";
    public string Message { get; init; } = "";
    public string? DataJson { get; init; }
    public string PrevHash { get; init; } = "";
    public string Hash { get; init; } = "";
}

public sealed class AuditVerifyResult
{
    public bool Ok { get; set; }
    public long Count { get; set; }
    public long FirstBadSeq { get; set; } = -1;
    public string HeadHash { get; set; } = "";
    public string Message { get; set; } = "";
}

/// <summary>
/// Append-only, hash-chained audit trail (JSON Lines). Every entry commits to the hash of the previous one,
/// so any later insertion, deletion or edit breaks verification. The head hash is recorded in the seal.
/// </summary>
public sealed class AuditLog : IDisposable
{
    private static readonly JsonWriterOptions WriterOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static readonly JsonSerializerOptions DataOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false
    };

    private readonly object _gate = new();
    private readonly FileStream _jsonl;
    private readonly StreamWriter? _text;
    private readonly bool _flushEveryEntry;
    private long _seq;
    private string _lastHash;
    private bool _closed;

    public string JsonlPath { get; }
    public string? TextPath { get; }
    public string SessionId { get; }

    public event Action<AuditEntry>? EntryAppended;

    public long Count { get { lock (_gate) return _seq; } }
    public string HeadHash { get { lock (_gate) return _lastHash; } }
    public bool IsClosed { get { lock (_gate) return _closed; } }

    public static string GenesisHash(string sessionId) => HashEngine.Sha256HexOfString("EVC-AUDIT-GENESIS|" + sessionId);

    public AuditLog(string directory, string sessionId, bool flushEveryEntry, bool writeTextLog)
    {
        Directory.CreateDirectory(directory);
        SessionId = sessionId;
        _flushEveryEntry = flushEveryEntry;
        JsonlPath = Path.Combine(directory, "audit.jsonl");
        _jsonl = new FileStream(JsonlPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
        if (writeTextLog)
        {
            TextPath = Path.Combine(directory, "audit.log");
            _text = new StreamWriter(new FileStream(TextPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough),
                new UTF8Encoding(false));
        }
        _lastHash = GenesisHash(sessionId);
    }

    public AuditEntry Append(AuditLevel level, int phase, string eventCode, string message, object? data = null)
    {
        AuditEntry entry;
        lock (_gate)
        {
            if (_closed) throw new InvalidOperationException("The audit log is closed.");

            string? dataJson = data == null ? null : JsonSerializer.Serialize(data, DataOptions);
            long seq = _seq + 1;
            string utc = TrustedClock.FormatIso(DateTime.UtcNow);
            long? offsetUs = TrustedClock.OffsetMicroseconds;
            string hash = ComputeHash(seq, utc, offsetUs, level.ToString(), phase, eventCode, message, dataJson, _lastHash);

            entry = new AuditEntry
            {
                Seq = seq,
                Utc = utc,
                ClockOffsetUs = offsetUs,
                Level = level,
                Phase = phase,
                Event = eventCode,
                Message = message,
                DataJson = dataJson,
                PrevHash = _lastHash,
                Hash = hash
            };

            byte[] line = SerializeLine(entry);
            _jsonl.Write(line, 0, line.Length);
            if (_flushEveryEntry) _jsonl.Flush(flushToDisk: true);

            if (_text != null)
            {
                _text.Write($"[{seq:D5}] {utc} {level,-8} P{phase} {eventCode,-24} {message.Replace('\r', ' ').Replace('\n', ' ')}\n");
                if (_flushEveryEntry) _text.Flush();
            }

            _seq = seq;
            _lastHash = hash;
        }

        try { EntryAppended?.Invoke(entry); }
        catch { /* a faulty UI subscriber must never break evidence logging */ }
        return entry;
    }

    // ------------------------------------------------------------------ convenience wrappers

    public AuditEntry Log(AuditLevel level, int phase, string eventCode, string message, object? data = null) =>
        Append(level, phase, eventCode, message, data);

    public AuditEntry Info(int phase, string eventCode, string message, object? data = null) =>
        Append(AuditLevel.Info, phase, eventCode, message, data);

    public AuditEntry Warn(int phase, string eventCode, string message, object? data = null) =>
        Append(AuditLevel.Warn, phase, eventCode, message, data);

    public AuditEntry Error(int phase, string eventCode, string message, object? data = null) =>
        Append(AuditLevel.Error, phase, eventCode, message, data);

    public AuditEntry Security(int phase, string eventCode, string message, object? data = null) =>
        Append(AuditLevel.Security, phase, eventCode, message, data);

    /// <summary>Appends unless the log is already closed (used by UI event handlers that may run after sealing).</summary>
    public bool TryAppend(AuditLevel level, int phase, string eventCode, string message, object? data = null)
    {
        try { Append(level, phase, eventCode, message, data); return true; }
        catch (InvalidOperationException) { return false; }
    }

    /// <summary>All entries written so far (read back from the file, so it is exactly what is on disk).</summary>
    public IReadOnlyList<AuditEntry> Snapshot()
    {
        lock (_gate)
        {
            if (!_closed) _jsonl.Flush(flushToDisk: true);
        }
        return ReadAll(JsonlPath).ToList();
    }

    public static string FormatText(IEnumerable<AuditEntry> entries)
    {
        var sb = new StringBuilder();
        foreach (AuditEntry e in entries)
            sb.Append($"[{e.Seq:D5}] {e.Utc} {e.Level,-8} P{e.Phase} {e.Event,-24} {e.Message.Replace('\r', ' ').Replace('\n', ' ')}\n");
        return sb.ToString();
    }

    /// <summary>Closes the log and returns the final head hash (nothing can be appended afterwards).</summary>
    public string CloseAndGetHead()
    {
        Close();
        return HeadHash;
    }

    public void Close()
    {
        lock (_gate)
        {
            if (_closed) return;
            _closed = true;
            _jsonl.Flush(flushToDisk: true);
            _jsonl.Dispose();
            _text?.Flush();
            _text?.Dispose();
        }
    }

    public void Dispose() => Close();

    // ------------------------------------------------------------------ canonical form and verification

    internal static string ComputeHash(long seq, string utc, long? offsetUs, string level, int phase,
        string eventCode, string message, string? dataJson, string prevHash)
    {
        var sb = new StringBuilder(256);
        sb.Append(seq.ToString(CultureInfo.InvariantCulture)).Append('\n')
          .Append(utc).Append('\n')
          .Append(offsetUs.HasValue ? offsetUs.Value.ToString(CultureInfo.InvariantCulture) : "null").Append('\n')
          .Append(level).Append('\n')
          .Append(phase.ToString(CultureInfo.InvariantCulture)).Append('\n')
          .Append(eventCode).Append('\n')
          .Append(message.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(message).Append('\n')
          .Append(dataJson ?? "null").Append('\n')
          .Append(prevHash);
        return HashEngine.Sha256HexOfString(sb.ToString());
    }

    private static byte[] SerializeLine(AuditEntry e)
    {
        using var ms = new MemoryStream(512);
        using (var w = new Utf8JsonWriter(ms, WriterOptions))
        {
            w.WriteStartObject();
            w.WriteNumber("seq", e.Seq);
            w.WriteString("utc", e.Utc);
            if (e.ClockOffsetUs.HasValue) w.WriteNumber("clockOffsetUs", e.ClockOffsetUs.Value); else w.WriteNull("clockOffsetUs");
            w.WriteString("level", e.Level.ToString());
            w.WriteNumber("phase", e.Phase);
            w.WriteString("event", e.Event);
            w.WriteString("message", e.Message);
            w.WritePropertyName("data");
            if (e.DataJson == null) w.WriteNullValue(); else w.WriteRawValue(e.DataJson, skipInputValidation: false);
            w.WriteString("prevHash", e.PrevHash);
            w.WriteString("hash", e.Hash);
            w.WriteEndObject();
        }
        ms.WriteByte((byte)'\n');
        return ms.ToArray();
    }

    public static AuditEntry ParseLine(string line)
    {
        using var doc = JsonDocument.Parse(line);
        JsonElement r = doc.RootElement;
        JsonElement data = r.GetProperty("data");
        JsonElement off = r.GetProperty("clockOffsetUs");
        return new AuditEntry
        {
            Seq = r.GetProperty("seq").GetInt64(),
            Utc = r.GetProperty("utc").GetString() ?? "",
            ClockOffsetUs = off.ValueKind == JsonValueKind.Null ? null : off.GetInt64(),
            Level = Enum.TryParse(r.GetProperty("level").GetString(), out AuditLevel lv) ? lv : AuditLevel.Info,
            Phase = r.GetProperty("phase").GetInt32(),
            Event = r.GetProperty("event").GetString() ?? "",
            Message = r.GetProperty("message").GetString() ?? "",
            DataJson = data.ValueKind == JsonValueKind.Null ? null : data.GetRawText(),
            PrevHash = r.GetProperty("prevHash").GetString() ?? "",
            Hash = r.GetProperty("hash").GetString() ?? ""
        };
    }

    public static IEnumerable<AuditEntry> ReadAll(string jsonlPath)
    {
        using var fs = new FileStream(jsonlPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(fs, Encoding.UTF8);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.Length == 0) continue;
            yield return ParseLine(line);
        }
    }

    /// <summary>Re-computes every hash and checks chain continuity. <paramref name="expectedGenesis"/> is optional.</summary>
    public static AuditVerifyResult Verify(string jsonlPath, string? expectedGenesis = null)
    {
        var result = new AuditVerifyResult();
        string? prev = expectedGenesis;
        long expectedSeq = 1;
        try
        {
            foreach (AuditEntry e in ReadAll(jsonlPath))
            {
                if (e.Seq != expectedSeq)
                    return Fail(result, e.Seq, $"Sequence gap: expected {expectedSeq}, found {e.Seq}.");
                if (prev != null && !string.Equals(e.PrevHash, prev, StringComparison.Ordinal))
                    return Fail(result, e.Seq, "Chain broken: previous-hash mismatch.");

                string recomputed = ComputeHash(e.Seq, e.Utc, e.ClockOffsetUs, e.Level.ToString(), e.Phase, e.Event, e.Message, e.DataJson, e.PrevHash);
                if (!string.Equals(recomputed, e.Hash, StringComparison.Ordinal))
                    return Fail(result, e.Seq, "Entry content does not match its hash (entry was modified).");

                prev = e.Hash;
                result.Count++;
                expectedSeq++;
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or KeyNotFoundException or InvalidOperationException)
        {
            return Fail(result, expectedSeq, "Log could not be parsed: " + ex.Message);
        }

        result.Ok = result.Count > 0;
        result.HeadHash = prev ?? "";
        result.Message = result.Ok
            ? $"Audit chain intact: {result.Count} entries, head hash {result.HeadHash}."
            : "Audit log is empty.";
        return result;
    }

    private static AuditVerifyResult Fail(AuditVerifyResult r, long seq, string message)
    {
        r.Ok = false;
        r.FirstBadSeq = seq;
        r.Message = $"Audit verification FAILED at entry {seq}: {message}";
        return r;
    }
}
