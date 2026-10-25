using System.Buffers;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace EvidenceCollector.Core;

public sealed record FileDigest(string Sha256, string? Sha512, long Length);

/// <summary>
/// Local cryptographic fingerprinting. Files are streamed once through a pooled buffer
/// (SHA-256 and optionally SHA-512 are updated from the same read) so memory stays flat
/// regardless of artifact size, and directories are hashed with bounded parallelism.
/// </summary>
public static class HashEngine
{
    public static string ToHex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static string Sha256Hex(ReadOnlySpan<byte> data) => ToHex(SHA256.HashData(data));

    public static string Sha256HexOfString(string text) => Sha256Hex(Encoding.UTF8.GetBytes(text));

    public static async Task<FileDigest> ComputeFileAsync(string path, bool includeSha512, int bufferSize, CancellationToken ct = default)
    {
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var sha512 = includeSha512 ? IncrementalHash.CreateHash(HashAlgorithmName.SHA512) : null;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Max(4096, bufferSize));
        try
        {
            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 1, FileOptions.Asynchronous | FileOptions.SequentialScan);
            long total = 0;
            int read;
            while ((read = await fs.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false)) > 0)
            {
                sha256.AppendData(buffer, 0, read);
                sha512?.AppendData(buffer, 0, read);
                total += read;
            }
            return new FileDigest(ToHex(sha256.GetHashAndReset()), sha512 == null ? null : ToHex(sha512.GetHashAndReset()), total);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Case-insensitive comparison of two hex digests.</summary>
    public static bool HexEquals(string? a, string? b) =>
        a != null && b != null && string.Equals(a.Trim(), b.Trim(), StringComparison.OrdinalIgnoreCase);

    /// <summary>Synchronous convenience wrapper (used by small files and by tests).</summary>
    public static FileDigest ComputeFile(string path, bool includeSha512, int bufferSizeKb = 512, CancellationToken ct = default) =>
        ComputeFileAsync(path, includeSha512, Math.Max(16, bufferSizeKb) * 1024, ct).GetAwaiter().GetResult();

    /// <summary>Hashes the given files with bounded parallelism; the dictionary is keyed by the path as passed in.</summary>
    public static async Task<Dictionary<string, FileDigest>> ComputeManyAsync(
        IReadOnlyList<string> paths, bool includeSha512, int bufferSizeKb, int maxParallelism,
        IProgress<StepProgress>? progress, CancellationToken ct = default)
    {
        var results = new ConcurrentDictionary<string, FileDigest>(StringComparer.OrdinalIgnoreCase);
        int done = 0;
        int total = Math.Max(1, paths.Count);
        await Parallel.ForEachAsync(paths,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, maxParallelism), CancellationToken = ct },
            async (file, token) =>
            {
                results[file] = await ComputeFileAsync(file, includeSha512, Math.Max(16, bufferSizeKb) * 1024, token).ConfigureAwait(false);
                int n = Interlocked.Increment(ref done);
                progress?.Report(new StepProgress($"Hashing {Path.GetFileName(file)}", n * 100 / total));
            }).ConfigureAwait(false);
        return new Dictionary<string, FileDigest>(results, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Hashes every file below <paramref name="root"/> (except those excluded) and returns sorted entries.</summary>
    public static async Task<List<ManifestEntry>> HashDirectoryAsync(
        string root,
        Func<string, bool> include,
        bool includeSha512,
        int bufferSize,
        int maxParallelism,
        IProgress<StepProgress>? progress,
        CancellationToken ct = default)
    {
        string fullRoot = Path.GetFullPath(root);
        var files = Directory.EnumerateFiles(fullRoot, "*", SearchOption.AllDirectories)
            .Where(f => include(ToRelative(fullRoot, f)))
            .ToList();

        var results = new ConcurrentBag<ManifestEntry>();
        int done = 0;
        int total = Math.Max(1, files.Count);

        await Parallel.ForEachAsync(files,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, maxParallelism), CancellationToken = ct },
            async (file, token) =>
            {
                FileDigest d = await ComputeFileAsync(file, includeSha512, bufferSize, token).ConfigureAwait(false);
                results.Add(new ManifestEntry
                {
                    Path = ToRelative(fullRoot, file),
                    Size = d.Length,
                    Sha256 = d.Sha256,
                    Sha512 = d.Sha512,
                    LastWriteUtc = TrustedClock.FormatIso(File.GetLastWriteTimeUtc(file))
                });
                int n = Interlocked.Increment(ref done);
                progress?.Report(new StepProgress($"Hashing {Path.GetFileName(file)}", n * 100 / total));
            }).ConfigureAwait(false);

        return [.. results.OrderBy(e => e.Path, StringComparer.Ordinal)];
    }

    /// <summary>Relative path with forward slashes (stable across machines, matches sha256sum conventions).</summary>
    public static string ToRelative(string root, string fullPath)
    {
        string rel = Path.GetRelativePath(root, fullPath);
        return rel.Replace('\\', '/');
    }

    /// <summary>Text compatible with "sha256sum -c" (two spaces + path, binary-mode marker not used).</summary>
    public static string FormatSha256Sum(IEnumerable<ManifestEntry> entries, string? pathPrefix = null)
    {
        var sb = new StringBuilder();
        foreach (var e in entries)
            sb.Append(e.Sha256).Append("  ").Append(pathPrefix).Append(e.Path).Append('\n');
        return sb.ToString();
    }
}
