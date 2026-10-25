using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace EvidenceCollector.Core;

public sealed record WipeReport(int FilesWiped, int FilesDeletedOnly, int Errors, string? FirstError);

/// <summary>
/// Handling of the temporary, isolated browser profile. The profile lives under a per-session folder
/// and is overwritten (best effort, single pass) and deleted when the session ends.
/// Note: overwriting cannot be guaranteed on SSDs or journaling/copy-on-write volumes; the isolated
/// profile and full deletion are the primary protection.
/// </summary>
public static class SecureTemp
{
    /// <summary>
    /// Creates the per-session temporary folder (browser profile + working files). On Windows the folder is
    /// restricted to the current user (inheritance removed); this is best effort and never blocks the session.
    /// </summary>
    public static string CreateSessionFolder(string tempRoot, string sessionId)
    {
        string path = Path.Combine(tempRoot, "wv2_" + sessionId);
        Directory.CreateDirectory(path);
        Directory.CreateDirectory(Path.Combine(path, "work"));
        if (OperatingSystem.IsWindows())
        {
            try { RestrictToCurrentUser(path); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
            { /* non-NTFS volume or policy: the isolated folder is still wiped at the end of the session */ }
        }
        return path;
    }

    /// <summary>Folder for short-lived working files (live network log) inside the session folder.</summary>
    public static string WorkFolder(string sessionTempFolder) => Path.Combine(sessionTempFolder, "work");

    [SupportedOSPlatform("windows")]
    private static void RestrictToCurrentUser(string path)
    {
        SecurityIdentifier user = WindowsIdentity.GetCurrent().User
                                  ?? throw new InvalidOperationException("The current user SID is not available.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            user, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    /// <summary>Total size of a folder in bytes (0 when it does not exist).</summary>
    public static long GetFolderSize(string path)
    {
        long total = 0;
        try
        {
            if (!Directory.Exists(path)) return 0;
            foreach (FileInfo f in new DirectoryInfo(path).EnumerateFiles("*", SearchOption.AllDirectories))
            {
                try { total += f.Length; } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* vanished */ }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return total;
    }

    /// <summary>Removes profile folders left behind by crashed sessions (older than <paramref name="olderThan"/>).</summary>
    public static int CleanupStale(string tempRoot, TimeSpan olderThan)
    {
        int removed = 0;
        try
        {
            if (!Directory.Exists(tempRoot)) return 0;
            foreach (string dir in Directory.EnumerateDirectories(tempRoot, "wv2_*"))
            {
                try
                {
                    if (DateTime.UtcNow - Directory.GetLastWriteTimeUtc(dir) < olderThan) continue;
                    Directory.Delete(dir, recursive: true);
                    removed++;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* still in use */ }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return removed;
    }

#pragma warning disable CA1068 // CancellationToken parameters must come last
    /// <summary>
    /// Overwrites and then deletes the folder. Synchronous I/O operations are executed entirely on the thread pool:
    /// the caller (UI thread) is never blocked, even if the first pass takes a long time.
    /// </summary>
    public static Task<WipeReport> WipeDirectoryAsync(string directory, bool overwrite, int maxFileMb, CancellationToken ct = default, int retries = 8)
        => Task.Run(() => WipeDirectoryCoreAsync(directory, overwrite, maxFileMb, ct, retries), ct);

    private static async Task<WipeReport> WipeDirectoryCoreAsync(string directory, bool overwrite, int maxFileMb, CancellationToken ct, int retries)
#pragma warning restore CA1068 // CancellationToken parameters must come last
    {
        int wiped = 0, deletedOnly = 0, errors = 0;
        string? firstError = null;

        for (int attempt = 0; attempt < retries && Directory.Exists(directory); attempt++)
        {
            errors = 0;
            firstError = null;
            foreach (string file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                    long length = new FileInfo(file).Length;
                    if (overwrite && length > 0 && length <= (long)maxFileMb * 1024 * 1024)
                    {
                        OverwriteWithZeros(file, length);
                        wiped++;
                    }
                    else deletedOnly++;
                    File.Delete(file);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    errors++;
                    firstError ??= $"{Path.GetFileName(file)}: {ex.Message}";
                }
            }

            try { Directory.Delete(directory, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errors++;
                firstError ??= ex.Message;
            }

            if (!Directory.Exists(directory)) { errors = 0; firstError = null; break; }
            await Task.Delay(500, ct).ConfigureAwait(false);   // browser processes may still be releasing handles
        }

        return new WipeReport(wiped, deletedOnly, errors, firstError);
    }

    private static void OverwriteWithZeros(string file, long length)
    {
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.None, 1, FileOptions.WriteThrough);
        var zeros = new byte[64 * 1024];
        long remaining = length;
        while (remaining > 0)
        {
            int n = (int)Math.Min(zeros.Length, remaining);
            fs.Write(zeros, 0, n);
            remaining -= n;
        }
        fs.Flush(flushToDisk: true);
    }
}
