using EvidenceCollector.Config;

namespace EvidenceCollector.Core;

/// <summary>
/// Synchronises <see cref="TrustedClock"/> with the configured NTP servers. The PC clock itself is never changed:
/// the measured offset is applied to every evidence timestamp and recorded in the audit log.
/// </summary>
public static class TimeSync
{
    public static async Task<NtpSyncResult> SyncAsync(NtpConfig cfg, CancellationToken ct = default)
    {
        NtpSyncResult result = await NtpClient.SyncAsync(cfg, ct).ConfigureAwait(false);
        if (result.Success) TrustedClock.SetOffset(TimeSpan.FromMilliseconds(result.MedianOffsetMs));
        return result;
    }
}
