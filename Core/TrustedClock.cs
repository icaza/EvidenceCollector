namespace EvidenceCollector.Core;

/// <summary>
/// Holds the offset between the local system clock and the NTP-derived reference time.
/// The system clock is never modified; evidence timestamps record both values.
/// </summary>
public static class TrustedClock
{
    private static readonly Lock Gate = new();
    private static TimeSpan _offset = TimeSpan.Zero;
    private static bool _synchronized;
    private static DateTime _lastSyncUtc = DateTime.MinValue;

    public static bool IsSynchronized { get { lock (Gate) return _synchronized; } }

    public static DateTime LastSyncUtc { get { lock (Gate) return _lastSyncUtc; } }

    /// <summary>Reference time minus system time, in milliseconds (null until first synchronization).</summary>
    public static double? OffsetMs { get { lock (Gate) return _synchronized ? _offset.TotalMilliseconds : null; } }

    /// <summary>Offset in whole microseconds, as stored in the audit log (null when unsynchronized).</summary>
    public static long? OffsetMicroseconds
    {
        get { lock (Gate) return _synchronized ? (long)Math.Round(_offset.TotalMilliseconds * 1000.0) : null; }
    }

    /// <summary>Best available UTC time: NTP-corrected when synchronized, otherwise the system clock.</summary>
    public static DateTime UtcNow
    {
        get { lock (Gate) return DateTime.UtcNow + (_synchronized ? _offset : TimeSpan.Zero); }
    }

    public static DateTime SystemUtcNow => DateTime.UtcNow;

    public static void SetOffset(TimeSpan offset)
    {
        lock (Gate)
        {
            _offset = offset;
            _synchronized = true;
            _lastSyncUtc = DateTime.UtcNow;
        }
    }

    public static void Reset()
    {
        lock (Gate)
        {
            _offset = TimeSpan.Zero;
            _synchronized = false;
            _lastSyncUtc = DateTime.MinValue;
        }
    }

    public static string FormatIso(DateTime utc) =>
        utc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture);
}
