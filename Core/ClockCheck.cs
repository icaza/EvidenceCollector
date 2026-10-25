using EvidenceCollector.Config;
using System.Globalization;
using System.Text;

namespace EvidenceCollector.Core;

/// <summary>Turns an NTP synchronisation result into a checklist line (used in Phases 1, 2 and 4).</summary>
public static class ClockCheck
{
    public static CheckResult FromSync(NtpSyncResult sync, AppConfig cfg, string id = "ntp", string title = "Official time (NTP)")
    {
        var sb = new StringBuilder();
        sb.AppendLine(sync.Summary);
        foreach (NtpSample s in sync.Samples)
            sb.AppendLine($"  {s.Server} ({s.Address}): offset {s.OffsetMs.ToString("+0.0;-0.0;0.0", CultureInfo.InvariantCulture)} ms, " +
                          $"round trip {s.RoundTripMs.ToString("0.0", CultureInfo.InvariantCulture)} ms, stratum {s.Stratum}");
        foreach (string f in sync.Failures) sb.AppendLine("  no answer: " + f);

        var data = new Dictionary<string, object?>
        {
            ["success"] = sync.Success,
            ["medianOffsetMs"] = sync.MedianOffsetMs,
            ["spreadMs"] = sync.SpreadMs,
            ["uncertaintyMs"] = sync.UncertaintyMs,
            ["servers"] = sync.Samples.Count
        };

        if (!sync.Success)
        {
            sb.Append("Timestamps would rely on the PC clock, which cannot be shown to be correct.");
            return new CheckResult
            {
                Id = id,
                Title = title,
                Data = data,
                Details = sb.ToString().TrimEnd(),
                Status = cfg.Workflow.RequireNtpSync ? CheckStatus.Fail : CheckStatus.Warn
            };
        }

        if (!sync.WithinTolerance)
        {
            sb.Append($"The PC clock differs from the reference by more than {cfg.Ntp.MaxAllowedOffsetMs} ms. " +
                      "Every evidence timestamp is corrected with the measured offset; consider fixing the PC clock.");
            return CheckResult.Warn(id, title, sb.ToString().TrimEnd(), data);
        }

        return CheckResult.Pass(id, title, sb.ToString().TrimEnd(), data);
    }
}
