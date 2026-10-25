using EvidenceCollector.Config;
using EvidenceCollector.Core;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Globalization;

namespace EvidenceCollector.Capture;

/// <summary>What is written on a stamped screenshot.</summary>
public sealed class StampInfo
{
    public string Url { get; init; } = "";
    public string Title { get; init; } = "";
    public string Kind { get; init; } = "Screenshot";
    public string CaseReference { get; init; } = "";
    public string OperatorName { get; init; } = "";
    public string SessionShortId { get; init; } = "";
    public int CaptureSeq { get; init; }
    /// <summary>NTP-corrected UTC time of the capture.</summary>
    public DateTime CapturedUtc { get; init; }
    public bool ClockSynced { get; init; }
    public double ClockOffsetMs { get; init; }
    /// <summary>For a segment of a full-page screenshot: "Part 2 of 5 | pixel rows 8000-15999 of 31200".</summary>
    public string? PartLabel { get; init; }

    public string Host
    {
        get
        {
            try { return Uri.TryCreate(Url, UriKind.Absolute, out Uri? u) && !string.IsNullOrEmpty(u.IdnHost) ? u.IdnHost : "page"; }
            catch (UriFormatException) { return "page"; }
        }
    }
}

/// <summary>
/// Adds the visible evidence marks to a screenshot: an information strip with the URL, the NTP-corrected UTC time,
/// the local time, the case and the capture number, plus an optional semi-transparent diagonal watermark (host name
/// and time) over the page itself.
///  - Band mode (default): the strip is added OUTSIDE the page image, so no pixel of the page is covered.
///  - Overlay mode: the strip is drawn over the page (the image keeps its size); the unmodified PNG should then be kept
///    (capture.screenshot.keepRawImage) because the strip hides part of the page.
/// </summary>
public static class ScreenshotStamper
{
    private static readonly Color Accent = Color.FromArgb(70, 140, 255);
    private static readonly Color WarnText = Color.FromArgb(255, 190, 90);

    public static byte[] Stamp(byte[] png, StampInfo info, OverlayConfig cfg)
    {
        using var input = new MemoryStream(png, writable: false);
        using var src = new Bitmap(input);
        int w = src.Width, h = src.Height;

        Color back = ParseColor(cfg.BandBackground, Color.FromArgb(16, 24, 32));
        Color fore = ParseColor(cfg.BandForeground, Color.White);
        TimeZoneInfo tz = ResolveTimeZone(cfg.LocalTimeZoneId);
        List<Line> lines = BuildLines(info, tz);

        float px = Math.Clamp(w / 100f, 11f, 15f);
        using var normal = new Font(cfg.FontFamily, px, FontStyle.Regular, GraphicsUnit.Pixel);
        using var bold = new Font(cfg.FontFamily, px, FontStyle.Bold, GraphicsUnit.Pixel);
        const int pad = 8, gap = 2;
        int textWidth = Math.Max(120, w - 2 * pad);

        // Measure the strip (long URLs wrap instead of being cut).
        float textHeight = 0;
        using (var probe = new Bitmap(1, 1))
        using (Graphics mg = Graphics.FromImage(probe))
        using (var sf = new StringFormat(StringFormat.GenericTypographic))
        {
            mg.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
            foreach (Line l in lines)
                textHeight += mg.MeasureString(l.Text, l.Bold ? bold : normal, textWidth, sf).Height + gap;
        }
        int bandH = (int)Math.Ceiling(textHeight) + 2 * pad;
        bool top = cfg.Position == OverlayPosition.Top;
        bool band = cfg.Mode == OverlayMode.Band;

        int outH = band ? h + bandH : h;
        int imgY = band && top ? bandH : 0;
        int stripY = band ? (top ? 0 : h) : (top ? 0 : Math.Max(0, h - bandH));

        using var dst = new Bitmap(w, outH, PixelFormat.Format32bppArgb);
        dst.SetResolution(src.HorizontalResolution, src.VerticalResolution);
        using (Graphics g = Graphics.FromImage(dst))
        {
            // 1. the page, copied pixel for pixel
            g.CompositingMode = CompositingMode.SourceCopy;
            g.InterpolationMode = InterpolationMode.NearestNeighbor;
            g.PixelOffsetMode = PixelOffsetMode.Half;
            g.DrawImage(src, new Rectangle(0, imgY, w, h), 0, 0, w, h, GraphicsUnit.Pixel);
            g.CompositingMode = CompositingMode.SourceOver;

            // 2. diagonal watermark over the page area only
            if (cfg.DiagonalWatermark && cfg.WatermarkOpacityPercent > 0)
                DrawWatermark(g, info, cfg, w, h, imgY);

            // 3. information strip
            int alpha = band ? 255 : 225;
            using (var brush = new SolidBrush(Color.FromArgb(alpha, back))) g.FillRectangle(brush, 0, stripY, w, bandH);
            using (var accent = new SolidBrush(Accent)) g.FillRectangle(accent, 0, top ? stripY + bandH - 2 : stripY, w, 2);
            g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
            using var sf = new StringFormat(StringFormat.GenericTypographic);
            float y = stripY + pad;
            foreach (Line l in lines)
            {
                Font font = l.Bold ? bold : normal;
                using var brush = new SolidBrush(l.Warn ? WarnText : fore);
                g.DrawString(l.Text, font, brush, new RectangleF(pad, y, textWidth, bandH), sf);
                y += g.MeasureString(l.Text, font, textWidth, sf).Height + gap;
            }
        }

        using var output = new MemoryStream();
        dst.Save(output, ImageFormat.Png);
        return output.ToArray();
    }

    // ------------------------------------------------------------------------------------------ text

    private readonly record struct Line(string Text, bool Bold, bool Warn);

    private static List<Line> BuildLines(StampInfo i, TimeZoneInfo tz)
    {
        DateTime utc = DateTime.SpecifyKind(i.CapturedUtc, DateTimeKind.Utc);
        DateTime local = TimeZoneInfo.ConvertTimeFromUtc(utc, tz);
        TimeSpan offset = tz.GetUtcOffset(utc);
        string offsetText = (offset < TimeSpan.Zero ? "-" : "+") + offset.ToString(@"hh\:mm", CultureInfo.InvariantCulture);

        string head = $"{i.Kind}  |  capture #{i.CaptureSeq:D4}" + (string.IsNullOrEmpty(i.PartLabel) ? "" : "  |  " + i.PartLabel);
        var lines = new List<Line>
        {
            new(head, true, false),
            new("URL: " + Clip(i.Url, 2000), false, false)
        };
        if (!string.IsNullOrWhiteSpace(i.Title)) lines.Add(new("Title: " + Clip(i.Title, 200), false, false));

        string clock = i.ClockSynced
            ? $"NTP-synchronised clock (offset {i.ClockOffsetMs.ToString("+0.0;-0.0;0.0", CultureInfo.InvariantCulture)} ms)"
            : "CLOCK NOT SYNCHRONISED WITH NTP (workstation clock)";
        lines.Add(new(
            $"Captured: {utc.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture)} UTC  |  local {local.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} (UTC{offsetText})  |  {clock}",
            false, !i.ClockSynced));
        lines.Add(new(
            $"Case: {Clip(i.CaseReference, 120)}  |  Operator: {Clip(i.OperatorName, 120)}  |  Session: {i.SessionShortId}  |  {AppInfo.Name} {AppInfo.Version}",
            false, false));
        return lines;
    }

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max] + "...";

    private static Color ParseColor(string? text, Color fallback)
    {
        if (string.IsNullOrWhiteSpace(text)) return fallback;
        try { return ColorTranslator.FromHtml(text.Trim()); }
        catch (Exception ex) when (ex is ArgumentException or FormatException) { return fallback; }
    }

    private static TimeZoneInfo ResolveTimeZone(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return TimeZoneInfo.Local;
        try { return TimeZoneInfo.FindSystemTimeZoneById(id.Trim()); }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException) { return TimeZoneInfo.Local; }
    }

    // ------------------------------------------------------------------------------------------ watermark

    private static void DrawWatermark(Graphics g, StampInfo info, OverlayConfig cfg, int w, int h, int imgY)
    {
        GraphicsState state = g.Save();
        try
        {
            g.SetClip(new Rectangle(0, imgY, w, h));
            g.TextRenderingHint = TextRenderingHint.AntiAlias;
            float size = Math.Clamp(w / 60f, 16f, 28f);
            using var font = new Font(cfg.FontFamily, size, FontStyle.Bold, GraphicsUnit.Pixel);
            int alpha = Math.Clamp((int)Math.Round(cfg.WatermarkOpacityPercent * 255 / 100.0), 0, 255);
            using var brush = new SolidBrush(Color.FromArgb(alpha, 190, 20, 20));
            DateTime utc = DateTime.SpecifyKind(info.CapturedUtc, DateTimeKind.Utc);
            string text = $"{info.Host}  {utc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)}Z";
            SizeF measured = g.MeasureString(text, font);
            float stepX = measured.Width + 140f;
            float stepY = measured.Height * 3.4f;

            g.TranslateTransform(w / 2f, imgY + h / 2f);
            g.RotateTransform(-28f);
            float half = (float)Math.Sqrt((double)w * w + (double)h * h) / 2f;
            int row = 0;
            for (float y = -half; y < half; y += stepY, row++)
            {
                float start = -half + (row % 2 == 0 ? 0 : stepX / 2f);
                for (float x = start; x < half; x += stepX)
                    g.DrawString(text, font, brush, x, y);
            }
        }
        finally
        {
            g.Restore(state);
        }
    }
}
