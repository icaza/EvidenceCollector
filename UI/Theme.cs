using EvidenceCollector.Config;
using System.Reflection;
using System.Runtime.InteropServices;

namespace EvidenceCollector.UI;

/// <summary>Colours of one theme.</summary>
internal sealed class Palette
{
    public Color Window { get; init; }
    public Color Surface { get; init; }
    public Color Input { get; init; }
    public Color RowAlt { get; init; }
    public Color Border { get; init; }
    public Color Text { get; init; }
    public Color Muted { get; init; }
    public Color Accent { get; init; }
    public Color AccentHover { get; init; }
    public Color AccentText { get; init; }
    public Color Success { get; init; }
    public Color Warning { get; init; }
    public Color Danger { get; init; }
    public Color Info { get; init; }
    public Color Selection { get; init; }
    public Color SelectionText { get; init; }
    public Color Header { get; init; }
    public Color HeaderText { get; init; }
    public Color HeaderMuted { get; init; }
    public bool IsDark { get; init; }
}

/// <summary>
/// Dark / light "corporate" theme. Controls are laid out and named in the *.Designer.cs files; this class only
/// applies colours (driven by the <c>Tag</c> of a control: "primary", "danger", "nav", "surface", "header", "muted"…)
/// and owner-draws the list views so they follow the theme.
/// </summary>
internal static class Theme
{
    public static readonly Palette Dark = new()
    {
        IsDark = true,
        Window = Color.FromArgb(24, 28, 36),
        Surface = Color.FromArgb(32, 38, 50),
        Input = Color.FromArgb(19, 23, 31),
        RowAlt = Color.FromArgb(25, 30, 40),
        Border = Color.FromArgb(57, 66, 84),
        Text = Color.FromArgb(228, 233, 242),
        Muted = Color.FromArgb(142, 154, 174),
        Accent = Color.FromArgb(59, 130, 246),
        AccentHover = Color.FromArgb(96, 153, 250),
        AccentText = Color.White,
        Success = Color.FromArgb(74, 203, 135),
        Warning = Color.FromArgb(245, 176, 65),
        Danger = Color.FromArgb(244, 100, 100),
        Info = Color.FromArgb(110, 168, 254),
        Selection = Color.FromArgb(38, 66, 112),
        SelectionText = Color.White,
        Header = Color.FromArgb(14, 18, 25),
        HeaderText = Color.FromArgb(240, 244, 250),
        HeaderMuted = Color.FromArgb(150, 163, 184)
    };

    public static readonly Palette Light = new()
    {
        IsDark = false,
        Window = Color.FromArgb(242, 245, 249),
        Surface = Color.White,
        Input = Color.White,
        RowAlt = Color.FromArgb(247, 249, 252),
        Border = Color.FromArgb(205, 212, 224),
        Text = Color.FromArgb(27, 36, 48),
        Muted = Color.FromArgb(96, 108, 126),
        Accent = Color.FromArgb(31, 78, 156),
        AccentHover = Color.FromArgb(48, 104, 190),
        AccentText = Color.White,
        Success = Color.FromArgb(22, 120, 76),
        Warning = Color.FromArgb(158, 90, 0),
        Danger = Color.FromArgb(180, 35, 24),
        Info = Color.FromArgb(23, 92, 211),
        Selection = Color.FromArgb(214, 228, 250),
        SelectionText = Color.FromArgb(27, 36, 48),
        Header = Color.FromArgb(22, 34, 56),
        HeaderText = Color.FromArgb(240, 244, 250),
        HeaderMuted = Color.FromArgb(160, 174, 196)
    };

    public static Palette Current { get; private set; } = Dark;
    public static ThemeMode Mode { get; private set; } = ThemeMode.Dark;

    public static void Set(ThemeMode mode)
    {
        Mode = mode;
        Current = mode == ThemeMode.Dark ? Dark : Light;
    }

    // ------------------------------------------------------------------------------------------ apply

    /// <summary>Applies the current palette to a control and all its children.</summary>
    public static void Apply(Control root)
    {
        ApplyTree(root);
        foreach (var lv in Lists.Keys.ToList()) lv.Invalidate();
    }

    private static void ApplyTree(Control c)
    {
        ApplyOne(c);
        foreach (Control child in c.Controls) ApplyTree(child);
    }

    private static void ApplyOne(Control c)
    {
        var p = Current;
        var tag = c.Tag as string ?? "";
        switch (c)
        {
            case Form f:
                f.BackColor = p.Window;
                f.ForeColor = p.Text;
                break;
            case TabPage tp:
                tp.UseVisualStyleBackColor = false;
                tp.BackColor = p.Window;
                tp.ForeColor = p.Text;
                break;
            case TabControl:
                break;
            case SplitContainer sc:
                sc.BackColor = p.Border;
                break;
            case Panel panel:
                panel.BackColor = tag switch
                {
                    "surface" => p.Surface,
                    "header" => p.Header,
                    "input" => p.Input,
                    "border" => p.Border,
                    _ => p.Window
                };
                panel.ForeColor = tag == "header" ? p.HeaderText : p.Text;
                break;
            case GroupBox gb:
                gb.ForeColor = p.Text;
                break;
            case LinkLabel ll:
                ll.BackColor = Color.Transparent;
                ll.LinkColor = p.Accent;
                ll.ActiveLinkColor = p.AccentHover;
                ll.VisitedLinkColor = p.Accent;
                break;
            case Label l:
                l.BackColor = Color.Transparent;
                l.ForeColor = tag switch
                {
                    "muted" => p.Muted,
                    "header" => p.HeaderText,
                    "headerMuted" => p.HeaderMuted,
                    "success" => p.Success,
                    "warning" => p.Warning,
                    "danger" => p.Danger,
                    "accent" => p.Accent,
                    _ => p.Text
                };
                break;
            case TextBox tb:
                tb.BackColor = p.Input;
                tb.ForeColor = p.Text;
                tb.BorderStyle = BorderStyle.FixedSingle;
                break;
            case CheckBox cb:
                cb.BackColor = Color.Transparent;
                cb.ForeColor = p.Text;
                break;
            case Button b:
                StyleButton(b, tag);
                break;
            case ListView lv:
                lv.BackColor = p.Input;
                lv.ForeColor = p.Text;
                lv.BorderStyle = BorderStyle.FixedSingle;
                break;
            case ToolStrip ts:
                ts.Renderer = new ThemedRenderer();
                ts.BackColor = p.Surface;
                ts.ForeColor = p.Text;
                foreach (ToolStripItem item in ts.Items) item.ForeColor = p.Text;
                break;
            case ProgressBar:
                break;
            default:
                c.ForeColor = p.Text;
                break;
        }

        if (c.ContextMenuStrip is { } menu)
        {
            menu.Renderer = new ThemedRenderer();
            menu.BackColor = p.Surface;
            menu.ForeColor = p.Text;
            foreach (ToolStripItem item in menu.Items) item.ForeColor = p.Text;
        }
    }

    private static void StyleButton(Button b, string tag)
    {
        var p = Current;
        b.FlatStyle = FlatStyle.Flat;
        b.UseVisualStyleBackColor = false;
        b.Cursor = Cursors.Hand;
        b.FlatAppearance.BorderSize = 1;
        switch (tag)
        {
            case "primary":
                b.BackColor = p.Accent; b.ForeColor = p.AccentText;
                b.FlatAppearance.BorderColor = p.Accent;
                b.FlatAppearance.MouseOverBackColor = p.AccentHover;
                b.FlatAppearance.MouseDownBackColor = Shift(p.Accent, -25);
                break;
            case "danger":
                b.BackColor = p.Danger; b.ForeColor = Color.White;
                b.FlatAppearance.BorderColor = p.Danger;
                b.FlatAppearance.MouseOverBackColor = Shift(p.Danger, 18);
                b.FlatAppearance.MouseDownBackColor = Shift(p.Danger, -25);
                break;
            case "nav":
                b.FlatAppearance.BorderSize = 0;
                break; // colours are set by StyleNav
            case "icon":
                b.BackColor = p.Header; b.ForeColor = p.HeaderText;
                b.FlatAppearance.BorderSize = 0;
                b.FlatAppearance.MouseOverBackColor = Shift(p.Header, 22);
                b.FlatAppearance.MouseDownBackColor = Shift(p.Header, 38);
                break;
            default:
                b.BackColor = p.Surface; b.ForeColor = p.Text;
                b.FlatAppearance.BorderColor = p.Border;
                b.FlatAppearance.MouseOverBackColor = Shift(p.Surface, p.IsDark ? 14 : -8);
                b.FlatAppearance.MouseDownBackColor = Shift(p.Surface, p.IsDark ? 26 : -18);
                break;
        }
    }

    /// <summary>Colours of a phase navigation button: current phase, reachable, or locked.</summary>
    public static void StyleNav(Button b, bool active, bool enabled)
    {
        var p = Current;
        b.FlatStyle = FlatStyle.Flat;
        b.UseVisualStyleBackColor = false;
        b.FlatAppearance.BorderSize = 0;
        b.BackColor = active ? p.Selection : p.Surface;
        b.ForeColor = active ? p.SelectionText : enabled ? p.Text : p.Muted;
        b.FlatAppearance.MouseOverBackColor = active ? p.Selection : Shift(p.Surface, p.IsDark ? 12 : -8);
        b.FlatAppearance.MouseDownBackColor = Shift(p.Selection, p.IsDark ? 10 : -10);
    }

    public static Color Shift(Color c, int delta) =>
        Color.FromArgb(c.A, Math.Clamp(c.R + delta, 0, 255), Math.Clamp(c.G + delta, 0, 255), Math.Clamp(c.B + delta, 0, 255));

    // ------------------------------------------------------------------------------------------ list views

    private static readonly Dictionary<ListView, Func<ListViewItem, Color?>?> Lists = new();
    private static readonly List<ImageList> RowHeightLists = new();

    /// <summary>
    /// Owner-draws a details-view list so it follows the theme. <paramref name="rowColor"/> may return a colour for
    /// the text of a row (e.g. a status colour); it is evaluated when the row is painted, so a theme change recolours it.
    /// </summary>
    public static void StyleList(ListView lv, Func<ListViewItem, Color?>? rowColor = null)
    {
        if (Lists.ContainsKey(lv)) { Lists[lv] = rowColor; return; }
        Lists[lv] = rowColor;

        lv.View = View.Details;
        lv.OwnerDraw = true;
        lv.FullRowSelect = true;
        DoubleBuffer(lv);

        var rows = new ImageList { ImageSize = new Size(1, 24) }; // gives the rows a comfortable height
        RowHeightLists.Add(rows);
        lv.SmallImageList = rows;

        lv.DrawColumnHeader += OnDrawColumnHeader;
        lv.DrawItem += (_, _) => { }; // the sub-items paint everything
        lv.DrawSubItem += OnDrawSubItem;
        lv.Disposed += (_, _) => Lists.Remove(lv);
    }

    private static void OnDrawColumnHeader(object? sender, DrawListViewColumnHeaderEventArgs e)
    {
        var p = Current;
        using (var back = new SolidBrush(p.Surface)) e.Graphics.FillRectangle(back, e.Bounds);
        using (var pen = new Pen(p.Border))
        {
            e.Graphics.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            e.Graphics.DrawLine(pen, e.Bounds.Right - 1, e.Bounds.Top + 4, e.Bounds.Right - 1, e.Bounds.Bottom - 5);
        }
        var font = sender is Control c ? c.Font : SystemFonts.DefaultFont;
        TextRenderer.DrawText(e.Graphics, e.Header?.Text ?? "", font,
            new Rectangle(e.Bounds.X + 6, e.Bounds.Y, Math.Max(0, e.Bounds.Width - 8), e.Bounds.Height), p.Muted,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
    }

    private static void OnDrawSubItem(object? sender, DrawListViewSubItemEventArgs e)
    {
        if (sender is not ListView lv || e.Item == null || e.SubItem == null) return;
        var p = Current;
        var selected = e.Item.Selected;
        var back = selected ? p.Selection : (e.ItemIndex % 2 == 1 ? p.RowAlt : p.Input);

        // The bounds of the first sub-item cover the whole row in Details view: restrict them to the first column.
        var bounds = e.ColumnIndex == 0 && lv.Columns.Count > 0
            ? new Rectangle(e.Bounds.X, e.Bounds.Y, lv.Columns[0].Width, e.Bounds.Height)
            : e.Bounds;

        using (var brush = new SolidBrush(back)) e.Graphics.FillRectangle(brush, bounds);

        Color fore = p.Text;
        if (Lists.TryGetValue(lv, out var rowColor) && rowColor != null && rowColor(e.Item) is { } custom) fore = custom;
        if (selected) fore = p.SelectionText;

        TextRenderer.DrawText(e.Graphics, e.SubItem.Text, lv.Font,
            new Rectangle(bounds.X + 6, bounds.Y, Math.Max(0, bounds.Width - 8), bounds.Height), fore,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
    }

    public static void DoubleBuffer(Control c) =>
        typeof(Control).GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic)?.SetValue(c, true);

    // ------------------------------------------------------------------------------------------ title bar

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    /// <summary>Dark or light window title bar (Windows 10 1809 and later; ignored elsewhere).</summary>
    public static void ApplyTitleBar(Form form)
    {
        if (!OperatingSystem.IsWindows() || !form.IsHandleCreated) return;
        try
        {
            var dark = Current.IsDark ? 1 : 0;
            if (DwmSetWindowAttribute(form.Handle, 20, ref dark, sizeof(int)) != 0)
                DwmSetWindowAttribute(form.Handle, 19, ref dark, sizeof(int));
        }
        catch { /* purely cosmetic */ }
    }

    // ------------------------------------------------------------------------------------------ tool strips

    private sealed class ThemedRenderer : ToolStripProfessionalRenderer
    {
        public ThemedRenderer() { RoundedEdges = false; }

        protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
        {
            using var brush = new SolidBrush(Current.Surface);
            e.Graphics.FillRectangle(brush, e.AffectedBounds);
        }

        protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
        {
            if (e.ToolStrip is ContextMenuStrip)
            {
                using var pen = new Pen(Current.Border);
                e.Graphics.DrawRectangle(pen, 0, 0, e.ToolStrip.Width - 1, e.ToolStrip.Height - 1);
            }
        }

        protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
        {
            if (!e.Item.Selected) return;
            using var brush = new SolidBrush(Current.Selection);
            e.Graphics.FillRectangle(brush, new Rectangle(Point.Empty, e.Item.Size));
        }

        protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
        {
            using var pen = new Pen(Current.Border);
            var y = e.Item.Height / 2;
            e.Graphics.DrawLine(pen, 4, y, e.Item.Width - 4, y);
        }
    }
}
