using System.ComponentModel;

namespace EvidenceCollector.UI;

/// <summary>
/// A TabControl without its tab strip at run time: the application switches the page itself (phase navigation on the
/// left), so the operator can only reach a phase when the workflow allows it. At design time the tabs stay visible so
/// the pages can still be edited in the Visual Studio designer. Ctrl+Tab / Ctrl+PageUp/Down page switching is disabled.
/// </summary>
[DesignerCategory("")]
public class HeaderlessTabControl : TabControl
{
    private const int TCM_ADJUSTRECT = 0x1328;
    private const int WM_KEYDOWN = 0x0100;

    protected override void WndProc(ref Message m)
    {
        // Asking Windows for the display area with no room for the tabs removes the strip.
        if (m.Msg == TCM_ADJUSTRECT && !DesignMode)
        {
            m.Result = (IntPtr)1;
            return;
        }
        base.WndProc(ref m);
    }

    protected override bool ProcessKeyPreview(ref Message m)
    {
        if (m.Msg == WM_KEYDOWN && (ModifierKeys & Keys.Control) == Keys.Control)
        {
            var key = (Keys)((int)m.WParam & 0xFFFF);
            if (key == Keys.Tab || key == Keys.PageUp || key == Keys.PageDown) return true;
        }
        return base.ProcessKeyPreview(ref m);
    }
}
