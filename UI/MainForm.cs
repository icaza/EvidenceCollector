using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using EvidenceCollector.Browser;
using EvidenceCollector.Capture;
using EvidenceCollector.Config;
using EvidenceCollector.Core;
using EvidenceCollector.Sealing;
using Microsoft.Web.WebView2.Core;

namespace EvidenceCollector.UI;

/// <summary>
/// Main window: guides the operator through the four phases of the collection (preparation, network diagnostics,
/// controlled navigation and capture, sealing). All controls are declared in MainForm.Designer.cs; this file only holds
/// the behaviour: phase gating, running the engine classes, and showing their results.
/// </summary>
public partial class MainForm : Form
{
    private static readonly string[] PageNames = { "Session", "Preparation", "Network", "Capture", "Sealing" };

    private readonly ConfigManager _cfgMgr;
    private readonly Button[] _navButtons;
    private readonly ConcurrentQueue<AuditEntry> _auditQueue = new();
    private readonly ConcurrentQueue<EvidenceItem> _evidenceQueue = new();

    private SessionContext? _ctx;
    private EvidenceBrowser? _browser;
    private WhoisCoordinator? _whois;
    private CaptureService? _capture;
    private CancellationTokenSource? _cts;
    private SealResult? _sealResult;

    private int _page;
    private int _prepRun;
    private int _netRun;
    private int _captureWarnings;
    private bool _busy;
    private bool _sessionStarting;
    private bool _browserFailed;
    private bool _closing;
    private bool _closeReady;
    private bool _minimised;
    private bool _autoCaptureRunning;
    private string? _lastAutoCaptureUrl;
    private DateTime _lastClockRefresh = DateTime.MinValue;

    private AppConfig Cfg => _cfgMgr.Config;

    public MainForm(ConfigManager config)
    {
        _cfgMgr = config;
        InitializeComponent();

        _navButtons = new[] { btnNav0, btnNav1, btnNav2, btnNav3, btnNav4 };
        Text = $"{AppInfo.Name} {AppInfo.Version}";
        txtDisclaimer.Text = AppInfo.Disclaimer;

        txtCaseRef.Text = Cfg.Session.CaseReference;
        txtOperatorName.Text = Cfg.Session.OperatorName;
        txtOperatorTitle.Text = Cfg.Session.OperatorTitle;
        txtOffice.Text = Cfg.Session.Office;
        txtLocation.Text = Cfg.Session.Location;

        Theme.StyleList(listAudit, AuditRowColor);
        Theme.StyleList(listPrepChecks, CheckRowColor);
        Theme.StyleList(listNetChecks, CheckRowColor);
        Theme.StyleList(listEvidence);

        ApplyTheme();
        RefreshUi();
    }

    // ================================================================================================ form events

    private void MainForm_Load(object? sender, EventArgs e)
    {
        Theme.ApplyTitleBar(this);
        ScaleColumns(listAudit, listPrepChecks, listNetChecks, listEvidence);
        splitMain.Panel2Collapsed = !Cfg.Ui.ShowAuditPanel;
        UpdateAuditToggleText();
        RefreshClock();
        txtCaseRef.Focus();

        // Browser profiles left behind by a crashed session (older than a day) are removed in the background.
        string tempRoot = AppConfig.ResolvePath(Cfg.Paths.TempRoot);
        _ = Task.Run(() => SecureTemp.CleanupStale(tempRoot, TimeSpan.FromDays(1)));
    }

    private void MainForm_Resize(object? sender, EventArgs e)
    {
        bool minimised = WindowState == FormWindowState.Minimized;
        if (minimised == _minimised) return;
        _minimised = minimised;
        if (Cfg.WebView.LowMemoryWhenMinimized) _browser?.SetLowMemory(minimised);
    }

    private void MainForm_FormClosing(object? sender, FormClosingEventArgs e)
    {
        if (_closeReady) return;

        bool forced = e.CloseReason is CloseReason.WindowsShutDown or CloseReason.TaskManagerClosing;
        if (!forced)
        {
            if (_busy)
            {
                if (Ask("An operation is still running. Cancel it and close the application?", "Operation in progress") != DialogResult.Yes)
                {
                    e.Cancel = true;
                    return;
                }
                _cts?.Cancel();
            }
            else if (_ctx != null && !_ctx.IsSealed)
            {
                string text = _ctx.Captures.Count == 0
                    ? "The session has no capture and is not sealed. Close the application?"
                    : "The session is NOT sealed: the evidence stays on disk but has no manifest, report or seal, so its integrity cannot be demonstrated later.\n\nClose without sealing?";
                if (Ask(text, "Session not sealed") != DialogResult.Yes)
                {
                    e.Cancel = true;
                    return;
                }
            }
        }

        e.Cancel = true; // the clean-up below is asynchronous; the form closes itself when it is done
        if (_closing) return;
        _closing = true;
        Enabled = false;
        Text += "  -  closing…";
        _ = ShutdownAsync();
    }

    private async Task ShutdownAsync()
    {
        try
        {
            timerUi.Stop();
            UseWaitCursor = true;
            Enabled = false;

            Stopwatch wait = Stopwatch.StartNew();
            while (_busy && wait.Elapsed < TimeSpan.FromSeconds(15)) await Task.Delay(100);

            SessionContext? ctx = _ctx;
            EvidenceBrowser? browser = _browser;
            string? profile = browser?.UserDataFolder;
            _capture = null;
            _browser = null;

            try { browser?.Dispose(); }
            catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException or System.Runtime.InteropServices.COMException) { /* already gone */ }

            if (!string.IsNullOrEmpty(profile))
            {
                try
                {
                    WipeReport report = await SecureTemp.WipeDirectoryAsync(profile, Cfg.Neutralization.SecureWipeTemp, Cfg.Neutralization.SecureWipeMaxFileMb);
                    ctx?.Audit.TryAppend(report.Errors == 0 ? AuditLevel.Info : AuditLevel.Warn, 4, "temp.wipe",
                        $"Temporary browser profile removed: {report.FilesWiped} file(s) overwritten, {report.FilesDeletedOnly} deleted, {report.Errors} error(s)"
                        + (report.FirstError != null ? " - " + report.FirstError : ""));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    ctx?.Audit.TryAppend(AuditLevel.Warn, 4, "temp.wipe", "The temporary browser profile could not be removed: " + ex.Message);
                }
            }

            if (ctx != null)
            {
                try { await Task.Run(ctx.Dispose); }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException) { /* log already closed */ }
            }
        }
        finally
        {
            _closeReady = true;
            if (!IsDisposed && IsHandleCreated) BeginInvoke(new Action(Close));
        }
    }

    // ================================================================================================ theme

    private void ApplyTheme()
    {
        Theme.Apply(this);
        if (IsHandleCreated) Theme.ApplyTitleBar(this);
        btnTheme.Text = Theme.Mode == ThemeMode.Dark ? "Light theme" : "Dark theme";
        RefreshUi();
    }

    private void BtnTheme_Click(object? sender, EventArgs e)
    {
        Theme.Set(Theme.Mode == ThemeMode.Dark ? ThemeMode.Light : ThemeMode.Dark);
        _cfgMgr.TrySaveTheme(Theme.Mode);
        ApplyTheme();
    }

    private static void Tone(Label label, string tag)
    {
        label.Tag = tag;
        Palette p = Theme.Current;
        label.ForeColor = tag switch
        {
            "danger" => p.Danger,
            "warning" => p.Warning,
            "success" => p.Success,
            "accent" => p.Accent,
            "muted" => p.Muted,
            _ => p.Text
        };
    }

    /// <summary>Column widths are not scaled by AutoScaleMode: scale them once, with the DPI of the monitor the window opened on.</summary>
    private void ScaleColumns(params ListView[] lists)
    {
        float f = DeviceDpi / 96f;
        if (f < 1.01f) return;
        foreach (ListView lv in lists)
            foreach (ColumnHeader c in lv.Columns) c.Width = (int)(c.Width * f);
    }

    private static Color? AuditRowColor(ListViewItem item)
    {
        if (item.Tag is not AuditEntry e) return null;
        return e.Level switch
        {
            AuditLevel.Warn => Theme.Current.Warning,
            AuditLevel.Error => Theme.Current.Danger,
            AuditLevel.Security => Theme.Current.Info,
            _ => null
        };
    }

    private static Color? CheckRowColor(ListViewItem item)
    {
        if (item.Tag is not CheckResult c) return null;
        return c.Status switch
        {
            CheckStatus.Pass => Theme.Current.Success,
            CheckStatus.Warn => Theme.Current.Warning,
            CheckStatus.Fail => Theme.Current.Danger,
            _ => null
        };
    }

    // ================================================================================================ header buttons

    private void BtnAuditToggle_Click(object? sender, EventArgs e)
    {
        splitMain.Panel2Collapsed = !splitMain.Panel2Collapsed;
        UpdateAuditToggleText();
    }

    private void UpdateAuditToggleText() => btnAuditToggle.Text = splitMain.Panel2Collapsed ? "Show log" : "Hide log";

    private void BtnConfig_Click(object? sender, EventArgs e) => OpenInExplorer(_cfgMgr.FilePath, select: true);

    private void BtnAbout_Click(object? sender, EventArgs e)
    {
        string text = $"{AppInfo.Name} {AppInfo.Version}\n{AppInfo.Standard}\n\n{AppInfo.Disclaimer}\n\n" +
                      $"Configuration file: {_cfgMgr.FilePath}\n" +
                      $"Browser engine: Microsoft Edge WebView2 {(_browser?.RuntimeVersion ?? "(not started yet)")}";
        MessageBox.Show(this, text, "About", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    // ================================================================================================ navigation between phases

    private bool PhaseDone(int phase) =>
        _ctx != null && _ctx.Phases[phase] is PhaseStatus.Passed or PhaseStatus.PassedWithWarnings;

    private bool CanOpen(int page)
    {
        if (page == 0) return true;
        if (_ctx == null || _browserFailed) return false;
        if (_ctx.IsSealed || !Cfg.Workflow.EnforcePhaseOrder) return true;
        for (int k = 1; k < page; k++)
            if (!PhaseDone(k)) return false;
        return true;
    }

    private void BtnNav_Click(object? sender, EventArgs e)
    {
        int index = Array.IndexOf(_navButtons, sender as Button);
        if (index >= 0) NavigateTo(index);
    }

    private void NavigateTo(int page)
    {
        if (_busy || !CanOpen(page)) return;
        _page = page;
        tabPhases.SelectedIndex = page;
        if (_browser != null) _browser.AuditPhase = Math.Max(1, page);

        if (page == 3 && _ctx != null && _ctx.Phases[3] == PhaseStatus.NotStarted)
            _ctx.SetPhase(3, PhaseStatus.Running);
        if (page == 4) RefreshSealSummary();
        RefreshUi();
        if (page == 3 && txtUrl.Enabled && !txtUrl.ReadOnly) txtUrl.Focus();
    }

    private static string PhaseGlyph(PhaseStatus s) => s switch
    {
        PhaseStatus.Running => "…",
        PhaseStatus.Passed => "✔",
        PhaseStatus.PassedWithWarnings => "⚠",
        PhaseStatus.Failed => "✖",
        _ => ""
    };

    private static string PhaseWord(PhaseStatus s) => s switch
    {
        PhaseStatus.NotStarted => "not started",
        PhaseStatus.Running => "in progress",
        PhaseStatus.Passed => "passed",
        PhaseStatus.PassedWithWarnings => "passed with warnings",
        _ => "failed"
    };

    // ================================================================================================ refresh of all controls

    private void RefreshUi()
    {
        if (_closing) return;
        SessionContext? ctx = _ctx;
        EvidenceBrowser? browser = _browser;
        bool has = ctx != null;
        bool isSealed = ctx?.IsSealed == true;
        bool idle = !_busy && !_sessionStarting;

        // phase navigation
        for (int i = 0; i < _navButtons.Length; i++)
        {
            bool open = CanOpen(i);
            string glyph = i == 0 ? (has ? "✔" : "") : (has ? PhaseGlyph(ctx!.Phases[i]) : "");
            Button b = _navButtons[i];
            b.Text = $"{i}   {PageNames[i]}" + (glyph.Length > 0 ? "   " + glyph : "");
            b.Enabled = open && (idle || i == _page);
            Theme.StyleNav(b, i == _page, open);
        }

        // header
        lblSessionId.Text = has ? $"Session {ctx!.Info.SessionId}" : "No session";
        tslPhase.Text = !has ? "Phase: —" : _page == 0 ? "Session started" : $"Phase {_page}: {PhaseWord(ctx!.Phases[_page])}";
        tslFiles.Text = $"Evidence files: {ctx?.Registry.Count ?? 0}";
        tslFolder.Text = has ? ctx!.Folder : "";

        // page 0
        bool editable = !has && !_sessionStarting;
        foreach (TextBox t in new[] { txtCaseRef, txtRequester, txtOperatorName, txtOperatorTitle, txtOffice, txtLocation, txtPurpose })
            t.ReadOnly = !editable;
        btnStartSession.Enabled = editable;
        btnVerifyOffline.Enabled = idle;

        // pages 1 and 2
        bool canRun = has && idle && !isSealed && !_browserFailed;
        btnRunPrep.Enabled = canRun;
        btnRunPrep.Text = _prepRun == 0 ? "Run preparation" : "Run preparation again";
        btnRunNet.Enabled = canRun && (!Cfg.Workflow.EnforcePhaseOrder || PhaseDone(1));
        btnRunNet.Text = _netRun == 0 ? "Run diagnostics" : "Run diagnostics again";
        btnCancelPrep.Enabled = _busy && _page == 1;
        btnCancelNet.Enabled = _busy && _page == 2;

        // page 3
        bool ready = browser is { IsReady: true } && has && !isSealed && idle && !_browserFailed;
        bool capturable = ready && CaptureService.IsCapturableUrl(browser!.CurrentUrl);
        txtUrl.ReadOnly = !ready;
        btnGo.Enabled = ready;
        btnBack.Enabled = ready && browser!.CanGoBack;
        btnForward.Enabled = ready && browser!.CanGoForward;
        btnReload.Enabled = capturable;
        btnStop.Enabled = ready && browser!.IsNavigating;
        foreach (Button b in new[] { btnCapViewport, btnCapFullPage, btnCapSource, btnCapArchive, btnCapConnection, btnCapWhois, btnCapAll })
            b.Enabled = capturable;
        btnReclean.Enabled = ready;
        txtCaptureNote.ReadOnly = !ready;
        btnCancelCapture.Enabled = _busy && _page == 3;

        // page 4
        btnSeal.Enabled = has && idle && !isSealed && ctx!.Captures.Count > 0 && !_browserFailed;
        btnOpenFolder.Enabled = has;
        btnCopyHash.Enabled = _sealResult != null;
        btnVerify.Enabled = has && idle && isSealed;
    }

    private void RefreshClock()
    {
        string sync = TrustedClock.IsSynchronized
            ? $"NTP synchronised, offset {TrustedClock.OffsetMs:+0.0;-0.0;0.0} ms"
            : "NTP not synchronised (PC clock)";
        lblClock.Text = $"{TrustedClock.UtcNow:yyyy-MM-dd HH:mm:ss} UTC  •  {sync}";
        tslClock.Text = TrustedClock.IsSynchronized ? $"Clock: NTP {TrustedClock.OffsetMs:+0.0;-0.0;0.0} ms" : "Clock: not synchronised";
        lblSealClock.Text = TrustedClock.IsSynchronized ? $"NTP synchronised ({TrustedClock.OffsetMs:+0.0;-0.0;0.0} ms)" : "not synchronised";
    }

    private void RefreshSealSummary()
    {
        if (_ctx == null) return;
        lblSealCase.Text = _ctx.Info.CaseReference;
        lblSealCaptures.Text = _ctx.Captures.Count.ToString();
        lblSealFiles.Text = _ctx.Registry.Count.ToString();
        RefreshClock();
    }

    // ================================================================================================ periodic UI pump

    private void TimerUi_Tick(object? sender, EventArgs e)
    {
        if (_closing) return;
        DrainQueues();
        if ((DateTime.UtcNow - _lastClockRefresh).TotalMilliseconds >= 1000)
        {
            _lastClockRefresh = DateTime.UtcNow;
            RefreshClock();
        }
    }

    private void DrainQueues()
    {
        if (!_auditQueue.IsEmpty)
        {
            listAudit.BeginUpdate();
            int n = 0;
            while (n++ < 500 && _auditQueue.TryDequeue(out AuditEntry? entry))
            {
                listAudit.Items.Add(new ListViewItem(new[]
                {
                    entry.Seq.ToString("D5"), entry.Utc, entry.Level.ToString(), entry.Phase.ToString(), entry.Event,
                    entry.Message.Replace('\r', ' ').Replace('\n', ' ')
                }) { Tag = entry });
            }
            int excess = listAudit.Items.Count - Cfg.Logging.UiMaxEntries;
            for (int i = 0; i < excess; i++) listAudit.Items.RemoveAt(0);
            if (listAudit.Items.Count > 0 && listAudit.SelectedItems.Count == 0)
                listAudit.EnsureVisible(listAudit.Items.Count - 1);
            listAudit.EndUpdate();
        }

        if (!_evidenceQueue.IsEmpty)
        {
            listEvidence.BeginUpdate();
            while (_evidenceQueue.TryDequeue(out EvidenceItem? item))
            {
                listEvidence.Items.Add(new ListViewItem(new[]
                {
                    item.Id.ToString(), item.Category.ToString(), item.RelativePath, FormatSize(item.SizeBytes), item.Sha256
                })
                {
                    Tag = item,
                    ToolTipText = $"{item.RelativePath}\nSHA-256: {item.Sha256}\n{item.Description}"
                });
            }
            if (listEvidence.Items.Count > 0) listEvidence.EnsureVisible(listEvidence.Items.Count - 1);
            listEvidence.EndUpdate();
            RefreshUi();
        }
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        _ => $"{bytes / 1048576.0:0.#} MB"
    };

    // ================================================================================================ long-running operations

    /// <summary>
    /// Runs one operation with the busy state, progress text, cancellation and error handling shared by every phase.
    /// Navigation and the other buttons are disabled while it runs.
    /// </summary>
    private async Task RunOperationAsync(string name, ProgressBar bar, Label status, Func<IProgress<string>, CancellationToken, Task> body)
    {
        if (_busy) return;
        _busy = true;
        _cts = new CancellationTokenSource();
        bar.Visible = true;
        Tone(status, "muted");
        status.Text = name + "…";
        RefreshUi();
        var progress = new Progress<string>(text => status.Text = text);
        try
        {
            await body(progress, _cts.Token);
        }
        catch (OperationCanceledException)
        {
            Tone(status, "warning");
            status.Text = name + " cancelled. Anything already written stays in the package and is recorded in the audit log.";
            _ctx?.Audit.TryAppend(AuditLevel.Warn, Math.Max(1, _page), "operation.cancelled", $"{name} cancelled by the operator");
        }
        catch (SealException ex)
        {
            Tone(status, "danger");
            status.Text = name + " failed: " + FirstLine(ex.Message);
            _ctx?.Audit.TryAppend(AuditLevel.Error, 4, "operation.failed", $"{name} failed: {ex.Message}");
            MessageBox.Show(this, ex.Message, name + " failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            Tone(status, "danger");
            status.Text = name + " failed: " + FirstLine(ex.Message);
            _ctx?.Audit.TryAppend(AuditLevel.Error, Math.Max(1, _page), "operation.failed", $"{name} failed: {ex}");
            MessageBox.Show(this, ex.Message, name + " failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            bar.Visible = false;
            _busy = false;
            _cts?.Dispose();
            _cts = null;
            RefreshUi();
        }
    }

    private static string FirstLine(string text)
    {
        int i = text.IndexOfAny(new[] { '\r', '\n' });
        return i < 0 ? text : text[..i];
    }

    private void BtnCancel_Click(object? sender, EventArgs e)
    {
        _cts?.Cancel();
        if (sender is Button b) b.Enabled = false;
    }

    private DialogResult Ask(string text, string title) =>
        MessageBox.Show(this, text, title, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);

    // ================================================================================================ page 0: session

    private async void BtnStartSession_Click(object? sender, EventArgs e)
    {
        if (_ctx != null || _sessionStarting) return;

        string caseRef = txtCaseRef.Text.Trim();
        string operatorName = txtOperatorName.Text.Trim();
        if (Cfg.Session.RequireCaseReference && caseRef.Length == 0)
        {
            ShowSessionMessage("Enter the case reference.", "danger");
            txtCaseRef.Focus();
            return;
        }
        if (Cfg.Session.RequireOperatorName && operatorName.Length == 0)
        {
            ShowSessionMessage("Enter the operator name.", "danger");
            txtOperatorName.Focus();
            return;
        }

        try
        {
            string? runtimeFolder = string.IsNullOrWhiteSpace(Cfg.Paths.WebViewRuntimeFolder) ? null : AppConfig.ResolvePath(Cfg.Paths.WebViewRuntimeFolder);
            CoreWebView2Environment.GetAvailableBrowserVersionString(runtimeFolder);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            ShowSessionMessage("The Microsoft Edge WebView2 Runtime is not installed.", "danger");
            MessageBox.Show(this,
                "The Microsoft Edge WebView2 Runtime is not installed on this computer.\n\nInstall the Evergreen runtime from " +
                "https://developer.microsoft.com/microsoft-edge/webview2/ and try again.",
                "WebView2 runtime missing", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        _sessionStarting = true;
        RefreshUi();
        SessionContext? ctx = null;
        try
        {
            ShowSessionMessage("Synchronising the clock (NTP)…", "muted");
            NtpSyncResult sync = await TimeSync.SyncAsync(Cfg.Ntp);
            RefreshClock();

            ShowSessionMessage("Creating the session…", "muted");
            var info = new SessionInfo
            {
                CaseReference = caseRef,
                Requester = txtRequester.Text.Trim(),
                OperatorName = operatorName,
                OperatorTitle = txtOperatorTitle.Text.Trim(),
                Office = txtOffice.Text.Trim(),
                Location = txtLocation.Text.Trim(),
                Purpose = txtPurpose.Text.Trim()
            };
            ctx = SessionContext.Create(_cfgMgr, info);
            ctx.StartTimeSync = sync;
            ctx.Audit.Log(sync.Success ? AuditLevel.Info : AuditLevel.Warn, 0, "session.ntp", sync.Summary);

            foreach (AuditEntry entry in ctx.Audit.Snapshot()) _auditQueue.Enqueue(entry);
            foreach (EvidenceItem item in ctx.Registry.Items) _evidenceQueue.Enqueue(item);
            ctx.Audit.EntryAppended += entry => _auditQueue.Enqueue(entry);
            ctx.Registry.ItemAdded += item => _evidenceQueue.Enqueue(item);

            _ctx = ctx;
            _whois = new WhoisCoordinator(ctx);

            ShowSessionMessage("Starting the evidence browser…", "muted");
            var browser = new EvidenceBrowser(webView, ctx) { AuditPhase = 1 };
            _browser = browser;
            try
            {
                await browser.InitializeAsync();
            }
            catch (Exception ex)
            {
                // The WebView2 control cannot be initialised twice: after this failure the application has to be restarted.
                _browserFailed = true;
                ctx.Audit.TryAppend(AuditLevel.Error, 1, "browser.failed", "The evidence browser could not be started: " + ex.Message);
                ShowSessionMessage("The evidence browser could not be started. Close and restart the application.", "danger");
                MessageBox.Show(this, ex.Message + "\n\nClose the application and start it again once the problem is fixed.",
                    "Evidence browser", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            browser.StateChanged += (_, _) => OnBrowserStateChanged();
            browser.Notice += message => ShowUrlMessage(message, "warning");
            browser.PageLoaded += url => { _ = OnPageLoadedAsync(url); };
            _capture = new CaptureService(ctx, browser, _whois);

            ShowSessionMessage($"Session {ctx.Info.SessionId} started.", "success");
            _sessionStarting = false;
            RefreshUi();
            NavigateTo(1);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ctx?.Audit.TryAppend(AuditLevel.Error, 0, "session.start-failed", "The session could not be started: " + ex.Message);
            ShowSessionMessage("The session could not be started: " + FirstLine(ex.Message), "danger");
            MessageBox.Show(this, ex.Message, "Session", MessageBoxButtons.OK, MessageBoxIcon.Error);
            if (_browser == null && ctx != null)
            {
                // nothing else is running: release the partial session so that the operator can try again
                _ctx = null;
                _whois = null;
                try { ctx.Dispose(); } catch (IOException) { /* ignore */ }
            }
        }
        finally
        {
            _sessionStarting = false;
            RefreshUi();
        }
    }

    private void ShowSessionMessage(string text, string tone)
    {
        lblSessionState.Text = text;
        Tone(lblSessionState, tone);
    }

    private async void BtnVerifyOffline_Click(object? sender, EventArgs e)
    {
        if (folderDialog.ShowDialog(this) != DialogResult.OK) return;
        await VerifyFolderAsync(folderDialog.SelectedPath, verifyProgress, lblVerifyStatus, txtVerifyResult);
    }

    private async Task VerifyFolderAsync(string folder, ProgressBar bar, Label status, TextBox output)
    {
        await RunOperationAsync("Verification", bar, status, async (progress, ct) =>
        {
            var files = new Progress<(int Done, int Total)>(p => progress.Report($"Verifying… {p.Done} of {p.Total} files"));
            VerificationReport report = await ManifestVerifier.VerifyAsync(folder, files, ct);
            output.Text = report.ToText().Replace("\r\n", "\n").Replace("\n", "\r\n");
            Tone(status, report.Ok ? "success" : "danger");
            status.Text = report.Ok ? "Verification passed." : "Verification FAILED: see the findings below.";
        });
    }

    // ================================================================================================ pages 1 and 2: checklists

    private static string StatusText(CheckStatus s) => s switch
    {
        CheckStatus.Pass => "✔  PASS",
        CheckStatus.Warn => "⚠  WARN",
        CheckStatus.Fail => "✖  FAIL",
        _ => "●  INFO"
    };

    private static void ShowChecks(ListView list, IReadOnlyList<CheckResult> checks)
    {
        list.BeginUpdate();
        list.Items.Clear();
        foreach (CheckResult c in checks)
            list.Items.Add(new ListViewItem(new[] { StatusText(c.Status), c.Title, FirstLine(c.Details) }) { Tag = c });
        list.EndUpdate();

        ListViewItem? focus = list.Items.Cast<ListViewItem>().FirstOrDefault(i => ((CheckResult)i.Tag!).Status is CheckStatus.Fail)
                              ?? list.Items.Cast<ListViewItem>().FirstOrDefault(i => ((CheckResult)i.Tag!).Status is CheckStatus.Warn)
                              ?? (list.Items.Count > 0 ? list.Items[0] : null);
        if (focus != null)
        {
            focus.Selected = true;
            focus.EnsureVisible();
        }
    }

    private void ListChecks_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (sender is not ListView list || list.SelectedItems.Count == 0 || list.SelectedItems[0].Tag is not CheckResult c) return;
        TextBox target = list == listPrepChecks ? txtPrepDetails : txtNetDetails;
        target.Text = $"{c.Title}\r\nResult: {c.Status}\r\n\r\n{c.Details.Replace("\r\n", "\n").Replace("\n", "\r\n")}";
    }

    private void UpdateBanner(Label banner, TableLayoutPanel layout, IEnumerable<CheckResult> checks)
    {
        List<CheckResult> issues = checks.Where(c => c.Status is CheckStatus.Warn or CheckStatus.Fail).ToList();
        if (issues.Count == 0)
        {
            banner.Visible = false;
            layout.RowStyles[2].Height = 0;
            return;
        }
        bool fail = issues.Any(c => c.Status == CheckStatus.Fail);
        var sb = new StringBuilder(fail ? "✖ Blocking problem: " : "⚠ Attention: ");
        sb.Append(string.Join("; ", issues.Select(c => c.Title)));
        if (issues.Any(c => c.Id is "proxy" or "vpn"))
            sb.Append(". A proxy or a VPN means the connection may not be direct: justify it in the official record, or disconnect and run the checks again.");
        banner.Text = sb.ToString();
        Tone(banner, fail ? "danger" : "warning");
        banner.Visible = true;
        layout.RowStyles[2].Height = 48f * DeviceDpi / 96f;
    }

    private static void ReportPhase(Label status, PhaseStatus result, int phase)
    {
        switch (result)
        {
            case PhaseStatus.Passed:
                Tone(status, "success");
                status.Text = $"Phase {phase} passed. You can continue with the next phase.";
                break;
            case PhaseStatus.PassedWithWarnings:
                Tone(status, "warning");
                status.Text = $"Phase {phase} passed with warnings. Review them: they are recorded in the report.";
                break;
            default:
                Tone(status, "danger");
                status.Text = $"Phase {phase} failed. Fix the blocking checks and run it again.";
                break;
        }
    }

    private async void BtnRunPrep_Click(object? sender, EventArgs e)
    {
        SessionContext? ctx = _ctx;
        EvidenceBrowser? browser = _browser;
        if (ctx == null || browser == null || _busy || ctx.IsSealed) return;

        await RunOperationAsync("Preparation", prepProgress, lblPrepStatus, async (progress, ct) =>
        {
            browser.AuditPhase = 1;
            PreparationResult result = await PreparationRunner.RunAsync(ctx, browser, ++_prepRun, progress, ct);
            ShowChecks(listPrepChecks, result.Checks);
            UpdateBanner(lblPrepBanner, tlpPrep, result.Checks);
            ReportPhase(lblPrepStatus, result.Status, 1);
        });
    }

    private async void BtnRunNet_Click(object? sender, EventArgs e)
    {
        SessionContext? ctx = _ctx;
        if (ctx == null || _busy || ctx.IsSealed) return;

        await RunOperationAsync("Network diagnostics", netProgress, lblNetStatus, async (progress, ct) =>
        {
            NetworkPhaseResult result = await NetworkPhaseRunner.RunAsync(ctx, ++_netRun, _whois, progress, ct);
            ShowChecks(listNetChecks, result.Checks);
            UpdateBanner(lblNetBanner, tlpNet, result.Checks);
            if (result.Snapshot is { } snap)
            {
                lblNetPublicIp.Text = snap.PublicIp ?? "not confirmed";
                lblNetDns.Text = snap.DnsServers.Count == 0 ? "none" : string.Join(", ", snap.DnsServers);
                List<string> local = snap.Interfaces.Where(i => i.Status == "Up").SelectMany(i => i.IPv4).ToList();
                lblNetLocal.Text = local.Count == 0 ? "none" : string.Join(", ", local);
            }
            ReportPhase(lblNetStatus, result.Status, 2);
        });
    }

    // ================================================================================================ page 3: navigation and capture

    private void OnBrowserStateChanged()
    {
        EvidenceBrowser? browser = _browser;
        if (browser == null || _closing) return;
        string url = browser.CurrentUrl;
        if (!txtUrl.Focused && !string.IsNullOrEmpty(url) && !url.Equals("about:blank", StringComparison.OrdinalIgnoreCase))
            txtUrl.Text = url;
        RefreshUi();
    }

    private void ShowUrlMessage(string text, string tone)
    {
        lblUrlMessage.Text = text;
        Tone(lblUrlMessage, tone);
    }

    private void NavigateFromUrlBar()
    {
        EvidenceBrowser? browser = _browser;
        if (browser is not { IsReady: true } || _busy || _ctx is not { IsSealed: false }) return;

        UrlValidationResult check = UrlValidator.Validate(txtUrl.Text, Cfg.WebView);
        if (!check.IsValid)
        {
            ShowUrlMessage(check.Error ?? "The address is not valid.", "danger");
            return;
        }
        txtUrl.Text = check.Normalized;
        ShowUrlMessage(string.Join("  ", check.Warnings), check.Warnings.Count == 0 ? "muted" : "warning");
        try { browser.Navigate(check.Normalized); }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException)
        {
            ShowUrlMessage("Navigation failed: " + ex.Message, "danger");
        }
    }

    private void TxtUrl_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode != Keys.Enter) return;
        e.SuppressKeyPress = true;
        NavigateFromUrlBar();
    }

    private void BtnGo_Click(object? sender, EventArgs e) => NavigateFromUrlBar();
    private void BtnBack_Click(object? sender, EventArgs e) => _browser?.GoBack();
    private void BtnForward_Click(object? sender, EventArgs e) => _browser?.GoForward();
    private void BtnReload_Click(object? sender, EventArgs e) => _browser?.Reload();
    private void BtnStop_Click(object? sender, EventArgs e) => _browser?.Stop();

    private async void BtnCapViewport_Click(object? sender, EventArgs e) => await RunCaptureAsync(CaptureParts.ViewportScreenshot, "Viewport screenshot");
    private async void BtnCapFullPage_Click(object? sender, EventArgs e) => await RunCaptureAsync(CaptureParts.FullPageScreenshot, "Full-page screenshot");
    private async void BtnCapSource_Click(object? sender, EventArgs e) => await RunCaptureAsync(CaptureParts.Source, "Page source");
    private async void BtnCapArchive_Click(object? sender, EventArgs e) => await RunCaptureAsync(CaptureParts.Archive, "Archive (MHTML and PDF)");
    private async void BtnCapConnection_Click(object? sender, EventArgs e) => await RunCaptureAsync(CaptureParts.Connection, "Connection data");
    private async void BtnCapWhois_Click(object? sender, EventArgs e) => await RunCaptureAsync(CaptureParts.Whois, "WHOIS / RDAP");
    private async void BtnCapAll_Click(object? sender, EventArgs e) => await RunCaptureAsync(CaptureParts.Full, "Full capture");

    private async Task RunCaptureAsync(CaptureParts parts, string label)
    {
        SessionContext? ctx = _ctx;
        CaptureService? capture = _capture;
        EvidenceBrowser? browser = _browser;
        if (ctx == null || capture == null || browser == null || _busy || ctx.IsSealed) return;
        string note = txtCaptureNote.Text;

        await RunOperationAsync("Capture", capProgress, lblCaptureStatus, async (progress, ct) =>
        {
            browser.AuditPhase = 3;
            CaptureOutcome outcome = await capture.RunAsync(parts, label, note, progress, ct);
            txtCaptureNote.Clear();
            _captureWarnings += outcome.Warnings.Count;
            MarkCaptureDone(ctx);

            string text = $"Capture #{outcome.Set.Seq:D4} finished: {outcome.FilesRegistered} file(s), {outcome.Warnings.Count} warning(s).";
            Tone(lblCaptureStatus, outcome.Warnings.Count == 0 ? "success" : "warning");
            lblCaptureStatus.Text = text;
            if (outcome.Warnings.Count > 0)
            {
                string list = string.Join("\n\n", outcome.Warnings.Take(8).Select(w => "• " + w));
                if (outcome.Warnings.Count > 8) list += $"\n\n… and {outcome.Warnings.Count - 8} more (see the audit log).";
                MessageBox.Show(this, text + "\n\nThe gaps below are recorded in the package:\n\n" + list,
                    "Capture completed with warnings", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        });
    }

    /// <summary>Phase 3 counts as passed as soon as one capture finished; warnings of any capture are kept in its status.</summary>
    private void MarkCaptureDone(SessionContext ctx)
    {
        PhaseStatus wanted = _captureWarnings > 0 ? PhaseStatus.PassedWithWarnings : PhaseStatus.Passed;
        if (ctx.Phases[3] != wanted) ctx.SetPhase(3, wanted);
    }

    private async void BtnReclean_Click(object? sender, EventArgs e)
    {
        SessionContext? ctx = _ctx;
        EvidenceBrowser? browser = _browser;
        if (ctx == null || browser == null || _busy || ctx.IsSealed) return;
        if (Ask("This clears the cache, cookies, storage and history of the evidence browser and returns it to a blank page.\n\n" +
                "Use it between two unrelated sites so that the second one cannot see traces of the first. The result is recorded as a new Phase 1 run.\n\nContinue?",
                "Re-neutralise the browser") != DialogResult.Yes) return;

        await RunOperationAsync("Neutralisation", capProgress, lblCaptureStatus, async (progress, ct) =>
        {
            browser.AuditPhase = 3;
            progress.Report("Clearing the evidence browser…");
            PreparationResult result = await PreparationRunner.CleanOnlyAsync(ctx, browser, ++_prepRun, ct);
            bool ok = result.Status != PhaseStatus.Failed;
            Tone(lblCaptureStatus, ok ? "success" : "danger");
            lblCaptureStatus.Text = ok ? "Browser neutralised and verified." : "Neutralisation reported a problem: see the audit log.";
            txtUrl.Clear();
        });
    }

    private async Task OnPageLoadedAsync(string url)
    {
        AutoCaptureConfig auto = Cfg.Capture.AutoCapture;
        if (!auto.Enabled || _page != 3 || _busy || _autoCaptureRunning || _closing) return;
        if (_ctx is not { IsSealed: false } || _capture == null || !CaptureService.IsCapturableUrl(url)) return;
        string stripped = NetworkRecorder.StripFragment(url);
        if (string.Equals(stripped, _lastAutoCaptureUrl, StringComparison.OrdinalIgnoreCase)) return;

        _autoCaptureRunning = true;
        try
        {
            if (auto.DelayAfterLoadMs > 0) await Task.Delay(auto.DelayAfterLoadMs);
            EvidenceBrowser? browser = _browser;
            if (browser == null || _busy || _closing || _ctx is not { IsSealed: false }) return;
            if (!string.Equals(NetworkRecorder.StripFragment(browser.CurrentUrl), stripped, StringComparison.OrdinalIgnoreCase)) return;

            CaptureParts parts = auto.FullPageScreenshot ? CaptureParts.FullPageScreenshot : CaptureParts.ViewportScreenshot;
            if (auto.Source) parts |= CaptureParts.Source;
            if (auto.DomainRecord) parts |= CaptureParts.Connection | CaptureParts.Whois;
            _lastAutoCaptureUrl = stripped;
            await RunCaptureAsync(parts, "Automatic capture");
        }
        finally
        {
            _autoCaptureRunning = false;
        }
    }

    // ================================================================================================ evidence list menu

    private EvidenceItem? SelectedEvidence() =>
        listEvidence.SelectedItems.Count > 0 ? listEvidence.SelectedItems[0].Tag as EvidenceItem : null;

    private void MiCopyHash_Click(object? sender, EventArgs e)
    {
        if (SelectedEvidence() is { } item) CopyToClipboard(item.Sha256);
    }

    private void MiCopyPath_Click(object? sender, EventArgs e)
    {
        if (SelectedEvidence() is { } item) CopyToClipboard(item.RelativePath);
    }

    private void MiShowInFolder_Click(object? sender, EventArgs e)
    {
        if (SelectedEvidence() is { } item && _ctx != null) OpenInExplorer(_ctx.Registry.ToAbsolute(item.RelativePath), select: true);
    }

    private static void CopyToClipboard(string text)
    {
        try { Clipboard.SetText(text); }
        catch (System.Runtime.InteropServices.ExternalException) { /* the clipboard is locked by another program */ }
    }

    private static void OpenInExplorer(string path, bool select)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrEmpty(path)) return;
        try
        {
            var psi = new ProcessStartInfo("explorer.exe") { UseShellExecute = true, Arguments = select ? $"/select,\"{path}\"" : $"\"{path}\"" };
            Process.Start(psi);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { /* no shell available */ }
    }

    // ================================================================================================ page 4: sealing

    private async void BtnSeal_Click(object? sender, EventArgs e)
    {
        SessionContext? ctx = _ctx;
        EvidenceBrowser? browser = _browser;
        if (ctx == null || _busy || ctx.IsSealed) return;

        string question = $"Seal this session now?\n\nCaptures: {ctx.Captures.Count}\nEvidence files: {ctx.Registry.Count}\n\n" +
                          "Sealing closes the audit log and fixes the manifest. Nothing can be added or changed afterwards. " +
                          "If something is missing, answer No and go back to Phase 3.";
        if (Ask(question, "Seal the session") != DialogResult.Yes) return;

        if (browser != null) browser.Locked = true;
        await RunOperationAsync("Sealing", sealProgress, lblSealStatus, async (progress, ct) =>
        {
            SealResult result = await SealEngine.SealAsync(ctx, progress, ct);
            _sealResult = result;
            txtSealResult.Text = result.ToText().Replace("\r\n", "\n").Replace("\n", "\r\n");
            bool verified = result.Verification?.Ok ?? true;
            Tone(lblSealStatus, verified ? "success" : "danger");
            lblSealStatus.Text = verified ? "Session sealed and verified." : "Session sealed, but the verification reported problems: read the result below.";
            RefreshSealSummary();
        });
        if (!ctx.IsSealed && browser != null) browser.Locked = false; // sealing was refused before it started
    }

    private void BtnOpenFolder_Click(object? sender, EventArgs e)
    {
        if (_ctx != null) OpenInExplorer(_ctx.Folder, select: false);
    }

    private void BtnCopyHash_Click(object? sender, EventArgs e)
    {
        if (_sealResult == null) return;
        CopyToClipboard(_sealResult.ManifestSha256);
        Tone(lblSealStatus, "success");
        lblSealStatus.Text = "manifest.json SHA-256 copied to the clipboard.";
    }

    private async void BtnVerify_Click(object? sender, EventArgs e)
    {
        if (_ctx == null || !_ctx.IsSealed) return;
        await VerifyFolderAsync(_ctx.Folder, sealProgress, lblSealStatus, txtSealResult);
    }
}
