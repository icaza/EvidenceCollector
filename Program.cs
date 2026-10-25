using EvidenceCollector.Config;
using EvidenceCollector.Core;
using EvidenceCollector.UI;
using System.Text;

namespace EvidenceCollector;

internal static class Program
{
    /// <summary>Usage: EvidenceCollector.exe [--config &lt;path to config.json&gt;]</summary>
    [STAThread]
    private static int Main(string[] args)
    {
        string? configPath = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--config", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                configPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(args[++i]));
        }

        ConfigManager config = ConfigManager.Load(configPath);
        Theme.Set(config.Config.Ui.Theme);

        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => ReportCrash(e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => ReportCrash(e.ExceptionObject as Exception);

        if (config.Warnings.Count > 0)
        {
            MessageBox.Show(
                "config.json: " + config.FilePath + "\n\n" + string.Join("\n", config.Warnings.Select(w => "• " + w)),
                AppInfo.Name + " - configuration", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        Application.Run(new MainForm(config));
        return 0;
    }

    /// <summary>Shows the error and keeps a copy in %LOCALAPPDATA%\EvidenceCollector\crash.log (best effort).</summary>
    private static void ReportCrash(Exception? ex)
    {
        string text = ex?.ToString() ?? "Unknown error";
        try
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EvidenceCollector");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "crash.log"),
                $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z] {AppInfo.Name} {AppInfo.Version}\n{text}\n\n", new UTF8Encoding(false));
        }
        catch (Exception logError) when (logError is IOException or UnauthorizedAccessException)
        {
            // the dialog below is still shown
        }

        MessageBox.Show(
            "An unexpected error occurred.\n\n" + (ex?.Message ?? text) +
            "\n\nThe session folder, if any, is intact: the audit log is written entry by entry. Details were saved to crash.log.",
            AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
