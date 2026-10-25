using System.Reflection;

namespace EvidenceCollector.Core;

public static class AppInfo
{
    public const string Name = "Evidence Collector";
    public const string Standard = "AFNOR NF Z67-147 (internet evidence collection methodology)";

    public const string Disclaimer = "\r\nThis tool is an open-source software solution designed to meet" +
        " the technical requirements of the AFNOR NF Z67-147 standard. Fully functional and developed" +
        " to ensure optimal technical reliability, this software serves as a collection aid. In accordance" +
        " with French law, only a public or ministerial officer (specifically a Commissaire de justice)" +
        " is authorized to draw up an official report (procès-verbal de constat) possessing evidentiary" +
        " value before French courts. The authors disclaim all liability for the use, interpretation, or" +
        " consequences arising from the use of this tool in the context of legal proceedings or actual disputes.";

    public static string Version =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";
}
