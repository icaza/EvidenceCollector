using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace EvidenceCollector.Core;

/// <summary>JSON helpers for evidence files: stable, readable, UTF-8 without BOM.</summary>
public static class JsonUtil
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string ToJson<T>(T value) => JsonSerializer.Serialize(value, Options);

    public static void WriteFile<T>(string path, T value)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(path, ToJson(value) + "\n", new UTF8Encoding(false));
    }

    public static void WriteText(string path, string text)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(path, text, new UTF8Encoding(false));
    }

    /// <summary>Makes a string safe to use as a single file or folder name.</summary>
    public static string SafeName(string? s, int maxLength = 48)
    {
        if (string.IsNullOrWhiteSpace(s)) return "x";
        var sb = new StringBuilder();
        foreach (var c in s.Trim())
        {
            if (char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_') sb.Append(c);
            else if (sb.Length > 0 && sb[^1] != '_') sb.Append('_');
        }
        var r = sb.ToString().Trim('_', '.');
        if (r.Length == 0) r = "x";
        return r.Length > maxLength ? r[..maxLength] : r;
    }
}
