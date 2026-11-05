using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// The contract's canonical JSON encoding: compact, object keys sorted by
/// ordinal (byte) order, and "/", "&lt;", "&gt;", "&amp;" and non-ASCII text
/// unescaped. Params are sent in this form, and it reproduces each contract
/// params file (minus its trailing newline). One divergence from the README's
/// rules, harmless on the wire: System.Text.Json's relaxed encoder still
/// writes characters outside the Basic Multilingual Plane (emoji), U+007F,
/// U+00A0, U+2028, U+2029 and U+FEFF as \u escapes, which decode to the same
/// string.
/// </summary>
public static class CanonicalJson
{
    private static readonly JsonWriterOptions s_writerOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Indented = false,
    };

    /// <summary>Encodes <paramref name="value"/> canonically, as UTF-8 bytes.</summary>
    internal static byte[] EncodeToUtf8<T>(T value, JsonTypeInfo<T> typeInfo)
    {
        ArgumentNullException.ThrowIfNull(typeInfo);
        return EncodeNode(JsonSerializer.SerializeToNode(value, typeInfo));
    }

    /// <summary>Encodes <paramref name="value"/> canonically.</summary>
    public static string Encode<T>(T value, JsonTypeInfo<T> typeInfo)
    {
        return Encoding.UTF8.GetString(EncodeToUtf8(value, typeInfo));
    }

    /// <summary>Encodes a JSON tree canonically (null as <c>null</c>).</summary>
    internal static byte[] EncodeNode(JsonNode? node)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, s_writerOptions))
        {
            Write(writer, node);
        }
        return buffer.ToArray();
    }

    private static void Write(Utf8JsonWriter writer, JsonNode? node)
    {
        switch (node)
        {
            case null:
                writer.WriteNullValue();
                break;
            case JsonObject obj:
                writer.WriteStartObject();
                foreach (var (key, value) in obj.OrderBy(p => p.Key, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(key);
                    Write(writer, value);
                }
                writer.WriteEndObject();
                break;
            case JsonArray array:
                writer.WriteStartArray();
                foreach (var item in array)
                {
                    Write(writer, item);
                }
                writer.WriteEndArray();
                break;
            default:
                node.WriteTo(writer);
                break;
        }
    }
}
