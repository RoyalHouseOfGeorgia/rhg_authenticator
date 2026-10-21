using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// Decodes response envelopes, <c>{"ok":true,"result":…}</c> or
/// <c>{"ok":false,"error":{…}}</c>.
/// </summary>
internal static class RpcEnvelope
{
    /// <summary>
    /// Returns the result of a success envelope, or throws the
    /// <see cref="RpcException"/> of an error envelope. A response that does not
    /// decode (including a result that does not match <typeparamref name="T"/>)
    /// throws <see cref="RpcException.BadResponse"/>.
    /// </summary>
    public static T Decode<T>(ReadOnlySpan<byte> utf8Json, JsonTypeInfo<T> resultTypeInfo)
    {
        ArgumentNullException.ThrowIfNull(resultTypeInfo);
        try
        {
            using var document = JsonDocument.Parse(utf8Json.ToArray());
            var root = document.RootElement;
            if (root.GetProperty("ok").GetBoolean())
            {
                return root.GetProperty("result").Deserialize(resultTypeInfo)
                    ?? throw new JsonException("The result is null.");
            }
            var error = root.GetProperty("error").Deserialize(WireJsonContext.Default.RpcErrorPayload)
                ?? throw new JsonException("The error is null.");
            throw error.ToException();
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or KeyNotFoundException)
        {
            throw RpcException.BadResponse();
        }
    }
}
