using System.Text.Json.Serialization;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.FlowRunner;

/// <summary>test.configure params (rhgfake only; not in the contract).</summary>
/// <param name="Online">Serve a registry holding the fake card's key on loopback.</param>
/// <param name="PinTimeoutMs">When positive, the PIN prompt timeout.</param>
internal sealed record TestConfigureParams(bool Online, int PinTimeoutMs = 0);

/// <summary>Metadata for the test.* DTOs.</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(TestConfigureParams))]
[JsonSerializable(typeof(Empty))]
internal sealed partial class TestHooksJsonContext : JsonSerializerContext
{
}
