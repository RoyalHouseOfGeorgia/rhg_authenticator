using System.Text.Json;

namespace RhgAuthenticator.Bridge.Tests;

public sealed class EnumTests
{
    private static BridgeJsonContext Json => BridgeJsonContext.Default;

    [Fact]
    public void UnknownValuesDecodeToUnknownAndTheDefaultEncodesAsUnknown()
    {
        const string later = "\"later\"";
        Assert.Equal(UpdateState.Unknown, JsonSerializer.Deserialize(later, Json.UpdateState));
        Assert.Equal(BulkStop.Unknown, JsonSerializer.Deserialize(later, Json.BulkStop));
        Assert.Equal(RevokeStatus.Unknown, JsonSerializer.Deserialize(later, Json.RevokeStatus));
        Assert.Equal(KeyCheckOutcome.Unknown, JsonSerializer.Deserialize(later, Json.KeyCheckOutcome));
        Assert.Equal(RpcErrorCode.Unknown, JsonSerializer.Deserialize(later, Json.RpcErrorCode));
        Assert.Equal("\"unknown\"", JsonSerializer.Serialize(default(UpdateState), Json.UpdateState));
        Assert.Equal("\"unknown\"", JsonSerializer.Serialize(default(BulkStop), Json.BulkStop));
        Assert.Equal("\"unknown\"", JsonSerializer.Serialize(default(RevokeStatus), Json.RevokeStatus));
        Assert.Equal("\"unknown\"", JsonSerializer.Serialize(default(KeyCheckOutcome), Json.KeyCheckOutcome));
        Assert.Equal("\"unknown\"", JsonSerializer.Serialize(default(RpcErrorCode), Json.RpcErrorCode));
    }

    [Fact]
    public void ANonStringValueDoesNotDecode()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize("7", Json.BulkStop));
        Assert.Throws<RpcException>(() => RpcEnvelope.Decode(
            """{"ok":true,"result":{"details":[],"outcome":7,"status":"s"}}"""u8, Json.KeyCheck));
    }

    [Fact]
    public void NameOfANonMemberThrows()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => WireEnum.NameOf((BulkStop)99));
        Assert.Throws<ArgumentNullException>(() => WireEnum.Parse<BulkStop>(null!));
        Assert.Throws<ArgumentNullException>(() => new WireEnumConverter<BulkStop>().Write(null!, BulkStop.Failed, new JsonSerializerOptions()));
    }
}
