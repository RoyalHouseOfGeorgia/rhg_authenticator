using System.Text.Json;

namespace RhgAuthenticator.Bridge.Tests;

public sealed class EnumTests
{
    private static BridgeJsonContext Json => BridgeJsonContext.Default;

    [Fact]
    public void UnknownValuesDecodeToUnknown()
    {
        const string later = "\"later\"";
        Assert.Equal(UpdateState.Unknown, JsonSerializer.Deserialize(later, Json.UpdateState));
        Assert.Equal(BulkStop.Unknown, JsonSerializer.Deserialize(later, Json.BulkStop));
        Assert.Equal(RevokeStatus.Unknown, JsonSerializer.Deserialize(later, Json.RevokeStatus));
        Assert.Equal(KeyCheckOutcome.Unknown, JsonSerializer.Deserialize(later, Json.KeyCheckOutcome));
        Assert.Equal(RpcErrorCode.Unknown, JsonSerializer.Deserialize(later, Json.RpcErrorCode));
    }

    [Fact]
    public void KnownValuesRoundTripThroughTheirWireNames()
    {
        RoundTrip(Json.UpdateState, ["idle", "ready", "manualOnly"]);
        RoundTrip(Json.BulkStop, ["completed", "cancelled", "failed"]);
        RoundTrip(Json.RevokeStatus, ["submitted", "alreadyRevoked", "pending"]);
        RoundTrip(Json.KeyCheckOutcome, ["found", "notFound", "failed"]);
        RoundTrip(Json.RpcErrorCode,
        [
            "cancelled", "input", "busy", "notLoggedIn", "sessionExpired", "registryChanged", "notFound",
            "nothingToExport", "loginUnavailable", "failed", "internal",
        ]);
    }

    private static void RoundTrip<TEnum>(System.Text.Json.Serialization.Metadata.JsonTypeInfo<TEnum> info, string[] names)
        where TEnum : struct, Enum
    {
        Assert.Equal(names, WireEnum.Known<TEnum>().Select(WireEnum.NameOf));
        foreach (var value in WireEnum.Known<TEnum>())
        {
            var json = JsonSerializer.Serialize(value, info);
            Assert.Equal(value, JsonSerializer.Deserialize(json, info));
            Assert.Equal(value, WireEnum.Parse<TEnum>(WireEnum.NameOf(value)));
        }
        Assert.Equal("\"unknown\"", JsonSerializer.Serialize(default(TEnum), info));
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
