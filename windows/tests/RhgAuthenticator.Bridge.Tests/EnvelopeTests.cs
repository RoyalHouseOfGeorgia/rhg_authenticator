using System.Text.Json;

namespace RhgAuthenticator.Bridge.Tests;

public sealed class EnvelopeTests
{
    private static BridgeJsonContext Json => BridgeJsonContext.Default;

    private static RpcException DecodeError(string body)
    {
        return Assert.Throws<RpcException>(() => RpcEnvelope.Decode(Support.Utf8(body), Json.Empty));
    }

    [Fact]
    public void UnknownErrorCodesAndFieldsDecodeKeepingTheRawCode()
    {
        var error = DecodeError("""{"ok":false,"error":{"code":"brandNew","extra":1,"message":"m","offerReport":false}}""");
        Assert.Equal(RpcErrorCode.Unknown, error.Code);
        Assert.Equal("brandNew", error.RawCode);
        Assert.Equal("m", error.Message);
    }

    [Fact]
    public void MissingReportIdIsNullAndMissingOfferReportIsFalse()
    {
        var error = DecodeError("""{"ok":false,"error":{"code":"failed","message":"m"}}""");
        Assert.Equal(RpcErrorCode.Failed, error.Code);
        Assert.False(error.OfferReport);
        Assert.Null(error.ReportId);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("""{"result":{}}""")]
    [InlineData("""{"ok":"yes","result":{}}""")]
    [InlineData("""{"ok":true}""")]
    [InlineData("""{"ok":false}""")]
    [InlineData("""{"ok":true,"result":null}""")]
    [InlineData("""{"ok":false,"error":null}""")]
    [InlineData("""{"ok":true,"result":{"dirty":"yes"}}""")]
    [InlineData("""{"ok":true,"result":{"dirty":null}}""")]
    [InlineData("""{"ok":false,"error":{"code":"failed"}}""")]
    [InlineData("""{"ok":false,"error":{"code":7,"message":"m"}}""")]
    [InlineData("""{"ok":false,"error":{"code":null,"message":"m"}}""")]
    public void UndecodableResponseIsBadResponse(string body)
    {
        var error = Assert.Throws<RpcException>(() => RpcEnvelope.Decode(Support.Utf8(body), Json.CanQuitResult));
        Assert.Equal(RpcErrorCode.Internal, error.Code);
        Assert.Equal(RpcException.BadResponseMessage, error.Message);
        Assert.False(error.OfferReport);
        Assert.Null(error.ReportId);
    }

    [Theory]
    [InlineData("""{}""")]
    [InlineData("""{"activeKeys":1,"online":true,"recentlyExpired":0,"version":"dev"}""")]
    [InlineData("""{"activeKeys":1,"online":true,"recentlyExpired":0,"version":"dev","statusItems":null}""")]
    [InlineData("""{"activeKeys":1,"online":true,"recentlyExpired":0,"version":null,"statusItems":[]}""")]
    public void ResultNotMatchingTheDtoIsBadResponse(string result)
    {
        var error = Assert.Throws<RpcException>(
            () => RpcEnvelope.Decode(Support.Utf8($$"""{"ok":true,"result":{{result}}}"""), Json.AppInfo));
        Assert.Equal(RpcException.BadResponseMessage, error.Message);
    }

    [Fact]
    public void UnknownResultFieldsAreIgnored()
    {
        var info = RpcEnvelope.Decode(
            """{"ok":true,"result":{"activeKeys":1,"later":{"x":[1]},"online":true,"recentlyExpired":0,"statusItems":["a"],"version":"dev"}}"""u8,
            Json.AppInfo);
        Assert.Equal(1, info.ActiveKeys);
        Assert.Equal(["a"], info.StatusItems);
    }

    [Fact]
    public void ErrorPayloadOmitsAMissingReportId()
    {
        var json = CanonicalJson.Encode(RpcErrorPayload.From(new RpcException(RpcErrorCode.Busy, "b")),
            WireJsonContext.Default.RpcErrorPayload);
        Assert.Equal("""{"code":"busy","message":"b","offerReport":false}""", json);
    }

    [Fact]
    public void NilUpdateNoticeEncodesAsNullAsTheCoreSendsIt()
    {
        var result = new UpdateCurrentResult(new UpdateStatus(UpdateState.Idle, "", "", false), null);
        var json = CanonicalJson.Encode(result, Json.UpdateCurrentResult);
        Assert.EndsWith("\"updated\":null}", json, StringComparison.Ordinal);
        var decoded = RpcEnvelope.Decode(Support.Utf8($$"""{"ok":true,"result":{{json}}}"""), Json.UpdateCurrentResult);
        Assert.Equal(result, decoded);
    }

    [Fact]
    public void PngPreviewIsBase64()
    {
        var signed = RpcEnvelope.Decode(Support.ContractFile("methods/sign.sign/result.json"), Json.SignResult);
        Assert.Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, signed.PngPreview);
        Assert.Contains("\"pngPreview\":\"iVBORw0KGgo=\"", CanonicalJson.Encode(signed, Json.SignResult), StringComparison.Ordinal);
    }
}

public sealed class CanonicalJsonTests
{
    private static BridgeJsonContext Json => BridgeJsonContext.Default;

    [Fact]
    public void SortsKeysAndEscapesNeitherSlashesNorNonAsciiNorHtml()
    {
        var json = CanonicalJson.Encode(new SaveQrParams("https://x/ნ?a=é&b=<c>", QrFormat.Png, "/OUT/a.png"), Json.SaveQrParams);
        Assert.Equal("""{"format":"png","path":"/OUT/a.png","url":"https://x/ნ?a=é&b=<c>"}""", json);
    }

    [Fact]
    public void SortsNestedObjectsByOrdinalKeyOrder()
    {
        var json = CanonicalJson.Encode(
            new AddEntryParams(new EntryForm("A", "2026-01-01", "", "n", true), "k"), Json.AddEntryParams);
        Assert.Equal("""{"form":{"authority":"A","from":"2026-01-01","noExpiry":true,"note":"n","to":""},"publicKey":"k"}""", json);
        var snapshot = new RegistrySnapshot([], [["b", "a"]], false, true);
        Assert.Equal("""{"dirty":false,"entries":[],"loaded":true,"rows":[["b","a"]]}""", CanonicalJson.Encode(snapshot, Json.RegistrySnapshot));
    }

    [Fact]
    public void EscapesQuotesBackslashesAndControlCharacters()
    {
        var json = CanonicalJson.Encode(new HistoryListParams("a\"b\\c\nd\u0001"), Json.HistoryListParams);
        Assert.Equal("""{"query":"a\"b\\c\nd\u0001"}""", json);
    }

    [Fact]
    public void EscapedSupplementaryCharactersDecodeToTheSameString()
    {
        var pin = new PinSubmitParams(1, "12😀", true);
        var json = CanonicalJson.Encode(pin, Json.PinSubmitParams);
        Assert.Equal(pin, JsonSerializer.Deserialize(json, Json.PinSubmitParams));
    }

    [Fact]
    public void OmittedDataDirIsAbsentFromAppInitParams()
    {
        Assert.Equal("{}", CanonicalJson.Encode(new AppInitParams(), Json.AppInitParams));
        Assert.Equal("""{"dataDir":"/DATA"}""", CanonicalJson.Encode(new AppInitParams("/DATA"), Json.AppInitParams));
        Assert.Equal("{}", CanonicalJson.Encode(Empty.Value, Json.Empty));
    }

    [Fact]
    public void EncodesANullNodeAsNull()
    {
        Assert.Equal("null"u8.ToArray(), CanonicalJson.EncodeNode(null));
        Assert.Equal("null", CanonicalJson.Encode<UpdatedNotice?>(null, Json.UpdatedNotice));
    }
}
