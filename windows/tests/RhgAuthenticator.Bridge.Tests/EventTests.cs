using System.Text.Json;

namespace RhgAuthenticator.Bridge.Tests;

public sealed class EventTests
{
    [Fact]
    public void UnknownEventNameDecodesToUnknownWithNullDataOnReencode()
    {
        var e = BridgeEvent.Parse("""{"event":"new.thing","data":{"x":1}}"""u8);
        Assert.Equal(new BridgeEvent.Unknown("new.thing"), e);
        Assert.Equal("new.thing", e.Name);
        Assert.Equal("""{"data":null,"event":"new.thing"}""", e.ToJson());
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("[]", "")]
    [InlineData("null", "")]
    [InlineData("""{"data":null}""", "")]
    [InlineData("""{"event":7}""", "")]
    [InlineData("""{"event":null}""", "")]
    [InlineData("""{"event":"pin.request","data":null}""", "pin.request")]
    [InlineData("""{"event":"pin.request","data":{"requestId":"x"}}""", "pin.request")]
    [InlineData("""{"event":"pin.request","data":{"requestId":1}}""", "pin.request")]
    [InlineData("""{"event":"update.status"}""", "update.status")]
    [InlineData("""{"event":"auth.changed","data":7}""", "auth.changed")]
    public void MalformedEventJsonBecomesUnknown(string json, string name)
    {
        Assert.Equal(new BridgeEvent.Unknown(name), BridgeEvent.Parse(Support.Utf8(json)));
    }

    [Fact]
    public void KnownEventWithABadPayloadThrowsInTheStrictParser()
    {
        Assert.Throws<JsonException>(() => BridgeEvent.ParseStrict("""{"event":"pin.dismiss","data":{}}"""u8));
        Assert.Throws<JsonException>(() => BridgeEvent.ParseStrict("null"u8));
    }

    [Fact]
    public void PayloadlessEventsIgnoreTheirData()
    {
        Assert.Equal(new BridgeEvent.HistoryChanged(), BridgeEvent.ParseStrict("""{"event":"history.changed","data":{"x":1}}"""u8));
        Assert.Equal(new BridgeEvent.SignConnecting(), BridgeEvent.ParseStrict("""{"event":"sign.connecting"}"""u8));
    }

    [Fact]
    public void UnknownPayloadFieldsAreIgnored()
    {
        Assert.Equal(new BridgeEvent.PinDismissed(new PinDismiss(4)),
            BridgeEvent.ParseStrict("""{"event":"pin.dismiss","data":{"requestId":4,"reason":"later"}}"""u8));
    }

    [Fact]
    public void AMaximalPinRequestIdSurvivesAnEncodeDecodeRoundTrip()
    {
        BridgeEvent e = new BridgeEvent.PinRequested(new PinRequest(ulong.MaxValue, false, 8));
        Assert.Equal(e, BridgeEvent.Parse(Support.Utf8(e.ToJson())));
        Assert.Equal(e, BridgeEvent.ParseStrict(Support.Utf8(e.ToJson())));
        Assert.StartsWith("{\"data\":", e.ToJson(), StringComparison.Ordinal);
        Assert.EndsWith($"\"event\":\"{e.Name}\"}}", e.ToJson(), StringComparison.Ordinal);
    }
}
