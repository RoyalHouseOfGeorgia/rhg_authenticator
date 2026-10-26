namespace RhgAuthenticator.Bridge.Tests;

public sealed class PinTests
{
    private static void AssertBytes(string expected, string actual)
    {
        Assert.Equal(Support.Utf8(expected), Support.Utf8(actual));
    }

    [Fact]
    public void TruncationCutsBetweenScalarsCountingUtf8Bytes()
    {
        // A decomposed é: the combining mark (2 bytes) does not fit.
        AssertBytes("123456e", PinTruncation.Truncate("123456é", 8));
        // A precomposed é (2 bytes) fits exactly.
        AssertBytes("123456é", PinTruncation.Truncate("123456é", 8));
        // A flag is two 4-byte scalars and one grapheme: only the first fits.
        AssertBytes("\U0001F1EC", PinTruncation.Truncate("\U0001F1EC\U0001F1EA", 7));
        Assert.Equal("", PinTruncation.Truncate("1234", -1));
        Assert.Equal("", PinTruncation.Truncate("", 8));
    }

    [Fact]
    public void LoneSurrogateCountsAsThreeBytes()
    {
        Assert.Equal("12\uD83D", PinTruncation.Truncate("12\uD83D3", 5));
        Assert.Equal("12", PinTruncation.Truncate("12\uDE003", 4));
    }

    [Fact]
    public void PinSubmitParamsNeverPrintThePin()
    {
        var p = new PinSubmitParams(7, "secret-987", true);
        Assert.DoesNotContain("secret-987", p.ToString(), StringComparison.Ordinal);
        Assert.Contains("<redacted>", p.ToString(), StringComparison.Ordinal);
        Assert.Contains("RequestId = 7", p.ToString(), StringComparison.Ordinal);
        Assert.Contains("Remember = True", p.ToString(), StringComparison.Ordinal);
    }
}
