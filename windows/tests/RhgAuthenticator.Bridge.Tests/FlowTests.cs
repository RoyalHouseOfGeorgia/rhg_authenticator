namespace RhgAuthenticator.Bridge.Tests;

/// <summary>Real-library flows, one FlowRunner process each.</summary>
public sealed class FlowTests(CoreLibraryFixture fixture)
{
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(90);

    public static TheoryData<string, string[]> Scenarios => new()
    {
        {
            "offline",
            [
                "app.init offline", "sign.sign offline is refused", "sign.sign offline asks for no PIN",
                "test.panic is an internal error", "app.canQuit after a panic", "app.shutdown", "app.info after app.shutdown",
            ]
        },
        {
            "online",
            [
                "app.init online with the fake card's key", "app.info matches app.init", "sign.sign with the PIN submitted",
                "one pin.request", "sign.connecting", "pin.submit with a stale requestId", "sign.saveQR wrote the file",
                "sign.reportError of an unknown report", "Georgian recipient round-trips byte for byte",
                "Georgian NFD recipient is signed as NFC bytes", "NFD recipient is signed as NFC bytes",
                "NFC name is the NFD name's credential", "app.canQuit is not dirty", "app.info after app.shutdown",
            ]
        },
        { "pinCancel", ["pin.cancel", "one pin.request", "sign.sign with the PIN cancelled", "app.info after app.shutdown"] },
        {
            "pinTimeout",
            [
                "one pin.request", "sign.sign fails when the PIN prompt times out",
                "pin.dismiss withdraws the timed-out request", "app.info after app.shutdown",
            ]
        },
        {
            "bulk",
            [
                "bulk.load plans 2 rows to sign and 1 invalid row", "bulk.cancel", "bulk.run cancelled at the PIN prompt",
                "bulk.cancel at the PIN prompt stops the run as cancelled", "pin.dismiss withdraws the cancelled run's request",
                "no bulk.connecting without a PIN", "the cancelled run signed nothing", "pin.submit", "bulk.run asks for the PIN",
                "bulk.run with the PIN submitted", "bulk.run completes", "bulk.run suggests a CSV results file name",
                "two bulk.progress events", "one PIN covers the whole run", "bulk.connecting before the first bulk.progress",
                "bulk.progress counts the rows in order", "bulk.exportResults wrote the file", "app.info after app.shutdown",
            ]
        },
    };

    [Theory]
    [MemberData(nameof(Scenarios))]
    public async Task EachScenarioPassesAgainstTheRhgfakeLibrary(string scenario, string[] expected)
    {
        Assert.NotNull(fixture);
        var (status, lines, stderr) = await Support.RunFlowAsync([scenario], s_timeout);
        var output = $"exit {status}\n{string.Join('\n', lines)}\nstderr:\n{stderr}";
        Assert.True(status == 0, output);
        Assert.StartsWith($"PASS: {scenario}", lines[^1], StringComparison.Ordinal);
        Assert.DoesNotContain(lines, l => l.StartsWith("FAIL:", StringComparison.Ordinal));
        foreach (var check in expected)
        {
            Assert.True(lines.Contains($"ok: {check}"), $"missing check: {check}\n{output}");
        }
        Assert.DoesNotContain(lines, l => l.Contains("123456", StringComparison.Ordinal));
    }

    [Fact]
    public async Task VersionPrintsTheRhgfakeVersionAndExits0()
    {
        var (status, lines, _) = await Support.RunFlowAsync(["--version"], s_timeout);
        Assert.Equal(0, status);
        Assert.EndsWith("(rhgfake)", Assert.Single(lines), StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownScenarioPrintsUsageAndExits2()
    {
        var (status, lines, _) = await Support.RunFlowAsync(["nope"], s_timeout);
        Assert.Equal(2, status);
        Assert.StartsWith("usage:", lines[0], StringComparison.Ordinal);
    }
}
