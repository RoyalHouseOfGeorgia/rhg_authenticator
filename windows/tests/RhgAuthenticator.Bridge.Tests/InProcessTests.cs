using System.Runtime.InteropServices;
using System.Text.Json.Serialization;

namespace RhgAuthenticator.Bridge.Tests;

/// <summary>Params System.Text.Json cannot encode (NaN without named literals).</summary>
public sealed record NotJsonParams(double Value);

[JsonSerializable(typeof(NotJsonParams))]
internal sealed partial class TestJsonContext : JsonSerializerContext
{
}

/// <summary>
/// The real library loaded in this process, never initialized (app.init can
/// run once per process: initialized flows run in FlowRunner).
/// </summary>
public sealed class LiveBridgeInProcessTests(CoreLibraryFixture fixture)
{
    private static BridgeJsonContext Json => BridgeJsonContext.Default;

    [Fact]
    public void InstallReturnsTheOneBridge()
    {
        Assert.Same(LiveBridge.Install(), LiveBridge.Install());
    }

    [Fact]
    public async Task UnknownMethodIsAnInputError()
    {
        var e = await Assert.ThrowsAsync<RpcException>(
            () => LiveBridge.Install().CallAsync("no.such.method", Empty.Value, Json.Empty, Json.Empty));
        Assert.Equal(RpcErrorCode.Input, e.Code);
        Assert.False(e.OfferReport);
        Assert.Null(e.ReportId);
    }

    [Fact]
    public async Task MethodBeforeInitIsAnInputError()
    {
        IBridge bridge = LiveBridge.Install();
        Assert.Equal(RpcErrorCode.Input, (await Assert.ThrowsAsync<RpcException>(() => bridge.AppInfoAsync())).Code);
    }

    [Fact]
    public async Task CanQuitBeforeInitSucceeds()
    {
        IBridge bridge = LiveBridge.Install();
        Assert.False((await bridge.CanQuitAsync()).Dirty);
    }

    [Fact]
    public async Task CallsRunConcurrently()
    {
        IBridge bridge = LiveBridge.Install();
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => bridge.CanQuitAsync()));
        Assert.All(results, r => Assert.False(r.Dirty));
    }

    [Fact]
    public async Task ParamsThatCannotBeEncodedAreBadParamsAndNotSent()
    {
        var e = await Assert.ThrowsAsync<RpcException>(() => LiveBridge.Install().CallAsync(
            RpcMethod.AppInfo, new NotJsonParams(double.NaN), TestJsonContext.Default.NotJsonParams, Json.Empty));
        Assert.Equal(RpcErrorCode.Input, e.Code);
        Assert.Equal(RpcException.BadParamsMessage, e.Message);
    }

    [Fact]
    public async Task MethodNameWithNonAsciiAndQuotesReachesTheCoreIntact()
    {
        var e = await Assert.ThrowsAsync<RpcException>(
            () => LiveBridge.Install().CallAsync("ნ\"\\.x", Empty.Value, Json.Empty, Json.Empty));
        Assert.Equal(RpcErrorCode.Input, e.Code);
    }

    [Fact]
    public async Task TheEventCallbackQueuesEachEventAndIgnoresNull()
    {
        var bridge = LiveBridge.Install();
        Deliver(null);
        Deliver("""{"event":"pin.request","data":{"maxBytes":8,"rememberDefault":true,"requestId":5}}""");
        Deliver("not json");
        Deliver("""{"event":"history.changed","data":null}""");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var received = new List<BridgeEvent>();
        for (var i = 0; i < 3; i++)
        {
            received.Add(await bridge.Events.ReadAsync(timeout.Token));
        }
        Assert.Equal(
            [new BridgeEvent.PinRequested(new PinRequest(5, true, 8)), new BridgeEvent.Unknown(""), new BridgeEvent.HistoryChanged()],
            received);
        Assert.False(bridge.Events.TryRead(out _));
    }

    /// <summary>Calls the registered C callback as the core does, with a NUL-terminated UTF-8 copy of <paramref name="json"/>.</summary>
    private static unsafe void Deliver(string? json)
    {
        if (json is null)
        {
            LiveBridge.EventCallback(null);
            return;
        }
        var p = Marshal.StringToCoTaskMemUTF8(json);
        try
        {
            LiveBridge.EventCallback((byte*)p);
        }
        finally
        {
            Marshal.FreeCoTaskMem(p);
        }
    }

    [Fact]
    public void ThePlantedLibraryIsNeverLoaded()
    {
        // A garbage library sits where a search path would look first; the
        // core still answers, so the real one was loaded by its full path.
        Assert.Equal(Path.Combine(AppContext.BaseDirectory, CoreLibrary.FileName), fixture.PlantedPath);
        Assert.True(File.Exists(fixture.PlantedPath));
        Assert.True(MainCli.RunArgv(["rhg-authenticator", "--verify-update-zip"]) > 0);
    }
}

/// <summary>
/// The core's CLI in this process. Only invocations that write to stderr: the
/// core writes straight to file descriptor 1, which here is xUnit's message
/// stream to the test runner, and a line landing inside a message drops that
/// test's result. --version runs in FlowRunner (FlowTests).
/// </summary>
public sealed class MainCliTests(CoreLibraryFixture fixture)
{
    public static TheoryData<string[]> NotCli => new()
    {
        Array.Empty<string>(),
        new[] { "rhg-authenticator" },
        new[] { "rhg-authenticator", "--other" },
        new[] { "rhg-authenticator", "-psn_0_12345" },
    };

    [Theory]
    [MemberData(nameof(NotCli))]
    public void ArgumentsThatAreNotACliInvocationStartTheUi(string[] argv)
    {
        Assert.Null(MainCli.RunArgv(argv));
    }

    [Fact]
    public void RunPrependsTheProgram()
    {
        Assert.NotNull(fixture);
        Assert.Null(MainCli.Run([]));
        Assert.Null(MainCli.Run(["--other"]));
        Assert.True(MainCli.Run(["--verify-update-zip"]) > 0);
        Assert.Throws<ArgumentNullException>(() => MainCli.Run(null!));
        Assert.Throws<ArgumentNullException>(() => MainCli.RunArgv(null!));
    }

    [Fact]
    public void ArgumentsWithNonAsciiReachTheCore()
    {
        Assert.Null(MainCli.RunArgv(["რ", "--ნ"]));
    }
}
