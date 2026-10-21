using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class AppViewModelTests
{
    private static readonly string s_reportSuffix =
        "\n\nPlease report this error at https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues";

    private readonly FakeBridge _fake = new();

    private AppViewModel NewApp()
    {
        return new AppViewModel(_fake, new FakeFileSave(), new FakeClipboard(), new FakeUrlOpener());
    }

    [Fact]
    public void CopyAndTabs()
    {
        Assert.Equal("RHG Authenticator", AppViewModel.WindowTitle);
        Assert.Equal("Loading key registry…", AppViewModel.LoadingText);
        Assert.Equal(AppViewModel.ReportSuffix, s_reportSuffix);
        var app = NewApp();
        Assert.Equal(["Sign", "History", "Registry", "Audit", "YubiKey"], app.Tabs.Select(t => t.Title));
        Assert.Same(app.Sign, app.Tabs[0].Content);
        Assert.False(app.Tabs[0].IsPlaceholder);
        Assert.All(app.Tabs.Skip(1), t => Assert.True(t.IsPlaceholder));
        Assert.Equal("Not yet available", AppTab.PlaceholderText);
    }

    [Fact]
    public void RequiresABridge()
    {
        Assert.Throws<ArgumentNullException>(
            () => new AppViewModel(null!, new FakeFileSave(), new FakeClipboard(), new FakeUrlOpener()));
    }

    [Fact]
    public async Task StartupInitHonorsStartInOrderThenReadyWithTheStatusBar()
    {
        var app = NewApp();
        Assert.Equal(AppPhase.Starting, app.Phase);
        Assert.Empty(app.StatusItems);
        var changed = new List<string?>();
        app.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        _fake.Respond(RpcMethod.AppInit, Fixtures.OnlineInfo);
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult(["A", "B"]));
        await app.StartAsync("/data");
        Assert.Equal(AppPhase.Ready, app.Phase);
        Assert.Null(app.FatalMessage);
        Assert.Same(Fixtures.OnlineInfo, app.Info);
        Assert.Equal(["Core keys: three", "Core expired: one", "Core version 1.2.3"], app.StatusItems);
        Assert.Contains(nameof(AppViewModel.StatusItems), changed);
        Assert.Equal(["A", "B"], app.Sign.Honors);
        Assert.Equal([RpcMethod.AppInit, RpcMethod.SignHonors, RpcMethod.AppStart], _fake.Methods);
        Assert.Equal(["{\"dataDir\":\"/data\"}"], _fake.Params(RpcMethod.AppInit));
    }

    [Fact]
    public async Task TheProgressPhaseLastsWhileAppInitRuns()
    {
        var held = _fake.Hold(RpcMethod.AppInit);
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult([]));
        var app = NewApp();
        var starting = app.StartAsync();
        Assert.Equal(AppPhase.Starting, app.Phase);
        held.Release(Fixtures.OnlineInfo);
        await starting;
        Assert.Equal(AppPhase.Ready, app.Phase);
    }

    [Fact]
    public async Task TheStatusItemsAreTheCoresAsGivenOfflineToo()
    {
        _fake.Respond(RpcMethod.AppInit, new AppInfo(0, false, 0, "vv2", ["Core offline — ქ", "Core build vv2"]));
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult([]));
        var app = NewApp();
        await app.StartAsync();
        Assert.Equal(AppPhase.Ready, app.Phase);
        Assert.Equal(["Core offline — ქ", "Core build vv2"], app.StatusItems);
        Assert.Equal(["{}"], _fake.Params(RpcMethod.AppInit));
    }

    [Fact]
    public async Task AppInitFailureIsFatalWithTheReportSuffixAndNothingElseIsCalled()
    {
        _fake.Fail(RpcMethod.AppInit, new RpcException(RpcErrorCode.Failed, "Could not create the data directory."));
        var app = NewApp();
        await app.StartAsync();
        Assert.Equal(AppPhase.Fatal, app.Phase);
        Assert.Equal(
            "Could not create the data directory.\n\n"
            + "Please report this error at https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues",
            app.FatalMessage);
        Assert.Equal([RpcMethod.AppInit], _fake.Methods);
        Assert.Empty(app.StatusItems);
    }

    [Fact]
    public async Task HonorsFailureIsFatalAndAppStartIsNotCalled()
    {
        _fake.Respond(RpcMethod.AppInit, Fixtures.OnlineInfo);
        _fake.Fail(RpcMethod.SignHonors, new RpcException(RpcErrorCode.Internal, "honors broke"));
        var app = NewApp();
        await app.StartAsync();
        Assert.Equal(AppPhase.Fatal, app.Phase);
        Assert.Equal("honors broke" + s_reportSuffix, app.FatalMessage);
        Assert.Equal([RpcMethod.AppInit, RpcMethod.SignHonors], _fake.Methods);
    }

    [Fact]
    public async Task AppStartFailureIsFatal()
    {
        _fake.Respond(RpcMethod.AppInit, Fixtures.OnlineInfo);
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult([]));
        _fake.Fail(RpcMethod.AppStart, new RpcException(RpcErrorCode.Input, "not initialized"));
        var app = NewApp();
        await app.StartAsync();
        Assert.Equal(AppPhase.Fatal, app.Phase);
        Assert.Equal("not initialized" + s_reportSuffix, app.FatalMessage);
    }

    [Fact]
    public async Task ASecondStartDoesNothing()
    {
        var app = await Fixtures.StartedApp(_fake);
        await app.StartAsync();
        Assert.Equal(1, _fake.Count(RpcMethod.AppInit));
    }

    [Fact]
    public async Task EventsEmittedBeforeStartAreDeliveredOnceItRuns()
    {
        _fake.Emit(new BridgeEvent.PinRequested(new PinRequest(4, true, 8)));
        var app = await Fixtures.StartedApp(_fake);
        Assert.True(await Fixtures.Settle(() => app.PinPrompt.Request is not null));
        Assert.Equal(4UL, app.PinPrompt.Request?.RequestId);
    }

    [Fact]
    public async Task EventsAreDrainedWhileAppInitRuns()
    {
        var held = _fake.Hold(RpcMethod.AppInit);
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult([]));
        var app = NewApp();
        var starting = app.StartAsync();
        _fake.Emit(new BridgeEvent.PinRequested(new PinRequest(3, false, 8)));
        Assert.True(await Fixtures.Settle(() => app.PinPrompt.Request?.RequestId == 3));
        held.Release(Fixtures.OnlineInfo);
        await starting;
    }

    [Fact]
    public async Task AppInternalErrorShowsTheRestartAlert()
    {
        var app = await Fixtures.StartedApp(_fake);
        Assert.Null(app.Alerts.Current);
        _fake.Emit(new BridgeEvent.AppInternalError());
        Assert.True(await Fixtures.Settle(() => app.Alerts.Current is not null));
        Assert.Equal(new AlertState("Error", "An internal error occurred — please restart"), app.Alerts.Current);
        app.Alerts.Dismiss();
        Assert.Null(app.Alerts.Current);
    }

    [Fact]
    public async Task AFailingEventHandlerShowsTheRestartAlertAndTheDrainGoesOn()
    {
        var app = await Fixtures.StartedApp(_fake);
        var fail = true;
        app.PinPrompt.PropertyChanged += (_, _) =>
        {
            if (fail)
            {
                fail = false;
                throw new InvalidOperationException("a view handler failed");
            }
        };
        _fake.Emit(new BridgeEvent.PinRequested(new PinRequest(4, false, 8)));
        Assert.True(await Fixtures.Settle(() => app.Alerts.Current is not null));
        Assert.Equal(new AlertState("Error", "An internal error occurred — please restart"), app.Alerts.Current);
        // The request it failed to present is answered at once, not left to time out.
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.PinCancel) == 1));
        Assert.Equal(["{\"requestId\":4}"], _fake.Params(RpcMethod.PinCancel));
        Assert.False(app.PinPrompt.IsOpen);
        _fake.Emit(new BridgeEvent.PinRequested(new PinRequest(5, false, 8)));
        Assert.True(await Fixtures.Settle(() => app.PinPrompt.Request?.RequestId == 5));
        Assert.False(app.EventLoop!.IsCompleted);
    }

    [Fact]
    public async Task PinEventsReachThePinPrompt()
    {
        var app = await Fixtures.StartedApp(_fake);
        _fake.Emit(new BridgeEvent.PinRequested(new PinRequest(9, false, 8)));
        Assert.True(await Fixtures.Settle(() => app.PinPrompt.Request is not null));
        // A stale dismiss leaves the prompt up; the matching one closes it.
        _fake.Emit(new BridgeEvent.PinDismissed(new PinDismiss(8)));
        _fake.Emit(new BridgeEvent.AppInternalError());
        Assert.True(await Fixtures.Settle(() => app.Alerts.Current is not null));
        Assert.Equal(9UL, app.PinPrompt.Request?.RequestId);
        _fake.Emit(new BridgeEvent.PinDismissed(new PinDismiss(9)));
        Assert.True(await Fixtures.Settle(() => app.PinPrompt.Request is null));
    }

    [Fact]
    public async Task EventsOfFeaturesNotBuiltYetAndUnknownEventsAreIgnored()
    {
        var app = await Fixtures.StartedApp(_fake);
        var callsBefore = _fake.Calls.Count;
        var loggedIn = new AuthState(true, false, "octocat", "Logged in as @octocat");
        BridgeEvent[] ignored =
        [
            new BridgeEvent.AuthChanged(loggedIn),
            new BridgeEvent.AuthDeviceCode(new DeviceCode("ABCD-1234", "https://github.com/login/device")),
            new BridgeEvent.BulkConnecting(),
            new BridgeEvent.BulkProgressed(new BulkProgress(1, 2, "A")),
            new BridgeEvent.HistoryChanged(),
            new BridgeEvent.HistoryRevocationsChanged(),
            new BridgeEvent.RegistryChanged(),
            new BridgeEvent.UpdateStatusChanged(new UpdateStatus(UpdateState.Ready, "1.3.0", "", false)),
            new BridgeEvent.UpdateUpdated(new UpdatedNotice("1.2.3", "")),
            new BridgeEvent.Unknown("future.event"),
        ];
        foreach (var bridgeEvent in ignored)
        {
            _fake.Emit(bridgeEvent);
        }
        // The loop is still draining after them.
        _fake.Emit(new BridgeEvent.PinRequested(new PinRequest(1, false, 8)));
        Assert.True(await Fixtures.Settle(() => app.PinPrompt.Request is not null));
        Assert.Equal(AppPhase.Ready, app.Phase);
        Assert.Null(app.Alerts.Current);
        Assert.Equal(callsBefore, _fake.Calls.Count);
    }

    [Fact]
    public async Task TheDrainStartsWithStartupAndEndsWithTheEventChannel()
    {
        var app = NewApp();
        Assert.Null(app.EventLoop);
        _fake.Fail(RpcMethod.AppInit, new RpcException(RpcErrorCode.Failed, "x"));
        await app.StartAsync();
        var loop = Assert.IsType<Task>(app.EventLoop, exactMatch: false);
        _fake.Emit(new BridgeEvent.AppInternalError());
        _fake.CompleteEvents();
        await loop.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal("An internal error occurred — please restart", app.Alerts.Current?.Message);
        Assert.Equal(AppPhase.Fatal, app.Phase);
    }

    [Fact]
    public async Task QuitShutsDownWithoutRelaunch()
    {
        var app = NewApp();
        Assert.True(await app.PrepareToQuitAsync());
        Assert.Equal([RpcMethod.AppShutdown], _fake.Methods);
        Assert.Equal(["{\"relaunch\":false}"], _fake.Params(RpcMethod.AppShutdown));
    }

    [Fact]
    public async Task CoreErrorsNeverBlockQuitting()
    {
        _fake.Fail(RpcMethod.AppShutdown, new RpcException(RpcErrorCode.Internal, "y"));
        var app = NewApp();
        Assert.True(await app.PrepareToQuitAsync());
        Assert.Equal([RpcMethod.AppShutdown], _fake.Methods);
    }

    [Fact]
    public async Task ABridgeFaultNeverBlocksQuittingEither()
    {
        _fake.Respond(RpcMethod.AppShutdown, "not the shutdown result"); // the fake throws InvalidOperationException
        var app = NewApp();
        Assert.True(await app.PrepareToQuitAsync());
    }

    [Fact]
    public async Task ConcurrentAndLaterQuitsShareOneShutdown()
    {
        var held = _fake.Hold(RpcMethod.AppShutdown);
        var app = NewApp();
        var first = app.PrepareToQuitAsync();
        var second = app.PrepareToQuitAsync();
        Assert.False(first.IsCompleted);
        Assert.False(second.IsCompleted);
        held.Release(Empty.Value);
        Assert.True(await first);
        Assert.True(await second);
        Assert.True(await app.PrepareToQuitAsync());
        Assert.Equal(1, _fake.Count(RpcMethod.AppShutdown));
    }
}
