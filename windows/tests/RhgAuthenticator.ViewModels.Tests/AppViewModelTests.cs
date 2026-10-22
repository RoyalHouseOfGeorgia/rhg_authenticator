using System.Text;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class AppViewModelTests
{
    private static readonly string s_reportSuffix =
        "\n\nPlease report this error at https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues";

    private readonly FakeBridge _fake = new();

    private readonly FakeFileSave _fileSave = new();
    private readonly FakeFileOpen _fileOpen = new();

    private AppViewModel NewApp(TimeProvider? clock = null)
    {
        return new AppViewModel(_fake, _fileSave, _fileOpen, new FakeClipboard(), new FakeUrlOpener(), clock);
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
        Assert.Same(app.YubiKey, app.Tabs[4].Content);
        Assert.Equal([false, true, true, true, false], app.Tabs.Select(t => t.IsPlaceholder));
        Assert.Equal([.. "Export Error Log"u8, 0xE2, 0x80, 0xA6], Encoding.UTF8.GetBytes(AppViewModel.ExportErrorLogTitle));
        Assert.Equal("Not yet available", AppTab.PlaceholderText);
    }

    [Fact]
    public void RequiresItsServices()
    {
        Assert.Throws<ArgumentNullException>(
            () => new AppViewModel(null!, _fileSave, _fileOpen, new FakeClipboard(), new FakeUrlOpener()));
        Assert.Throws<ArgumentNullException>(
            () => new AppViewModel(_fake, null!, _fileOpen, new FakeClipboard(), new FakeUrlOpener()));
        Assert.Throws<ArgumentNullException>(
            () => new AppViewModel(_fake, _fileSave, null!, new FakeClipboard(), new FakeUrlOpener()));
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
        // Shown as an alert offering the error log; the host exits after it.
        Assert.Equal(new AlertState(AlertState.ErrorTitle, app.FatalMessage!, OffersErrorLogExport: true), app.Alerts.Current);
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
        Assert.Equal(new AlertState(AlertState.ErrorTitle, app.FatalMessage!, OffersErrorLogExport: true), app.Alerts.Current);
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
        Assert.Equal(new AlertState(AlertState.ErrorTitle, app.FatalMessage!, OffersErrorLogExport: true), app.Alerts.Current);
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
    public async Task EventsOfFeaturesNotBuiltYetBulkEventsOutsideARunAndUnknownEventsAreIgnored()
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
        Assert.Equal(BulkPhase.Idle, app.Bulk.Phase);
        Assert.Null(app.Bulk.Progress);
    }

    [Fact]
    public async Task TheDrainStartsWithStartupAndEndsWithTheEventChannel()
    {
        var app = NewApp();
        Assert.Null(app.EventLoop);
        _fake.Fail(RpcMethod.AppInit, new RpcException(RpcErrorCode.Failed, "x"));
        await app.StartAsync();
        app.Alerts.Dismiss(); // the fatal error's
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

    [Fact]
    public async Task ASigningDisablesBulkSignAndABulkFlowDisablesSignCredential()
    {
        var held = _fake.Hold(RpcMethod.SignSign);
        var app = await Fixtures.StartedApp(_fake, fileOpen: _fileOpen);
        // Only the app raises each command's CanExecuteChanged for the other
        // flow's state; without it WPF never re-checks the button.
        var bulkCommandChanges = 0;
        var signCommandChanges = 0;
        app.Bulk.BulkSignCommand.CanExecuteChanged += (_, _) => bulkCommandChanges++;
        app.Sign.SignCommand.CanExecuteChanged += (_, _) => signCommandChanges++;
        Assert.True(app.Bulk.BulkSignCommand.CanExecute(null));
        Assert.True(app.Sign.SignCommand.CanExecute(null));

        var signing = app.Sign.SignCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.SignSign) == 1));
        Assert.True(app.Sign.IsBusy);
        Assert.False(app.Bulk.IsActive);
        Assert.Equal(1, bulkCommandChanges);
        Assert.False(app.Bulk.BulkSignCommand.CanExecute(null));
        await app.Bulk.BulkSignCommand.ExecuteAsync(null); // ignored while signing
        Assert.Equal(BulkPhase.Idle, app.Bulk.Phase);
        Assert.Empty(_fileOpen.Requests);
        bulkCommandChanges = 0;
        held.Release(Fixtures.SignResult());
        await signing;
        Assert.False(app.Sign.IsBusy);
        Assert.Equal(1, bulkCommandChanges);
        Assert.True(app.Bulk.BulkSignCommand.CanExecute(null));

        signCommandChanges = 0;
        var loadHeld = _fake.Hold(RpcMethod.BulkLoad);
        _fileOpen.Answer("/in/bulk.csv");
        var bulk = app.Bulk.BulkSignCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.BulkLoad) == 1));
        Assert.True(app.Bulk.IsActive);
        Assert.False(app.Sign.IsBusy);
        Assert.True(signCommandChanges > 0);
        Assert.False(app.Sign.SignCommand.CanExecute(null));
        await app.Sign.SignCommand.ExecuteAsync(null); // ignored during a bulk flow
        Assert.Equal(1, _fake.Count(RpcMethod.SignValidate)); // the first signing's only
        Assert.False(app.Bulk.BulkSignCommand.CanExecute(null));
        loadHeld.Release(Fixtures.BulkPlan());
        await bulk;
        Assert.Equal(BulkPhase.Confirming, app.Bulk.Phase);
        signCommandChanges = 0;
        app.Bulk.CancelConfirmCommand.Execute(null);
        Assert.False(app.Bulk.IsActive);
        Assert.True(signCommandChanges > 0);
        Assert.True(app.Sign.SignCommand.CanExecute(null));
        Assert.True(app.Bulk.BulkSignCommand.CanExecute(null));
    }

    [Fact]
    public async Task BulkProgressReachesTheRunningBulkFlowAndThePinPromptStacksOnIt()
    {
        _fake.Respond(RpcMethod.BulkLoad, Fixtures.BulkPlan(1));
        var held = _fake.Hold(RpcMethod.BulkRun);
        var app = await Fixtures.StartedApp(_fake, fileOpen: _fileOpen);
        _fileOpen.Answer("/in/x.csv");
        await app.Bulk.BulkSignCommand.ExecuteAsync(null);
        var running = app.Bulk.ConfirmCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.BulkRun) == 1));
        _fake.Emit(new BridgeEvent.PinRequested(new PinRequest(11, false, 8)));
        Assert.True(await Fixtures.Settle(() => app.PinPrompt.Request?.RequestId == 11));
        // The progress dialog stays up under the prompt.
        Assert.True(app.Bulk.IsRunning && app.Bulk.IsShowingDialog);
        _fake.Emit(new BridgeEvent.BulkConnecting());
        _fake.Emit(new BridgeEvent.BulkProgressed(new BulkProgress(0, 1, "Jane Doe")));
        Assert.True(await Fixtures.Settle(() => app.Bulk.Progress is not null));
        Assert.Equal(
            "Signing 1 of 1: Jane Doe — touch your YubiKey if it is blinking", app.Bulk.ProgressLabel);
        held.Release(Fixtures.BulkOutcome());
        await running;
        Assert.Equal(BulkPhase.Results, app.Bulk.Phase);
    }

    [Theory]
    [InlineData(0, "rhg-error-log-2026-01-01.log")]
    [InlineData(4, "rhg-error-log-2026-01-02.log")] // Tbilisi
    [InlineData(-8, "rhg-error-log-2026-01-01.log")] // Los Angeles
    public void TheErrorLogIsNamedByTodaysDateInTheMachinesTimeZone(int offsetHours, string name)
    {
        var zone = TimeZoneInfo.CreateCustomTimeZone("test", TimeSpan.FromHours(offsetHours), "test", "test");
        var app = NewApp(new FixedClock(Fixtures.LateNewYearsDay, zone)); // 2026-01-01T23:30Z
        Assert.Equal(name, app.SuggestedErrorLogFilename);
    }

    [Fact]
    public async Task ErrorLogExportShowsTheCoresAlertAsGivenEvenBeforeStartup()
    {
        _fake.Respond(RpcMethod.AppExportErrorLog, new ExportResult("Core Export Title", "Core says: saved it."));
        var app = NewApp(new FixedClock(Fixtures.LateNewYearsDay));
        Assert.Equal(AppPhase.Starting, app.Phase);
        Assert.True(app.ExportErrorLogCommand.CanExecute(null));
        _fileSave.Answer("/out/rhg-error-log-2026-01-01.log");
        await app.ExportErrorLogCommand.ExecuteAsync(null);
        Assert.Equal([("rhg-error-log-2026-01-01.log", "log")], _fileSave.Requests);
        Assert.Equal(["{\"path\":\"/out/rhg-error-log-2026-01-01.log\"}"], _fake.Params(RpcMethod.AppExportErrorLog));
        Assert.Equal(new AlertState("Core Export Title", "Core says: saved it."), app.Alerts.Current);
        Assert.False(app.Alerts.Current!.IsError);
    }

    [Fact]
    public async Task ErrorLogExportFailureShowsTheCoresMessageAfterAFatalStartup()
    {
        _fake.Fail(RpcMethod.AppInit, new RpcException(RpcErrorCode.Failed, "x"));
        _fake.Fail(
            RpcMethod.AppExportErrorLog, new RpcException(RpcErrorCode.Failed, "Choose a folder outside the app's data folder."));
        var app = NewApp();
        await app.StartAsync();
        Assert.Equal(AppPhase.Fatal, app.Phase);
        Assert.True(app.Alerts.Current?.OffersErrorLogExport);
        app.Alerts.Dismiss(); // as the host does before exporting from it
        _fileSave.Answer("/data/x.log");
        await app.ExportErrorLogCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Error", "Choose a folder outside the app's data folder."), app.Alerts.Current);
    }

    [Fact]
    public async Task ACancelledErrorLogSaveDialogDoesNothing()
    {
        var app = NewApp();
        await app.ExportErrorLogCommand.ExecuteAsync(null);
        Assert.Single(_fileSave.Requests);
        Assert.Empty(_fake.Calls);
        Assert.Null(app.Alerts.Current);
    }
}
