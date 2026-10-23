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
    private readonly FakeConfirm _confirm = new();

    private AppViewModel NewApp(TimeProvider? clock = null)
    {
        return new AppViewModel(_fake, _fileSave, _fileOpen, new FakeClipboard(), new FakeUrlOpener(), _confirm, clock);
    }

    [Fact]
    public void CopyAndTabs()
    {
        Assert.Equal("RHG Authenticator", AppViewModel.WindowTitle);
        Assert.Equal("Loading key registry…", AppViewModel.LoadingText);
        Assert.Equal(AppViewModel.ReportSuffix, s_reportSuffix);
        var app = NewApp();
        Assert.Equal(["Sign", "History", "Registry", "Audit", "YubiKey", "Help"], app.Tabs.Select(t => t.Title));
        Assert.Equal("Help", AppViewModel.HelpTitle);
        Assert.Same(app.Sign, app.Tabs[0].Content);
        Assert.Same(app.History, app.Tabs[1].Content);
        Assert.Same(app.Registry, app.Tabs[2].Content);
        Assert.Same(app.Audit, app.Tabs[3].Content);
        Assert.Same(app.Login, app.Registry.Login);
        Assert.Same(app.Login, app.History.Login);
        Assert.Same(app.YubiKey, app.Tabs[4].Content);
        Assert.Same(app, app.Tabs[5].Content);
        Assert.Null(app.UpdateBanner);
        Assert.Equal(
            new Confirmation(
                "Unsubmitted Changes", "The registry has unsubmitted changes. Exit anyway?", "Exit", "Cancel", IsDestructive: true),
            AppViewModel.QuitConfirmation);
        Assert.Equal([.. "Export Error Log"u8, 0xE2, 0x80, 0xA6], Encoding.UTF8.GetBytes(AppViewModel.ExportErrorLogTitle));
        Assert.Equal(
            "Saves the app's diagnostic log to a file you choose, to attach to an issue report.", AppViewModel.HelpText);
    }

    [Fact]
    public void AFreshAppEnablesAndSelectsOnlyHelpAndShowsLoading()
    {
        var app = NewApp();
        Assert.Equal([false, false, false, false, false, true], app.Tabs.Select(t => t.IsEnabled));
        Assert.Same(app.Tabs[5], app.SelectedTab);
        Assert.True(app.IsStarting);
    }

    [Fact]
    public async Task ReadyEnablesEveryTabAndSelectsSign()
    {
        var app = await Fixtures.StartedApp(_fake);
        Assert.Equal(AppPhase.Ready, app.Phase);
        Assert.All(app.Tabs, t => Assert.True(t.IsEnabled));
        Assert.Same(app.Tabs[0], app.SelectedTab);
        Assert.False(app.IsStarting);
        // Any tab can be selected once ready; nothing selected falls back to Help.
        app.SelectedTab = app.Tabs[2];
        Assert.Same(app.Tabs[2], app.SelectedTab);
        app.SelectedTab = null;
        Assert.Same(app.Tabs[5], app.SelectedTab);
    }

    [Fact]
    public async Task FatalDisablesEveryTabAndKeepsHelpSelected()
    {
        _fake.Fail(RpcMethod.AppInit, new RpcException(RpcErrorCode.Failed, "x"));
        var app = NewApp();
        await app.StartAsync();
        Assert.Equal(AppPhase.Fatal, app.Phase);
        Assert.All(app.Tabs, t => Assert.False(t.IsEnabled));
        Assert.Same(app.Tabs[5], app.SelectedTab);
        Assert.False(app.IsStarting);
        // With every tab disabled, the view's selections stand.
        app.SelectedTab = app.Tabs[0];
        Assert.Same(app.Tabs[0], app.SelectedTab);
        app.SelectedTab = null;
        Assert.Null(app.SelectedTab);
    }

    [Fact]
    public void WhileStartingSelectingADisabledTabOrNothingKeepsHelpSelected()
    {
        var app = NewApp();
        app.SelectedTab = app.Tabs[0];
        Assert.Same(app.Tabs[5], app.SelectedTab);
        app.SelectedTab = app.Tabs[3];
        Assert.Same(app.Tabs[5], app.SelectedTab);
        app.SelectedTab = null;
        Assert.Same(app.Tabs[5], app.SelectedTab);
    }

    [Fact]
    public async Task TheTabsStayStartingWhileAppInitRuns()
    {
        var held = _fake.Hold(RpcMethod.AppInit);
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult([]));
        Fixtures.ScriptStartupReads(_fake);
        var app = NewApp();
        // The views bind these, so they must notify (order and count aside).
        var changed = new List<string?>();
        var signTabChanged = new List<string?>();
        app.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        app.Tabs[0].PropertyChanged += (_, e) => signTabChanged.Add(e.PropertyName);
        var starting = app.StartAsync();
        Assert.Equal(AppPhase.Starting, app.Phase);
        Assert.True(app.IsStarting);
        Assert.Equal([false, false, false, false, false, true], app.Tabs.Select(t => t.IsEnabled));
        Assert.Same(app.Tabs[5], app.SelectedTab);
        held.Release(Fixtures.OnlineInfo);
        await starting;
        Assert.Equal(AppPhase.Ready, app.Phase);
        Assert.False(app.IsStarting);
        Assert.Same(app.Tabs[0], app.SelectedTab);
        Assert.Contains(nameof(AppViewModel.IsStarting), changed);
        Assert.Contains(nameof(AppViewModel.SelectedTab), changed);
        Assert.Contains(nameof(AppTab.IsEnabled), signTabChanged);
    }

    [Fact]
    public void RequiresItsServices()
    {
        Assert.Throws<ArgumentNullException>(
            () => new AppViewModel(null!, _fileSave, _fileOpen, new FakeClipboard(), new FakeUrlOpener(), _confirm));
        Assert.Throws<ArgumentNullException>(
            () => new AppViewModel(_fake, null!, _fileOpen, new FakeClipboard(), new FakeUrlOpener(), _confirm));
        Assert.Throws<ArgumentNullException>(
            () => new AppViewModel(_fake, _fileSave, null!, new FakeClipboard(), new FakeUrlOpener(), _confirm));
        Assert.Throws<ArgumentNullException>(
            () => new AppViewModel(_fake, _fileSave, _fileOpen, null!, new FakeUrlOpener(), _confirm));
        Assert.Throws<ArgumentNullException>(
            () => new AppViewModel(_fake, _fileSave, _fileOpen, new FakeClipboard(), null!, _confirm));
        Assert.Throws<ArgumentNullException>(
            () => new AppViewModel(_fake, _fileSave, _fileOpen, new FakeClipboard(), new FakeUrlOpener(), null!));
    }

    [Fact]
    public async Task StartupInitHonorsLoginRegistryStartInOrderThenReadyWithTheStatusBar()
    {
        var app = NewApp();
        Assert.Equal(AppPhase.Starting, app.Phase);
        Assert.Empty(app.StatusItems);
        var changed = new List<string?>();
        app.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        _fake.Respond(RpcMethod.AppInit, Fixtures.OnlineInfo);
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult(["A", "B"]));
        var snapshot = Fixtures.Snapshot(1);
        Fixtures.ScriptStartupReads(_fake, Fixtures.LoggedIn, snapshot);
        await app.StartAsync("/data");
        Assert.Equal(AppPhase.Ready, app.Phase);
        Assert.Null(app.FatalMessage);
        Assert.Same(Fixtures.OnlineInfo, app.Info);
        Assert.Equal(["Core keys: three", "Core expired: one", "Core version 1.2.3"], app.StatusItems);
        Assert.Contains(nameof(AppViewModel.StatusItems), changed);
        Assert.Equal(["A", "B"], app.Sign.Honors);
        Assert.Equal(Fixtures.LoggedIn, app.Login.AuthState);
        Assert.Equal(Fixtures.RegistryColumns, app.Registry.Columns);
        Assert.Same(snapshot, app.Registry.Snapshot);
        Assert.Equal(RegistryViewModel.LoadedStatus, app.Registry.Status);
        Assert.Equal(
            [
                RpcMethod.AppInit, RpcMethod.SignHonors, RpcMethod.AuthState, RpcMethod.RegistryColumns,
                RpcMethod.RegistrySnapshot, RpcMethod.AppStart, RpcMethod.AuditCommits,
            ],
            _fake.Methods);
        Assert.Equal(["{\"dataDir\":\"/data\"}"], _fake.Params(RpcMethod.AppInit));
    }

    [Fact]
    public async Task TheStatusItemsAreTheCoresAsGivenOfflineToo()
    {
        _fake.Respond(RpcMethod.AppInit, new AppInfo(0, false, 0, "vv2", ["Core offline — ქ", "Core build vv2"]));
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult([]));
        Fixtures.ScriptStartupReads(_fake);
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

    [Theory]
    [InlineData(RpcMethod.AuthState)]
    [InlineData(RpcMethod.RegistryColumns)]
    [InlineData(RpcMethod.RegistrySnapshot)]
    public async Task AStartupReadFailureIsFatalAndAppStartIsNotCalled(string failing)
    {
        _fake.Respond(RpcMethod.AppInit, Fixtures.OnlineInfo);
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult(["Order of Queen Tamar"]));
        Fixtures.ScriptStartupReads(_fake);
        _fake.Reset(failing);
        _fake.Fail(failing, new RpcException(RpcErrorCode.Internal, "read broke"));
        var app = NewApp();
        await app.StartAsync();
        Assert.Equal(AppPhase.Fatal, app.Phase);
        Assert.Equal("read broke" + s_reportSuffix, app.FatalMessage);
        Assert.Equal(new AlertState(AlertState.ErrorTitle, app.FatalMessage!, OffersErrorLogExport: true), app.Alerts.Current);
        Assert.Equal(failing, _fake.Methods[^1]);
        Assert.Equal(0, _fake.Count(RpcMethod.AppStart));
        Assert.Equal(0, _fake.Count(RpcMethod.AuditCommits));
    }

    [Fact]
    public async Task AppStartFailureIsFatal()
    {
        _fake.Respond(RpcMethod.AppInit, Fixtures.OnlineInfo);
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult([]));
        Fixtures.ScriptStartupReads(_fake);
        _fake.Fail(RpcMethod.AppStart, new RpcException(RpcErrorCode.Input, "not initialized"));
        var app = NewApp();
        await app.StartAsync();
        Assert.Equal(AppPhase.Fatal, app.Phase);
        Assert.Equal("not initialized" + s_reportSuffix, app.FatalMessage);
        Assert.Equal(new AlertState(AlertState.ErrorTitle, app.FatalMessage!, OffersErrorLogExport: true), app.Alerts.Current);
        Assert.Equal(0, _fake.Count(RpcMethod.AuditCommits));
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
        Fixtures.ScriptStartupReads(_fake);
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
        await app.Alerts.DismissAsync();
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
    public async Task UpdatedNoticesBulkEventsOutsideARunAndUnknownEventsAreIgnored()
    {
        var app = await Fixtures.StartedApp(_fake);
        var callsBefore = _fake.Calls.Count;
        BridgeEvent[] ignored =
        [
            // No login is running: the code is not shown.
            new BridgeEvent.AuthDeviceCode(new DeviceCode("ABCD-1234", "https://github.com/login/device")),
            new BridgeEvent.BulkConnecting(),
            new BridgeEvent.BulkProgressed(new BulkProgress(1, 2, "A")),
            // Windows never updates in place, so it is never just updated.
            new BridgeEvent.UpdateUpdated(new UpdatedNotice("1.2.3", "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases")),
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
        Assert.Null(app.Login.DeviceCode);
        Assert.Null(app.UpdateBanner);
    }

    [Fact]
    public async Task TheDrainStartsWithStartupAndEndsWithTheEventChannel()
    {
        var app = NewApp();
        Assert.Null(app.EventLoop);
        _fake.Fail(RpcMethod.AppInit, new RpcException(RpcErrorCode.Failed, "x"));
        await app.StartAsync();
        await app.Alerts.DismissAsync(); // the fatal error's
        var loop = Assert.IsType<Task>(app.EventLoop, exactMatch: false);
        _fake.Emit(new BridgeEvent.AppInternalError());
        _fake.CompleteEvents();
        await loop.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal("An internal error occurred — please restart", app.Alerts.Current?.Message);
        Assert.Equal(AppPhase.Fatal, app.Phase);
    }

    [Fact]
    public async Task ACleanQuitShutsDownWithoutRelaunchAndAsksNothing()
    {
        _fake.Respond(RpcMethod.AppCanQuit, new CanQuitResult(false));
        var app = NewApp();
        Assert.True(await app.PrepareToQuitAsync());
        Assert.Equal([RpcMethod.AppCanQuit, RpcMethod.AppShutdown], _fake.Methods);
        Assert.Equal(["{\"relaunch\":false}"], _fake.Params(RpcMethod.AppShutdown));
        Assert.Empty(_confirm.Questions);
    }

    [Fact]
    public async Task CoreErrorsNeverBlockQuitting()
    {
        _fake.Fail(RpcMethod.AppCanQuit, new RpcException(RpcErrorCode.Internal, "x"));
        _fake.Fail(RpcMethod.AppShutdown, new RpcException(RpcErrorCode.Internal, "y"));
        var app = NewApp();
        Assert.True(await app.PrepareToQuitAsync());
        Assert.Equal([RpcMethod.AppCanQuit, RpcMethod.AppShutdown], _fake.Methods);
        Assert.Empty(_confirm.Questions);
    }

    [Fact]
    public async Task ABridgeFaultNeverBlocksQuittingEither()
    {
        // The fake throws InvalidOperationException for both.
        _fake.Respond(RpcMethod.AppCanQuit, "not the canQuit result");
        _fake.Respond(RpcMethod.AppShutdown, "not the shutdown result");
        var app = NewApp();
        Assert.True(await app.PrepareToQuitAsync());
        Assert.Equal([RpcMethod.AppCanQuit, RpcMethod.AppShutdown], _fake.Methods);
    }

    [Fact]
    public async Task ConcurrentAndLaterQuitsShareOneSequence()
    {
        var canQuit = _fake.Hold(RpcMethod.AppCanQuit);
        var held = _fake.Hold(RpcMethod.AppShutdown);
        _confirm.Answer(true);
        var app = NewApp();
        var first = app.PrepareToQuitAsync();
        var second = app.PrepareToQuitAsync();
        Assert.False(first.IsCompleted);
        Assert.False(second.IsCompleted);
        canQuit.Release(new CanQuitResult(true));
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.AppShutdown) == 1));
        Assert.False(first.IsCompleted);
        held.Release(Empty.Value);
        Assert.True(await first);
        Assert.True(await second);
        Assert.True(await app.PrepareToQuitAsync());
        Assert.Equal(1, _fake.Count(RpcMethod.AppCanQuit));
        Assert.Equal(1, _fake.Count(RpcMethod.AppShutdown));
        Assert.Single(_confirm.Questions);
    }

    [Fact]
    public async Task UnsubmittedEditsAskAndExitShutsDown()
    {
        _fake.Respond(RpcMethod.AppCanQuit, new CanQuitResult(true));
        _confirm.Answer(true);
        var app = NewApp();
        Assert.True(await app.PrepareToQuitAsync());
        Assert.Equal([AppViewModel.QuitConfirmation], _confirm.Questions);
        Assert.Equal([RpcMethod.AppCanQuit, RpcMethod.AppShutdown], _fake.Methods);
    }

    [Fact]
    public async Task KeepingUnsubmittedEditsKeepsTheAppRunningAndALaterQuitAsksAgain()
    {
        _fake.Respond(RpcMethod.AppCanQuit, new CanQuitResult(true));
        _confirm.Answer(false);
        _confirm.Answer(true);
        var app = NewApp();
        Assert.False(await app.PrepareToQuitAsync());
        Assert.Equal([RpcMethod.AppCanQuit], _fake.Methods);
        Assert.True(await app.PrepareToQuitAsync());
        Assert.Equal([RpcMethod.AppCanQuit, RpcMethod.AppCanQuit, RpcMethod.AppShutdown], _fake.Methods);
        Assert.Equal([AppViewModel.QuitConfirmation, AppViewModel.QuitConfirmation], _confirm.Questions);
    }

    [Fact]
    public async Task ConcurrentQuitsKeepingTheEditsBothKeepTheAppRunning()
    {
        var canQuit = _fake.Hold(RpcMethod.AppCanQuit);
        var app = NewApp();
        var first = app.PrepareToQuitAsync();
        var second = app.PrepareToQuitAsync();
        canQuit.Release(new CanQuitResult(true));
        Assert.False(await first);
        Assert.False(await second);
        Assert.Single(_confirm.Questions);
        Assert.Equal(0, _fake.Count(RpcMethod.AppShutdown));
    }

    [Fact]
    public async Task AuthChangedRereadsTheLoginStateWhateverItsPayload()
    {
        var app = await Fixtures.StartedApp(_fake);
        _fake.Respond(RpcMethod.AuthState, Fixtures.LoggedIn);
        _fake.Emit(new BridgeEvent.AuthChanged(Fixtures.LoggedOut));
        Assert.True(await Fixtures.Settle(() => app.Login.AuthState == Fixtures.LoggedIn));
        Assert.Equal(2, _fake.Count(RpcMethod.AuthState));
    }

    [Fact]
    public async Task AuthAndRegistryEventsReachTheLoginAndTheRegistryTab()
    {
        var app = await Fixtures.StartedApp(_fake);
        app.Registry.SelectCell(0, 1);
        Assert.NotNull(app.Registry.SelectedCell);
        var snapshot = Fixtures.Snapshot(3);
        _fake.Respond(RpcMethod.RegistrySnapshot, snapshot);
        var held = _fake.Hold(RpcMethod.AuthLogin);
        var login = app.Login.StartAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.AuthLogin) == 1));
        // Login status texts land on the Registry tab's status line.
        Assert.Equal(LoginViewModel.RequestingCodeStatus, app.Registry.Status);
        _fake.Emit(new BridgeEvent.AuthDeviceCode(new DeviceCode("ABCD-1234", "https://github.com/login/device")));
        Assert.True(await Fixtures.Settle(() => app.Login.DeviceCode is not null));
        Assert.Equal("ABCD-1234", app.Login.DeviceCode!.UserCode);
        _fake.Emit(new BridgeEvent.RegistryChanged());
        Assert.True(await Fixtures.Settle(() => app.Registry.Snapshot == snapshot));
        Assert.Null(app.Registry.SelectedCell);
        Assert.Equal(RegistryViewModel.LoadedStatus, app.Registry.Status);
        held.Release(Fixtures.LoggedIn);
        await login;
        Assert.Equal("Logged in as @octocat", app.Registry.Status);
        Assert.Null(app.Alerts.Current);
    }

    [Fact]
    public async Task AFailingReReadShowsTheRestartAlertAndTheDrainGoesOn()
    {
        var app = await Fixtures.StartedApp(_fake);
        var fail = true;
        app.Login.PropertyChanged += (_, _) =>
        {
            if (fail)
            {
                fail = false;
                throw new InvalidOperationException("a view handler failed");
            }
        };
        _fake.Respond(RpcMethod.AuthState, Fixtures.LoggedIn);
        _fake.Emit(new BridgeEvent.AuthChanged(Fixtures.LoggedIn));
        Assert.True(await Fixtures.Settle(() => app.Alerts.Current is not null));
        Assert.Equal(new AlertState("Error", "An internal error occurred — please restart"), app.Alerts.Current);
        _fake.Emit(new BridgeEvent.PinRequested(new PinRequest(5, false, 8)));
        Assert.True(await Fixtures.Settle(() => app.PinPrompt.Request?.RequestId == 5));
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
        await app.Alerts.DismissAsync(); // as the host does before exporting from it
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

    // History, Audit and the update banner

    private const string ReleaseUrl = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/tag/v1.3.0";

    private static HistoryListResult HistoryList(int count, bool loadFailed = false)
    {
        var rows = Enumerable.Range(1, count)
            .Select(n => new HistoryRow(
                new HistoryRecord($"2026-01-{n:D2}T10:00:00Z", $"R{n}", "Order of the Eagle", "", $"2026-01-{n:D2}", $"h{n}", $"s{n}"),
                $"R{n}",
                false))
            .ToList();
        return new HistoryListResult(
            Rows: rows, LoadFailed: loadFailed, RevocationsUnavailable: false, RevocationsLoaded: true, RevokeAvailable: true);
    }

    /// <summary>A started app whose History shows <paramref name="count"/> rows with the first selected.</summary>
    private async Task<AppViewModel> AppWithHistorySelection(int count)
    {
        var app = await Fixtures.StartedApp(_fake);
        _fake.Respond(RpcMethod.HistoryList, HistoryList(count));
        _fake.Emit(new BridgeEvent.HistoryChanged());
        Assert.True(await Fixtures.Settle(() => app.History.Snapshot.Rows.Count == count));
        _fake.Reset(RpcMethod.HistoryList);
        _fake.Respond(RpcMethod.HistoryRecordText, new RecordTextResult("detail", "revoke?", "delete?", OfferRevoke: true));
        await app.History.SelectAsync(0);
        Assert.Equal("detail", app.History.SelectedDetail);
        return app;
    }

    [Fact]
    public async Task TheAuditTabFetchesItsCommitsOnceReady()
    {
        _fake.Respond(RpcMethod.AuditCommits, new AuditResult([new AuditRow("Add key", "")], "1 commit"));
        var app = await Fixtures.StartedApp(_fake);
        Assert.True(await Fixtures.Settle(() => app.Audit.Status == "1 commit"));
        Assert.Single(app.Audit.Rows);
        Assert.Equal(1, _fake.Count(RpcMethod.AuditCommits));
    }

    [Fact]
    public async Task ASlowAuditFetchDoesNotHoldStartup()
    {
        var held = _fake.Hold(RpcMethod.AuditCommits);
        var app = await Fixtures.StartedApp(_fake);
        Assert.Equal(AppPhase.Ready, app.Phase);
        Assert.True(app.Audit.IsRefreshing);
        Assert.Equal(AuditViewModel.FetchingStatus, app.Audit.Status);
        held.Release(new AuditResult([], "No commits"));
        Assert.True(await Fixtures.Settle(() => !app.Audit.IsRefreshing));
        Assert.Equal("No commits", app.Audit.Status);
    }

    [Fact]
    public async Task HistoryChangedClearsTheSelectionAndReReadsTheLog()
    {
        var app = await AppWithHistorySelection(2);
        var list = HistoryList(3);
        _fake.Respond(RpcMethod.HistoryList, list);
        _fake.Emit(new BridgeEvent.HistoryChanged());
        Assert.True(await Fixtures.Settle(() => ReferenceEquals(app.History.Snapshot, list)));
        Assert.Null(app.History.SelectedIndex);
        Assert.Null(app.History.SelectedDetail);
        Assert.Equal(["{\"query\":\"\"}", "{\"query\":\"\"}"], _fake.Params(RpcMethod.HistoryList));
    }

    [Fact]
    public async Task HistoryChangedReportsALogThatFailedToLoad()
    {
        var app = await Fixtures.StartedApp(_fake);
        _fake.Respond(RpcMethod.HistoryList, HistoryList(0, loadFailed: true));
        _fake.Emit(new BridgeEvent.HistoryChanged());
        Assert.True(await Fixtures.Settle(() => app.Alerts.Current is not null));
        Assert.Equal(new AlertState("Error", "unable to load history"), app.Alerts.Current);
    }

    [Fact]
    public async Task RevocationsChangedReReadsTheLogKeepingTheSelection()
    {
        var app = await AppWithHistorySelection(2);
        // The same rows; only the flags change, so the read is applied.
        var list = HistoryList(2) with { RevokeAvailable = false };
        var reads = _fake.Count(RpcMethod.HistoryList);
        _fake.Respond(RpcMethod.HistoryList, list);
        _fake.Emit(new BridgeEvent.HistoryRevocationsChanged());
        Assert.True(await Fixtures.Settle(() => ReferenceEquals(app.History.Snapshot, list)));
        Assert.Equal(reads + 1, _fake.Count(RpcMethod.HistoryList));
        Assert.Equal(0, app.History.SelectedIndex);
        Assert.Equal("detail", app.History.SelectedDetail);
        // The kept row's record is unchanged: its detail is not asked for again.
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryRecordText));
    }

    [Fact]
    public async Task AuthChangedReReadsTheLogToo()
    {
        var app = await Fixtures.StartedApp(_fake);
        _fake.Respond(RpcMethod.AuthState, Fixtures.LoggedIn);
        var list = HistoryList(1);
        _fake.Respond(RpcMethod.HistoryList, list);
        _fake.Emit(new BridgeEvent.AuthChanged(Fixtures.LoggedIn));
        Assert.True(await Fixtures.Settle(() => ReferenceEquals(app.History.Snapshot, list)));
        Assert.True(await Fixtures.Settle(() => app.Login.AuthState == Fixtures.LoggedIn));
    }

    [Fact]
    public async Task LoginStatusTextsReachTheRegistryAndHistoryStatusLines()
    {
        var app = await Fixtures.StartedApp(_fake);
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedIn);
        await app.Login.StartAsync();
        Assert.Equal("Logged in as @octocat", app.Registry.Status);
        Assert.Equal("Logged in as @octocat", app.History.Status);
    }

    [Fact]
    public async Task UpdateStatusSetsAndClearsTheBanner()
    {
        var app = await Fixtures.StartedApp(_fake);
        var changed = new List<string?>();
        app.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        _fake.Emit(new BridgeEvent.UpdateStatusChanged(new UpdateStatus(UpdateState.ManualOnly, "1.3.0", ReleaseUrl, false)));
        Assert.True(await Fixtures.Settle(() => app.UpdateBanner is not null));
        Assert.Equal(new UpdateBanner("Version 1.3.0 is available —", new Uri(ReleaseUrl)), app.UpdateBanner);
        Assert.Contains(nameof(AppViewModel.UpdateBanner), changed);
        _fake.Emit(new BridgeEvent.UpdateStatusChanged(new UpdateStatus(UpdateState.Idle, "", "", false)));
        Assert.True(await Fixtures.Settle(() => app.UpdateBanner is null));
    }

    [Fact]
    public async Task DownloadOpensTheReleasePage()
    {
        var urls = new FakeUrlOpener();
        var app = await Fixtures.StartedApp(_fake, urls: urls);
        app.OpenReleaseCommand.Execute(null); // no banner: nothing
        Assert.Empty(urls.Opened);
        _fake.Emit(new BridgeEvent.UpdateStatusChanged(new UpdateStatus(UpdateState.ManualOnly, "1.3.0", ReleaseUrl, false)));
        Assert.True(await Fixtures.Settle(() => app.UpdateBanner is not null));
        app.OpenReleaseCommand.Execute(null);
        Assert.Equal([new Uri(ReleaseUrl)], urls.Opened);
        Assert.Null(app.Alerts.Current);
    }

    [Fact]
    public async Task ABrowserThatFailsToOpenTheReleaseShowsAnErrorAlert()
    {
        var urls = new FakeUrlOpener { Failure = "Could not open the browser." };
        var app = await Fixtures.StartedApp(_fake, urls: urls);
        _fake.Emit(new BridgeEvent.UpdateStatusChanged(new UpdateStatus(UpdateState.ManualOnly, "1.3.0", ReleaseUrl, false)));
        Assert.True(await Fixtures.Settle(() => app.UpdateBanner is not null));
        app.OpenReleaseCommand.Execute(null);
        Assert.Equal(new AlertState("Error", "Could not open the browser."), app.Alerts.Current);
    }
}
