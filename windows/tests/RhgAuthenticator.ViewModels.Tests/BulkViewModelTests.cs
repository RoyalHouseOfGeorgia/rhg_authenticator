using System.Text;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class BulkViewModelTests
{
    private readonly FakeBridge _fake = new();
    private readonly FakeFileOpen _fileOpen = new();
    private readonly FakeFileSave _fileSave = new();
    private readonly AlertQueue _alerts = new();
    private bool _signing;

    private BulkViewModel NewModel()
    {
        return new BulkViewModel(_fake, _fileOpen, _fileSave, _alerts, () => _signing);
    }

    /// <summary>A model in <see cref="BulkPhase.Confirming"/> for <see cref="Fixtures.BulkPlan"/>.</summary>
    private async Task<BulkViewModel> ConfirmingModel()
    {
        _fake.Respond(RpcMethod.BulkLoad, Fixtures.BulkPlan());
        _fileOpen.Answer("/in/x.csv");
        var model = NewModel();
        await model.BulkSignCommand.ExecuteAsync(null);
        Assert.Equal(BulkPhase.Confirming, model.Phase);
        return model;
    }

    /// <summary>A model showing the results of a plan with nothing to sign.</summary>
    private async Task<BulkViewModel> ResultsModel()
    {
        _fake.Respond(RpcMethod.BulkLoad, Fixtures.BulkPlan(0));
        _fake.Respond(RpcMethod.BulkRun, Fixtures.BulkOutcome());
        _fileOpen.Answer("/in/done.csv");
        var model = NewModel();
        await model.BulkSignCommand.ExecuteAsync(null);
        Assert.Equal(BulkPhase.Results, model.Phase);
        return model;
    }

    private static void AssertShows(BulkViewModel model, bool dialog, bool confirming, bool running, bool results)
    {
        Assert.Equal(
            (dialog, confirming, running, results),
            (model.IsShowingDialog, model.IsConfirming, model.IsRunning, model.IsShowingResults));
    }

    [Fact]
    public void CopyMatchesTheFyneApp()
    {
        Assert.Equal([.. "Bulk Sign from File"u8, 0xE2, 0x80, 0xA6], Encoding.UTF8.GetBytes(BulkViewModel.BulkSignTitle));
        Assert.Equal(
            ["Bulk Sign", "Sign", "Cancel"], [BulkViewModel.Title, BulkViewModel.SignTitle, BulkViewModel.CancelTitle]);
        Assert.Equal("First names to be signed:", BulkViewModel.PreviewHeading);
        Assert.Equal("Invalid rows (will be skipped):", BulkViewModel.InvalidToSkipHeading);
        Assert.Equal(
            [.. "Bulk Sign "u8, 0xE2, 0x80, 0x94, .. " Results"u8], Encoding.UTF8.GetBytes(BulkViewModel.ResultsTitle));
        Assert.Equal("Failed rows:", BulkViewModel.FailedHeading);
        Assert.Equal("Invalid rows (skipped):", BulkViewModel.InvalidSkippedHeading);
        Assert.Equal([.. "Export Results CSV"u8, 0xE2, 0x80, 0xA6], Encoding.UTF8.GetBytes(BulkViewModel.ExportTitle));
        Assert.Equal("Re-open the same file to regenerate results later.", BulkViewModel.RegenerateNote);
        Assert.Equal("Close", BulkViewModel.CloseTitle);
        Assert.Equal("Connecting to YubiKey...", BulkViewModel.ConnectingLabel);
        Assert.Equal(
            [.. "Stopping after current row"u8, 0xE2, 0x80, 0xA6], Encoding.UTF8.GetBytes(BulkViewModel.StoppingLabel));
    }

    [Fact]
    public void RequiresItsServices()
    {
        Func<bool> idle = () => false;
        Assert.Throws<ArgumentNullException>(() => new BulkViewModel(null!, _fileOpen, _fileSave, _alerts, idle));
        Assert.Throws<ArgumentNullException>(() => new BulkViewModel(_fake, null!, _fileSave, _alerts, idle));
        Assert.Throws<ArgumentNullException>(() => new BulkViewModel(_fake, _fileOpen, null!, _alerts, idle));
        Assert.Throws<ArgumentNullException>(() => new BulkViewModel(_fake, _fileOpen, _fileSave, null!, idle));
        Assert.Throws<ArgumentNullException>(() => new BulkViewModel(_fake, _fileOpen, _fileSave, _alerts, null!));
    }

    [Fact]
    public async Task HappyPathLoadConfirmRunWithProgressResultsClose()
    {
        var plan = Fixtures.BulkPlan();
        var loadHeld = _fake.Hold(RpcMethod.BulkLoad);
        var runHeld = _fake.Hold(RpcMethod.BulkRun);
        _fileOpen.Answer("/in/bulk.csv");
        var model = NewModel();
        var changed = new List<string?>();
        model.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        Assert.Equal(BulkPhase.Idle, model.Phase);
        Assert.False(model.IsActive);
        AssertShows(model, dialog: false, confirming: false, running: false, results: false);
        Assert.True(model.BulkSignCommand.CanExecute(null));
        Assert.Null(model.Plan);
        Assert.False(model.HasInvalidLines);

        var loading = model.BulkSignCommand.ExecuteAsync(null);
        Assert.Equal(["csv"], _fileOpen.Requests);
        Assert.Equal(BulkPhase.Loading, model.Phase);
        Assert.True(model.IsActive);
        AssertShows(model, dialog: false, confirming: false, running: false, results: false);
        Assert.False(model.BulkSignCommand.CanExecute(null));
        loadHeld.Release(plan);
        await loading;
        Assert.Equal(BulkPhase.Confirming, model.Phase);
        AssertShows(model, dialog: true, confirming: true, running: false, results: false);
        Assert.Same(plan, model.Plan);
        Assert.Equal("Bulk Sign", model.DialogTitle);
        Assert.True(model.HasInvalidLines);
        Assert.Equal(["{\"path\":\"/in/bulk.csv\"}"], _fake.Params(RpcMethod.BulkLoad));
        Assert.Equal("", model.SuggestedResultsFilename);
        Assert.True(model.ConfirmCommand.CanExecute(null));
        Assert.True(model.CancelConfirmCommand.CanExecute(null));
        Assert.False(model.CancelRunCommand.CanExecute(null));
        Assert.False(model.IsCancelEnabled);

        var running = model.ConfirmCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.BulkRun) == 1));
        Assert.Equal(BulkPhase.Running, model.Phase);
        AssertShows(model, dialog: true, confirming: false, running: true, results: false);
        Assert.Null(model.Progress);
        Assert.False(model.IsStopping);
        Assert.Equal("Connecting to YubiKey...", model.ProgressLabel);
        Assert.Equal(0, model.ProgressFraction);
        Assert.True(model.IsCancelEnabled);
        Assert.True(model.CancelRunCommand.CanExecute(null));
        Assert.False(model.ConfirmCommand.CanExecute(null));

        model.OnBulkProgress(new BulkProgress(0, 2, "Jane Doe"));
        Assert.Equal("Signing 1 of 2: Jane Doe — touch your YubiKey if it is blinking", model.ProgressLabel);
        Assert.Equal(0, model.ProgressFraction);
        model.OnBulkProgress(new BulkProgress(1, 2, "Carol White"));
        Assert.Equal("Signing 2 of 2: Carol White — touch your YubiKey if it is blinking", model.ProgressLabel);
        Assert.Equal(0.5, model.ProgressFraction);

        var outcome = Fixtures.BulkOutcome(failed: ["line 3: Carol White: card removed"]);
        runHeld.Release(outcome);
        await running;
        Assert.Equal(BulkPhase.Results, model.Phase);
        AssertShows(model, dialog: true, confirming: false, running: false, results: true);
        Assert.Same(plan, model.Plan);
        Assert.Same(outcome, model.Outcome);
        Assert.Equal("Bulk Sign — Results", model.DialogTitle);
        Assert.True(model.HasFailedLines);
        Assert.Equal("rhg-bulk-results-2026-01-02-030405.csv", model.SuggestedResultsFilename);
        Assert.False(model.IsCancelEnabled);
        Assert.True(model.CloseResultsCommand.CanExecute(null));
        Assert.True(model.ExportResultsCommand.CanExecute(null));
        Assert.Null(_alerts.Current);
        Assert.Equal(0, _fake.Count(RpcMethod.BulkCancel));
        Assert.Equal(["{}"], _fake.Params(RpcMethod.BulkRun));

        model.CloseResultsCommand.Execute(null);
        Assert.Equal(BulkPhase.Idle, model.Phase);
        Assert.False(model.IsActive);
        AssertShows(model, dialog: false, confirming: false, running: false, results: false);
        Assert.Null(model.Plan);
        Assert.Null(model.Outcome);
        Assert.Null(model.Progress);
        Assert.False(model.HasFailedLines);
        Assert.False(model.HasInvalidLines);
        Assert.Equal("", model.SuggestedResultsFilename);
        Assert.True(model.BulkSignCommand.CanExecute(null));

        // Every derived property a view binds to was announced.
        string[] derived =
        [
            nameof(BulkViewModel.IsActive), nameof(BulkViewModel.IsShowingDialog), nameof(BulkViewModel.IsConfirming),
            nameof(BulkViewModel.IsRunning), nameof(BulkViewModel.IsShowingResults), nameof(BulkViewModel.DialogTitle),
            nameof(BulkViewModel.IsCancelEnabled), nameof(BulkViewModel.SuggestedResultsFilename),
            nameof(BulkViewModel.Plan), nameof(BulkViewModel.Outcome),
            nameof(BulkViewModel.HasInvalidLines), nameof(BulkViewModel.HasFailedLines), nameof(BulkViewModel.ProgressLabel),
            nameof(BulkViewModel.ProgressFraction),
        ];
        Assert.All(derived, name => Assert.Contains(name, changed));
    }

    [Fact]
    public async Task NothingToSignRunsAtOnceWithoutTheDialog()
    {
        // A file with nothing to sign and no invalid rows: neither row list shows.
        var plan = Fixtures.BulkPlan(0, invalid: []);
        _fake.Respond(RpcMethod.BulkLoad, plan);
        var held = _fake.Hold(RpcMethod.BulkRun);
        _fileOpen.Answer("/in/done.csv");
        var model = NewModel();
        var loading = model.BulkSignCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.BulkRun) == 1));
        Assert.Equal(BulkPhase.Loading, model.Phase);
        Assert.True(model.IsActive);
        Assert.False(model.IsShowingDialog);
        await model.CancelRunCommand.ExecuteAsync(null); // no progress dialog, no Cancel
        var outcome = Fixtures.BulkOutcome();
        held.Release(outcome);
        await loading;
        Assert.Equal(BulkPhase.Results, model.Phase);
        Assert.Same(plan, model.Plan);
        Assert.Same(outcome, model.Outcome);
        Assert.Empty(outcome.FailedLines);
        Assert.False(model.HasInvalidLines);
        Assert.False(model.HasFailedLines);
        Assert.Equal([RpcMethod.BulkLoad, RpcMethod.BulkRun], _fake.Methods);
    }

    [Fact]
    public async Task NothingToSignRunErrorEndsTheFlowThenShowsTheAlert()
    {
        _fake.Respond(RpcMethod.BulkLoad, Fixtures.BulkPlan(0));
        _fake.Fail(RpcMethod.BulkRun, new RpcException(RpcErrorCode.Busy, "Another operation is in progress."));
        _fileOpen.Answer("/in/done.csv");
        var model = NewModel();
        await model.BulkSignCommand.ExecuteAsync(null);
        Assert.Equal(BulkPhase.Idle, model.Phase);
        Assert.Null(model.Plan);
        Assert.Equal(new AlertState("Error", "Another operation is in progress."), _alerts.Current);
    }

    [Fact]
    public async Task ALoadErrorShowsTheCoresMessageAndEndsTheFlow()
    {
        _fake.Fail(RpcMethod.BulkLoad, new RpcException(RpcErrorCode.Failed, "Could not open the CSV file."));
        _fileOpen.Answer("/in/x.csv");
        var model = NewModel();
        await model.BulkSignCommand.ExecuteAsync(null);
        Assert.Equal(BulkPhase.Idle, model.Phase);
        Assert.False(model.IsActive);
        Assert.Equal(new AlertState("Error", "Could not open the CSV file."), _alerts.Current);
        Assert.Equal(0, _fake.Count(RpcMethod.BulkRun));
    }

    [Fact]
    public async Task ARunErrorClosesTheDialogBeforeItsAlertShows()
    {
        var model = await ConfirmingModel();
        _fake.Fail(
            RpcMethod.BulkRun,
            new RpcException(
                RpcErrorCode.Failed, "Registry unavailable — cannot sign offline.", offerReport: true, reportId: "9"));
        var phaseWhenShown = (BulkPhase?)null;
        _alerts.PropertyChanged += (_, _) => phaseWhenShown ??= model.Phase;
        await model.ConfirmCommand.ExecuteAsync(null);
        Assert.Equal(BulkPhase.Idle, phaseWhenShown);
        Assert.Equal(BulkPhase.Idle, model.Phase);
        Assert.False(model.IsShowingDialog);
        Assert.Null(model.Plan);
        // No report is offered.
        Assert.Equal(new AlertState("Error", "Registry unavailable — cannot sign offline."), _alerts.Current);
        await model.CancelRunCommand.ExecuteAsync(null); // the run is over: nothing to cancel
        Assert.Equal(0, _fake.Count(RpcMethod.BulkCancel));
    }

    [Fact]
    public async Task CancelMidRunStopsAfterTheCurrentRowAndShowsTheCancelledResults()
    {
        var model = await ConfirmingModel();
        var held = _fake.Hold(RpcMethod.BulkRun);
        var running = model.ConfirmCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.BulkRun) == 1));
        model.OnBulkProgress(new BulkProgress(0, 3, "Jane Doe"));

        await model.CancelRunCommand.ExecuteAsync(null);
        Assert.Equal(1, _fake.Count(RpcMethod.BulkCancel));
        Assert.True(model.IsStopping);
        Assert.Equal("Stopping after current row…", model.ProgressLabel);
        Assert.False(model.IsCancelEnabled);
        Assert.False(model.CancelRunCommand.CanExecute(null));
        await model.CancelRunCommand.ExecuteAsync(null); // ignored while stopping
        Assert.Equal(1, _fake.Count(RpcMethod.BulkCancel));

        model.OnBulkProgress(new BulkProgress(1, 3, "Carol White"));
        Assert.Equal("Stopping after current row…", model.ProgressLabel);
        Assert.Equal(1.0 / 3.0, model.ProgressFraction, 9);

        var outcome = Fixtures.BulkOutcome(BulkStop.Cancelled, "Cancelled.");
        held.Release(outcome);
        await running;
        Assert.Equal(BulkPhase.Results, model.Phase);
        Assert.Equal("Cancelled.", model.Outcome?.StopMessage);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task ABulkCancelFailureIsIgnored()
    {
        var model = await ConfirmingModel();
        _fake.Fail(RpcMethod.BulkCancel, new RpcException(RpcErrorCode.Internal, "x"));
        var held = _fake.Hold(RpcMethod.BulkRun);
        var running = model.ConfirmCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.BulkRun) == 1));
        await model.CancelRunCommand.ExecuteAsync(null);
        Assert.True(model.IsStopping);
        Assert.Null(_alerts.Current);
        held.Release(Fixtures.BulkOutcome(BulkStop.Cancelled));
        await running;
        Assert.Null(_alerts.Current);
        Assert.Equal(BulkPhase.Results, model.Phase);
    }

    [Fact]
    public async Task ProgressOutsideARunIsIgnored()
    {
        var model = NewModel();
        model.OnBulkProgress(new BulkProgress(0, 2, "Jane Doe"));
        Assert.Null(model.Progress);

        model = await ResultsModel();
        model.OnBulkProgress(new BulkProgress(1, 2, "Carol White"));
        Assert.Null(model.Progress);
        Assert.Equal(BulkPhase.Results, model.Phase);
    }

    [Fact]
    public async Task AProgressFractionWithTotalZeroIsZero()
    {
        var model = await ConfirmingModel();
        var held = _fake.Hold(RpcMethod.BulkRun);
        var running = model.ConfirmCommand.ExecuteAsync(null);
        model.OnBulkProgress(new BulkProgress(0, 0, ""));
        Assert.NotNull(model.Progress);
        Assert.Equal(0, model.ProgressFraction);
        held.Release(Fixtures.BulkOutcome());
        await running;
    }

    [Fact]
    public async Task DialogAndConfirmCancelsEndTheFlowWithoutCallingTheCore()
    {
        var model = NewModel();
        await model.BulkSignCommand.ExecuteAsync(null); // the dialog answers null: cancelled
        Assert.Equal(["csv"], _fileOpen.Requests);
        Assert.Equal(BulkPhase.Idle, model.Phase);
        Assert.Empty(_fake.Calls);

        _fake.Respond(RpcMethod.BulkLoad, Fixtures.BulkPlan());
        _fileOpen.Answer("/in/x.csv");
        await model.BulkSignCommand.ExecuteAsync(null);
        model.CancelConfirmCommand.Execute(null);
        Assert.Equal(BulkPhase.Idle, model.Phase);
        Assert.Null(model.Plan);
        Assert.Equal([RpcMethod.BulkLoad], _fake.Methods);
    }

    [Fact]
    public async Task ThePhaseIsChoosingFileWhileTheDialogIsOpen()
    {
        BulkViewModel? model = null;
        BulkPhase? phaseInDialog = null;
        bool? activeInDialog = null;
        var fileOpen = new CallbackFileOpen(() =>
        {
            phaseInDialog = model!.Phase;
            activeInDialog = model.IsActive;
        });
        model = new BulkViewModel(_fake, fileOpen, _fileSave, _alerts, () => false);
        await model.BulkSignCommand.ExecuteAsync(null);
        Assert.Equal(BulkPhase.ChoosingFile, phaseInDialog);
        Assert.True(activeInDialog);
        Assert.Equal(BulkPhase.Idle, model.Phase);
    }

    [Fact]
    public async Task ActionsOutOfTheirPhaseAreIgnored()
    {
        var model = NewModel();
        await model.ConfirmCommand.ExecuteAsync(null);
        await model.CancelRunCommand.ExecuteAsync(null);
        model.CancelConfirmCommand.Execute(null);
        model.CloseResultsCommand.Execute(null);
        await model.ExportResultsCommand.ExecuteAsync(null);
        Assert.Equal(BulkPhase.Idle, model.Phase);
        Assert.Empty(_fake.Calls);
        Assert.Empty(_fileSave.Requests);
        Assert.False(model.ConfirmCommand.CanExecute(null));
        Assert.False(model.CancelConfirmCommand.CanExecute(null));
        Assert.False(model.CloseResultsCommand.CanExecute(null));
        Assert.False(model.ExportResultsCommand.CanExecute(null));

        model = await ConfirmingModel();
        await model.BulkSignCommand.ExecuteAsync(null); // under way
        model.CloseResultsCommand.Execute(null);
        Assert.Equal(BulkPhase.Confirming, model.Phase);
        Assert.Equal(1, _fake.Count(RpcMethod.BulkLoad));
        Assert.Single(_fileOpen.Requests);
    }

    [Fact]
    public async Task BulkSignIsIgnoredWhileASigningIsBusy()
    {
        _signing = true;
        var model = NewModel();
        Assert.False(model.BulkSignCommand.CanExecute(null));
        await model.BulkSignCommand.ExecuteAsync(null);
        Assert.Equal(BulkPhase.Idle, model.Phase);
        Assert.Empty(_fileOpen.Requests);
        _signing = false;
        Assert.True(model.BulkSignCommand.CanExecute(null));
    }

    [Fact]
    public async Task ExportSendsTheChosenPathAndSuccessShowsNothing()
    {
        var model = await ResultsModel();
        _fileSave.Answer("/out/results.csv");
        await model.ExportResultsCommand.ExecuteAsync(null);
        Assert.Equal([("rhg-bulk-results-2026-01-02-030405.csv", "csv")], _fileSave.Requests);
        Assert.Equal(["{\"path\":\"/out/results.csv\"}"], _fake.Params(RpcMethod.BulkExportResults));
        Assert.Null(_alerts.Current);
        Assert.Equal(BulkPhase.Results, model.Phase);
    }

    [Fact]
    public async Task ACancelledExportDialogDoesNothing()
    {
        var model = await ResultsModel();
        await model.ExportResultsCommand.ExecuteAsync(null);
        Assert.Single(_fileSave.Requests);
        Assert.Equal(0, _fake.Count(RpcMethod.BulkExportResults));
    }

    [Fact]
    public async Task AnExportFailureShowsTheCoresMessageAndTheResultsStay()
    {
        var model = await ResultsModel();
        _fake.Fail(RpcMethod.BulkExportResults, new RpcException(RpcErrorCode.Busy, "Another YubiKey operation is running."));
        _fileSave.Answer("/out/results.csv");
        await model.ExportResultsCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Error", "Another YubiKey operation is running."), _alerts.Current);
        Assert.Equal(BulkPhase.Results, model.Phase);
    }

    /// <summary>An open dialog that runs <paramref name="onOpen"/>, then is cancelled.</summary>
    private sealed class CallbackFileOpen(Action onOpen) : IFileOpenService
    {
        public string? ChooseOpenPath(params string[] extensions)
        {
            onOpen();
            return null;
        }
    }
}
