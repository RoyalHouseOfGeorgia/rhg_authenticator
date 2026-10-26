using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class RegistryViewModelTests
{
    private const string PrUrl = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/pull/42";

    private readonly FakeBridge _fake = new();
    private readonly FakeConfirm _confirm = new();
    private readonly FakeFileOpen _fileOpen = new();
    private readonly FakeUrlOpener _urls = new();
    private readonly AlertQueue _alerts = new();

    private RegistryViewModel NewModel()
    {
        var login = new LoginViewModel(_fake, _confirm, new FakeClipboard(), _urls, _alerts);
        return new RegistryViewModel(_fake, login, _confirm, _fileOpen, _urls, _alerts, new FixedClock(Fixtures.LateNewYearsDay));
    }

    /// <summary>A loaded model over <paramref name="snapshot"/> (default two entries); later reads answer from each test's own script.</summary>
    private async Task<RegistryViewModel> Loaded(RegistrySnapshot? snapshot = null)
    {
        _fake.Respond(RpcMethod.RegistryColumns, new ColumnsResult(Fixtures.RegistryColumns));
        _fake.Respond(RpcMethod.RegistrySnapshot, snapshot ?? Fixtures.Snapshot(2));
        var registry = NewModel();
        await registry.LoadAsync();
        _fake.Reset(RpcMethod.RegistrySnapshot);
        return registry;
    }

    [Fact]
    public void Copy()
    {
        Assert.Equal("Fetch from Server", RegistryViewModel.FetchTitle);
        Assert.Equal("Fetch from Server (F5)", RegistryViewModel.FetchTooltip);
        Assert.Equal("Submit for Review", RegistryViewModel.SubmitTitle);
        Assert.Equal(["Add Entry", "Edit Entry"], [RegistryViewModel.AddEntryTitle, RegistryViewModel.EditEntryTitle]);
        Assert.Equal("Select an entry to edit it.", RegistryViewModel.EditEntryTooltip);
        Assert.Equal(
            ["Loaded from registry server", "Fetching...", "Failed to load registry"],
            [RegistryViewModel.LoadedStatus, RegistryViewModel.FetchingStatus, RegistryViewModel.LoadFailedStatus]);
        Assert.Equal(
            new Confirmation(
                "Discard Local Edits?",
                "This will re-fetch the live registry from the server, discarding your local edits. Continue?",
                "Discard and Fetch",
                "Cancel",
                IsDestructive: true),
            RegistryViewModel.DiscardConfirmation);
    }

    [Fact]
    public void ANewModelIsEmptyAndNotLoaded()
    {
        var registry = NewModel();
        Assert.Empty(registry.Columns);
        Assert.Empty(registry.Snapshot.Entries);
        Assert.False(registry.Snapshot.Loaded);
        Assert.Null(registry.SelectedCell);
        Assert.Equal("", registry.Status);
        Assert.Null(registry.EntryForm);
        Assert.False(registry.EditEntryCommand.CanExecute(null));
        Assert.False(registry.SubmitForReviewCommand.CanExecute(null));
    }

    [Fact]
    public async Task LoadBeforeTheRegistryArrivedSaysFetching()
    {
        var registry = await Loaded(Fixtures.Snapshot(0, loaded: false));
        Assert.Equal("Fetching...", registry.Status);
    }

    [Fact]
    public async Task LoadIsNewerThanASnapshotReadStillRunning()
    {
        var registry = NewModel();
        var older = _fake.Hold(RpcMethod.RegistrySnapshot);
        var snapshot = Fixtures.Snapshot(2);
        _fake.Respond(RpcMethod.RegistrySnapshot, snapshot);
        _fake.Respond(RpcMethod.RegistryColumns, new ColumnsResult(Fixtures.RegistryColumns));
        var pending = registry.RegistryChangedAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.RegistrySnapshot) == 1));
        await registry.LoadAsync();
        older.Release(Fixtures.Snapshot(0, loaded: false));
        await pending;
        Assert.Same(snapshot, registry.Snapshot);
        Assert.Equal("Loaded from registry server", registry.Status);
    }

    // Selection

    [Fact]
    public async Task SelectingACellShowsItsTextAnEmptyCellLeavesTheStatusOutOfRangeIsIgnored()
    {
        var registry = await Loaded();
        registry.SelectCell(1, 1);
        Assert.Equal(new RegistryCell(1, 1), registry.SelectedCell);
        Assert.Equal("Authority 2", registry.Status);
        registry.SelectCell(0, 5); // the note column is empty
        Assert.Equal(new RegistryCell(0, 5), registry.SelectedCell);
        Assert.Equal("Authority 2", registry.Status);
        registry.SelectCell(2, 0);
        registry.SelectCell(0, 7);
        registry.SelectCell(-1, 0);
        registry.SelectCell(0, -1);
        Assert.Equal(new RegistryCell(0, 5), registry.SelectedCell);
    }

    [Fact]
    public async Task ClearingTheSelectionDisablesEditEntryAndKeepsTheStatus()
    {
        var registry = await Loaded();
        registry.SelectCell(1, 1);
        Assert.NotNull(registry.SelectedCell);
        Assert.True(registry.EditEntryCommand.CanExecute(null));
        var status = registry.Status;
        registry.ClearSelection();
        Assert.Null(registry.SelectedCell);
        Assert.False(registry.EditEntryCommand.CanExecute(null));
        Assert.Equal(status, registry.Status);
    }

    [Fact]
    public async Task RegistryChangedClearsTheSelectionAndReReadsTheRegistry()
    {
        var registry = await Loaded();
        registry.SelectCell(0, 0);
        var snapshot = Fixtures.Snapshot(3);
        _fake.Respond(RpcMethod.RegistrySnapshot, snapshot);
        await registry.RegistryChangedAsync();
        Assert.Null(registry.SelectedCell);
        Assert.Same(snapshot, registry.Snapshot);
        Assert.Equal("Loaded from registry server", registry.Status);
    }

    [Fact]
    public async Task RegistryChangedWithoutALoadedRegistrySaysFailedToLoad()
    {
        var registry = await Loaded(Fixtures.Snapshot(0, loaded: false));
        _fake.Respond(RpcMethod.RegistrySnapshot, Fixtures.Snapshot(0, loaded: false));
        await registry.RegistryChangedAsync();
        Assert.Equal("Failed to load registry", registry.Status);
        Assert.Equal(2, _fake.Count(RpcMethod.RegistrySnapshot));
    }

    [Fact]
    public async Task AFailedSnapshotReadKeepsTheTable()
    {
        var registry = await Loaded();
        var before = registry.Snapshot;
        _fake.Fail(RpcMethod.RegistrySnapshot, new RpcException(RpcErrorCode.Internal, "x"));
        await registry.RegistryChangedAsync();
        Assert.Same(before, registry.Snapshot);
        Assert.Equal("Loaded from registry server", registry.Status);
    }

    [Fact]
    public async Task AnOlderSnapshotReadFinishingLastIsDroppedStatusIncluded()
    {
        var registry = await Loaded();
        var first = _fake.Hold(RpcMethod.RegistrySnapshot);
        var newer = Fixtures.Snapshot(4);
        _fake.Respond(RpcMethod.RegistrySnapshot, newer);
        var older = registry.RegistryChangedAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.RegistrySnapshot) == 2));
        await registry.RegistryChangedAsync();
        Assert.Same(newer, registry.Snapshot);
        // A status set after the newer read stays when the older one lands.
        registry.SelectCell(3, 1);
        Assert.Equal("Authority 4", registry.Status);
        first.Release(Fixtures.Snapshot(1));
        await older;
        Assert.Same(newer, registry.Snapshot);
        Assert.Equal("Authority 4", registry.Status);
        Assert.Equal(new RegistryCell(3, 1), registry.SelectedCell);
    }

    // Fetch

    [Fact]
    public async Task FetchWithNoEditsFetchesAtOnce()
    {
        var registry = await Loaded();
        await registry.FetchCommand.ExecuteAsync(null);
        Assert.Empty(_confirm.Questions);
        Assert.Equal(["{}"], _fake.Params(RpcMethod.RegistryFetch));
        Assert.Equal("Fetching...", registry.Status);
    }

    [Fact]
    public async Task FetchWithEditsAsksFirstAndConfirmingFetches()
    {
        var registry = await Loaded(Fixtures.Snapshot(2, dirty: true));
        _confirm.Answer(true);
        await registry.FetchCommand.ExecuteAsync(null);
        Assert.Equal([RegistryViewModel.DiscardConfirmation], _confirm.Questions);
        Assert.Equal(1, _fake.Count(RpcMethod.RegistryFetch));
        Assert.Equal("Fetching...", registry.Status);
    }

    [Fact]
    public async Task FetchWithEditsDeclinedFetchesNothing()
    {
        var registry = await Loaded(Fixtures.Snapshot(2, dirty: true));
        await registry.FetchCommand.ExecuteAsync(null);
        Assert.Single(_confirm.Questions);
        Assert.Equal(0, _fake.Count(RpcMethod.RegistryFetch));
        Assert.Equal("Loaded from registry server", registry.Status);
    }

    [Fact]
    public async Task AFailedFetchSaysFailedToLoad()
    {
        _fake.Fail(RpcMethod.RegistryFetch, new RpcException(RpcErrorCode.Failed, "offline"));
        var registry = await Loaded();
        await registry.FetchCommand.ExecuteAsync(null);
        Assert.Equal("Failed to load registry", registry.Status);
        Assert.Null(_alerts.Current);
    }

    // Add and Edit

    [Fact]
    public async Task AddEntryOpensAnAddFormAndCancelClosesIt()
    {
        var registry = await Loaded();
        registry.AddEntryCommand.Execute(null);
        var form = Assert.IsType<EntryFormViewModel>(registry.EntryForm);
        Assert.True(form.IsAdding);
        Assert.Equal("2026-01-01", form.Form.From);
        registry.CancelEntry();
        Assert.Null(registry.EntryForm);
    }

    [Fact]
    public async Task EditEntryIsEnabledOnlyWithASelectedEntry()
    {
        var registry = await Loaded();
        var changes = 0;
        registry.EditEntryCommand.CanExecuteChanged += (_, _) => changes++;
        Assert.False(registry.EditEntryCommand.CanExecute(null));
        registry.EditEntryCommand.Execute(null); // ignored
        Assert.Null(registry.EntryForm);
        registry.SelectCell(1, 0);
        Assert.True(registry.EditEntryCommand.CanExecute(null));
        Assert.True(changes > 0);
    }

    [Fact]
    public async Task EditEntryIsDisabledOnceTheSelectedRowIsGone()
    {
        var registry = await Loaded();
        registry.SelectCell(1, 0);
        var changes = 0;
        registry.EditEntryCommand.CanExecuteChanged += (_, _) => changes++;
        _fake.Respond(RpcMethod.RegistrySnapshot, Fixtures.Snapshot(1));
        registry.AddEntryCommand.Execute(null);
        await registry.SubmitEntryAsync();
        Assert.Null(registry.SelectedCell);
        Assert.False(registry.EditEntryCommand.CanExecute(null));
        Assert.True(changes > 0);
    }

    [Fact]
    public async Task EditEntryIsDisabledWhenTheSelectedRowHasNoEntry()
    {
        // The core's rows and entries always match; a mismatch must not open a form.
        var entries = Fixtures.Snapshot(1);
        var rows = Fixtures.Snapshot(2);
        var registry = await Loaded(new RegistrySnapshot(entries.Entries, rows.Rows, false, true));
        registry.SelectCell(1, 0);
        Assert.NotNull(registry.SelectedCell);
        Assert.False(registry.EditEntryCommand.CanExecute(null));
        registry.EditEntryCommand.Execute(null);
        Assert.Null(registry.EntryForm);
    }

    [Fact]
    public async Task EditEntryOpensTheSelectedEntrysForm()
    {
        var registry = await Loaded();
        registry.SelectCell(1, 3);
        registry.EditEntryCommand.Execute(null);
        var form = Assert.IsType<EntryFormViewModel>(registry.EntryForm);
        Assert.Equal(new EntryFormMode.Edit(1, "KEY2="), form.Mode);
        Assert.Equal(new EntryForm("Authority 2", "2025-01-02", "2030-12-22", "", false), form.Form);
    }

    [Fact]
    public async Task AnAcceptedAddClosesTheFormAndReReadsTheRegistryKeepingTheSelection()
    {
        var registry = await Loaded();
        registry.SelectCell(1, 1);
        registry.AddEntryCommand.Execute(null);
        var snapshot = Fixtures.Snapshot(3, dirty: true);
        _fake.Respond(RpcMethod.RegistrySnapshot, snapshot);
        await registry.SubmitEntryAsync();
        Assert.Null(registry.EntryForm);
        Assert.Same(snapshot, registry.Snapshot);
        Assert.Equal(new RegistryCell(1, 1), registry.SelectedCell);
        Assert.Equal(1, _fake.Count(RpcMethod.RegistryAddEntry));
    }

    [Fact]
    public async Task AnEditTheCoreRefusesKeepsTheFormOpenWithItsMessage()
    {
        _fake.Fail(
            RpcMethod.RegistryUpdateEntry, new RpcException(RpcErrorCode.Failed, "The entry's key no longer matches; fetch again."));
        var registry = await Loaded();
        registry.SelectCell(0, 0);
        registry.EditEntryCommand.Execute(null);
        var form = registry.EntryForm;
        await registry.SubmitEntryAsync();
        Assert.NotNull(form);
        Assert.Same(form, registry.EntryForm);
        Assert.Equal("The entry's key no longer matches; fetch again.", form.ErrorText);
        Assert.Equal(1, _fake.Count(RpcMethod.RegistrySnapshot)); // the load's only
        Assert.Contains("\"index\":0,\"publicKey\":\"KEY1=\"", _fake.Params(RpcMethod.RegistryUpdateEntry)[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAcceptedEditClosesTheFormAndKeepsTheSelection()
    {
        var registry = await Loaded();
        registry.SelectCell(0, 1);
        registry.EditEntryCommand.Execute(null);
        registry.EntryForm!.Authority = "Renamed";
        _fake.Respond(RpcMethod.RegistrySnapshot, Fixtures.Snapshot(2, dirty: true));
        await registry.SubmitEntryAsync();
        Assert.Null(registry.EntryForm);
        Assert.True(registry.Snapshot.Dirty);
        Assert.Equal(new RegistryCell(0, 1), registry.SelectedCell);
        Assert.Contains("\"authority\":\"Renamed\"", _fake.Params(RpcMethod.RegistryUpdateEntry)[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task SubmittingWithNoFormUpDoesNothing()
    {
        var registry = await Loaded();
        await registry.SubmitEntryAsync();
        Assert.Equal(0, _fake.Count(RpcMethod.RegistryAddEntry));
        Assert.Equal(0, _fake.Count(RpcMethod.RegistryUpdateEntry));
    }

    [Fact]
    public async Task AFormCancelledWhileItsAddRunsIsNotClosedAgainOnSuccess()
    {
        var held = _fake.Hold(RpcMethod.RegistryAddEntry);
        var registry = await Loaded();
        registry.AddEntryCommand.Execute(null);
        var submit = registry.SubmitEntryAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.RegistryAddEntry) == 1));
        registry.CancelEntry();
        registry.AddEntryCommand.Execute(null);
        var second = registry.EntryForm;
        var snapshot = Fixtures.Snapshot(3, dirty: true);
        _fake.Respond(RpcMethod.RegistrySnapshot, snapshot);
        held.Release(Empty.Value);
        await submit;
        Assert.NotNull(second);
        Assert.Same(second, registry.EntryForm);
        Assert.Same(snapshot, registry.Snapshot);
    }

    // Submit for Review

    [Fact]
    public async Task SubmitWithNoEntriesIsDisabledAndCallsNothing()
    {
        var registry = await Loaded(Fixtures.Snapshot(0));
        Assert.False(registry.SubmitForReviewCommand.CanExecute(null));
        await registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.Equal(0, _fake.Count(RpcMethod.RegistrySubmit));
        Assert.Equal("Loaded from registry server", registry.Status);
    }

    [Fact]
    public async Task SubmitIsEnabledOnceTheRegistryHasEntries()
    {
        var registry = await Loaded(Fixtures.Snapshot(0));
        var changes = 0;
        registry.SubmitForReviewCommand.CanExecuteChanged += (_, _) => changes++;
        _fake.Respond(RpcMethod.RegistrySnapshot, Fixtures.Snapshot(1));
        await registry.RegistryChangedAsync();
        Assert.True(registry.SubmitForReviewCommand.CanExecute(null));
        Assert.True(changes > 0);
    }

    [Fact]
    public async Task SubmitSuccessWithAUrlAsksToOpenItAndConfirmingOpensIt()
    {
        var held = _fake.Hold(RpcMethod.RegistrySubmit);
        var registry = await Loaded();
        var clean = Fixtures.Snapshot(2);
        _fake.Respond(RpcMethod.RegistrySnapshot, clean);
        _confirm.Answer(true);
        var submit = registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.RegistrySubmit) == 1));
        Assert.Equal("Creating pull request...", registry.Status);
        held.Release(new SubmitResult(42, PrUrl));
        await submit;
        Assert.Equal("PR #42 created", registry.Status);
        Assert.Same(clean, registry.Snapshot);
        Assert.Equal(
            [new Confirmation("Pull Request Created", "PR #42 has been created.\n\nOpen in browser?", "Open in Browser", "Close")],
            _confirm.Questions);
        Assert.Equal([new Uri(PrUrl)], _urls.Opened);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task SubmitSuccessWithTheBrowserDeclinedOpensNothing()
    {
        _fake.Respond(RpcMethod.RegistrySubmit, new SubmitResult(7, PrUrl));
        var registry = await Loaded();
        _fake.Respond(RpcMethod.RegistrySnapshot, Fixtures.Snapshot(2));
        await registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.Single(_confirm.Questions);
        Assert.Empty(_urls.Opened);
        Assert.Null(_alerts.Current);
        Assert.Equal("PR #7 created", registry.Status);
    }

    [Fact]
    public async Task ABrowserThatFailsToOpenShowsAnErrorAlert()
    {
        _fake.Respond(RpcMethod.RegistrySubmit, new SubmitResult(8, PrUrl));
        _urls.Failure = "Could not open " + PrUrl;
        var registry = await Loaded();
        _fake.Respond(RpcMethod.RegistrySnapshot, Fixtures.Snapshot(2));
        _confirm.Answer(true);
        await registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Error", "Could not open " + PrUrl), _alerts.Current);
    }

    [Fact]
    public async Task ASuccessfulSubmitReReadsTheRegistrySoALaterFetchDoesNotAsk()
    {
        _fake.Respond(RpcMethod.RegistrySubmit, new SubmitResult(5, ""));
        var registry = await Loaded(Fixtures.Snapshot(2, dirty: true));
        _fake.Respond(RpcMethod.RegistrySnapshot, Fixtures.Snapshot(2));
        await registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.False(registry.Snapshot.Dirty);
        await _alerts.DismissAsync();
        await registry.FetchCommand.ExecuteAsync(null);
        Assert.Empty(_confirm.Questions);
        Assert.Equal(1, _fake.Count(RpcMethod.RegistryFetch));
    }

    [Fact]
    public async Task SubmitSuccessWithoutAnHttpsUrlShowsAnInformationAlert()
    {
        _fake.Respond(RpcMethod.RegistrySubmit, new SubmitResult(9, "http://github.com/RoyalHouseOfGeorgia/rhg_authenticator/pull/9"));
        var registry = await Loaded();
        _fake.Respond(RpcMethod.RegistrySnapshot, Fixtures.Snapshot(2));
        await registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.Equal("PR #9 created", registry.Status);
        Assert.Empty(_confirm.Questions);
        Assert.Equal(new AlertState("Pull Request Created", "PR #9 has been created."), _alerts.Current);
        Assert.False(_alerts.Current!.IsError);
        await _alerts.DismissAsync();
        Assert.Empty(_urls.Opened);
        Assert.Equal(0, _fake.Count(RpcMethod.AuthLogin));
    }

    [Fact]
    public async Task NotLoggedInSubmitStartsTheLoginWhoseStatusTextsShow()
    {
        _fake.Fail(RpcMethod.RegistrySubmit, new RpcException(RpcErrorCode.NotLoggedIn, "Not logged in to GitHub."));
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedIn);
        var registry = await Loaded();
        await registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.Equal([RpcMethod.RegistrySubmit, RpcMethod.AuthLogin], _fake.Methods.TakeLast(2));
        Assert.Equal("Logged in as @octocat", registry.Status);
        Assert.Equal(Fixtures.LoggedIn, registry.Login.AuthState);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task BusySaysSubmitAlreadyInProgress()
    {
        _fake.Fail(RpcMethod.RegistrySubmit, new RpcException(RpcErrorCode.Busy, "Another operation is in progress."));
        var registry = await Loaded();
        await registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.Equal("Submit already in progress", registry.Status);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task SessionExpiredShowsTheAlertThenLogsInOnlyOnceItIsDismissed()
    {
        const string Message = "Your GitHub session expired. Please log in again.";
        _fake.Fail(RpcMethod.RegistrySubmit, new RpcException(RpcErrorCode.SessionExpired, Message));
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedIn);
        var registry = await Loaded();
        await registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Session Expired", Message), _alerts.Current);
        Assert.Equal("", registry.Status);
        Assert.Equal(0, _fake.Count(RpcMethod.AuthLogin));
        await _alerts.DismissAsync();
        Assert.Null(_alerts.Current);
        Assert.Equal(1, _fake.Count(RpcMethod.AuthLogin));
        Assert.Equal("Logged in as @octocat", registry.Status);
        // The follow-up runs once.
        await _alerts.DismissAsync();
        Assert.Equal(1, _fake.Count(RpcMethod.AuthLogin));
    }

    [Fact]
    public async Task RegistryChangedUpstreamShowsRegistryChangedWithTheCoresMessage()
    {
        const string Message = "The registry on GitHub doesn't match the copy you loaded (it changed since).";
        _fake.Fail(RpcMethod.RegistrySubmit, new RpcException(RpcErrorCode.RegistryChanged, Message));
        var registry = await Loaded();
        await registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Registry Changed", Message), _alerts.Current);
        Assert.Equal("", registry.Status);
    }

    [Theory]
    [InlineData("failed")]
    [InlineData("future")]
    public async Task AnyOtherFailureShowsSubmissionFailedOfferingTheErrorLog(string code)
    {
        _fake.Fail(RpcMethod.RegistrySubmit, new RpcException(code, "GitHub returned an error."));
        var registry = await Loaded();
        await registry.SubmitForReviewCommand.ExecuteAsync(null);
        Assert.Equal(
            new AlertState("Submission Failed", "GitHub returned an error.", OffersErrorLogExport: true), _alerts.Current);
        Assert.Equal("", registry.Status);
        await _alerts.DismissAsync();
        Assert.Null(_alerts.Current);
        Assert.Equal(0, _fake.Count(RpcMethod.AuthLogin));
    }
}
