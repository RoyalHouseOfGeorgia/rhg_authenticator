using System.Text;
using Microsoft.Extensions.Time.Testing;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class HistoryViewModelTests
{
    private readonly FakeBridge _fake = new();
    private readonly FakeConfirm _confirm = new();
    private readonly FakeFileSave _fileSave = new();
    private readonly AlertQueue _alerts = new();
    private readonly FakeTimeProvider _time = new(Fixtures.LateNewYearsDay);

    private HistoryViewModel NewModel(TimeProvider? clock = null)
    {
        var login = new LoginViewModel(_fake, _confirm, new FakeClipboard(), new FakeUrlOpener(), _alerts);
        return new HistoryViewModel(_fake, login, _confirm, _fileSave, _alerts, clock ?? _time);
    }

    /// <summary>Record <paramref name="n"/> of the issuance log.</summary>
    private static HistoryRecord Record(int n)
    {
        return new HistoryRecord(
            $"2026-01-{n:D2}T10:00:00Z", $"Recipient {n}", "Order of the Eagle", "Knight", $"2026-01-{n:D2}", $"hash{n}", $"sig{n}");
    }

    /// <summary>A new list of records <paramref name="records"/>, in order, those in <paramref name="revoked"/> revoked.</summary>
    private static HistoryListResult List(
        int[] records,
        bool revokeAvailable = true,
        bool loadFailed = false,
        bool revocationsUnavailable = false,
        int[]? revoked = null)
    {
        var rows = records
            .Select(n => new HistoryRow(Record(n), $"2026-Jan-{n:D2} — Recipient {n}", revoked?.Contains(n) ?? false))
            .ToList();
        return new HistoryListResult(
            Rows: rows,
            LoadFailed: loadFailed,
            RevocationsUnavailable: revocationsUnavailable,
            RevocationsLoaded: !revocationsUnavailable,
            RevokeAvailable: revokeAvailable);
    }

    /// <summary><paramref name="task"/>, failing after 5 s instead of hanging the run (a debounce that never fires).</summary>
    private static Task Bounded(Task task)
    {
        return task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
    }

    private static RecordTextResult Text(int n, bool offerRevoke = true)
    {
        return new RecordTextResult(
            $"Detail of record {n}", $"Revoke the credential of Recipient {n}?", $"Delete the record of Recipient {n}?", offerRevoke);
    }

    /// <summary>The delete question the core's text for record <paramref name="n"/> asks.</summary>
    private static Confirmation DeleteQuestion(int n, bool offerRevoke = true)
    {
        return new Confirmation(
            "Delete Issuance Record", $"Delete the record of Recipient {n}?", "Delete", "Cancel", IsDestructive: true,
            AlternateTitle: offerRevoke ? "Revoke Instead" : null);
    }

    /// <summary>The revoke question the core's text for record <paramref name="n"/> asks.</summary>
    private static Confirmation RevokeQuestion(int n)
    {
        return new Confirmation("Confirm Revocation", $"Revoke the credential of Recipient {n}?", "Revoke", "Cancel", IsDestructive: true);
    }

    private static readonly RevokeResult s_submitted =
        new(RevokeStatus.Submitted, 12, "https://github.com/x/pull/12", "Revocation Submitted", "PR #12 opened.");

    private static readonly DeleteEntryResult s_deleted =
        new("/data/issuances.json.bak", "Core Deleted Title", "Core says: deleted it.");

    private static string RecordJson(int n)
    {
        return CanonicalJson.Encode(new RecordParams(Record(n)), BridgeJsonContext.Default.RecordParams);
    }

    /// <summary>A model whose first rows (default records 1 to 3) landed; later reads answer from each test's own script.</summary>
    private async Task<HistoryViewModel> Loaded(HistoryListResult? list = null)
    {
        _fake.Respond(RpcMethod.HistoryList, list ?? List([1, 2, 3]));
        var history = NewModel();
        await history.HistoryChangedAsync();
        _fake.Reset(RpcMethod.HistoryList);
        return history;
    }

    /// <summary>A loaded model with <paramref name="row"/> selected and its detail shown.</summary>
    private async Task<HistoryViewModel> Selected(int row, HistoryListResult? list = null)
    {
        var history = await Loaded(list);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(row + 1));
        await history.SelectAsync(row);
        _fake.Reset(RpcMethod.HistoryRecordText);
        Assert.Equal($"Detail of record {row + 1}", history.SelectedDetail);
        return history;
    }

    [Fact]
    public void Copy()
    {
        Assert.Equal("Search by recipient...", HistoryViewModel.SearchPlaceholder);
        Assert.Equal(["Refresh", "Revoke"], [HistoryViewModel.RefreshTitle, HistoryViewModel.RevokeTitle]);
        Assert.Equal([.. "Delete Entry"u8, 0xE2, 0x80, 0xA6], Encoding.UTF8.GetBytes(HistoryViewModel.DeleteEntryTitle));
        Assert.Equal("Select a record to delete it. In the list, Del deletes the selected record.", HistoryViewModel.DeleteEntryTooltip);
        Assert.Equal(["Refresh (F5)", "Search (Ctrl+F)"], [HistoryViewModel.RefreshTooltip, HistoryViewModel.SearchTooltip]);
        Assert.Equal(
            ["Delete Issuance Record", "Delete", "Revoke Instead", "Record Not Found", "Delete Failed"],
            [
                HistoryViewModel.DeleteRecordConfirmTitle, HistoryViewModel.DeleteTitle, HistoryViewModel.RevokeInsteadTitle,
                HistoryViewModel.RecordNotFoundTitle, HistoryViewModel.DeleteFailedTitle,
            ]);
        Assert.Equal([.. "Export Issuance Log"u8, 0xE2, 0x80, 0xA6], Encoding.UTF8.GetBytes(HistoryViewModel.ExportTitle));
        Assert.Equal([.. "Remove Duplicates"u8, 0xE2, 0x80, 0xA6], Encoding.UTF8.GetBytes(HistoryViewModel.RemoveDuplicatesTitle));
        Assert.Equal("Revocation unavailable", HistoryViewModel.RevocationUnavailableStatus);
        Assert.Equal("Select a record to see its details.", HistoryViewModel.EmptyDetailText);
        Assert.Equal(
            ["Confirm Revocation", "Session Expired", "Revocation Failed", "Nothing to Export"],
            [
                HistoryViewModel.ConfirmRevocationTitle, HistoryViewModel.SessionExpiredTitle,
                HistoryViewModel.RevocationFailedTitle, HistoryViewModel.NothingToExportTitle,
            ]);
        Assert.Equal(
            ["Remove Duplicates", "Remove Entries", "No Duplicates", "The issuance log has no duplicate entries."],
            [
                HistoryViewModel.RemoveDuplicatesConfirmTitle, HistoryViewModel.RemoveEntriesTitle,
                HistoryViewModel.NoDuplicatesTitle, HistoryViewModel.NoDuplicatesMessage,
            ]);
        Assert.Equal(
            ["Duplicates Removed", "Remove Duplicates Failed", "unable to load history"],
            [
                HistoryViewModel.DuplicatesRemovedTitle, HistoryViewModel.RemoveDuplicatesFailedTitle,
                HistoryViewModel.LoadFailedMessage,
            ]);
        Assert.Equal(TimeSpan.FromMilliseconds(200), HistoryViewModel.SearchDebounce);
    }

    [Fact]
    public void RequiresItsServices()
    {
        var login = new LoginViewModel(_fake, _confirm, new FakeClipboard(), new FakeUrlOpener(), _alerts);
        Assert.Throws<ArgumentNullException>(() => new HistoryViewModel(null!, login, _confirm, _fileSave, _alerts));
        Assert.Throws<ArgumentNullException>(() => new HistoryViewModel(_fake, null!, _confirm, _fileSave, _alerts));
        Assert.Throws<ArgumentNullException>(() => new HistoryViewModel(_fake, login, null!, _fileSave, _alerts));
        Assert.Throws<ArgumentNullException>(() => new HistoryViewModel(_fake, login, _confirm, null!, _alerts));
        Assert.Throws<ArgumentNullException>(() => new HistoryViewModel(_fake, login, _confirm, _fileSave, null!));
    }

    [Fact]
    public void ANewModelIsEmptyAndNotLoaded()
    {
        var history = NewModel();
        Assert.Empty(history.Snapshot.Rows);
        Assert.False(history.Snapshot.RevocationsLoaded);
        Assert.Equal("", history.Query);
        Assert.Null(history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
        Assert.Equal("", history.Status);
        Assert.Equal("", history.RevocationStatus);
        Assert.False(history.IsRevoking);
        Assert.False(history.IsDeleting);
        Assert.True(history.PendingSearch.IsCompleted);
        Assert.False(history.RevokeCommand.CanExecute(null));
        Assert.False(history.DeleteEntryCommand.CanExecute(null));
        Assert.True(history.RefreshCommand.CanExecute(null));
        Assert.Empty(_fake.Calls);
    }

    [Fact]
    public async Task HistoryChangedReadsTheLogForTheQuery()
    {
        var list = List([1, 2]);
        _fake.Respond(RpcMethod.HistoryList, list);
        var history = NewModel();
        await history.HistoryChangedAsync();
        Assert.Same(list, history.Snapshot);
        Assert.Equal(["{\"query\":\"\"}"], _fake.Params(RpcMethod.HistoryList));
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task AReReadWithTheSameRowsKeepsTheSnapshot()
    {
        var history = await Selected(1);
        var shown = history.Snapshot;
        var changed = new List<string?>();
        history.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        // Equal content in new lists, as every history.list reply is.
        _fake.Respond(RpcMethod.HistoryList, List([1, 2, 3]));
        await history.RereadAsync();
        Assert.Same(shown, history.Snapshot);
        Assert.Empty(changed);
        Assert.Equal(1, history.SelectedIndex);
        _fake.Reset(RpcMethod.HistoryList);
        _fake.Respond(RpcMethod.HistoryList, List([1, 2, 3], revoked: [2]));
        await history.RereadAsync();
        Assert.True(history.Snapshot.Rows[1].Revoked);
        Assert.Contains(nameof(HistoryViewModel.Snapshot), changed);
    }

    // The search

    [Fact]
    public async Task ASearchReadsOnceTypingPausesAndClearsTheSelectionAtOnce()
    {
        var history = await Selected(1);
        var changed = new List<string?>();
        history.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        var filtered = List([2]);
        _fake.Respond(RpcMethod.HistoryList, filtered);
        history.Query = "Recipient 2";
        Assert.Contains(nameof(HistoryViewModel.Query), changed);
        Assert.Null(history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
        _time.Advance(TimeSpan.FromMilliseconds(199));
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryList)); // the load's only
        Assert.False(history.PendingSearch.IsCompleted);
        _time.Advance(TimeSpan.FromMilliseconds(1));
        await Bounded(history.PendingSearch);
        Assert.Equal(["{\"query\":\"\"}", "{\"query\":\"Recipient 2\"}"], _fake.Params(RpcMethod.HistoryList));
        Assert.Same(filtered, history.Snapshot);
        Assert.Null(history.SelectedIndex);
        _time.Advance(TimeSpan.FromSeconds(5));
        Assert.Equal(2, _fake.Count(RpcMethod.HistoryList));
    }

    [Fact]
    public async Task TheSearchWaitsOnTheInjectedClockNotRealTime()
    {
        var history = await Loaded();
        _fake.Respond(RpcMethod.HistoryList, List([1]));
        history.Query = "R";
        // Well past the pause in real time, with the fake clock never moved:
        // fails only if the debounce runs on real time, and could wrongly pass
        // only under a scheduler stall of over 400 ms. Do not shorten the wait.
        await Task.WhenAny(history.PendingSearch, Task.Delay(HistoryViewModel.SearchDebounce * 3, TestContext.Current.CancellationToken));
        Assert.False(history.PendingSearch.IsCompleted);
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryList)); // the load's only
        _time.Advance(HistoryViewModel.SearchDebounce);
        await Bounded(history.PendingSearch);
        Assert.Equal(2, _fake.Count(RpcMethod.HistoryList));
    }

    [Fact]
    public async Task ANewerQuerySupersedesThePendingOne()
    {
        var history = await Loaded();
        _fake.Respond(RpcMethod.HistoryList, List([1]));
        history.Query = "R";
        var first = history.PendingSearch;
        _time.Advance(TimeSpan.FromMilliseconds(100));
        history.Query = "Re";
        await Bounded(first);
        _time.Advance(TimeSpan.FromMilliseconds(150));
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryList)); // the load's only
        _time.Advance(TimeSpan.FromMilliseconds(50));
        await Bounded(history.PendingSearch);
        Assert.Equal(["{\"query\":\"\"}", "{\"query\":\"Re\"}"], _fake.Params(RpcMethod.HistoryList));
    }

    [Fact]
    public async Task SettingTheSameQueryDoesNothing()
    {
        var history = await Selected(0);
        var pending = history.PendingSearch;
        history.Query = "";
        Assert.Same(pending, history.PendingSearch);
        Assert.Equal(0, history.SelectedIndex);
        Assert.Equal("Detail of record 1", history.SelectedDetail);
        _time.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryList)); // the load's only
    }

    [Fact]
    public async Task AQueryChangeDropsAReadAlreadySentAndARowPickedMeanwhile()
    {
        var history = await Loaded();
        var older = _fake.Hold(RpcMethod.HistoryList);
        var newer = List([3]);
        _fake.Respond(RpcMethod.HistoryList, newer);
        var reread = history.RereadAsync();
        history.Query = "3";
        // A row picked from the old rows before the search's read lands.
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        await history.SelectAsync(0);
        Assert.Equal(0, history.SelectedIndex);
        older.Release(List([1, 2]));
        await Bounded(reread);
        Assert.Equal(3, history.Snapshot.Rows.Count);
        _time.Advance(HistoryViewModel.SearchDebounce);
        await Bounded(history.PendingSearch);
        Assert.Same(newer, history.Snapshot);
        Assert.Null(history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
    }

    // Selection

    [Fact]
    public async Task SelectingARowShowsItsDetail()
    {
        var history = await Loaded();
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        await history.SelectAsync(1);
        Assert.Equal(1, history.SelectedIndex);
        Assert.Equal("Detail of record 2", history.SelectedDetail);
        Assert.Equal([RecordJson(2)], _fake.Params(RpcMethod.HistoryRecordText));
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task TheDetailStaysUntilTheNextRowsDetailArrives()
    {
        var history = await Selected(0);
        var held = _fake.Hold(RpcMethod.HistoryRecordText);
        var select = history.SelectAsync(1);
        Assert.Equal(1, history.SelectedIndex);
        Assert.Equal("Detail of record 1", history.SelectedDetail);
        held.Release(Text(2));
        await select;
        Assert.Equal("Detail of record 2", history.SelectedDetail);
    }

    [Fact]
    public async Task AFailedDetailReadClearsTheDetailAndShowsTheCoresError()
    {
        var history = await Selected(0);
        _fake.Fail(RpcMethod.HistoryRecordText, new RpcException(RpcErrorCode.Failed, "cannot word it"));
        await history.SelectAsync(2);
        Assert.Equal(2, history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
        Assert.Equal(new AlertState("Error", "cannot word it"), _alerts.Current);
    }

    [Fact]
    public async Task TheLatestSelectionWinsItsRepliesAndFailuresIncluded()
    {
        var history = await Loaded();
        var first = _fake.Hold(RpcMethod.HistoryRecordText);
        var second = _fake.Hold(RpcMethod.HistoryRecordText);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(3));
        var one = history.SelectAsync(0);
        var two = history.SelectAsync(1);
        await history.SelectAsync(2);
        Assert.Equal("Detail of record 3", history.SelectedDetail);
        first.Release(Text(1));
        second.ReleaseFailing(new RpcException(RpcErrorCode.Failed, "stale"));
        await one;
        await two;
        Assert.Equal(2, history.SelectedIndex);
        Assert.Equal("Detail of record 3", history.SelectedDetail);
        Assert.Null(_alerts.Current);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(-1)]
    [InlineData(3)]
    public async Task NoRowOrOneOutOfRangeClearsTheSelection(int? row)
    {
        var history = await Selected(1);
        await history.SelectAsync(row);
        Assert.Null(history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryRecordText)); // the first selection's only
    }

    [Fact]
    public async Task ClearingTheSelectionDropsADetailReadStillRunning()
    {
        var history = await Loaded();
        var held = _fake.Hold(RpcMethod.HistoryRecordText);
        var select = history.SelectAsync(0);
        await history.SelectAsync(null);
        held.Release(Text(1));
        await select;
        Assert.Null(history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
    }

    // Re-reads

    [Fact]
    public async Task HistoryChangedClearsTheSelectionEvenWhenTheRowStillExists()
    {
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryList, List([1, 2, 3]));
        var changed = history.HistoryChangedAsync();
        Assert.Null(history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
        await changed;
        Assert.Null(history.SelectedIndex);
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryRecordText)); // the selection's only
    }

    [Fact]
    public async Task ARowPickedBeforeHistoryChangedsReadLandsIsClearedWhenTheRowsDiffer()
    {
        var history = await Loaded();
        var read = _fake.Hold(RpcMethod.HistoryList);
        var changed = history.HistoryChangedAsync();
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        await history.SelectAsync(1);
        Assert.Equal(1, history.SelectedIndex);
        read.Release(List([4, 1, 2, 3]));
        await changed;
        Assert.Null(history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
    }

    [Fact]
    public async Task ARowPickedBeforeHistoryChangedsReadLandsSurvivesTheSameRows()
    {
        var history = await Loaded();
        var shown = history.Snapshot;
        var read = _fake.Hold(RpcMethod.HistoryList);
        var changed = history.HistoryChangedAsync();
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        await history.SelectAsync(1);
        var names = new List<string?>();
        history.PropertyChanged += (_, e) => names.Add(e.PropertyName);
        read.Release(List([1, 2, 3]));
        await changed;
        Assert.Same(shown, history.Snapshot);
        Assert.DoesNotContain(nameof(HistoryViewModel.Snapshot), names);
        Assert.Equal(1, history.SelectedIndex);
        Assert.Equal("Detail of record 2", history.SelectedDetail);
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryRecordText)); // the pick's only
    }

    [Fact]
    public async Task AReReadWhereOnlyTheRevocationListFailedIsShown()
    {
        var history = await Loaded(List([1]) with { RevocationsLoaded = true });
        var failed = List([1], revocationsUnavailable: true) with { RevocationsLoaded = true };
        _fake.Respond(RpcMethod.HistoryList, failed);
        await history.RereadAsync();
        Assert.Same(failed, history.Snapshot);
        Assert.Equal("Revocation unavailable", history.RevocationStatus);
    }

    [Fact]
    public async Task AReReadKeepsASelectionInRangeWithoutReReadingAnUnchangedRecord()
    {
        var history = await Selected(1);
        var list = List([1, 2, 3], revoked: [2]);
        _fake.Respond(RpcMethod.HistoryList, list);
        await history.RereadAsync();
        Assert.Same(list, history.Snapshot);
        Assert.Equal(1, history.SelectedIndex);
        Assert.Equal("Detail of record 2", history.SelectedDetail);
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryRecordText)); // the selection's only
    }

    [Fact]
    public async Task AReReadDropsASelectionOutOfRange()
    {
        var history = await Selected(2);
        _fake.Respond(RpcMethod.HistoryList, List([1, 2]));
        await history.RereadAsync();
        Assert.Null(history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
    }

    [Fact]
    public async Task AKeptRowWhoseRecordChangedHasItsDetailReRead()
    {
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryList, List([4, 1, 2, 3]));
        _fake.Respond(RpcMethod.HistoryRecordText, Text(4));
        await history.RereadAsync();
        Assert.Equal(0, history.SelectedIndex);
        Assert.Equal("Detail of record 4", history.SelectedDetail);
        Assert.Equal([RecordJson(1), RecordJson(4)], _fake.Params(RpcMethod.HistoryRecordText));
    }

    [Fact]
    public async Task AFailedDetailIsNotAskedForAgainByAReReadOfTheSameRecord()
    {
        var history = await Loaded();
        _fake.Fail(RpcMethod.HistoryRecordText, new RpcException(RpcErrorCode.Failed, "no"));
        await history.SelectAsync(0);
        await _alerts.DismissAsync();
        _fake.Respond(RpcMethod.HistoryList, List([1, 2, 3]));
        await history.RereadAsync();
        Assert.Equal(0, history.SelectedIndex);
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryRecordText));
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task AnOlderReadFinishingLastIsDropped()
    {
        var history = await Loaded();
        var older = _fake.Hold(RpcMethod.HistoryList);
        var newer = List([1]);
        _fake.Respond(RpcMethod.HistoryList, newer);
        var first = history.RereadAsync();
        await history.RereadAsync();
        Assert.Same(newer, history.Snapshot);
        older.Release(List([1, 2, 3, 4]));
        await Bounded(first);
        Assert.Same(newer, history.Snapshot);
    }

    [Fact]
    public async Task AFailedReadKeepsTheRowsAndLeavesThePendingClearAndReportToTheNextRead()
    {
        var history = await Loaded();
        var before = history.Snapshot;
        _fake.Fail(RpcMethod.HistoryList, new RpcException(RpcErrorCode.Internal, "x"));
        await history.HistoryChangedAsync();
        Assert.Same(before, history.Snapshot);
        Assert.Null(_alerts.Current);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        await history.SelectAsync(0);
        _fake.Reset(RpcMethod.HistoryList);
        _fake.Respond(RpcMethod.HistoryList, List([], loadFailed: true));
        await history.RereadAsync(); // as history.revocationsChanged does
        Assert.Null(history.SelectedIndex);
        Assert.Equal(new AlertState("Error", "unable to load history"), _alerts.Current);
    }

    [Fact]
    public async Task TheLoadFailureIsReportedOncePerHistoryChanged()
    {
        _fake.Respond(RpcMethod.HistoryList, List([], loadFailed: true));
        var history = NewModel();
        await history.HistoryChangedAsync();
        Assert.Equal(new AlertState("Error", "unable to load history"), _alerts.Current);
        Assert.True(_alerts.Current!.IsError);
        await _alerts.DismissAsync();
        await history.RereadAsync();
        Assert.Null(_alerts.Current);
        await history.HistoryChangedAsync();
        Assert.Equal(new AlertState("Error", "unable to load history"), _alerts.Current);
    }

    [Fact]
    public async Task AFailedLoadIsNotReportedWithoutHistoryChangedNorAfterALoadThatWorked()
    {
        _fake.Respond(RpcMethod.HistoryList, List([], loadFailed: true));
        var history = NewModel();
        await history.RereadAsync(); // revocationsChanged, auth.changed: not armed
        Assert.True(history.Snapshot.LoadFailed);
        Assert.Null(_alerts.Current);
        _fake.Reset(RpcMethod.HistoryList);
        _fake.Respond(RpcMethod.HistoryList, List([1]));
        _fake.Respond(RpcMethod.HistoryList, List([], loadFailed: true));
        await history.HistoryChangedAsync(); // consumes the report: the log loaded
        Assert.Null(_alerts.Current);
        await history.RereadAsync();
        Assert.True(history.Snapshot.LoadFailed);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task RevocationStatusFollowsTheSnapshot()
    {
        var history = await Loaded(List([1], revocationsUnavailable: true));
        Assert.Equal("Revocation unavailable", history.RevocationStatus);
        var changed = new List<string?>();
        history.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        _fake.Respond(RpcMethod.HistoryList, List([1]));
        await history.RereadAsync();
        Assert.Equal("", history.RevocationStatus);
        Assert.Contains(nameof(HistoryViewModel.RevocationStatus), changed);
    }

    // Refresh

    [Fact]
    public async Task RefreshAsksTheCoreAndTheResultsArriveAsEvents()
    {
        var history = await Loaded();
        await history.RefreshCommand.ExecuteAsync(null);
        Assert.Equal(["{}"], _fake.Params(RpcMethod.HistoryRefresh));
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryList)); // the load's only
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task AFailedRefreshShowsTheCoresError()
    {
        _fake.Fail(RpcMethod.HistoryRefresh, new RpcException(RpcErrorCode.Busy, "Already refreshing."));
        var history = await Loaded();
        await history.RefreshCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Error", "Already refreshing."), _alerts.Current);
    }

    // Revoke

    [Fact]
    public async Task RevokeNeedsASelectedUnrevokedRowAndTheCoresGoAhead()
    {
        var history = await Loaded(List([1, 2], revoked: [2]));
        var changes = 0;
        history.RevokeCommand.CanExecuteChanged += (_, _) => changes++;
        Assert.False(history.RevokeCommand.CanExecute(null));
        await history.RevokeCommand.ExecuteAsync(null); // ignored
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRecordText));

        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        await history.SelectAsync(1);
        Assert.True(changes > 0);
        Assert.False(history.RevokeCommand.CanExecute(null)); // already revoked

        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        await history.SelectAsync(0);
        Assert.True(history.RevokeCommand.CanExecute(null));

        changes = 0;
        _fake.Respond(RpcMethod.HistoryList, List([1, 2], revokeAvailable: false, revoked: [2]));
        await history.RereadAsync();
        Assert.Equal(0, history.SelectedIndex);
        Assert.True(changes > 0);
        Assert.False(history.RevokeCommand.CanExecute(null)); // logged out, offline or no revocation list
    }

    [Fact]
    public async Task RevokeIsDisabledWhileARevocationRuns()
    {
        var held = _fake.Hold(RpcMethod.HistoryRevoke);
        _confirm.Answer(true);
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        var changes = 0;
        history.RevokeCommand.CanExecuteChanged += (_, _) => changes++;
        var revoking = history.RevokeCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.HistoryRevoke) == 1));
        Assert.True(history.IsRevoking);
        Assert.False(history.RevokeCommand.CanExecute(null));
        Assert.True(changes > 0);
        _fake.Respond(RpcMethod.HistoryList, List([1, 2, 3], revoked: [1]));
        held.Release(new RevokeResult(RevokeStatus.Submitted, 12, "https://github.com/x/pull/12", "Revocation Submitted", "PR #12"));
        await revoking;
        Assert.False(history.IsRevoking);
    }

    [Fact]
    public async Task ConfirmedRevokeOpensThePullRequestReReadsAndShowsTheCoresOutcome()
    {
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _confirm.Answer(true);
        var revoked = List([1, 2, 3], revoked: [1]);
        _fake.Respond(RpcMethod.HistoryList, revoked);
        _fake.Respond(
            RpcMethod.HistoryRevoke,
            new RevokeResult(RevokeStatus.Submitted, 12, "https://github.com/x/pull/12", "Revocation Submitted", "PR #12 opened."));
        await history.RevokeCommand.ExecuteAsync(null);
        Assert.Equal(
            [new Confirmation("Confirm Revocation", "Revoke the credential of Recipient 1?", "Revoke", "Cancel", IsDestructive: true)],
            _confirm.Questions);
        Assert.Equal([RecordJson(1), RecordJson(1)], _fake.Params(RpcMethod.HistoryRecordText));
        Assert.Equal(["{\"payloadSha256\":\"hash1\"}"], _fake.Params(RpcMethod.HistoryRevoke));
        Assert.Same(revoked, history.Snapshot);
        Assert.Null(history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
        Assert.False(history.IsRevoking);
        Assert.Equal(new AlertState("Revocation Submitted", "PR #12 opened."), _alerts.Current);
    }

    [Fact]
    public async Task ASuccessfulRevocationWhoseReReadFailsStillShowsTheCoresOutcome()
    {
        var history = await Selected(0);
        var shown = history.Snapshot;
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _confirm.Answer(true);
        _fake.Fail(RpcMethod.HistoryList, new RpcException(RpcErrorCode.Internal, "x"));
        _fake.Respond(
            RpcMethod.HistoryRevoke,
            new RevokeResult(RevokeStatus.Submitted, 12, "https://github.com/x/pull/12", "Revocation Submitted", "PR #12 opened."));
        await history.RevokeCommand.ExecuteAsync(null);
        Assert.Same(shown, history.Snapshot);
        Assert.Null(history.SelectedIndex);
        Assert.False(history.IsRevoking);
        Assert.Equal(new AlertState("Revocation Submitted", "PR #12 opened."), _alerts.Current);
    }

    [Fact]
    public async Task DecliningTheRevocationRevokesNothing()
    {
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        await history.RevokeCommand.ExecuteAsync(null);
        Assert.Single(_confirm.Questions);
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRevoke));
        Assert.Equal(0, history.SelectedIndex);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task ARecordTextFailureBeforeRevokingShowsTheCoresErrorAndAsksNothing()
    {
        var history = await Selected(0);
        _fake.Fail(RpcMethod.HistoryRecordText, new RpcException(RpcErrorCode.Failed, "no text"));
        await history.RevokeCommand.ExecuteAsync(null);
        Assert.Empty(_confirm.Questions);
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRevoke));
        Assert.Equal(new AlertState("Error", "no text"), _alerts.Current);
    }

    [Fact]
    public async Task ABusyRevocationShowsNothing()
    {
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _confirm.Answer(true);
        _fake.Fail(RpcMethod.HistoryRevoke, new RpcException(RpcErrorCode.Busy, "busy"));
        await history.RevokeCommand.ExecuteAsync(null);
        Assert.Null(_alerts.Current);
        Assert.False(history.IsRevoking);
        Assert.Equal(0, _fake.Count(RpcMethod.AuthLogin));
        Assert.Equal(0, history.SelectedIndex);
    }

    [Fact]
    public async Task NotLoggedInStartsTheLoginWhoseStatusTextsShowOnHistory()
    {
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _confirm.Answer(true);
        _fake.Fail(RpcMethod.HistoryRevoke, new RpcException(RpcErrorCode.NotLoggedIn, "Not logged in to GitHub."));
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedIn);
        await history.RevokeCommand.ExecuteAsync(null);
        Assert.Equal([RpcMethod.HistoryRevoke, RpcMethod.AuthLogin], _fake.Methods.TakeLast(2));
        Assert.False(history.IsRevoking);
        Assert.Equal("Logged in as @octocat", history.Status);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task SessionExpiredShowsTheAlertThenLogsInOnlyOnceItIsDismissed()
    {
        const string Message = "Your GitHub session expired. Please log in again.";
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _confirm.Answer(true);
        _fake.Fail(RpcMethod.HistoryRevoke, new RpcException(RpcErrorCode.SessionExpired, Message));
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedIn);
        await history.RevokeCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Session Expired", Message), _alerts.Current);
        Assert.Equal(0, _fake.Count(RpcMethod.AuthLogin));
        await _alerts.DismissAsync();
        Assert.Equal(1, _fake.Count(RpcMethod.AuthLogin));
        Assert.Equal("Logged in as @octocat", history.Status);
    }

    [Theory]
    [InlineData("failed")]
    [InlineData("internal")]
    [InlineData("future")]
    public async Task AnyOtherRevocationFailureShowsRevocationFailedOfferingTheErrorLog(string code)
    {
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _confirm.Answer(true);
        _fake.Fail(RpcMethod.HistoryRevoke, new RpcException(code, "GitHub returned an error."));
        await history.RevokeCommand.ExecuteAsync(null);
        Assert.Equal(
            new AlertState("Revocation Failed", "GitHub returned an error.", OffersErrorLogExport: true), _alerts.Current);
        Assert.False(history.IsRevoking);
        await _alerts.DismissAsync();
        Assert.Equal(0, _fake.Count(RpcMethod.AuthLogin));
    }

    // Delete Entry…

    [Fact]
    public async Task DeleteEntryNeedsASelectedRowRevokedOrNotWithRevokingUnavailable()
    {
        var history = await Loaded(List([1, 2], revokeAvailable: false, revoked: [2]));
        var changes = 0;
        history.DeleteEntryCommand.CanExecuteChanged += (_, _) => changes++;
        Assert.False(history.DeleteEntryCommand.CanExecute(null));
        await history.DeleteEntryCommand.ExecuteAsync(null); // ignored
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRecordText));
        Assert.Empty(_confirm.Questions);

        _fake.Respond(RpcMethod.HistoryRecordText, Text(2, offerRevoke: false));
        await history.SelectAsync(1);
        Assert.True(changes > 0);
        Assert.True(history.DeleteEntryCommand.CanExecute(null)); // revoked, revoking unavailable: still deletable
        Assert.False(history.RevokeCommand.CanExecute(null));

        changes = 0;
        _fake.Respond(RpcMethod.HistoryList, List([1]));
        await history.RereadAsync(); // the selected row is gone
        Assert.True(changes > 0);
        Assert.Null(history.SelectedIndex);
        Assert.False(history.DeleteEntryCommand.CanExecute(null));
    }

    [Fact]
    public async Task ASnapshotChangeReRaisesDeleteEntrysCanExecute()
    {
        var history = await Selected(0);
        var changes = 0;
        history.DeleteEntryCommand.CanExecuteChanged += (_, _) => changes++;
        _fake.Respond(RpcMethod.HistoryList, List([1, 2, 3], revoked: [1]));
        await history.RereadAsync();
        Assert.Equal(0, history.SelectedIndex);
        Assert.True(changes > 0);
        Assert.True(history.DeleteEntryCommand.CanExecute(null));
    }

    [Fact]
    public async Task DeleteEntryIsDisabledWhileARevocationRuns()
    {
        var held = _fake.Hold(RpcMethod.HistoryRevoke);
        _confirm.Answer(true);
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        var changes = 0;
        history.DeleteEntryCommand.CanExecuteChanged += (_, _) => changes++;
        var revoking = history.RevokeCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.HistoryRevoke) == 1));
        Assert.True(history.IsRevoking);
        Assert.Equal(0, history.SelectedIndex);
        Assert.False(history.DeleteEntryCommand.CanExecute(null));
        Assert.True(changes > 0);
        _fake.Respond(RpcMethod.HistoryList, List([1, 2, 3], revoked: [1]));
        held.Release(s_submitted);
        await revoking;
        Assert.False(history.IsRevoking);
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryDeleteEntry));
    }

    [Fact]
    public async Task RevokeAndDeleteEntryAreDisabledWhileADeletionRuns()
    {
        var held = _fake.Hold(RpcMethod.HistoryDeleteEntry);
        _confirm.Answer(ConfirmChoice.Confirm);
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        Assert.True(history.RevokeCommand.CanExecute(null));
        var revokeChanges = 0;
        history.RevokeCommand.CanExecuteChanged += (_, _) => revokeChanges++;
        var deleting = history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.HistoryDeleteEntry) == 1));
        Assert.True(history.IsDeleting);
        Assert.Equal(0, history.SelectedIndex);
        Assert.False(history.RevokeCommand.CanExecute(null));
        Assert.False(history.DeleteEntryCommand.CanExecute(null));
        Assert.True(revokeChanges > 0);
        await history.RevokeCommand.ExecuteAsync(null); // ignored
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRevoke));
        held.Release(s_deleted);
        await deleting;
        Assert.False(history.IsDeleting);
        Assert.True(history.RevokeCommand.CanExecute(null));
        Assert.True(history.DeleteEntryCommand.CanExecute(null));
    }

    [Fact]
    public async Task DeleteEntryIsDisabledWhileARevokeInsteadRuns()
    {
        var held = _fake.Hold(RpcMethod.HistoryRevoke);
        _confirm.Answer(ConfirmChoice.Alternate);
        _confirm.Answer(ConfirmChoice.Confirm);
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        var revoking = history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.HistoryRevoke) == 1));
        Assert.True(history.IsRevoking);
        Assert.False(history.IsDeleting);
        Assert.False(history.DeleteEntryCommand.CanExecute(null));
        Assert.False(history.RevokeCommand.CanExecute(null));
        _fake.Respond(RpcMethod.HistoryList, List([1, 2, 3], revoked: [1]));
        held.Release(s_submitted);
        await revoking;
        Assert.False(history.IsRevoking);
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryDeleteEntry));
    }

    [Fact]
    public async Task AnActiveRecordsQuestionOffersRevokeInsteadInTheCoresWords()
    {
        var history = await Selected(1);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        await history.DeleteEntryCommand.ExecuteAsync(null); // cancelled
        Assert.Equal([DeleteQuestion(2)], _confirm.Questions);
        Assert.Equal([RecordJson(2), RecordJson(2)], _fake.Params(RpcMethod.HistoryRecordText));
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryDeleteEntry));
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRevoke));
        Assert.Equal(1, history.SelectedIndex);
        Assert.False(history.IsDeleting);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task ARevokedRecordsQuestionHasTwoButtons()
    {
        var history = await Selected(0, List([1, 2], revoked: [1]));
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1, offerRevoke: false));
        await history.DeleteEntryCommand.ExecuteAsync(null);
        var question = Assert.Single(_confirm.Questions);
        Assert.Equal(DeleteQuestion(1, offerRevoke: false), question);
        Assert.Null(question.AlternateTitle);
    }

    [Fact]
    public async Task WithoutRevokeInsteadAnAlternateAnswerDoesNothing()
    {
        var history = await Selected(0, List([1, 2], revoked: [1]));
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1, offerRevoke: false));
        _confirm.Answer(ConfirmChoice.Alternate);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.Single(_confirm.Questions);
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRevoke));
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryDeleteEntry));
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task ConfirmedDeleteDeletesTheRecordAndShowsTheCoresAlert()
    {
        var history = await Selected(1);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        _fake.Respond(RpcMethod.HistoryDeleteEntry, s_deleted);
        _confirm.Answer(ConfirmChoice.Confirm);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.Equal([RecordJson(2)], _fake.Params(RpcMethod.HistoryDeleteEntry));
        Assert.Equal(new AlertState("Core Deleted Title", "Core says: deleted it."), _alerts.Current);
        Assert.False(_alerts.Current!.IsError);
        Assert.False(history.IsDeleting);
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRevoke));
        // The list reloads on the core's history.changed, not here.
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryList)); // the load's only
    }

    [Fact]
    public async Task RevokeInsteadRevokesTheCapturedRecordAfterTheRevokeQuestion()
    {
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _confirm.Answer(ConfirmChoice.Alternate);
        _confirm.Answer(ConfirmChoice.Confirm);
        var revoked = List([1, 2, 3], revoked: [1]);
        _fake.Respond(RpcMethod.HistoryList, revoked);
        _fake.Respond(RpcMethod.HistoryRevoke, s_submitted);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.Equal([DeleteQuestion(1), RevokeQuestion(1)], _confirm.Questions);
        Assert.Equal(["{\"payloadSha256\":\"hash1\"}"], _fake.Params(RpcMethod.HistoryRevoke));
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryDeleteEntry));
        Assert.Same(revoked, history.Snapshot);
        Assert.False(history.IsRevoking);
        Assert.Equal(new AlertState("Revocation Submitted", "PR #12 opened."), _alerts.Current);
    }

    [Fact]
    public async Task DecliningTheRevokeQuestionAfterRevokeInsteadDoesNothing()
    {
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _confirm.Answer(ConfirmChoice.Alternate);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.Equal([DeleteQuestion(1), RevokeQuestion(1)], _confirm.Questions);
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRevoke));
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryDeleteEntry));
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task RevokeInsteadWhileLoggedOutStartsTheLogin()
    {
        var history = await Selected(0, List([1, 2, 3], revokeAvailable: false));
        Assert.False(history.RevokeCommand.CanExecute(null));
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _confirm.Answer(ConfirmChoice.Alternate);
        _confirm.Answer(ConfirmChoice.Confirm);
        _fake.Fail(RpcMethod.HistoryRevoke, new RpcException(RpcErrorCode.NotLoggedIn, "Not logged in to GitHub."));
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedIn);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.Equal([RpcMethod.HistoryRevoke, RpcMethod.AuthLogin], _fake.Methods.TakeLast(2));
        Assert.False(history.IsRevoking);
        Assert.Equal("Logged in as @octocat", history.Status);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task RevokeInsteadWithTheRevocationListNotLoadedShowsRevocationFailed()
    {
        const string Message = "The revocation list has not loaded yet.";
        var history = await Selected(0, List([1, 2, 3], revokeAvailable: false, revocationsUnavailable: true));
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _confirm.Answer(ConfirmChoice.Alternate);
        _confirm.Answer(ConfirmChoice.Confirm);
        _fake.Fail(RpcMethod.HistoryRevoke, new RpcException(RpcErrorCode.Failed, Message));
        await history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Revocation Failed", Message, OffersErrorLogExport: true), _alerts.Current);
        Assert.False(history.IsRevoking);
        Assert.Equal(0, _fake.Count(RpcMethod.AuthLogin));
    }

    [Fact]
    public async Task HistoryChangedWhileTheQuestionIsOpenStillDeletesTheCapturedRecord()
    {
        var history = await Selected(1);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        _fake.Respond(RpcMethod.HistoryDeleteEntry, s_deleted);
        var moved = List([4, 1, 2, 3]);
        _fake.Respond(RpcMethod.HistoryList, moved);
        Task changed = Task.CompletedTask;
        _confirm.OnAsk = _ => changed = history.HistoryChangedAsync();
        _confirm.Answer(ConfirmChoice.Confirm);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        await changed;
        Assert.Same(moved, history.Snapshot);
        Assert.Null(history.SelectedIndex);
        Assert.Equal([RecordJson(2)], _fake.Params(RpcMethod.HistoryDeleteEntry));
        Assert.Equal(new AlertState("Core Deleted Title", "Core says: deleted it."), _alerts.Current);
        // The deletion's own history.changed: the record was found in the
        // moved rows, so the row now in its place is selected.
        _fake.Reset(RpcMethod.HistoryList);
        _fake.Respond(RpcMethod.HistoryList, List([4, 1, 3]));
        await history.HistoryChangedAsync();
        Assert.Equal(2, history.SelectedIndex);
    }

    [Fact]
    public async Task HistoryChangedWhileTheQuestionIsOpenStillRevokesTheCapturedRecord()
    {
        var history = await Selected(1);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        _fake.Respond(RpcMethod.HistoryRevoke, s_submitted);
        var moved = List([4, 1, 2, 3]);
        _fake.Respond(RpcMethod.HistoryList, moved);
        Task changed = Task.CompletedTask;
        _confirm.OnAsk = question =>
        {
            if (question.Title == HistoryViewModel.DeleteRecordConfirmTitle)
            {
                changed = history.HistoryChangedAsync();
            }
        };
        _confirm.Answer(ConfirmChoice.Alternate);
        _confirm.Answer(ConfirmChoice.Confirm);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        await changed;
        Assert.Equal([DeleteQuestion(2), RevokeQuestion(2)], _confirm.Questions);
        Assert.Equal(["{\"payloadSha256\":\"hash2\"}"], _fake.Params(RpcMethod.HistoryRevoke));
        Assert.Equal([RecordJson(2), RecordJson(2), RecordJson(2)], _fake.Params(RpcMethod.HistoryRecordText));
        Assert.Equal(new AlertState("Revocation Submitted", "PR #12 opened."), _alerts.Current);
    }

    [Fact]
    public async Task ARecordNoLongerInTheLogShowsRecordNotFound()
    {
        const string Message = "This record is no longer in the issuance log.";
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _fake.Fail(RpcMethod.HistoryDeleteEntry, new RpcException(RpcErrorCode.NotFound, Message));
        _confirm.Answer(ConfirmChoice.Confirm);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Record Not Found", Message), _alerts.Current);
        Assert.False(_alerts.Current!.OffersErrorLogExport);
        Assert.False(history.IsDeleting);
    }

    [Theory]
    [InlineData("failed")]
    [InlineData("input")]
    [InlineData("internal")]
    [InlineData("future")]
    public async Task AnyOtherDeleteFailureShowsDeleteFailedOfferingTheErrorLog(string code)
    {
        const string Message = "Could not delete the record. The issuance log was not changed.";
        var history = await Selected(0);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(1));
        _fake.Fail(RpcMethod.HistoryDeleteEntry, new RpcException(code, Message));
        _confirm.Answer(ConfirmChoice.Confirm);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Delete Failed", Message, OffersErrorLogExport: true), _alerts.Current);
        Assert.False(history.IsDeleting);
        Assert.True(history.DeleteEntryCommand.CanExecute(null));
    }

    /// <summary>
    /// A model with <paramref name="row"/> of <paramref name="list"/> deleted
    /// (row n holding record n + 1); its history.changed is not raised yet.
    /// </summary>
    private async Task<HistoryViewModel> DeletedRow(int row, HistoryListResult? list = null)
    {
        var history = await Selected(row, list);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(row + 1));
        _fake.Respond(RpcMethod.HistoryDeleteEntry, s_deleted);
        _confirm.Answer(ConfirmChoice.Confirm);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        _fake.Reset(RpcMethod.HistoryRecordText);
        return history;
    }

    [Fact]
    public async Task AfterADeletionTheRowInItsPlaceIsSelectedWithItsDetail()
    {
        var history = await DeletedRow(1);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(3));
        _fake.Respond(RpcMethod.HistoryList, List([1, 3]));
        await history.HistoryChangedAsync();
        Assert.Equal(1, history.SelectedIndex);
        Assert.Equal(RecordJson(3), _fake.Params(RpcMethod.HistoryRecordText)[^1]);
        Assert.Equal("Detail of record 3", history.SelectedDetail);
    }

    [Fact]
    public async Task AfterDeletingTheLastRowTheNewLastRowIsSelected()
    {
        var history = await DeletedRow(2);
        _fake.Respond(RpcMethod.HistoryList, List([1, 2]));
        await history.HistoryChangedAsync();
        Assert.Equal(1, history.SelectedIndex);
    }

    [Fact]
    public async Task AfterDeletingTheOnlyRowNothingIsSelected()
    {
        var history = await DeletedRow(0, List([1]));
        var empty = List([]);
        _fake.Respond(RpcMethod.HistoryList, empty);
        await history.HistoryChangedAsync();
        Assert.Same(empty, history.Snapshot);
        Assert.Null(history.SelectedIndex);
        Assert.Null(history.SelectedDetail);
        // Taken by that read: a later issuance selects nothing.
        _fake.Respond(RpcMethod.HistoryList, List([5]));
        await history.HistoryChangedAsync();
        Assert.Null(history.SelectedIndex);
    }

    [Fact]
    public async Task ARereadShowingTheDeletionFirstStillSelectsTheRowInItsPlace()
    {
        // A revocations or login re-read lands after the core's write but
        // before its history.changed: that one then reads the same rows.
        var history = await DeletedRow(1);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(3));
        var rows = List([1, 3]);
        _fake.Respond(RpcMethod.HistoryList, rows);
        await history.RereadAsync();
        Assert.Same(rows, history.Snapshot);
        await history.HistoryChangedAsync();
        Assert.Equal(1, history.SelectedIndex);
        Assert.Equal(RecordJson(3), _fake.Params(RpcMethod.HistoryRecordText)[^1]);
        Assert.Equal("Detail of record 3", history.SelectedDetail);
        // Taken: a later change selects nothing.
        _fake.Reset(RpcMethod.HistoryList);
        _fake.Respond(RpcMethod.HistoryList, List([1, 3, 4]));
        await history.HistoryChangedAsync();
        Assert.Null(history.SelectedIndex);
    }

    [Fact]
    public async Task AHistoryChangedStillHoldingTheDeletedRecordDoesNotTakeItsPlace()
    {
        // An unrelated history.changed read before the core's write.
        var history = await DeletedRow(1);
        _fake.Respond(RpcMethod.HistoryList, List([1, 2, 3]));
        await history.HistoryChangedAsync();
        Assert.Null(history.SelectedIndex);
        _fake.Reset(RpcMethod.HistoryList);
        _fake.Respond(RpcMethod.HistoryList, List([1, 3]));
        await history.HistoryChangedAsync();
        Assert.Equal(1, history.SelectedIndex);
    }

    [Fact]
    public async Task ADeletionDuringAPendingSearchSelectsNothingAfterIt()
    {
        // A row picked from the old rows while the search waits for typing to
        // pause: its position is not in the rows the search reads.
        var history = await Selected(1);
        history.Query = "Recipient";
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        await history.SelectAsync(1);
        Assert.Equal(1, history.SelectedIndex);
        _fake.Respond(RpcMethod.HistoryDeleteEntry, s_deleted);
        _confirm.Answer(ConfirmChoice.Confirm);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryDeleteEntry));
        var rows = List([1, 3]);
        _fake.Respond(RpcMethod.HistoryList, rows);
        await history.HistoryChangedAsync();
        Assert.Same(rows, history.Snapshot);
        Assert.Null(history.SelectedIndex);
    }

    [Fact]
    public async Task HistoryChangedBeforeTheDeleteReplyStillSelectsTheRowInItsPlace()
    {
        var history = await Selected(1);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        var held = _fake.Hold(RpcMethod.HistoryDeleteEntry);
        _confirm.Answer(ConfirmChoice.Confirm);
        var deleting = history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.HistoryDeleteEntry) == 1));
        _fake.Reset(RpcMethod.HistoryRecordText);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(3));
        _fake.Respond(RpcMethod.HistoryList, List([1, 3]));
        await history.HistoryChangedAsync();
        held.Release(s_deleted);
        await Bounded(deleting);
        Assert.Equal(1, history.SelectedIndex);
        Assert.Equal(RecordJson(3), _fake.Params(RpcMethod.HistoryRecordText)[^1]);
        Assert.Equal("Detail of record 3", history.SelectedDetail);
    }

    [Fact]
    public async Task DeletingTheLaterOfTwoIdenticalDuplicatesKeepsTheSelectionInPlace()
    {
        // The first identical copy is row 0: the first-match rule alone would give 0.
        var history = await DeletedRow(1, List([2, 2, 3]));
        Assert.Equal([RecordJson(2)], _fake.Params(RpcMethod.HistoryDeleteEntry));
        _fake.Respond(RpcMethod.HistoryList, List([2, 3]));
        await history.HistoryChangedAsync();
        Assert.Equal(1, history.SelectedIndex);
    }

    [Fact]
    public async Task OnlyTheAppliedReadAfterADeletionTakesItsPlace()
    {
        var history = await DeletedRow(3, List([1, 2, 3, 4, 5]));
        var shown = history.Snapshot;
        var superseded = _fake.Hold(RpcMethod.HistoryList);
        var latest = _fake.Hold(RpcMethod.HistoryList);
        var first = history.HistoryChangedAsync();
        var second = history.HistoryChangedAsync();
        superseded.Release(List([1, 2]));
        await Bounded(first);
        Assert.Same(shown, history.Snapshot);
        Assert.Null(history.SelectedIndex);
        var rows = List([1, 2, 3, 5]);
        latest.Release(rows);
        await Bounded(second);
        Assert.Same(rows, history.Snapshot);
        Assert.Equal(3, history.SelectedIndex);
    }

    [Theory]
    [InlineData("notFound")]
    [InlineData("failed")]
    public async Task AFailedDeletionSelectsNothingOnTheNextHistoryChanged(string code)
    {
        var history = await Selected(1);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        _fake.Fail(RpcMethod.HistoryDeleteEntry, new RpcException(code, "no"));
        _confirm.Answer(ConfirmChoice.Confirm);
        await history.DeleteEntryCommand.ExecuteAsync(null);
        var rows = List([1, 3]);
        _fake.Respond(RpcMethod.HistoryList, rows);
        await history.HistoryChangedAsync();
        Assert.Same(rows, history.Snapshot);
        Assert.Null(history.SelectedIndex);
    }

    [Fact]
    public async Task ASearchChangedWhileDeletingSelectsNothingAfterIt()
    {
        var history = await Selected(1);
        _fake.Respond(RpcMethod.HistoryRecordText, Text(2));
        var held = _fake.Hold(RpcMethod.HistoryDeleteEntry);
        _confirm.Answer(ConfirmChoice.Confirm);
        var deleting = history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.HistoryDeleteEntry) == 1));
        history.Query = "Recipient";
        held.Release(s_deleted);
        await Bounded(deleting);
        var rows = List([1, 3]);
        _fake.Respond(RpcMethod.HistoryList, rows);
        await history.HistoryChangedAsync();
        Assert.Same(rows, history.Snapshot);
        Assert.Null(history.SelectedIndex);
    }

    [Fact]
    public async Task ARecordTextFailureBeforeDeletingShowsTheCoresErrorAndAsksNothing()
    {
        var history = await Selected(0);
        _fake.Fail(RpcMethod.HistoryRecordText, new RpcException(RpcErrorCode.Failed, "no text"));
        await history.DeleteEntryCommand.ExecuteAsync(null);
        Assert.Empty(_confirm.Questions);
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryDeleteEntry));
        Assert.Equal(new AlertState("Error", "no text"), _alerts.Current);
    }

    // Export Issuance Log…

    [Theory]
    [InlineData(0, "rhg-issuances-2026-01-01.json")]
    [InlineData(4, "rhg-issuances-2026-01-02.json")] // Tbilisi
    [InlineData(-8, "rhg-issuances-2026-01-01.json")] // Los Angeles
    public void TheExportIsNamedByTodaysDateInTheMachinesTimeZone(int offsetHours, string name)
    {
        var zone = TimeZoneInfo.CreateCustomTimeZone("test", TimeSpan.FromHours(offsetHours), "test", "test");
        var history = NewModel(new FixedClock(Fixtures.LateNewYearsDay, zone)); // 2026-01-01T23:30Z
        Assert.Equal(name, history.SuggestedExportFilename);
    }

    [Fact]
    public void WithoutAClockTheExportIsNamedByTheSystemsDate()
    {
        var login = new LoginViewModel(_fake, _confirm, new FakeClipboard(), new FakeUrlOpener(), _alerts);
        var history = new HistoryViewModel(_fake, login, _confirm, _fileSave, _alerts);
        var before = DisplayDate.Ymd(TimeProvider.System.GetLocalNow().DateTime);
        var name = history.SuggestedExportFilename;
        var after = DisplayDate.Ymd(TimeProvider.System.GetLocalNow().DateTime);
        Assert.Contains(name, new[] { $"rhg-issuances-{before}.json", $"rhg-issuances-{after}.json" });
    }

    [Fact]
    public async Task ACancelledExportDoesNothing()
    {
        var history = NewModel();
        await history.ExportIssuanceLogCommand.ExecuteAsync(null);
        Assert.Equal([("rhg-issuances-2026-01-01.json", "json")], _fileSave.Requests);
        Assert.Empty(_fake.Calls);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task AnExportShowsTheCoresAlertAsGiven()
    {
        _fake.Respond(RpcMethod.HistoryExportIssuanceLog, new ExportResult("Core Export Title", "Core says: saved it."));
        _fileSave.Answer("/out/log.json");
        var history = NewModel();
        await history.ExportIssuanceLogCommand.ExecuteAsync(null);
        Assert.Equal(["{\"path\":\"/out/log.json\"}"], _fake.Params(RpcMethod.HistoryExportIssuanceLog));
        Assert.Equal(new AlertState("Core Export Title", "Core says: saved it."), _alerts.Current);
    }

    [Fact]
    public async Task NothingToExportShowsItsOwnAlert()
    {
        _fake.Fail(RpcMethod.HistoryExportIssuanceLog, new RpcException(RpcErrorCode.NothingToExport, "No issuances yet."));
        _fileSave.Answer("/out/log.json");
        var history = NewModel();
        await history.ExportIssuanceLogCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Nothing to Export", "No issuances yet."), _alerts.Current);
        Assert.False(_alerts.Current!.IsError);
    }

    [Fact]
    public async Task AnyOtherExportFailureShowsTheCoresError()
    {
        _fake.Fail(RpcMethod.HistoryExportIssuanceLog, new RpcException(RpcErrorCode.Failed, "Disk full."));
        _fileSave.Answer("/out/log.json");
        var history = NewModel();
        await history.ExportIssuanceLogCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Error", "Disk full."), _alerts.Current);
    }

    // Remove Duplicates…

    [Fact]
    public async Task NoDuplicatesInThePreviewAsksNothing()
    {
        _fake.Respond(RpcMethod.HistoryDuplicatePreview, new DuplicatePreviewResult(0, ""));
        var history = NewModel();
        await history.RemoveDuplicatesCommand.ExecuteAsync(null);
        Assert.Empty(_confirm.Questions);
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRemoveDuplicates));
        Assert.Equal(new AlertState("No Duplicates", "The issuance log has no duplicate entries."), _alerts.Current);
    }

    [Fact]
    public async Task DecliningTheRemovalRemovesNothing()
    {
        _fake.Respond(RpcMethod.HistoryDuplicatePreview, new DuplicatePreviewResult(2, "Remove 2 duplicate entries?"));
        var history = NewModel();
        await history.RemoveDuplicatesCommand.ExecuteAsync(null);
        Assert.Equal(
            [new Confirmation("Remove Duplicates", "Remove 2 duplicate entries?", "Remove Entries", "Cancel", IsDestructive: true)],
            _confirm.Questions);
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryRemoveDuplicates));
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task ConfirmedRemovalShowsTheCoresReport()
    {
        _fake.Respond(RpcMethod.HistoryDuplicatePreview, new DuplicatePreviewResult(2, "Remove 2 duplicate entries?"));
        _fake.Respond(RpcMethod.HistoryRemoveDuplicates, new RemoveDuplicatesResult(2, "/data/log.bak", "Removed 2 entries."));
        _confirm.Answer(true);
        var history = NewModel();
        await history.RemoveDuplicatesCommand.ExecuteAsync(null);
        Assert.Equal(1, _fake.Count(RpcMethod.HistoryRemoveDuplicates));
        Assert.Equal(new AlertState("Duplicates Removed", "Removed 2 entries."), _alerts.Current);
        // The list reloads on the core's history.changed, not here.
        Assert.Equal(0, _fake.Count(RpcMethod.HistoryList));
    }

    [Fact]
    public async Task NothingRemovedAfterConfirmingSaysNoDuplicates()
    {
        _fake.Respond(RpcMethod.HistoryDuplicatePreview, new DuplicatePreviewResult(1, "Remove 1 duplicate entry?"));
        _fake.Respond(RpcMethod.HistoryRemoveDuplicates, new RemoveDuplicatesResult(0, "", ""));
        _confirm.Answer(true);
        var history = NewModel();
        await history.RemoveDuplicatesCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("No Duplicates", "The issuance log has no duplicate entries."), _alerts.Current);
    }

    [Fact]
    public async Task APreviewFailureShowsRemoveDuplicatesFailedOfferingTheErrorLog()
    {
        _fake.Fail(RpcMethod.HistoryDuplicatePreview, new RpcException(RpcErrorCode.Failed, "Cannot read the log."));
        var history = NewModel();
        await history.RemoveDuplicatesCommand.ExecuteAsync(null);
        Assert.Empty(_confirm.Questions);
        Assert.Equal(
            new AlertState("Remove Duplicates Failed", "Cannot read the log.", OffersErrorLogExport: true), _alerts.Current);
    }

    [Fact]
    public async Task ARemovalFailureShowsRemoveDuplicatesFailedOfferingTheErrorLog()
    {
        _fake.Respond(RpcMethod.HistoryDuplicatePreview, new DuplicatePreviewResult(1, "Remove 1 duplicate entry?"));
        _fake.Fail(RpcMethod.HistoryRemoveDuplicates, new RpcException(RpcErrorCode.Failed, "Cannot back up the log."));
        _confirm.Answer(true);
        var history = NewModel();
        await history.RemoveDuplicatesCommand.ExecuteAsync(null);
        Assert.Equal(
            new AlertState("Remove Duplicates Failed", "Cannot back up the log.", OffersErrorLogExport: true), _alerts.Current);
    }
}
