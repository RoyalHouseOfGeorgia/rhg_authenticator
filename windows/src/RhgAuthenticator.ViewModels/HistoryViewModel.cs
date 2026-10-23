using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>
/// The History tab: the issuance log with its search, the selected record's
/// detail, Refresh, Revoke, Export Issuance Log… and Remove Duplicates…. The
/// core reads, filters, words and revokes; this view model shows what it
/// returns.
/// </summary>
public sealed partial class HistoryViewModel : ObservableObject
{
#pragma warning disable CS1591 // UI copy; each constant's name says where it shows.
    public const string SearchPlaceholder = "Search by recipient...";
    public const string RefreshTitle = "Refresh";
    public const string RevokeTitle = "Revoke";
    public const string ExportTitle = "Export Issuance Log…";
    public const string RemoveDuplicatesTitle = "Remove Duplicates…";
    public const string RevocationUnavailableStatus = "Revocation unavailable";
    public const string EmptyDetailText = "Select a record to see its details.";
    public const string ConfirmRevocationTitle = "Confirm Revocation";
    public const string SessionExpiredTitle = "Session Expired";
    public const string RevocationFailedTitle = "Revocation Failed";
    public const string NothingToExportTitle = "Nothing to Export";
    public const string RemoveDuplicatesConfirmTitle = "Remove Duplicates";
    public const string RemoveEntriesTitle = "Remove Entries";
    public const string NoDuplicatesTitle = "No Duplicates";
    public const string NoDuplicatesMessage = "The issuance log has no duplicate entries.";
    public const string DuplicatesRemovedTitle = "Duplicates Removed";
    public const string RemoveDuplicatesFailedTitle = "Remove Duplicates Failed";
    public const string LoadFailedMessage = "unable to load history";
#pragma warning restore CS1591

    /// <summary>How long the search waits for typing to pause before re-reading.</summary>
    public static readonly TimeSpan SearchDebounce = TimeSpan.FromMilliseconds(200);

    private readonly IBridge _bridge;
    private readonly IConfirmService _confirm;
    private readonly IFileSaveService _fileSave;
    private readonly AlertQueue _alerts;
    private readonly TimeProvider _clock;

    /// <summary>Counts list reads, so only the latest one is applied.</summary>
    private int _listReads;

    /// <summary>Counts detail reads, so only the latest one is applied (a cleared selection drops them all).</summary>
    private int _detailReads;

    /// <summary>
    /// The record whose detail was last asked for (history.recordText), kept
    /// after a failed read so a re-read of the same rows does not ask again.
    /// </summary>
    private HistoryRecord? _detailRecord;

    /// <summary>
    /// The rows are being replaced (history.changed, a new search, a
    /// revocation): the next read applied clears the selection if its rows
    /// differ, so a row picked from the old rows meanwhile is not carried
    /// onto the new ones.
    /// </summary>
    private bool _rowsReplaced;

    /// <summary>history.changed: the next read applied reports a log that failed to load.</summary>
    private bool _reportLoadFailure;

    /// <summary>Cancels the pending debounced search.</summary>
    private CancellationTokenSource? _searchCancel;

    /// <summary>
    /// Creates the tab's view model, posting its alerts to
    /// <paramref name="alerts"/>. <paramref name="login"/>'s status texts land
    /// on <see cref="Status"/>; a refused revocation starts it.
    /// <paramref name="clock"/> (default the system clock) times the search's
    /// pause and names the exported log.
    /// </summary>
    public HistoryViewModel(
        IBridge bridge,
        LoginViewModel login,
        IConfirmService confirm,
        IFileSaveService fileSave,
        AlertQueue alerts,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        ArgumentNullException.ThrowIfNull(login);
        ArgumentNullException.ThrowIfNull(confirm);
        ArgumentNullException.ThrowIfNull(fileSave);
        ArgumentNullException.ThrowIfNull(alerts);
        _bridge = bridge;
        Login = login;
        _confirm = confirm;
        _fileSave = fileSave;
        _alerts = alerts;
        _clock = clock ?? TimeProvider.System;
        login.StatusChanged += text => Status = text;
    }

    /// <summary>The GitHub login, whose button sits on this tab too.</summary>
    public LoginViewModel Login { get; }

    /// <summary>The log as last read, filtered by <see cref="Query"/>; empty and not loaded until app.start's history.changed.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RevocationStatus))]
    [NotifyCanExecuteChangedFor(nameof(RevokeCommand))]
    public partial HistoryListResult Snapshot { get; private set; } = new(
        Rows: [], LoadFailed: false, RevocationsUnavailable: false, RevocationsLoaded: false, RevokeAvailable: false);

    /// <summary>
    /// The search text (two-way bound). A change clears the selection at once
    /// and re-reads once typing pauses for <see cref="SearchDebounce"/>; a
    /// newer change supersedes a pending one.
    /// </summary>
    [ObservableProperty]
    public partial string Query { get; set; } = "";

    /// <summary>
    /// The selected row's index in the snapshot's rows; null when none is. An
    /// index, not a credential id: duplicate rows share a payload hash.
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RevokeCommand))]
    public partial int? SelectedIndex { get; private set; }

    /// <summary>The selected record's detail (history.recordText); null shows <see cref="EmptyDetailText"/>.</summary>
    [ObservableProperty]
    public partial string? SelectedDetail { get; private set; }

    /// <summary>The status line; the login's status texts land here.</summary>
    [ObservableProperty]
    public partial string Status { get; private set; } = "";

    /// <summary>A revocation is being submitted; Revoke stays disabled.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RevokeCommand))]
    public partial bool IsRevoking { get; private set; }

    /// <summary><see cref="RevocationUnavailableStatus"/> when the revocation list could not be fetched; "" otherwise.</summary>
    public string RevocationStatus => Snapshot.RevocationsUnavailable ? RevocationUnavailableStatus : "";

    /// <summary>
    /// The export's suggested file name, rhg-issuances-YYYY-MM-DD.json, by
    /// today's date in the machine's time zone.
    /// </summary>
    public string SuggestedExportFilename => $"rhg-issuances-{DisplayDate.Ymd(_clock.GetLocalNow().DateTime)}.json";

    /// <summary>The pending debounced search: it ends once its re-read has, or once it is superseded.</summary>
    internal Task PendingSearch { get; private set; } = Task.CompletedTask;

    /// <summary>
    /// The operator selected a row (mouse or arrow keys): shows its record's
    /// detail (history.recordText). Null or out of range clears the selection.
    /// The previous detail stays until the new one arrives; only the latest
    /// selection's reply is applied, and a failure clears the detail and
    /// shows the core's error.
    /// </summary>
    public async Task SelectAsync(int? row)
    {
        if (row is not { } index || index < 0 || index >= Snapshot.Rows.Count)
        {
            ClearSelection();
            return;
        }
        SelectedIndex = index;
        await ShowDetailAsync(index);
    }

    /// <summary>
    /// history.changed: the log was re-read, so its rows may have moved. Clears
    /// the selection, arms the report of a log that failed to load, and
    /// re-reads the log (<see cref="RereadAsync"/>).
    /// </summary>
    internal Task HistoryChangedAsync()
    {
        BeginRowsReplacement();
        _reportLoadFailure = true;
        return RereadAsync();
    }

    /// <summary>
    /// Re-reads the log for the current search (history.changed,
    /// history.revocationsChanged, auth.changed). The selected row stays while
    /// it is in range, unless the rows were replaced meanwhile; its detail is
    /// re-read when its record changed. Only the latest read is applied; a
    /// failed one keeps the current rows and leaves a pending replacement and
    /// load-failure report to the next read applied. A read equal to the rows
    /// shown keeps <see cref="Snapshot"/>, so the list is not rebuilt.
    /// </summary>
    internal async Task RereadAsync()
    {
        var read = ++_listReads;
        HistoryListResult latest;
        try
        {
            latest = await _bridge.ListHistoryAsync(Query);
        }
        catch (RpcException)
        {
            return;
        }
        if (read != _listReads)
        {
            return;
        }
        // The selection is settled before the rows are shown, so the list
        // never shows a stale selection on the new rows. Rows equal to those
        // shown replace nothing: a row picked meanwhile is the same record.
        var same = SameList(latest, Snapshot);
        int? reread = null;
        if (_rowsReplaced)
        {
            _rowsReplaced = false;
            if (!same)
            {
                ClearSelection();
            }
        }
        if (SelectedIndex is { } index)
        {
            if (index >= latest.Rows.Count)
            {
                ClearSelection();
            }
            else if (latest.Rows[index].Record != _detailRecord)
            {
                reread = index;
            }
        }
        if (!same)
        {
            Snapshot = latest;
        }
        if (_reportLoadFailure)
        {
            _reportLoadFailure = false;
            if (latest.LoadFailed)
            {
                _alerts.Show(new AlertState(AlertState.ErrorTitle, LoadFailedMessage));
            }
        }
        if (reread is { } row)
        {
            await ShowDetailAsync(row);
        }
    }

    partial void OnQueryChanged(string value)
    {
        // Any read from now on is for the new search, so its rows reorder.
        BeginRowsReplacement();
        var previous = _searchCancel;
        _searchCancel = new CancellationTokenSource();
        previous?.Cancel();
        previous?.Dispose();
        PendingSearch = SearchAsync(_searchCancel.Token);
    }

    private async Task SearchAsync(CancellationToken token)
    {
        try
        {
            await Task.Delay(SearchDebounce, _clock, token);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        await RereadAsync();
    }

    /// <summary>Refresh: re-reads the log and the revocation list (history.refresh); the results arrive as events.</summary>
    [RelayCommand]
    private async Task RefreshAsync()
    {
        try
        {
            await _bridge.RefreshHistoryAsync();
        }
        catch (RpcException error)
        {
            _alerts.Show(AlertState.Error(error));
        }
    }

    private bool CanRevoke()
    {
        return !IsRevoking
            && Snapshot.RevokeAvailable
            && SelectedIndex is { } index
            && index < Snapshot.Rows.Count
            && !Snapshot.Rows[index].Revoked;
    }

    /// <summary>
    /// Revoke: asks the core's question about the selected record, then opens
    /// a revocation pull request (history.revoke) and shows the outcome the
    /// core words. Enabled for a selected, unrevoked row when the core allows
    /// revoking and no revocation is being submitted.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanRevoke))]
    private async Task RevokeAsync()
    {
        if (!CanRevoke())
        {
            return;
        }
        var record = Snapshot.Rows[SelectedIndex!.Value].Record;
        RecordTextResult text;
        try
        {
            text = await _bridge.RecordTextAsync(record);
        }
        catch (RpcException error)
        {
            _alerts.Show(AlertState.Error(error));
            return;
        }
        var question = new Confirmation(ConfirmRevocationTitle, text.RevokeConfirm, RevokeTitle, IsDestructive: true);
        if (!_confirm.Ask(question))
        {
            return;
        }
        IsRevoking = true;
        RevokeResult result;
        try
        {
            result = await _bridge.RevokeAsync(record.PayloadSha256);
        }
        catch (RpcException error)
        {
            IsRevoking = false;
            switch (error.Code)
            {
                case RpcErrorCode.Busy:
                    // The running revocation reports its own outcome.
                    break;
                case RpcErrorCode.NotLoggedIn:
                    await Login.StartAsync();
                    break;
                case RpcErrorCode.SessionExpired:
                    // The core has logged out; log in again once the alert closes.
                    _alerts.Show(new AlertState(SessionExpiredTitle, error.Message), Login.StartAsync);
                    break;
                default:
                    _alerts.Show(new AlertState(RevocationFailedTitle, error.Message, OffersErrorLogExport: true));
                    break;
            }
            return;
        }
        IsRevoking = false;
        // The row now reads revoked.
        BeginRowsReplacement();
        await RereadAsync();
        _alerts.Show(new AlertState(result.Title, result.Message));
    }

    /// <summary>
    /// Export Issuance Log…: asks where, then copies the log there
    /// (history.exportIssuanceLog) and shows the core's alert saying where it went.
    /// </summary>
    [RelayCommand]
    private async Task ExportIssuanceLogAsync()
    {
        if (_fileSave.ChooseSavePath(SuggestedExportFilename, "json") is not { } path)
        {
            return;
        }
        ExportResult result;
        try
        {
            result = await _bridge.ExportIssuanceLogAsync(path);
        }
        catch (RpcException error)
        {
            _alerts.Show(error.Code == RpcErrorCode.NothingToExport
                ? new AlertState(NothingToExportTitle, error.Message)
                : AlertState.Error(error));
            return;
        }
        _alerts.Show(new AlertState(result.Title, result.Message));
    }

    /// <summary>
    /// Remove Duplicates…: counts the duplicates (history.duplicatePreview),
    /// asks the core's question, then removes them (history.removeDuplicates)
    /// and shows the core's report; the list reloads on history.changed.
    /// </summary>
    [RelayCommand]
    private async Task RemoveDuplicatesAsync()
    {
        DuplicatePreviewResult preview;
        try
        {
            preview = await _bridge.DuplicatePreviewAsync();
        }
        catch (RpcException error)
        {
            ShowDedupeFailure(error);
            return;
        }
        if (preview.Count <= 0)
        {
            ShowNoDuplicates();
            return;
        }
        var question = new Confirmation(
            RemoveDuplicatesConfirmTitle, preview.ConfirmMessage, RemoveEntriesTitle, IsDestructive: true);
        if (!_confirm.Ask(question))
        {
            return;
        }
        RemoveDuplicatesResult result;
        try
        {
            result = await _bridge.RemoveDuplicatesAsync();
        }
        catch (RpcException error)
        {
            ShowDedupeFailure(error);
            return;
        }
        if (result.Removed <= 0)
        {
            // The log changed between the preview and the confirm.
            ShowNoDuplicates();
            return;
        }
        _alerts.Show(new AlertState(DuplicatesRemovedTitle, result.Message));
    }

    /// <summary>Reads the detail of row <paramref name="index"/>'s record; only the latest detail read is applied.</summary>
    private async Task ShowDetailAsync(int index)
    {
        var read = ++_detailReads;
        var record = Snapshot.Rows[index].Record;
        _detailRecord = record;
        RecordTextResult text;
        try
        {
            text = await _bridge.RecordTextAsync(record);
        }
        catch (RpcException error)
        {
            if (read == _detailReads)
            {
                SelectedDetail = null;
                _alerts.Show(AlertState.Error(error));
            }
            return;
        }
        if (read == _detailReads)
        {
            SelectedDetail = text.Detail;
        }
    }

    /// <summary>No row is selected and no detail shown; detail reads still running are dropped.</summary>
    private void ClearSelection()
    {
        _detailReads++;
        _detailRecord = null;
        SelectedIndex = null;
        SelectedDetail = null;
    }

    /// <summary>
    /// The rows are about to be replaced: clears the selection now and once
    /// more when the next read lands with different rows, and drops every list read already sent,
    /// so only one sent from now on can land. Every caller follows with
    /// <see cref="RereadAsync"/> (directly or through the debounced search).
    /// </summary>
    private void BeginRowsReplacement()
    {
        ClearSelection();
        _rowsReplaced = true;
        _listReads++;
    }

    /// <summary>
    /// The two reads hold the same rows and the same other fields. Records
    /// compare lists by reference, and every history.list reply is a new list,
    /// so the rows are compared one by one and every other field by the record.
    /// </summary>
    private static bool SameList(HistoryListResult a, HistoryListResult b)
    {
        return a with { Rows = b.Rows } == b && a.Rows.SequenceEqual(b.Rows);
    }

    private void ShowDedupeFailure(RpcException error)
    {
        _alerts.Show(new AlertState(RemoveDuplicatesFailedTitle, error.Message, OffersErrorLogExport: true));
    }

    private void ShowNoDuplicates()
    {
        _alerts.Show(new AlertState(NoDuplicatesTitle, NoDuplicatesMessage));
    }
}
