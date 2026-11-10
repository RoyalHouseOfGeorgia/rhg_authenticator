using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>A selected table cell: <paramref name="Row"/> indexes the snapshot's entries and rows.</summary>
/// <param name="Row">The row.</param>
/// <param name="Column">The column, in registry.columns order.</param>
public readonly record struct RegistryCell(int Row, int Column);

/// <summary>
/// The Registry tab: the edited registry's table, Fetch from Server, Add and
/// Edit Entry, and Submit for Review. The core edits, validates and submits;
/// this view model shows what it returns.
/// </summary>
public sealed partial class RegistryViewModel : ObservableObject
{
#pragma warning disable CS1591 // UI copy; each constant's name says where it shows.
    public const string FetchTitle = "Fetch from Server";
    public const string FetchTooltip = FetchTitle + " (F5)";
    public const string SubmitTitle = "Submit for Review";
    public const string AddEntryTitle = EntryFormViewModel.AddTitle;
    public const string EditEntryTitle = EntryFormViewModel.EditTitle;
    public const string EditEntryTooltip = "Select an entry to edit it.";
    public const string LoadedStatus = "Loaded from registry server";
    public const string FetchingStatus = "Fetching...";
    public const string LoadFailedStatus = "Failed to load registry";
    public const string SubmittingStatus = "Creating pull request...";
    public const string SubmitBusyStatus = "Submit already in progress";
    public const string SessionExpiredTitle = "Session Expired";
    public const string RegistryChangedTitle = "Registry Changed";
    public const string SubmissionFailedTitle = "Submission Failed";
    public const string PullRequestCreatedTitle = "Pull Request Created";
#pragma warning restore CS1591

    /// <summary>Fetch from Server with unsubmitted edits.</summary>
    public static readonly Confirmation DiscardConfirmation = new(
        "Discard Local Edits?",
        "This will re-fetch the live registry from the server, discarding your local edits. Continue?",
        "Discard and Fetch",
        IsDestructive: true);

    private readonly IBridge _bridge;
    private readonly IConfirmService _confirm;
    private readonly IFileOpenService _fileOpen;
    private readonly IUrlOpener _urlOpener;
    private readonly AlertQueue _alerts;
    private readonly TimeProvider? _clock;

    /// <summary>Counts snapshot reads, so only the latest one is applied.</summary>
    private int _snapshotReads;

    /// <summary>
    /// Creates the tab's view model, posting its alerts to
    /// <paramref name="alerts"/>. <paramref name="login"/>'s status texts land
    /// on <see cref="Status"/>; Submit for Review starts it without a session.
    /// <paramref name="clock"/> (default the system clock) dates new entry forms.
    /// </summary>
    public RegistryViewModel(
        IBridge bridge,
        LoginViewModel login,
        IConfirmService confirm,
        IFileOpenService fileOpen,
        IUrlOpener urlOpener,
        AlertQueue alerts,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        ArgumentNullException.ThrowIfNull(login);
        ArgumentNullException.ThrowIfNull(confirm);
        ArgumentNullException.ThrowIfNull(fileOpen);
        ArgumentNullException.ThrowIfNull(urlOpener);
        ArgumentNullException.ThrowIfNull(alerts);
        _bridge = bridge;
        Login = login;
        _confirm = confirm;
        _fileOpen = fileOpen;
        _urlOpener = urlOpener;
        _alerts = alerts;
        _clock = clock;
        login.StatusChanged += text => Status = text;
    }

    /// <summary>The GitHub login, whose button sits on this tab.</summary>
    public LoginViewModel Login { get; }

    /// <summary>The table's column headings (registry.columns).</summary>
    [ObservableProperty]
    public partial IReadOnlyList<string> Columns { get; private set; } = [];

    /// <summary>The registry as edited; empty and not loaded until startup reads it.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(EditEntryCommand), nameof(SubmitForReviewCommand))]
    public partial RegistrySnapshot Snapshot { get; private set; } = new([], [], false, false);

    /// <summary>The selected cell; null when none is.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(EditEntryCommand))]
    public partial RegistryCell? SelectedCell { get; private set; }

    /// <summary>The status line; the login's status texts land here too.</summary>
    [ObservableProperty]
    public partial string Status { get; private set; } = "";

    /// <summary>
    /// Show the entry dialog while non-null; its buttons call
    /// <see cref="SubmitEntryAsync"/> and <see cref="CancelEntry"/>.
    /// </summary>
    [ObservableProperty]
    public partial EntryFormViewModel? EntryForm { get; private set; }

    /// <summary>
    /// Loads the columns and the registry (registry.columns,
    /// registry.snapshot). The registry may still be loading: app.start
    /// finishes it, ending in registry.changed.
    /// </summary>
    internal async Task LoadAsync()
    {
        Columns = await _bridge.RegistryColumnsAsync();
        var snapshot = await _bridge.RegistrySnapshotAsync();
        // Newer than any snapshot read still running.
        _snapshotReads++;
        Snapshot = snapshot;
        Status = snapshot.Loaded ? LoadedStatus : FetchingStatus;
    }

    /// <summary>registry.changed: a fetch (or the startup load) replaced the registry.</summary>
    internal async Task RegistryChangedAsync()
    {
        SelectedCell = null;
        if (await RefreshAsync())
        {
            Status = Snapshot.Loaded ? LoadedStatus : LoadFailedStatus;
        }
    }

    /// <summary>The operator selected a table cell: its text, if any, goes to the status line. Ignored out of range.</summary>
    public void SelectCell(int row, int column)
    {
        if (row < 0 || row >= Snapshot.Rows.Count || column < 0 || column >= Snapshot.Rows[row].Count)
        {
            return;
        }
        SelectedCell = new RegistryCell(row, column);
        var text = Snapshot.Rows[row][column];
        if (text.Length > 0)
        {
            Status = text;
        }
    }

    /// <summary>The operator deselected the cell (Ctrl+click): no entry is selected; the status line stays.</summary>
    public void ClearSelection()
    {
        SelectedCell = null;
    }

    /// <summary>
    /// Add / Save on the entry dialog: closes it and re-reads the registry once
    /// the core accepts the entry; else the dialog stays with the core's message.
    /// </summary>
    public async Task SubmitEntryAsync()
    {
        if (EntryForm is not { } form || !await form.SubmitAsync())
        {
            return;
        }
        if (EntryForm == form)
        {
            EntryForm = null;
        }
        await RefreshAsync();
    }

    /// <summary>Cancel on the entry dialog.</summary>
    public void CancelEntry()
    {
        EntryForm = null;
    }

    /// <summary>Fetch from Server: asks first when there are unsubmitted edits.</summary>
    [RelayCommand]
    private async Task FetchAsync()
    {
        if (Snapshot.Dirty && !_confirm.Ask(DiscardConfirmation))
        {
            return;
        }
        Status = FetchingStatus;
        try
        {
            // Success arrives as registry.changed.
            await _bridge.FetchRegistryAsync();
        }
        catch (RpcException)
        {
            Status = LoadFailedStatus;
        }
    }

    /// <summary>Add Entry: opens an empty entry dialog.</summary>
    [RelayCommand]
    private void AddEntry()
    {
        EntryForm = new EntryFormViewModel(_bridge, _fileOpen, _clock);
    }

    private bool CanEditEntry()
    {
        return SelectedCell is { Row: var row } && row < Snapshot.Entries.Count;
    }

    /// <summary>Edit Entry: opens the selected entry's dialog. Disabled with no entry selected (<see cref="EditEntryTooltip"/>).</summary>
    [RelayCommand(CanExecute = nameof(CanEditEntry))]
    private void EditEntry()
    {
        if (!CanEditEntry())
        {
            return;
        }
        var row = SelectedCell!.Value.Row;
        EntryForm = new EntryFormViewModel(_bridge, _fileOpen, row, Snapshot.Entries[row], _clock);
    }

    private bool CanSubmitForReview()
    {
        return Snapshot.Entries.Count > 0;
    }

    /// <summary>
    /// Submit for Review: opens a pull request with the edited registry
    /// (registry.submit), logging in first without a session. Disabled with
    /// no entries.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanSubmitForReview))]
    private async Task SubmitForReviewAsync()
    {
        if (!CanSubmitForReview())
        {
            return;
        }
        Status = SubmittingStatus;
        SubmitResult result;
        try
        {
            result = await _bridge.SubmitRegistryAsync();
        }
        catch (RpcException error)
        {
            switch (error.Code)
            {
                case RpcErrorCode.NotLoggedIn:
                    await Login.StartAsync();
                    break;
                case RpcErrorCode.Busy:
                    Status = SubmitBusyStatus;
                    break;
                case RpcErrorCode.SessionExpired:
                    // The core has logged out; log in again once the alert closes.
                    Status = "";
                    _alerts.Show(new AlertState(SessionExpiredTitle, error.Message), Login.StartAsync);
                    break;
                case RpcErrorCode.RegistryChanged:
                    Status = "";
                    _alerts.Show(new AlertState(RegistryChangedTitle, error.Message));
                    break;
                default:
                    Status = "";
                    _alerts.Show(new AlertState(SubmissionFailedTitle, error.Message, OffersErrorLogExport: true));
                    break;
            }
            return;
        }
        // The core is clean now but sends no registry.changed for a submit.
        await RefreshAsync();
        Status = $"PR #{result.PrNumber} created";
        var created = $"PR #{result.PrNumber} has been created.";
        if (HttpsUrl.Parse(result.Url) is { } url)
        {
            var question = new Confirmation(
                PullRequestCreatedTitle,
                created + "\n\nOpen in browser?",
                "Open in Browser",
                "Close");
            if (_confirm.Ask(question) && _urlOpener.Open(url) is { } failure)
            {
                _alerts.Show(new AlertState(AlertState.ErrorTitle, failure));
            }
        }
        else
        {
            _alerts.Show(new AlertState(PullRequestCreatedTitle, created));
        }
    }

    /// <summary>
    /// Re-reads the snapshot, keeping the selection while its row exists. A
    /// failed read keeps the current table. Returns false when a newer read
    /// started meanwhile; its result is then dropped.
    /// </summary>
    private async Task<bool> RefreshAsync()
    {
        var read = ++_snapshotReads;
        RegistrySnapshot? latest;
        try
        {
            latest = await _bridge.RegistrySnapshotAsync();
        }
        catch (RpcException)
        {
            latest = null;
        }
        if (read != _snapshotReads)
        {
            return false;
        }
        if (latest is not null)
        {
            Snapshot = latest;
            if (SelectedCell is { Row: var row } && row >= latest.Rows.Count)
            {
                SelectedCell = null;
            }
        }
        return true;
    }
}
