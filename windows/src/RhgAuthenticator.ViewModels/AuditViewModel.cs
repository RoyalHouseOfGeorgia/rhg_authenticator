using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>
/// The Audit tab: the registry's GitHub commit history; Open on GitHub opens
/// the selected commit's page. The core fetches and words the rows; this view
/// model shows them.
/// </summary>
public sealed partial class AuditViewModel : ObservableObject
{
#pragma warning disable CS1591 // UI copy; each constant's name says where it shows.
    public const string RefreshTitle = "Refresh";
    public const string OpenTitle = "Open on GitHub";
    public const string OpenTooltip = "Select a commit to open it.";
    public const string FetchingStatus = "Fetching...";
#pragma warning restore CS1591

    private readonly IBridge _bridge;
    private readonly IUrlOpener _urlOpener;
    private readonly AlertQueue _alerts;

    /// <summary>Creates the tab's view model, posting its alerts to <paramref name="alerts"/>.</summary>
    public AuditViewModel(IBridge bridge, IUrlOpener urlOpener, AlertQueue alerts)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        ArgumentNullException.ThrowIfNull(urlOpener);
        ArgumentNullException.ThrowIfNull(alerts);
        _bridge = bridge;
        _urlOpener = urlOpener;
        _alerts = alerts;
    }

    /// <summary>The commits, newest first; empty until the first fetch.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(OpenCommand))]
    public partial IReadOnlyList<AuditRow> Rows { get; private set; } = [];

    /// <summary>The status line.</summary>
    [ObservableProperty]
    public partial string Status { get; private set; } = "";

    /// <summary>A fetch is running; Refresh is disabled.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RefreshCommand))]
    public partial bool IsRefreshing { get; private set; }

    /// <summary>The selected row's index in <see cref="Rows"/>; null when none is. Cleared when the rows are replaced.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(OpenCommand))]
    public partial int? SelectedIndex { get; private set; }

    /// <summary>The operator selected a row; null or out of range clears the selection. Never opens the browser.</summary>
    public void Select(int? row)
    {
        SelectedIndex = row is { } index && index >= 0 && index < Rows.Count ? index : null;
    }

    private bool CanRefresh()
    {
        return !IsRefreshing;
    }

    /// <summary>
    /// Refresh (and the startup load): fetches the commit history
    /// (audit.commits). Ignored while a fetch runs. A busy core (a fetch
    /// started elsewhere) keeps the rows and the status; any other failure
    /// shows the core's message on the status line.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanRefresh))]
    internal async Task RefreshAsync()
    {
        if (IsRefreshing)
        {
            return;
        }
        IsRefreshing = true;
        var previous = Status;
        Status = FetchingStatus;
        try
        {
            var result = await _bridge.AuditCommitsAsync();
            SelectedIndex = null;
            Rows = result.Rows;
            Status = result.Status;
        }
        catch (RpcException error)
        {
            Status = error.Code == RpcErrorCode.Busy ? previous : error.Message;
        }
        finally
        {
            IsRefreshing = false;
        }
    }

    /// <summary>The selected commit's page; null with none selected or without an https URL.</summary>
    private Uri? SelectedUrl()
    {
        return SelectedIndex is { } index && index < Rows.Count ? HttpsUrl.Parse(Rows[index].Url) : null;
    }

    private bool CanOpen()
    {
        return SelectedUrl() is not null;
    }

    /// <summary>Open on GitHub: opens the selected commit's page. Disabled without one (<see cref="OpenTooltip"/>).</summary>
    [RelayCommand(CanExecute = nameof(CanOpen))]
    private void Open()
    {
        if (SelectedUrl() is { } url && _urlOpener.Open(url) is { } failure)
        {
            _alerts.Show(new AlertState(AlertState.ErrorTitle, failure));
        }
    }
}
