using CommunityToolkit.Mvvm.ComponentModel;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>An alert to show: title and message, both display only.</summary>
/// <param name="Title">The alert's title.</param>
/// <param name="Message">The alert's text.</param>
/// <param name="OffersErrorLogExport">
/// The alert gets an "Export Error Log…" button
/// (<see cref="AppViewModel.ExportErrorLogCommand"/>) beside OK.
/// </param>
public sealed record AlertState(string Title, string Message, bool OffersErrorLogExport = false)
{
    /// <summary>The title of a core error's alert.</summary>
    public const string ErrorTitle = "Error";

    /// <summary>A core error, shown as-is under the title "Error".</summary>
    public static AlertState Error(RpcException error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new AlertState(ErrorTitle, error.Message);
    }

    /// <summary>The alert is an error (style it so).</summary>
    public bool IsError => Title == ErrorTitle;
}

/// <summary>
/// The app's alerts, one at a time, in the order they were posted: every view
/// model posts here, and the view shows <see cref="Current"/> until it calls
/// <see cref="DismissAsync"/>.
/// </summary>
public sealed partial class AlertQueue : ObservableObject
{
    private readonly Queue<(AlertState Alert, Func<Task>? Then)> _waiting = new();
    private Func<Task>? _currentThen;

    /// <summary>The alert to show now; null when there is none.</summary>
    [ObservableProperty]
    public partial AlertState? Current { get; private set; }

    /// <summary>
    /// Shows <paramref name="alert"/> now, or after the alerts already posted;
    /// <paramref name="then"/>, if any, runs once it is dismissed.
    /// </summary>
    public void Show(AlertState alert, Func<Task>? then = null)
    {
        ArgumentNullException.ThrowIfNull(alert);
        if (Current is null)
        {
            _currentThen = then;
            Current = alert;
        }
        else
        {
            _waiting.Enqueue((alert, then));
        }
    }

    /// <summary>
    /// The operator dismissed <see cref="Current"/>: the next alert, if any,
    /// becomes current, then the dismissed alert's follow-up, if any, runs.
    /// </summary>
    public async Task DismissAsync()
    {
        var then = _currentThen;
        if (_waiting.TryDequeue(out var next))
        {
            _currentThen = next.Then;
            Current = next.Alert;
        }
        else
        {
            _currentThen = null;
            Current = null;
        }
        if (then is not null)
        {
            await then();
        }
    }
}
