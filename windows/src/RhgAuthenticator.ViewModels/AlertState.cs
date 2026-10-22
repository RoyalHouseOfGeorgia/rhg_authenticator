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
/// <see cref="Dismiss"/>.
/// </summary>
public sealed partial class AlertQueue : ObservableObject
{
    private readonly Queue<AlertState> _waiting = new();

    /// <summary>The alert to show now; null when there is none.</summary>
    [ObservableProperty]
    public partial AlertState? Current { get; private set; }

    /// <summary>Shows <paramref name="alert"/> now, or after the alerts already posted.</summary>
    public void Show(AlertState alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        if (Current is null)
        {
            Current = alert;
        }
        else
        {
            _waiting.Enqueue(alert);
        }
    }

    /// <summary>The operator dismissed <see cref="Current"/>: the next alert, if any, becomes current.</summary>
    public void Dismiss()
    {
        Current = _waiting.TryDequeue(out var next) ? next : null;
    }
}
