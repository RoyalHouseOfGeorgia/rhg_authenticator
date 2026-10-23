using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// Bulk Sign from File's one dialog: a modal window up while the
/// <see cref="BulkViewModel"/> shows its dialog, from confirm through
/// progress to the results, switching content by phase. Staying up across
/// the run lets the PIN prompt stack on it (PinDialog opens over the active
/// window). Only the view model closes it: closing it by hand (the close
/// button, Alt+F4, Escape) cancels the confirm or closes the results, and
/// does nothing while the run is signing.
/// </summary>
public partial class BulkDialog : Window
{
    private readonly BulkViewModel _bulk;

    private BulkDialog(BulkViewModel bulk)
    {
        _bulk = bulk;
        InitializeComponent();
        DataContext = bulk;
        bulk.PropertyChanged += OnBulkChanged;
        // The dialog may open on any phase (straight on the results when
        // nothing was to be signed).
        Loaded += (_, _) => FocusMainButton();
        Closing += OnClosing;
        Closed += (_, _) => bulk.PropertyChanged -= OnBulkChanged;
    }

    /// <summary>
    /// Shows a new dialog whenever <paramref name="bulk"/> starts showing
    /// its dialog, and closes it when the flow ends. Call once, on the UI thread.
    /// </summary>
    public static void Attach(BulkViewModel bulk)
    {
        ArgumentNullException.ThrowIfNull(bulk);
        _ = new ModalPresenter<BulkDialog>(
            bulk, nameof(BulkViewModel.IsShowingDialog), () => bulk.IsShowingDialog ? bulk : null, _ => new BulkDialog(bulk));
    }

    /// <summary>
    /// Closing while the view model still shows the dialog maps to the
    /// phase's command (none while signing); the view model's change then
    /// closes the window.
    /// </summary>
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        ICommand? command = _bulk.Phase switch
        {
            BulkPhase.Confirming => _bulk.CancelConfirmCommand,
            BulkPhase.Results => _bulk.CloseResultsCommand,
            _ => null,
        };
        _ = ModalPresenter.CloseByHand(this, e, () => _bulk.IsShowingDialog, () => command?.Execute(null));
    }

    /// <summary>A new phase collapses the focused button with its content: focus the new content's main button.</summary>
    private void OnBulkChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(BulkViewModel.Phase))
        {
            FocusMainButton();
        }
    }

    /// <summary>Focuses the current content's main button, once the layout has made it visible.</summary>
    private void FocusMainButton()
    {
        UIElement? target = _bulk.Phase switch
        {
            BulkPhase.Confirming => SignButton,
            BulkPhase.Running => CancelRunButton,
            BulkPhase.Results => CloseButton,
            _ => null,
        };
        if (target is not null)
        {
            _ = Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() => _ = target.Focus()));
        }
    }
}
