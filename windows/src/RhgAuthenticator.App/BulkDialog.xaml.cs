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
        bulk.PropertyChanged += new Presenter(bulk).OnBulkChanged;
    }

    /// <summary>
    /// At most one dialog per flow. The dialog opens on a later dispatcher
    /// turn, never inside the change: whatever changed the phase (a command's
    /// continuation) is not held up by the modal loop. BeginInvoke, not
    /// InvokeAsync, so a failure ends the app instead of vanishing into a
    /// discarded task.
    /// </summary>
    private sealed class Presenter(BulkViewModel bulk)
    {
        private BulkDialog? _shown;
        private bool _isPending;

        public void OnBulkChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName != nameof(BulkViewModel.IsShowingDialog))
            {
                return;
            }
            if (!bulk.IsShowingDialog)
            {
                _shown?.Close();
                return;
            }
            if (_shown is null && !_isPending)
            {
                _isPending = true;
                _ = Application.Current.Dispatcher.BeginInvoke(new Action(ShowPending));
            }
        }

        private void ShowPending()
        {
            _isPending = false;
            if (!bulk.IsShowingDialog || _shown is not null)
            {
                return;
            }
            var dialog = new BulkDialog(bulk);
            // Closed runs inside Close, so a flow started right after this one ends gets a new dialog.
            dialog.Closed += (_, _) => OnDialogClosed(dialog);
            _shown = dialog;
            _ = DialogOwner.ShowModal(dialog);
        }

        private void OnDialogClosed(BulkDialog dialog)
        {
            if (_shown == dialog)
            {
                _shown = null;
            }
        }
    }

    /// <summary>
    /// Closing while the view model still shows the dialog maps to the
    /// phase's command; the view model's change then closes the window. The
    /// command runs on a later dispatcher turn: closing the window from
    /// inside its own Closing event throws.
    /// </summary>
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!_bulk.IsShowingDialog)
        {
            return;
        }
        e.Cancel = true;
        ICommand? command = _bulk.Phase switch
        {
            BulkPhase.Confirming => _bulk.CancelConfirmCommand,
            BulkPhase.Results => _bulk.CloseResultsCommand,
            _ => null,
        };
        if (command is not null)
        {
            _ = Dispatcher.BeginInvoke(new Action(() => command.Execute(null)));
        }
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
