using System.ComponentModel;
using System.Windows;

namespace RhgAuthenticator.App;

/// <summary>
/// Shows a view model's modal dialog: at most one at a time, for the object
/// <c>shownFor</c> returns (null: no dialog). Whenever <c>property</c>
/// changes, a dialog shown for another object (or none) is closed, and a
/// dialog for the current one opens on a later dispatcher turn, never inside
/// the change: whatever raised it (the core's event drain, a command's
/// continuation) is not held up by the modal loop. BeginInvoke, not
/// InvokeAsync, so a failure ends the app instead of vanishing into a
/// discarded task.
/// </summary>
/// <remarks>
/// Only the view model closes the dialog. A dialog closed by hand (its
/// Cancel, Escape, the close button) cancels its own Closing while the view
/// model still shows it, and runs the view model's cancel on a later
/// dispatcher turn (<see cref="ModalPresenter.CloseByHand"/>); the view model's change then
/// closes it here. Closing a window from inside its own Closing throws.
/// </remarks>
/// <typeparam name="TDialog">The dialog window.</typeparam>
internal sealed class ModalPresenter<TDialog>
    where TDialog : Window
{
    private readonly Func<object?> _shownFor;
    private readonly Func<object, TDialog> _create;
    private readonly Action<TDialog> _show;
    private TDialog? _shown;
    private object? _shownKey;
    private bool _isPending;

    /// <summary>
    /// Presents <paramref name="create"/>'s dialog for <paramref name="shownFor"/>'s
    /// object on each change of <paramref name="property"/> of
    /// <paramref name="model"/>, shown with <paramref name="show"/> (default
    /// <see cref="DialogOwner.ShowModal"/>). Create it once, on the UI thread.
    /// </summary>
    public ModalPresenter(
        INotifyPropertyChanged model,
        string property,
        Func<object?> shownFor,
        Func<object, TDialog> create,
        Action<TDialog>? show = null)
    {
        _shownFor = shownFor;
        _create = create;
        _show = show ?? (dialog => _ = DialogOwner.ShowModal(dialog));
        model.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == property)
            {
                Sync();
            }
        };
    }

    private void Sync()
    {
        var key = _shownFor();
        if (_shown is not null && !ReferenceEquals(key, _shownKey))
        {
            // Closed runs inside Close and clears _shown, so a replacing object gets a new dialog.
            _shown.Close();
        }
        if (key is not null && _shown is null && !_isPending)
        {
            _isPending = true;
            _ = Application.Current.Dispatcher.BeginInvoke(new Action(ShowPending));
        }
    }

    private void ShowPending()
    {
        _isPending = false;
        if (_shownFor() is not { } key || _shown is not null)
        {
            return;
        }
        var dialog = _create(key);
        dialog.Closed += (_, _) =>
        {
            if (_shown == dialog)
            {
                _shown = null;
                _shownKey = null;
            }
        };
        _shown = dialog;
        _shownKey = key;
        _show(dialog);
    }
}

/// <summary>The close-by-hand rule of the dialogs a <see cref="ModalPresenter{TDialog}"/> shows.</summary>
internal static class ModalPresenter
{
    /// <summary>
    /// The handler of a presented dialog's Closing: while <paramref name="isStillShown"/>,
    /// cancels the close and runs <paramref name="cancel"/> on a later turn,
    /// if still shown then (a second close before it runs adds nothing).
    /// Returns whether the close was cancelled.
    /// </summary>
    public static bool CloseByHand(Window dialog, CancelEventArgs e, Func<bool> isStillShown, Action cancel)
    {
        if (!isStillShown())
        {
            return false;
        }
        e.Cancel = true;
        _ = dialog.Dispatcher.BeginInvoke(new Action(() =>
        {
            if (isStillShown())
            {
                cancel();
            }
        }));
        return true;
    }
}
