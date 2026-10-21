using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using RhgAuthenticator.Bridge;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The YubiKey PIN prompt: a modal window shown while the
/// <see cref="PinPromptViewModel"/> is open, over the app's active window so
/// it stacks on any dialog already up. OK submits; Cancel, Escape and the
/// close button cancel. The PIN goes from the field to the view model only;
/// it is never logged.
/// </summary>
public partial class PinDialog : Window
{
    private readonly PinPromptViewModel _prompt;
    private bool _isClosing;

    private PinDialog(PinPromptViewModel prompt)
    {
        _prompt = prompt;
        InitializeComponent();
        DataContext = prompt;
        prompt.PropertyChanged += OnPromptChanged;
        Closing += OnClosing;
        Closed += (_, _) => prompt.PropertyChanged -= OnPromptChanged;
    }

    /// <summary>
    /// Shows a new dialog whenever <paramref name="prompt"/> opens, and
    /// closes it when the prompt closes (answered, or withdrawn by the core).
    /// Call once, on the UI thread.
    /// </summary>
    public static void Attach(PinPromptViewModel prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        prompt.PropertyChanged += new Presenter(prompt).OnPromptChanged;
    }

    /// <summary>
    /// At most one dialog per open prompt. The dialog opens on a later
    /// dispatcher turn: the prompt opens from the core's event drain, which
    /// must not wait behind a modal loop. BeginInvoke, not InvokeAsync, so a
    /// failure ends the app instead of vanishing into a discarded task.
    /// </summary>
    private sealed class Presenter(PinPromptViewModel prompt)
    {
        private PinDialog? _shown;
        private bool _isPending;

        public void OnPromptChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName != nameof(PinPromptViewModel.IsOpen))
            {
                return;
            }
            if (!prompt.IsOpen)
            {
                _shown?.CloseForPrompt();
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
            if (!prompt.IsOpen || _shown is not null)
            {
                return;
            }
            var dialog = new PinDialog(prompt);
            // Closed runs inside Close, so a request that replaces a withdrawn
            // one in the same event batch gets a new dialog.
            dialog.Closed += (_, _) => OnDialogClosed(dialog);
            _shown = dialog;
            dialog.ShowOverActiveWindow();
        }

        private void OnDialogClosed(PinDialog dialog)
        {
            if (_shown == dialog)
            {
                _shown = null;
            }
        }
    }

    /// <summary>Shows the dialog modally over the active window; flashes the taskbar if the app is in the background.</summary>
    private void ShowOverActiveWindow()
    {
        var isAppActive = DialogOwner.IsAppActive;
        if (DialogOwner.Current is { IsVisible: true } owner)
        {
            if (owner.WindowState == WindowState.Minimized)
            {
                owner.WindowState = WindowState.Normal;
            }
            Owner = owner;
        }
        else
        {
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }
        if (!isAppActive)
        {
            // The dialog has no taskbar button of its own: flash the main window's.
            ContentRendered += (_, _) => NativeMethods.FlashUntilActivated(
                new WindowInteropHelper(Application.Current.MainWindow ?? this).Handle);
        }
        ShowDialog();
    }

    /// <summary>The prompt closed: close the window, unless it is closing already.</summary>
    private void CloseForPrompt()
    {
        if (!_isClosing)
        {
            Close();
        }
    }

    /// <summary>Closing while the prompt is still open (Cancel, Escape, the close button) cancels it.</summary>
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        _isClosing = true;
        PinBox.Clear();
        if (_prompt.IsOpen)
        {
            _prompt.CancelCommand.Execute(null);
        }
    }

    private void OnPromptChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(PinPromptViewModel.Pin):
                ShowPin();
                break;
            case nameof(PinPromptViewModel.Request) when _prompt.IsOpen:
                // A new request replaced the one on screen.
                _ = PinBox.Focus();
                break;
            default:
                break;
        }
    }

    /// <summary>
    /// Passes each edit to the view model, which caps the PIN to the core's
    /// byte limit; a capped PIN is written back to the field.
    /// </summary>
    private void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        _prompt.Pin = PinBox.Password;
        ShowPin();
    }

    /// <summary>
    /// Refuses typing past the byte cap, so the cap never rewrites the field
    /// under the caret (rewriting a PasswordBox moves its caret to the start).
    /// Pastes are capped by <see cref="OnPasswordChanged"/>.
    /// </summary>
    private void OnPreviewTextInput(object sender, TextCompositionEventArgs e)
    {
        if (_prompt.Request is { } request)
        {
            var typed = PinBox.Password + e.Text;
            e.Handled = PinTruncation.Truncate(typed, request.MaxBytes).Length < typed.Length;
        }
    }

    private void ShowPin()
    {
        if (PinBox.Password != _prompt.Pin)
        {
            PinBox.Password = _prompt.Pin;
        }
    }
}
