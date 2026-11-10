using System.ComponentModel;
using System.Windows;
using System.Windows.Threading;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The GitHub device-code dialog: a modal window up while the
/// <see cref="LoginViewModel"/> shows a <see cref="LoginViewModel.DeviceCode"/>,
/// over the app's active window. Only the view model closes it (the login
/// ended, or was cancelled): closing it by hand (Cancel, Escape, the close
/// button) cancels the login, whose change then closes the window.
/// </summary>
public partial class DeviceCodeDialog : Window
{
    private readonly LoginViewModel _login;

    private DeviceCodeDialog(LoginViewModel login)
    {
        _login = login;
        InitializeComponent();
        DataContext = login;
        Loaded += (_, _) => FocusMainButton();
        Closing += OnClosing;
    }

    /// <summary>
    /// Shows a new dialog whenever <paramref name="login"/> shows a device
    /// code, and closes it when the code is withdrawn. Call once, on the UI thread.
    /// </summary>
    public static void Attach(LoginViewModel login)
    {
        ArgumentNullException.ThrowIfNull(login);
        // Keyed on the login while a code shows: a new code replaces the
        // one shown in the same dialog (bound).
        _ = new ModalPresenter<DeviceCodeDialog>(
            login, nameof(LoginViewModel.DeviceCode), () => login.DeviceCode is null ? null : login, _ => new DeviceCodeDialog(login));
    }

    /// <summary>
    /// Closing while the view model still shows the code cancels the login;
    /// the view model's change then closes the window.
    /// </summary>
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        _ = ModalPresenter.CloseByHand(this, e, () => _login.DeviceCode is not null, () => _login.CancelCommand.Execute(null));
    }

    /// <summary>Focuses Open GitHub, or Copy Code when there is no page to open, once the layout has run.</summary>
    private void FocusMainButton()
    {
        UIElement target = OpenButton.IsEnabled ? OpenButton : CopyButton;
        _ = Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() => _ = target.Focus()));
    }
}
