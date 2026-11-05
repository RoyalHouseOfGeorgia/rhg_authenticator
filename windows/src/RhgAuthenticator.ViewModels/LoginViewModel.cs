using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>The device-code dialog's contents (auth.deviceCode).</summary>
/// <param name="UserCode">The code to enter at GitHub.</param>
/// <param name="VerificationUri">
/// Where to enter it; null when the core sent none or not an https URL (Open
/// GitHub is then disabled; the code can still be entered by hand).
/// </param>
public sealed record DeviceCodePrompt(string UserCode, Uri? VerificationUri);

/// <summary>
/// GitHub login: the login button, the device-code dialog and logging out.
/// The core runs the login and words its state; this view model shows what it
/// returns. Its status texts go to the Registry and History tabs' status
/// lines (<see cref="StatusChanged"/>), whichever tab started the login.
/// </summary>
public sealed partial class LoginViewModel : ObservableObject
{
#pragma warning disable CS1591 // UI copy; each constant's name says where it shows.
    public const string LoginTitle = "Login to GitHub";
    public const string ReconnectTitle = "Offline — Reconnect";
    public const string DeviceCodeTitle = "GitHub Login";
    public const string DeviceCodePromptText = "Enter this code at GitHub:";
    public const string CopyCodeTitle = "Copy Code";
    public const string OpenGitHubTitle = "Open GitHub";
    public const string CancelTitle = "Cancel";
    public const string ReconnectingStatus = "Reconnecting to GitHub...";
    public const string RequestingCodeStatus = "Requesting device code...";
    public const string LoginBusyStatus = "Login already in progress";
    public const string WaitingStatus = "Waiting for GitHub authorization...";
    public const string LoggedOutStatus = "Logged out";
    public const string UnreachableTitle = "GitHub Unreachable";
    public const string UnreachableMessage = "Still can't reach GitHub. Check your connection and try again.";
#pragma warning restore CS1591

    /// <summary>The Log Out question.</summary>
    public static readonly Confirmation LogoutConfirmation = new(
        "Log Out", "Log out of GitHub? You'll need to re-authorize to submit future updates.", "Log Out");

    private readonly IBridge _bridge;
    private readonly IConfirmService _confirm;
    private readonly IClipboard _clipboard;
    private readonly IUrlOpener _urlOpener;
    private readonly AlertQueue _alerts;

    /// <summary>
    /// auth.login calls in flight: the one login the core runs, plus any
    /// second attempt it is about to refuse as busy.
    /// </summary>
    private int _loginCalls;

    /// <summary>Counts auth.state reads, so only the latest one is applied.</summary>
    private int _stateReads;

    /// <summary>Creates the login's view model, posting its alerts to <paramref name="alerts"/>.</summary>
    public LoginViewModel(
        IBridge bridge, IConfirmService confirm, IClipboard clipboard, IUrlOpener urlOpener, AlertQueue alerts)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        ArgumentNullException.ThrowIfNull(confirm);
        ArgumentNullException.ThrowIfNull(clipboard);
        ArgumentNullException.ThrowIfNull(urlOpener);
        ArgumentNullException.ThrowIfNull(alerts);
        _bridge = bridge;
        _confirm = confirm;
        _clipboard = clipboard;
        _urlOpener = urlOpener;
        _alerts = alerts;
    }

    /// <summary>Receives the login's status texts: the Registry and History tabs' status lines.</summary>
    public event Action<string>? StatusChanged;

    /// <summary>The login state; logged out until startup reads it.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasUsableSession), nameof(ButtonTitle))]
    public partial AuthState AuthState { get; private set; } = new(false, false, "", "");

    /// <summary>Show the device-code dialog while non-null; only this view model closes it. Its Cancel is <see cref="CancelCommand"/>.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(OpenGitHubCommand))]
    public partial DeviceCodePrompt? DeviceCode { get; private set; }

    /// <summary>Logged in and online: GitHub calls can go ahead.</summary>
    public bool HasUsableSession => AuthState.LoggedIn && !AuthState.Offline;

    /// <summary>auth.login is running.</summary>
    public bool IsLoggingIn => _loginCalls > 0;

    /// <summary>The login button's title: "Login to GitHub", "Offline — Reconnect" or "@user ▾".</summary>
    public string ButtonTitle
    {
        get
        {
            if (!AuthState.LoggedIn)
            {
                return LoginTitle;
            }
            return AuthState.Offline ? ReconnectTitle : "@" + AuthState.User + " ▾";
        }
    }

    /// <summary>Reads the login state (auth.state) at startup.</summary>
    internal async Task LoadStateAsync()
    {
        var state = await _bridge.AuthStateAsync();
        // Newer than any auth.state read still running.
        _stateReads++;
        AuthState = state;
    }

    /// <summary>
    /// auth.changed: re-reads the login state (auth.state). The core's
    /// payloads can arrive out of order, so the event is only a signal; only
    /// the latest read is applied, and a failed one keeps the current state.
    /// </summary>
    internal async Task AuthChangedAsync()
    {
        var read = ++_stateReads;
        AuthState state;
        try
        {
            state = await _bridge.AuthStateAsync();
        }
        catch (RpcException)
        {
            return;
        }
        if (read == _stateReads)
        {
            AuthState = state;
        }
    }

    /// <summary>
    /// Logs in: reconnects a session that was offline, or else runs the
    /// device flow (auth.login, which emits auth.deviceCode), and shows the
    /// outcome. The single entry point of every "log in" button.
    /// </summary>
    public async Task StartAsync()
    {
        PostStatus(AuthState is { LoggedIn: true, Offline: true } ? ReconnectingStatus : RequestingCodeStatus);
        SetLoginCalls(_loginCalls + 1);
        AuthState state;
        try
        {
            state = await _bridge.LoginAsync();
        }
        catch (RpcException error)
        {
            // Another login is running and owns the dialog.
            if (error.Code == RpcErrorCode.Busy)
            {
                SetLoginCalls(_loginCalls - 1);
                if (!IsLoggingIn)
                {
                    // A late code of a login that has ended: with none running, its
                    // dialog could not be cancelled (Cancel stops only a running login).
                    DeviceCode = null;
                }
                PostStatus(LoginBusyStatus);
                return;
            }
            Finished();
            if (error.Code != RpcErrorCode.Cancelled)
            {
                _alerts.Show(AlertState.Error(error));
            }
            PostStatus("");
            return;
        }
        Finished();
        // Newer than any auth.state read still running.
        _stateReads++;
        AuthState = state;
        if (state.Offline)
        {
            PostStatus("");
            _alerts.Show(new AlertState(UnreachableTitle, UnreachableMessage));
            return;
        }
        PostStatus(state.StatusText);
    }

    /// <summary>auth.deviceCode: shows the code. Ignored when no login is running.</summary>
    internal void ShowDeviceCode(DeviceCode code)
    {
        ArgumentNullException.ThrowIfNull(code);
        if (!IsLoggingIn)
        {
            return;
        }
        PostStatus(WaitingStatus);
        DeviceCode = new DeviceCodePrompt(code.UserCode, HttpsUrl.Parse(code.VerificationUri));
    }

    /// <summary>
    /// The login button: logs in (or reconnects an offline session), or,
    /// when logged in and online, asks to log out (auth.logout); auth.changed
    /// then updates the button. Disabled while any login runs (one started
    /// by Submit for Review included), as its dialog is up meanwhile.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanPressButton))]
    private async Task ButtonAsync()
    {
        if (!HasUsableSession)
        {
            await StartAsync();
            return;
        }
        if (!_confirm.Ask(LogoutConfirmation))
        {
            return;
        }
        try
        {
            await _bridge.LogoutAsync();
        }
        catch (RpcException error)
        {
            _alerts.Show(AlertState.Error(error));
            return;
        }
        PostStatus(LoggedOutStatus);
    }

    /// <summary>Copy Code: puts the device code on the clipboard.</summary>
    [RelayCommand]
    private void CopyCode()
    {
        if (DeviceCode is { } prompt)
        {
            ShowIfFailed(_clipboard.SetText(prompt.UserCode));
        }
    }

    private bool CanOpenGitHub()
    {
        return DeviceCode?.VerificationUri is not null;
    }

    /// <summary>Open GitHub: opens the verification page. Disabled without one.</summary>
    [RelayCommand(CanExecute = nameof(CanOpenGitHub))]
    private void OpenGitHub()
    {
        if (DeviceCode?.VerificationUri is { } url)
        {
            ShowIfFailed(_urlOpener.Open(url));
        }
    }

    /// <summary>
    /// Cancel on the device-code dialog: closes it and stops the login
    /// (auth.cancelLogin). Nothing when the core already ended it, or for a
    /// second Cancel.
    /// </summary>
    [RelayCommand]
    private async Task CancelAsync()
    {
        if (!IsLoggingIn || DeviceCode is null)
        {
            return;
        }
        DeviceCode = null;
        try
        {
            await _bridge.CancelLoginAsync();
        }
        catch (RpcException)
        {
            // The login reports its own outcome either way.
        }
    }

    /// <summary>
    /// The login ended: closes the device-code dialog without cancelling. The
    /// login stops counting as running first, so a Cancel after this sends no
    /// auth.cancelLogin.
    /// </summary>
    private void Finished()
    {
        SetLoginCalls(_loginCalls - 1);
        DeviceCode = null;
    }

    private bool CanPressButton()
    {
        return !IsLoggingIn;
    }

    private void SetLoginCalls(int value)
    {
        _loginCalls = value;
        OnPropertyChanged(nameof(IsLoggingIn));
        ButtonCommand.NotifyCanExecuteChanged();
    }

    private void PostStatus(string text)
    {
        StatusChanged?.Invoke(text);
    }

    /// <summary>Shows a host service's failure, if any, as an error alert.</summary>
    private void ShowIfFailed(string? failure)
    {
        if (failure is not null)
        {
            _alerts.Show(new AlertState(AlertState.ErrorTitle, failure));
        }
    }
}
