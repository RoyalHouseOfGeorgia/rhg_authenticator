using System.Text;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class LoginViewModelTests
{
    private static readonly DeviceCode s_code = new("ABCD-1234", "https://github.com/login/device");

    private readonly FakeBridge _fake = new();
    private readonly FakeConfirm _confirm = new();
    private readonly FakeClipboard _clipboard = new();
    private readonly FakeUrlOpener _urls = new();
    private readonly AlertQueue _alerts = new();
    private readonly List<string> _statuses = [];

    private LoginViewModel NewModel()
    {
        var login = new LoginViewModel(_fake, _confirm, _clipboard, _urls, _alerts);
        login.StatusChanged += _statuses.Add;
        return login;
    }

    /// <summary>A model whose state <paramref name="state"/> was read (auth.state, then forgotten from the script).</summary>
    private async Task<LoginViewModel> ModelIn(AuthState state)
    {
        var login = NewModel();
        await SetAuth(login, state);
        return login;
    }

    private async Task SetAuth(LoginViewModel login, AuthState state)
    {
        _fake.Reset(RpcMethod.AuthState);
        _fake.Respond(RpcMethod.AuthState, state);
        await login.AuthChangedAsync();
        _fake.Reset(RpcMethod.AuthState);
    }

    /// <summary>Starts a held login and waits until auth.login is called.</summary>
    private async Task<(Hold Held, Task Login)> StartHeld(LoginViewModel login)
    {
        var held = _fake.Hold(RpcMethod.AuthLogin);
        var before = _fake.Count(RpcMethod.AuthLogin);
        var task = login.StartAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.AuthLogin) == before + 1));
        return (held, task);
    }

    [Fact]
    public void Copy()
    {
        Assert.Equal([.. "Offline "u8, 0xE2, 0x80, 0x94, .. " Reconnect"u8], Encoding.UTF8.GetBytes(LoginViewModel.ReconnectTitle));
        Assert.Equal("Login to GitHub", LoginViewModel.LoginTitle);
        Assert.Equal("GitHub Login", LoginViewModel.DeviceCodeTitle);
        Assert.Equal("Enter this code at GitHub:", LoginViewModel.DeviceCodePromptText);
        Assert.Equal(
            ["Copy Code", "Open GitHub", "Cancel"],
            [LoginViewModel.CopyCodeTitle, LoginViewModel.OpenGitHubTitle, LoginViewModel.CancelTitle]);
        Assert.Equal(
            new Confirmation("Log Out", "Log out of GitHub? You'll need to re-authorize to submit future updates.", "Log Out"),
            LoginViewModel.LogoutConfirmation);
        Assert.Equal("Cancel", LoginViewModel.LogoutConfirmation.CancelTitle);
        Assert.False(LoginViewModel.LogoutConfirmation.IsDestructive);
    }

    [Fact]
    public void RequiresItsServices()
    {
        Assert.Throws<ArgumentNullException>(() => new LoginViewModel(null!, _confirm, _clipboard, _urls, _alerts));
        Assert.Throws<ArgumentNullException>(() => new LoginViewModel(_fake, null!, _clipboard, _urls, _alerts));
        Assert.Throws<ArgumentNullException>(() => new LoginViewModel(_fake, _confirm, null!, _urls, _alerts));
        Assert.Throws<ArgumentNullException>(() => new LoginViewModel(_fake, _confirm, _clipboard, null!, _alerts));
        Assert.Throws<ArgumentNullException>(() => new LoginViewModel(_fake, _confirm, _clipboard, _urls, null!));
    }

    [Fact]
    public async Task TheButtonTitleFollowsTheLoginState()
    {
        var login = NewModel();
        var changed = new List<string?>();
        login.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        Assert.Equal(new AuthState(false, false, "", ""), login.AuthState);
        Assert.False(login.HasUsableSession);
        Assert.Equal("Login to GitHub", login.ButtonTitle);
        await SetAuth(login, Fixtures.LoggedInOffline);
        Assert.Equal("Offline — Reconnect", login.ButtonTitle);
        Assert.False(login.HasUsableSession);
        await SetAuth(login, Fixtures.LoggedIn);
        Assert.Equal([.. "@octocat "u8, 0xE2, 0x96, 0xBE], Encoding.UTF8.GetBytes(login.ButtonTitle));
        Assert.True(login.HasUsableSession);
        await SetAuth(login, Fixtures.LoggedOut);
        Assert.Equal("Login to GitHub", login.ButtonTitle);
        Assert.Contains(nameof(LoginViewModel.ButtonTitle), changed);
        Assert.Contains(nameof(LoginViewModel.HasUsableSession), changed);
    }

    [Fact]
    public async Task AuthChangedIsASignalAndTheLatestReadWins()
    {
        var login = NewModel();
        var older = _fake.Hold(RpcMethod.AuthState);
        _fake.Respond(RpcMethod.AuthState, Fixtures.LoggedIn);
        var first = login.AuthChangedAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.AuthState) == 1));
        await login.AuthChangedAsync();
        Assert.Equal(Fixtures.LoggedIn, login.AuthState);
        older.Release(Fixtures.LoggedOut);
        await first;
        Assert.Equal(Fixtures.LoggedIn, login.AuthState);
        // A failed read keeps the state.
        _fake.Reset(RpcMethod.AuthState);
        _fake.Fail(RpcMethod.AuthState, new RpcException(RpcErrorCode.Internal, "x"));
        await login.AuthChangedAsync();
        Assert.Equal(Fixtures.LoggedIn, login.AuthState);
    }

    [Fact]
    public async Task ALoginsOwnResultIsNewerThanAnAuthStateReadStillRunning()
    {
        var login = NewModel();
        var read = _fake.Hold(RpcMethod.AuthState);
        var pending = login.AuthChangedAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.AuthState) == 1));
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedIn);
        await login.StartAsync();
        read.Release(Fixtures.LoggedOut);
        await pending;
        Assert.Equal(Fixtures.LoggedIn, login.AuthState);
    }

    [Fact]
    public async Task LoadStateReadsAuthStateAndIsNewerThanAReadStillRunning()
    {
        var login = NewModel();
        var older = _fake.Hold(RpcMethod.AuthState);
        _fake.Respond(RpcMethod.AuthState, Fixtures.LoggedIn);
        var pending = login.AuthChangedAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.AuthState) == 1));
        await login.LoadStateAsync();
        Assert.Equal(Fixtures.LoggedIn, login.AuthState);
        older.Release(Fixtures.LoggedOut);
        await pending;
        Assert.Equal(Fixtures.LoggedIn, login.AuthState);
        Assert.Equal(["{}", "{}"], _fake.Params(RpcMethod.AuthState));
    }

    [Fact]
    public async Task LoadStateThrowsTheCoresError()
    {
        _fake.Fail(RpcMethod.AuthState, new RpcException(RpcErrorCode.Internal, "broke"));
        var login = NewModel();
        var error = await Assert.ThrowsAsync<RpcException>(login.LoadStateAsync);
        Assert.Equal("broke", error.Message);
    }

    [Fact]
    public async Task LoggedOutTheLoginSucceedsWithTheCoresStatusTextAndState()
    {
        var login = await ModelIn(Fixtures.LoggedOut);
        var changed = new List<string?>();
        login.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        var (held, task) = await StartHeld(login);
        Assert.True(login.IsLoggingIn);
        Assert.Contains(nameof(LoginViewModel.IsLoggingIn), changed);
        Assert.Equal(["Requesting device code..."], _statuses);
        held.Release(Fixtures.LoggedIn);
        await task;
        Assert.False(login.IsLoggingIn);
        Assert.Equal(Fixtures.LoggedIn, login.AuthState);
        Assert.Equal(["Requesting device code...", "Logged in as @octocat"], _statuses);
        Assert.Null(_alerts.Current);
        Assert.Equal(["{}"], _fake.Params(RpcMethod.AuthLogin));
        Assert.Equal(0, _fake.Count(RpcMethod.AuthCancelLogin));
    }

    [Fact]
    public async Task TheButtonWithNoSessionStartsTheLogin()
    {
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedIn);
        var login = await ModelIn(Fixtures.LoggedOut);
        await login.ButtonCommand.ExecuteAsync(null);
        Assert.Equal(1, _fake.Count(RpcMethod.AuthLogin));
        Assert.Empty(_confirm.Questions);
        Assert.Equal("Logged in as @octocat", _statuses[^1]);
    }

    [Fact]
    public async Task TheButtonIsDisabledWhileALoginItDidNotStartRuns()
    {
        var login = NewModel();
        var changes = 0;
        login.ButtonCommand.CanExecuteChanged += (_, _) => changes++;
        Assert.True(login.ButtonCommand.CanExecute(null));
        var (held, task) = await StartHeld(login);
        Assert.False(login.ButtonCommand.CanExecute(null));
        held.Release(Fixtures.LoggedIn);
        await task;
        Assert.True(login.ButtonCommand.CanExecute(null));
        Assert.Equal(2, changes);
    }

    [Fact]
    public async Task OfflineTheButtonReconnects()
    {
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedIn);
        var login = await ModelIn(Fixtures.LoggedInOffline);
        await login.ButtonCommand.ExecuteAsync(null);
        Assert.Equal(["Reconnecting to GitHub...", "Logged in as @octocat"], _statuses);
        Assert.Equal(Fixtures.LoggedIn, login.AuthState);
    }

    [Fact]
    public async Task StillOfflineAfterReconnectingShowsGitHubUnreachableAndClearsTheStatus()
    {
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedInOffline);
        var login = await ModelIn(Fixtures.LoggedInOffline);
        await login.StartAsync();
        Assert.Equal("", _statuses[^1]);
        Assert.Equal(
            new AlertState("GitHub Unreachable", "Still can't reach GitHub. Check your connection and try again."),
            _alerts.Current);
        Assert.False(_alerts.Current!.IsError);
        Assert.Equal(Fixtures.LoggedInOffline, login.AuthState);
    }

    [Fact]
    public async Task ACancelledLoginClearsTheStatusWithoutAnAlert()
    {
        _fake.Fail(RpcMethod.AuthLogin, new RpcException(RpcErrorCode.Cancelled, "Login cancelled."));
        var login = NewModel();
        await login.StartAsync();
        Assert.Equal(["Requesting device code...", ""], _statuses);
        Assert.Null(_alerts.Current);
        Assert.False(login.IsLoggingIn);
    }

    [Theory]
    [InlineData(RpcErrorCode.LoginUnavailable, "GitHub login isn't available: no secure credential store on this computer.")]
    [InlineData(RpcErrorCode.Failed, "GitHub didn't grant the public_repo permission the app needs.")]
    public async Task AFailedLoginShowsTheCoresMessageAsAnError(RpcErrorCode code, string message)
    {
        _fake.Fail(RpcMethod.AuthLogin, new RpcException(code, message));
        var login = NewModel();
        await login.StartAsync();
        Assert.Equal(new AlertState("Error", message), _alerts.Current);
        Assert.Equal("", _statuses[^1]);
        Assert.False(login.IsLoggingIn);
        Assert.Equal(new AuthState(false, false, "", ""), login.AuthState);
    }

    [Fact]
    public async Task BusyLoginAlreadyInProgressAndTheRunningLoginKeepsItsDialog()
    {
        var login = NewModel();
        var held = _fake.Hold(RpcMethod.AuthLogin);
        _fake.Fail(RpcMethod.AuthLogin, new RpcException(RpcErrorCode.Busy, "Another operation is in progress."));
        var task = login.StartAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.AuthLogin) == 1));
        login.ShowDeviceCode(s_code);
        await login.StartAsync();
        Assert.Equal("Login already in progress", _statuses[^1]);
        Assert.NotNull(login.DeviceCode);
        Assert.True(login.IsLoggingIn);
        Assert.Null(_alerts.Current);
        held.Release(Fixtures.LoggedIn);
        await task;
        Assert.Null(login.DeviceCode);
        Assert.False(login.IsLoggingIn);
    }

    [Fact]
    public async Task BusyWithNoLoginOfOursRunningLeavesNothingRunning()
    {
        _fake.Fail(RpcMethod.AuthLogin, new RpcException(RpcErrorCode.Busy, "Another operation is in progress."));
        var login = NewModel();
        await login.StartAsync();
        Assert.Equal("Login already in progress", _statuses[^1]);
        Assert.False(login.IsLoggingIn);
    }

    [Fact]
    public async Task ADeviceCodeWithAUriShowsWaitingTheCodeAndTheUrl()
    {
        var login = NewModel();
        var (held, task) = await StartHeld(login);
        Assert.False(login.OpenGitHubCommand.CanExecute(null));
        var openChanges = 0;
        login.OpenGitHubCommand.CanExecuteChanged += (_, _) => openChanges++;
        login.ShowDeviceCode(s_code);
        Assert.Equal("Waiting for GitHub authorization...", _statuses[^1]);
        Assert.Equal(new DeviceCodePrompt("ABCD-1234", new Uri("https://github.com/login/device")), login.DeviceCode);
        Assert.True(login.OpenGitHubCommand.CanExecute(null));
        Assert.True(openChanges > 0);
        held.Release(Fixtures.LoggedIn);
        await task;
        Assert.False(login.OpenGitHubCommand.CanExecute(null));
    }

    [Theory]
    [InlineData("")]
    [InlineData("http://github.com/login/device")]
    [InlineData("/login/device")]
    [InlineData("not a url")]
    public async Task ADeviceCodeWithoutAnHttpsUriHasNoUrlAndOpenGitHubIsDisabled(string uri)
    {
        var login = NewModel();
        var (held, task) = await StartHeld(login);
        login.ShowDeviceCode(new DeviceCode("WXYZ-0000", uri));
        Assert.Equal(new DeviceCodePrompt("WXYZ-0000", null), login.DeviceCode);
        Assert.False(login.OpenGitHubCommand.CanExecute(null));
        login.OpenGitHubCommand.Execute(null);
        Assert.Empty(_urls.Opened);
        held.Release(Fixtures.LoggedIn);
        await task;
    }

    [Fact]
    public void ADeviceCodeWithNoLoginRunningIsIgnored()
    {
        var login = NewModel();
        login.ShowDeviceCode(s_code);
        Assert.Null(login.DeviceCode);
        Assert.Empty(_statuses);
        login.OpenGitHubCommand.Execute(null); // no dialog: nothing to open
        Assert.Empty(_urls.Opened);
        Assert.Throws<ArgumentNullException>(() => login.ShowDeviceCode(null!));
    }

    [Fact]
    public async Task ALoginWithNoStatusListenerStillRuns()
    {
        _fake.Respond(RpcMethod.AuthLogin, Fixtures.LoggedIn);
        var login = new LoginViewModel(_fake, _confirm, _clipboard, _urls, _alerts);
        await login.StartAsync();
        Assert.Equal(Fixtures.LoggedIn, login.AuthState);
    }

    [Fact]
    public async Task AFinishedLoginClosesTheDialogWithoutCancellingAndALaterCancelSendsNothing()
    {
        var login = NewModel();
        var (held, task) = await StartHeld(login);
        login.ShowDeviceCode(s_code);
        held.Release(Fixtures.LoggedIn);
        await task;
        Assert.Null(login.DeviceCode);
        await login.CancelCommand.ExecuteAsync(null);
        Assert.Equal(0, _fake.Count(RpcMethod.AuthCancelLogin));
    }

    [Fact]
    public async Task ACodeLeftUpWhenTheLastLoginEndsBusyIsClosed()
    {
        var login = NewModel();
        var first = _fake.Hold(RpcMethod.AuthLogin);
        var second = _fake.Hold(RpcMethod.AuthLogin);
        var firstLogin = login.StartAsync();
        var secondLogin = login.StartAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.AuthLogin) == 2));
        first.Release(Fixtures.LoggedIn);
        await firstLogin;
        // The first login's code arrives late, while the second call still counts.
        login.ShowDeviceCode(s_code);
        Assert.NotNull(login.DeviceCode);
        second.ReleaseFailing(new RpcException(RpcErrorCode.Busy, "Another operation is in progress."));
        await secondLogin;
        Assert.False(login.IsLoggingIn);
        Assert.Null(login.DeviceCode);
    }

    [Fact]
    public async Task CancelSendsExactlyOneCancelLogin()
    {
        var login = NewModel();
        var (held, task) = await StartHeld(login);
        login.ShowDeviceCode(s_code);
        await login.CancelCommand.ExecuteAsync(null);
        Assert.Null(login.DeviceCode);
        await login.CancelCommand.ExecuteAsync(null);
        Assert.Equal(["{}"], _fake.Params(RpcMethod.AuthCancelLogin));
        held.ReleaseFailing(new RpcException(RpcErrorCode.Cancelled, "Login cancelled."));
        await task;
        Assert.Equal("", _statuses[^1]);
        Assert.Null(_alerts.Current);
        Assert.Equal(1, _fake.Count(RpcMethod.AuthCancelLogin));
    }

    [Fact]
    public async Task ACancelLoginFailureIsIgnored()
    {
        _fake.Fail(RpcMethod.AuthCancelLogin, new RpcException(RpcErrorCode.Internal, "x"));
        var login = NewModel();
        var (held, task) = await StartHeld(login);
        login.ShowDeviceCode(s_code);
        await login.CancelCommand.ExecuteAsync(null);
        Assert.Null(login.DeviceCode);
        Assert.Null(_alerts.Current);
        held.ReleaseFailing(new RpcException(RpcErrorCode.Cancelled, "Login cancelled."));
        await task;
    }

    [Fact]
    public async Task CancellingWithNoDialogUpSendsNothing()
    {
        var login = NewModel();
        await login.CancelCommand.ExecuteAsync(null);
        var (held, task) = await StartHeld(login);
        await login.CancelCommand.ExecuteAsync(null);
        Assert.Equal(0, _fake.Count(RpcMethod.AuthCancelLogin));
        held.Release(Fixtures.LoggedIn);
        await task;
    }

    [Fact]
    public async Task CopyCodePutsTheCodeOnTheClipboardAndAFailureIsAnErrorAlert()
    {
        var login = NewModel();
        login.CopyCodeCommand.Execute(null); // no dialog: nothing to copy
        Assert.Empty(_clipboard.Texts);
        var (held, task) = await StartHeld(login);
        login.ShowDeviceCode(s_code);
        login.CopyCodeCommand.Execute(null);
        Assert.Equal(["ABCD-1234"], _clipboard.Texts);
        Assert.Null(_alerts.Current);
        _clipboard.Failure = "Could not copy to the clipboard.";
        login.CopyCodeCommand.Execute(null);
        Assert.Equal(new AlertState("Error", "Could not copy to the clipboard."), _alerts.Current);
        held.Release(Fixtures.LoggedIn);
        await task;
    }

    [Fact]
    public async Task OpenGitHubOpensTheVerificationPageAndAFailureIsAnErrorAlert()
    {
        var login = NewModel();
        var (held, task) = await StartHeld(login);
        login.ShowDeviceCode(s_code);
        login.OpenGitHubCommand.Execute(null);
        Assert.Equal([new Uri("https://github.com/login/device")], _urls.Opened);
        Assert.Null(_alerts.Current);
        _urls.Failure = "Could not open https://github.com/login/device";
        login.OpenGitHubCommand.Execute(null);
        Assert.Equal(new AlertState("Error", "Could not open https://github.com/login/device"), _alerts.Current);
        held.Release(Fixtures.LoggedIn);
        await task;
    }

    [Fact]
    public async Task LoggedInTheButtonAsksToLogOutAndConfirmingLogsOut()
    {
        var login = await ModelIn(Fixtures.LoggedIn);
        _confirm.Answer(true);
        await login.ButtonCommand.ExecuteAsync(null);
        Assert.Equal(0, _fake.Count(RpcMethod.AuthLogin));
        Assert.Equal([LoginViewModel.LogoutConfirmation], _confirm.Questions);
        Assert.Equal(["{}"], _fake.Params(RpcMethod.AuthLogout));
        Assert.Equal(["Logged out"], _statuses);
        // auth.changed, not the call, updates the state.
        Assert.Equal(Fixtures.LoggedIn, login.AuthState);
    }

    [Fact]
    public async Task DecliningLogOutDoesNothing()
    {
        var login = await ModelIn(Fixtures.LoggedIn);
        await login.ButtonCommand.ExecuteAsync(null);
        Assert.Single(_confirm.Questions);
        Assert.Equal(0, _fake.Count(RpcMethod.AuthLogout));
        Assert.Empty(_statuses);
    }

    [Fact]
    public async Task AFailedLogoutShowsTheCoresMessage()
    {
        _fake.Fail(RpcMethod.AuthLogout, new RpcException(RpcErrorCode.Internal, "An internal error occurred — please restart"));
        var login = await ModelIn(Fixtures.LoggedIn);
        _confirm.Answer(true);
        await login.ButtonCommand.ExecuteAsync(null);
        Assert.Equal(new AlertState("Error", "An internal error occurred — please restart"), _alerts.Current);
        Assert.Empty(_statuses);
    }
}
