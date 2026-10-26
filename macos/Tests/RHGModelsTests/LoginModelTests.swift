import Foundation
import RHGBridge
import Testing

@testable import RHGModels

/// Records the status texts a LoginModel sends.
@MainActor
final class StatusRecorder {
    var texts: [String] = []

    var last: String? { texts.last }

    func attach(_ login: LoginModel) {
        login.addStatusHandler { [self] text in texts.append(text) }
    }
}

@Suite("LoginModel")
@MainActor
struct LoginModelTests {
    let code = DeviceCode(userCode: "ABCD-1234", verificationUri: "https://github.com/login/device")

    func model(_ fake: FakeBridge, state: AuthState? = nil) async -> (LoginModel, StatusRecorder) {
        let login = LoginModel(bridge: fake)
        let status = StatusRecorder()
        status.attach(login)
        if let state {
            await setAuth(login, state, fake)
        }
        return (login, status)
    }

    /// Starts a held login and waits until auth.login is called.
    func startHeld(_ fake: FakeBridge, _ login: LoginModel) async -> (Hold, Task<Void, Never>) {
        let held = fake.hold(.authLogin)
        let before = fake.count(.authLogin)
        let task = Task { await login.start() }
        #expect(await settle { fake.count(.authLogin) == before + 1 })
        return (held, task)
    }

    @Test("UI copy")
    func copy() {
        #expect(LoginModel.loginTitle == "Log In to GitHub\u{2026}")
        #expect(LoginModel.logOutTitle == "Log Out\u{2026}")
        #expect(LoginModel.reconnectingStatus == "Reconnecting to GitHub\u{2026}")
        #expect(LoginModel.requestingCodeStatus == "Requesting device code\u{2026}")
        #expect(LoginModel.waitingStatus == "Waiting for GitHub authorization\u{2026}")
        #expect(LoginModel.deviceCodeTitle == "GitHub Login")
        #expect(LoginModel.deviceCodePrompt == "Enter this code at GitHub:")
        #expect(
            [LoginModel.copyCodeTitle, LoginModel.openGitHubTitle, LoginModel.cancelTitle]
                == ["Copy Code", "Open GitHub", "Cancel"])
    }

    @Test("the button title follows the login state")
    func buttonTitle() async {
        let fake = FakeBridge()
        let (login, _) = await model(fake)
        #expect(login.authState == AuthState(loggedIn: false, offline: false, user: "", statusText: ""))
        #expect(login.buttonTitle == LoginModel.loginTitle)
        await setAuth(login, loggedInOffline, fake)
        #expect(login.buttonTitle == "Offline \u{2014} Reconnect")
        await setAuth(login, loggedIn, fake)
        #expect(login.buttonTitle == "@octocat")
        await setAuth(login, loggedOut, fake)
        #expect(login.buttonTitle == LoginModel.loginTitle)
    }

    @Test("auth.changed is a signal: the latest auth.state read wins, whatever the payload or the order")
    func authChangedRereads() async {
        let fake = FakeBridge()
        let (login, _) = await model(fake)
        let older = fake.hold(.authState)
        fake.respond(.authState, loggedIn)
        let first = Task { await login.authChanged() }
        #expect(await settle { fake.count(.authState) == 1 })
        await login.authChanged()
        #expect(login.authState == loggedIn)
        older.release(loggedOut)
        await first.value
        #expect(login.authState == loggedIn)
        // A failed read keeps the state.
        fake.reset(.authState)
        fake.fail(.authState, RPCError(code: .internal, message: "x"))
        await login.authChanged()
        #expect(login.authState == loggedIn)
    }

    @Test("a login's own result is newer than an auth.state read still running")
    func loginBeatsRunningRead() async {
        let fake = FakeBridge()
        let (login, _) = await model(fake)
        let read = fake.hold(.authState)
        let pending = Task { await login.authChanged() }
        #expect(await settle { fake.count(.authState) == 1 })
        fake.respond(.authLogin, loggedIn)
        await login.start()
        read.release(loggedOut)
        await pending.value
        #expect(login.authState == loggedIn)
    }

    @Test("loadState is newer than an auth.state read still running")
    func loadStateBeatsRunningRead() async throws {
        let fake = FakeBridge()
        let (login, _) = await model(fake)
        let older = fake.hold(.authState)
        fake.respond(.authState, loggedIn)
        let pending = Task { await login.authChanged() }
        #expect(await settle { fake.count(.authState) == 1 })
        try await login.loadState()
        older.release(loggedOut)
        await pending.value
        #expect(login.authState == loggedIn)
    }

    @Test("logged out: the button logs in; success shows the core's status text and state")
    func loginSuccess() async {
        let fake = FakeBridge()
        let (login, status) = await model(fake, state: loggedOut)
        let (held, task) = await startHeld(fake, login)
        #expect(login.isLoggingIn)
        #expect(status.texts == [LoginModel.requestingCodeStatus])
        held.release(loggedIn)
        await task.value
        #expect(!login.isLoggingIn)
        #expect(login.authState == loggedIn)
        #expect(status.texts == [LoginModel.requestingCodeStatus, "Logged in as @octocat"])
        #expect(login.alert == nil)
        #expect(fake.params(.authLogin) == ["{}"])
        #expect(fake.count(.authCancelLogin) == 0)
    }

    @Test("the login button with no login starts it")
    func buttonStartsLogin() async {
        let fake = FakeBridge()
        fake.respond(.authLogin, loggedIn)
        let (login, status) = await model(fake, state: loggedOut)
        await login.buttonTapped()
        #expect(fake.count(.authLogin) == 1)
        #expect(login.pendingConfirmation == nil)
        #expect(status.last == "Logged in as @octocat")
    }

    @Test("offline: the button reconnects")
    func reconnect() async {
        let fake = FakeBridge()
        fake.respond(.authLogin, loggedIn)
        let (login, status) = await model(fake, state: loggedInOffline)
        await login.buttonTapped()
        #expect(status.texts == [LoginModel.reconnectingStatus, "Logged in as @octocat"])
        #expect(login.authState == loggedIn)
    }

    @Test("still offline after reconnecting: GitHub Unreachable, status cleared")
    func stillOffline() async {
        let fake = FakeBridge()
        fake.respond(.authLogin, loggedInOffline)
        let (login, status) = await model(fake, state: loggedInOffline)
        await login.start()
        #expect(status.last == "")
        #expect(
            login.alert
                == AlertState(
                    title: "GitHub Unreachable", message: "Still can't reach GitHub. Check your connection and try again."))
        #expect(login.authState == loggedInOffline)
    }

    @Test("a cancelled login clears the status without an alert")
    func cancelled() async {
        let fake = FakeBridge()
        fake.fail(.authLogin, RPCError(code: .cancelled, message: "Login cancelled."))
        let (login, status) = await model(fake)
        await login.start()
        #expect(status.last == "")
        #expect(login.alert == nil)
        #expect(!login.isLoggingIn)
    }

    @Test("a failed login shows the core's message as an error")
    func failed() async {
        let error = RPCError(
            code: .loginUnavailable, message: "GitHub login isn't available: no secure credential store on this computer.")
        let fake = FakeBridge()
        fake.fail(.authLogin, error)
        let (login, status) = await model(fake)
        await login.start()
        #expect(login.alert == AlertState(title: "Unable to Log In", message: error.message))
        login.alertDismissed()
        #expect(login.alert == nil)
        #expect(status.last == "")
        #expect(login.authState == AuthState(loggedIn: false, offline: false, user: "", statusText: ""))
    }

    @Test("busy: Login already in progress; the running login keeps its sheet")
    func busy() async {
        let fake = FakeBridge()
        let (login, status) = await model(fake)
        let held = fake.hold(.authLogin)
        fake.fail(.authLogin, RPCError(code: .busy, message: "Another operation is in progress."))
        let task = Task { await login.start() }
        #expect(await settle { fake.count(.authLogin) == 1 })
        login.showDeviceCode(code)
        await login.start()
        #expect(status.last == "Login already in progress")
        #expect(login.deviceCode != nil)
        #expect(login.isLoggingIn)
        #expect(login.alert == nil)
        held.release(loggedIn)
        await task.value
        #expect(login.deviceCode == nil)
        #expect(!login.isLoggingIn)
    }

    @Test("busy with no login of ours running leaves nothing running")
    func busyAlone() async {
        let fake = FakeBridge()
        fake.fail(.authLogin, RPCError(code: .busy, message: "Another operation is in progress."))
        let (login, status) = await model(fake)
        await login.start()
        #expect(status.last == "Login already in progress")
        #expect(!login.isLoggingIn)
    }

    @Test("device code with a URI: Waiting status, code and URL")
    func deviceCodeWithURI() async throws {
        let fake = FakeBridge()
        let (login, status) = await model(fake)
        let (held, task) = await startHeld(fake, login)
        login.showDeviceCode(code)
        #expect(status.last == LoginModel.waitingStatus)
        let prompt = try #require(login.deviceCode)
        #expect(prompt.userCode == "ABCD-1234")
        #expect(prompt.verificationURL == URL(string: "https://github.com/login/device"))
        held.release(loggedIn)
        await task.value
    }

    @Test("device code without a URI: no URL (Open GitHub disabled)")
    func deviceCodeWithoutURI() async {
        let fake = FakeBridge()
        let (login, _) = await model(fake)
        let (held, task) = await startHeld(fake, login)
        login.showDeviceCode(DeviceCode(userCode: "WXYZ-0000", verificationUri: ""))
        #expect(login.deviceCode == LoginModel.DeviceCodePrompt(userCode: "WXYZ-0000", verificationURL: nil))
        held.release(loggedIn)
        await task.value
    }

    @Test("a device code with no login running is ignored")
    func strayDeviceCode() async {
        let (login, status) = await model(FakeBridge())
        login.showDeviceCode(code)
        #expect(login.deviceCode == nil)
        #expect(status.texts.isEmpty)
    }

    @Test("a finished login closes the sheet without cancelling; a later dismissal cancels nothing")
    func finishedNoCancel() async {
        let fake = FakeBridge()
        let (login, _) = await model(fake)
        let (held, task) = await startHeld(fake, login)
        login.showDeviceCode(code)
        held.release(loggedIn)
        await task.value
        #expect(login.deviceCode == nil)
        // The sheet's onDismiss fires after the core closed it.
        await login.cancelLogin()
        #expect(fake.count(.authCancelLogin) == 0)
    }

    @Test("Cancel on the sheet: exactly one auth.cancelLogin, even with a second dismissal")
    func cancelOnce() async {
        let fake = FakeBridge()
        let (login, status) = await model(fake)
        let (held, task) = await startHeld(fake, login)
        login.showDeviceCode(code)
        await login.cancelLogin()
        #expect(login.deviceCode == nil)
        await login.cancelLogin()
        #expect(fake.count(.authCancelLogin) == 1)
        #expect(fake.params(.authCancelLogin) == ["{}"])
        held.release(failing: RPCError(code: .cancelled, message: "Login cancelled."))
        await task.value
        #expect(status.last == "")
        #expect(login.alert == nil)
        #expect(fake.count(.authCancelLogin) == 1)
    }

    @Test("cancelling with no sheet up sends nothing")
    func cancelWithoutSheet() async {
        let fake = FakeBridge()
        let (login, _) = await model(fake)
        await login.cancelLogin()
        let (held, task) = await startHeld(fake, login)
        await login.cancelLogin()
        #expect(fake.count(.authCancelLogin) == 0)
        held.release(loggedIn)
        await task.value
    }

    @Test("logged in: the button asks to log out; confirming logs out")
    func logout() async {
        let fake = FakeBridge()
        let (login, status) = await model(fake, state: loggedIn)
        await login.buttonTapped()
        #expect(fake.count(.authLogin) == 0)
        #expect(
            login.pendingConfirmation
                == Confirmation(
                    title: "Log Out", message: "Log out of GitHub? You'll need to re-authorize to submit future updates.",
                    confirmTitle: "Log Out"))
        await login.confirmLogout()
        #expect(login.pendingConfirmation == nil)
        #expect(fake.params(.authLogout) == ["{}"])
        #expect(status.texts == ["Logged out"])
        // auth.changed, not the call, updates the state.
        #expect(login.authState == loggedIn)
    }

    @Test("the menu's Log Out… asks to log out, offline too (never a reconnect); logged out, nothing")
    func logOutTapped() async {
        for state in [loggedIn, loggedInOffline] {
            let fake = FakeBridge()
            let (login, _) = await model(fake, state: state)
            login.logOutTapped()
            #expect(login.pendingConfirmation == LoginModel.logoutConfirmation)
            #expect(fake.count(.authLogin) == 0)
        }
        let fake = FakeBridge()
        let (login, _) = await model(fake, state: loggedOut)
        login.logOutTapped()
        #expect(login.pendingConfirmation == nil)
    }

    @Test("declining Log Out does nothing; confirming with nothing asked does nothing")
    func logoutDeclined() async {
        let fake = FakeBridge()
        let (login, status) = await model(fake, state: loggedIn)
        await login.buttonTapped()
        login.dismissConfirmation()
        #expect(login.pendingConfirmation == nil)
        await login.confirmLogout()
        #expect(fake.count(.authLogout) == 0)
        #expect(status.texts.isEmpty)
    }

    @Test("a failed logout shows the core's message")
    func logoutFailure() async {
        let fake = FakeBridge()
        fake.fail(.authLogout, RPCError(code: .internal, message: "An internal error occurred — please restart"))
        let (login, status) = await model(fake, state: loggedIn)
        await login.buttonTapped()
        await login.confirmLogout()
        #expect(login.alert == AlertState(title: "Unable to Log Out", message: "An internal error occurred — please restart"))
        #expect(status.texts.isEmpty)
    }

    @Test("a status text lands on both the Registry and the History tab's status line, and every handler gets it")
    func statusReachesBothTabs() async {
        let fake = FakeBridge()
        let login = LoginModel(bridge: fake)
        let registry = RegistryModel(bridge: fake, login: login)
        let history = HistoryModel(bridge: fake, login: login)
        let status = StatusRecorder()
        status.attach(login)
        let held = fake.hold(.authLogin)
        let running = Task { await login.start() }
        #expect(await settle { fake.count(.authLogin) == 1 })
        #expect(registry.status == LoginModel.requestingCodeStatus)
        #expect(history.status == LoginModel.requestingCodeStatus)
        held.release(loggedIn)
        await running.value
        #expect(registry.status == "Logged in as @octocat")
        #expect(history.status == "Logged in as @octocat")
        #expect(status.texts == [LoginModel.requestingCodeStatus, "Logged in as @octocat"])
    }

    // Handlers are never removed: the released model's still runs, and does
    // nothing because it holds its model weakly.
    @Test("a status text after a tab model is released still reaches the others")
    func statusAfterATabModelIsReleasedStillReachesTheOthers() async {
        let fake = FakeBridge()
        fake.respond(.authLogin, loggedIn)
        let login = LoginModel(bridge: fake)
        var history: HistoryModel? = HistoryModel(bridge: fake, login: login)
        weak let released = history
        history = nil
        #expect(released == nil)
        let registry = RegistryModel(bridge: fake, login: login)
        await login.start()
        #expect(registry.status == "Logged in as @octocat")
    }
}
