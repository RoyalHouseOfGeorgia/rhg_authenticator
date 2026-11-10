import Foundation
import Observation
import RHGBridge

/// GitHub login: the login button, the device-code sheet and logging out.
/// The core runs the login and words its state; this model shows what it
/// returns. Its status texts go to every status line that asked for them
/// (`addStatusHandler(_:)`: the Registry and History tabs'), whichever tab
/// started the login.
@MainActor
@Observable
public final class LoginModel {
    /// Opens the device-code sheet, hence the ellipsis.
    nonisolated public static let loginTitle = "Log In to GitHub\u{2026}"
    nonisolated public static let reconnectTitle = "Offline \u{2014} Reconnect"
    nonisolated public static let deviceCodeTitle = "GitHub Login"
    nonisolated public static let deviceCodePrompt = "Enter this code at GitHub:"
    nonisolated public static let copyCodeTitle = "Copy Code"
    nonisolated public static let openGitHubTitle = "Open GitHub"
    nonisolated public static let cancelTitle = "Cancel"
    /// The logged-in button's Log Out item, which asks first.
    nonisolated public static let logOutTitle = "Log Out\u{2026}"
    /// The status texts of a login under way.
    nonisolated public static let reconnectingStatus = "Reconnecting to GitHub\u{2026}"
    nonisolated public static let requestingCodeStatus = "Requesting device code\u{2026}"
    nonisolated public static let waitingStatus = "Waiting for GitHub authorization\u{2026}"

    /// The Log Out question.
    nonisolated public static let logoutConfirmation = Confirmation(
        title: "Log Out", message: "Log out of GitHub? You'll need to re-authorize to submit future updates.",
        confirmTitle: "Log Out")

    /// The device-code sheet's contents (auth.deviceCode).
    public struct DeviceCodePrompt: Sendable, Equatable {
        /// The code to enter at GitHub.
        public var userCode: String
        /// Where to enter it; nil when the core sent none (Open GitHub is then
        /// disabled; the code can still be entered by hand).
        public var verificationURL: URL?

        public init(userCode: String, verificationURL: URL?) {
            self.userCode = userCode
            self.verificationURL = verificationURL
        }
    }

    /// The login state; logged out until startup reads it.
    public private(set) var authState = AuthState(loggedIn: false, offline: false, user: "", statusText: "")
    /// Show the device-code sheet while non-nil; only this model closes it.
    /// Its Cancel calls `cancelLogin()`.
    public private(set) var deviceCode: DeviceCodePrompt?
    /// auth.login calls in flight: the one login the core runs, plus any
    /// second attempt it is about to refuse as busy.
    private var loginCalls = 0
    /// Ask this; answer with `confirmLogout()` or `dismissConfirmation()`.
    public private(set) var pendingConfirmation: Confirmation?
    /// The alert to show; `alertDismissed()` when the operator closes it.
    public private(set) var alert: AlertState?

    /// Counts auth.state reads, so only the latest one is applied.
    @ObservationIgnored private var stateReads = 0

    /// Receive the login status texts: the tabs' status lines.
    @ObservationIgnored private var statusHandlers: [@MainActor (String) -> Void] = []

    @ObservationIgnored private let bridge: any Bridge

    public init(bridge: any Bridge) {
        self.bridge = bridge
    }

    /// Adds a receiver of the login status texts; each text goes to all of
    /// them, in the order they were added.
    func addStatusHandler(_ handler: @escaping @MainActor (String) -> Void) {
        statusHandlers.append(handler)
    }

    private func publishStatus(_ text: String) {
        for handler in statusHandlers {
            handler(text)
        }
    }

    /// Logged in and online: GitHub calls can go ahead.
    public var hasUsableSession: Bool { authState.loggedIn && !authState.offline }

    /// auth.login is running.
    public var isLoggingIn: Bool { loginCalls > 0 }

    /// The login button's title: `loginTitle`, `reconnectTitle` or, logged in
    /// and online, "@user".
    public var buttonTitle: String {
        if !authState.loggedIn {
            return Self.loginTitle
        }
        if authState.offline {
            return Self.reconnectTitle
        }
        return "@" + authState.user
    }

    /// Reads the login state (auth.state).
    func loadState() async throws(RPCError) {
        let state = try await bridge.authState()
        // Newer than any auth.state read still running.
        stateReads += 1
        authState = state
    }

    /// The login button: logs in (or reconnects an offline session), or,
    /// when logged in and online, asks to log out.
    public func buttonTapped() async {
        if !hasUsableSession {
            await start()
        } else {
            pendingConfirmation = Self.logoutConfirmation
        }
    }

    /// The login menu's Log Out…: asks to log out, whatever the session
    /// became while the menu was open (a reconnect is never started from
    /// it); nothing when logged out.
    public func logOutTapped() {
        guard authState.loggedIn else { return }
        pendingConfirmation = Self.logoutConfirmation
    }

    /// Log Out confirmed: logs out (auth.logout); auth.changed updates the
    /// button.
    public func confirmLogout() async {
        guard pendingConfirmation != nil else { return }
        pendingConfirmation = nil
        do {
            try await bridge.logout()
        } catch {
            alert = .error(error, title: "Unable to Log Out")
            return
        }
        publishStatus("Logged out")
    }

    /// Log Out declined.
    public func dismissConfirmation() {
        pendingConfirmation = nil
    }

    /// Logs in: reconnects a session that was offline, or else runs the
    /// device flow (auth.login, which emits auth.deviceCode), and shows the
    /// outcome. The single entry point of every "log in" button.
    public func start() async {
        publishStatus(authState.loggedIn && authState.offline ? Self.reconnectingStatus : Self.requestingCodeStatus)
        loginCalls += 1
        let state: AuthState
        do {
            state = try await bridge.login()
        } catch {
            // Another login is running and owns the sheet.
            if error.code == .busy {
                loginCalls -= 1
                publishStatus("Login already in progress")
                return
            }
            finished()
            if error.code != .cancelled {
                alert = .error(error, title: "Unable to Log In")
            }
            publishStatus("")
            return
        }
        finished()
        // Newer than any auth.state read still running.
        stateReads += 1
        authState = state
        if state.offline {
            publishStatus("")
            alert = AlertState(
                title: "GitHub Unreachable", message: "Still can't reach GitHub. Check your connection and try again.")
            return
        }
        publishStatus(state.statusText)
    }

    /// The login ended: closes the device-code sheet without cancelling.
    /// The login stops counting as running first, so a Cancel after this
    /// sends no auth.cancelLogin.
    private func finished() {
        loginCalls -= 1
        deviceCode = nil
    }

    /// Cancel on the device-code sheet: closes it and stops the login
    /// (auth.cancelLogin). Nothing when the core already ended it, or for a
    /// second Cancel.
    public func cancelLogin() async {
        guard isLoggingIn, deviceCode != nil else { return }
        deviceCode = nil
        try? await bridge.cancelLogin()
    }

    /// auth.deviceCode: shows the code. Ignored when no login is running.
    func showDeviceCode(_ code: DeviceCode) {
        guard isLoggingIn else { return }
        publishStatus(Self.waitingStatus)
        let url = code.verificationUri.isEmpty ? nil : URL(string: code.verificationUri)
        deviceCode = DeviceCodePrompt(userCode: code.userCode, verificationURL: url)
    }

    /// The operator closed the alert.
    public func alertDismissed() {
        alert = nil
    }

    /// auth.changed: re-reads the login state (auth.state). The core's
    /// payloads can arrive out of order, so the event is only a signal; only
    /// the latest read is applied, and a failed one keeps the current state.
    func authChanged() async {
        stateReads += 1
        let read = stateReads
        guard let state = try? await bridge.authState(), read == stateReads else { return }
        authState = state
    }
}
