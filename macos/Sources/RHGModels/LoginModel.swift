import Foundation
import Observation
import RHGBridge

/// GitHub login: the login button, the device-code sheet and logging out.
/// The core runs the login and words its state; this model shows what it
/// returns. Its status texts go to the Registry tab's status line (`onStatus`),
/// whichever tab started the login, as in the Fyne app.
@MainActor
@Observable
public final class LoginModel {
    nonisolated public static let loginTitle = "Login to GitHub"
    nonisolated public static let reconnectTitle = "Offline \u{2014} Reconnect"
    nonisolated public static let deviceCodeTitle = "GitHub Login"
    nonisolated public static let deviceCodePrompt = "Enter this code at GitHub:"
    nonisolated public static let copyCodeTitle = "Copy Code"
    nonisolated public static let openGitHubTitle = "Open GitHub"
    nonisolated public static let cancelTitle = "Cancel"

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

    /// Receives the login status texts: the Registry tab's status line.
    @ObservationIgnored var onStatus: @MainActor (String) -> Void = { _ in }

    @ObservationIgnored private let bridge: any Bridge

    public init(bridge: any Bridge) {
        self.bridge = bridge
    }

    /// auth.login is running.
    public var isLoggingIn: Bool { loginCalls > 0 }

    /// The login button's title: "Login to GitHub", "Offline — Reconnect" or
    /// "@user ▾".
    public var buttonTitle: String {
        if !authState.loggedIn {
            return Self.loginTitle
        }
        if authState.offline {
            return Self.reconnectTitle
        }
        return "@" + authState.user + " \u{25BE}"
    }

    /// Reads the login state (auth.state).
    func loadState() async throws(RPCError) {
        authState = try await bridge.authState()
    }

    /// The login button: logs in (or reconnects an offline session), or,
    /// when logged in and online, asks to log out.
    public func buttonTapped() async {
        if !authState.loggedIn || authState.offline {
            await start()
        } else {
            pendingConfirmation = Self.logoutConfirmation
        }
    }

    /// Log Out confirmed: logs out (auth.logout); auth.changed updates the
    /// button.
    public func confirmLogout() async {
        guard pendingConfirmation != nil else { return }
        pendingConfirmation = nil
        do {
            try await bridge.logout()
        } catch {
            alert = .error(error)
            return
        }
        onStatus("Logged out")
    }

    /// Log Out declined.
    public func dismissConfirmation() {
        pendingConfirmation = nil
    }

    /// Logs in: reconnects a session that was offline, or else runs the
    /// device flow (auth.login, which emits auth.deviceCode), and shows the
    /// outcome. The single entry point of every "log in" button.
    public func start() async {
        onStatus(authState.loggedIn && authState.offline ? "Reconnecting to GitHub..." : "Requesting device code...")
        loginCalls += 1
        let state: AuthState
        do {
            state = try await bridge.login()
        } catch {
            // Another login is running and owns the sheet.
            if error.code == .busy {
                loginCalls -= 1
                onStatus("Login already in progress")
                return
            }
            finished()
            if error.code != .cancelled {
                alert = .error(error)
            }
            onStatus("")
            return
        }
        finished()
        authState = state
        if state.offline {
            onStatus("")
            alert = AlertState(
                title: "GitHub Unreachable", message: "Still can't reach GitHub. Check your connection and try again.")
            return
        }
        onStatus(state.statusText)
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
        onStatus("Waiting for GitHub authorization...")
        let url = code.verificationUri.isEmpty ? nil : URL(string: code.verificationUri)
        deviceCode = DeviceCodePrompt(userCode: code.userCode, verificationURL: url)
    }

    /// The operator closed the alert.
    public func alertDismissed() {
        alert = nil
    }

    /// auth.changed.
    func authChanged(_ state: AuthState) {
        authState = state
    }
}
