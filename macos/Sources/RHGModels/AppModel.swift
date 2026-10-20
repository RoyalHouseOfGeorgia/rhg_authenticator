import Foundation
import Observation
import RHGBridge

/// The app: startup, the status bar, core events and the quit sequence. It
/// owns the tab and prompt models and routes the core's events to them.
@MainActor
@Observable
public final class AppModel {
    public enum Phase: Sendable, Equatable {
        /// app.init is fetching the registry: show a progress view.
        case starting
        case ready
        /// Startup failed: show `message`, then quit.
        case fatal(message: String)
    }

    /// The Help menu's one item.
    nonisolated public static let exportErrorLogTitle = "Export Error Log\u{2026}"

    /// The quit confirmation with unsubmitted registry edits (`confirmDiscard`).
    nonisolated public static let quitConfirmation = Confirmation(
        title: "Unsubmitted Changes", message: "The registry has unsubmitted changes. Exit anyway?",
        confirmTitle: "Exit", isDestructive: true)

    /// Appended to a startup failure's message.
    nonisolated public static let reportSuffix =
        "\n\nPlease report this error at https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues"

    public private(set) var phase: Phase = .starting
    /// The app.init result; nil until startup succeeds.
    public private(set) var info: AppInfo?
    /// app.internalError: show this alert; the view sets it back to nil.
    public var internalErrorMessage: String?
    /// The latest update.status event.
    public private(set) var updateStatus: UpdateStatus?
    /// The latest update.updated event.
    public private(set) var updatedNotice: UpdatedNotice?

    public let sign: SignModel
    public let bulk: BulkModel
    public let yubiKey: YubiKeyModel
    public let pinPrompt: PINPromptModel
    public let registry: RegistryModel
    public let history: HistoryModel
    public let audit: AuditModel
    public let login: LoginModel

    /// Asked before quitting with unsubmitted registry edits; false keeps the
    /// app running.
    @ObservationIgnored public var confirmDiscard: @MainActor () async -> Bool = { true }

    @ObservationIgnored private let bridge: any Bridge
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private let timeZone: TimeZone
    @ObservationIgnored private var eventTask: Task<Void, Never>?
    @ObservationIgnored private var quitTask: Task<Bool, Never>?
    @ObservationIgnored private var restartRequested = false

    /// `clock` is now and `timeZone` the machine's zone; tests inject both.
    public init(
        bridge: any Bridge, clock: @escaping () -> Date = Date.init, timeZone: TimeZone = .current,
        openURL: @escaping @MainActor (URL) -> Void = { _ in }
    ) {
        self.bridge = bridge
        self.clock = clock
        self.timeZone = timeZone
        sign = SignModel(bridge: bridge, clock: clock, openURL: openURL)
        bulk = BulkModel(bridge: bridge)
        yubiKey = YubiKeyModel(bridge: bridge)
        pinPrompt = PINPromptModel(bridge: bridge)
        let login = LoginModel(bridge: bridge)
        let registry = RegistryModel(bridge: bridge, login: login, clock: clock, openURL: openURL)
        self.login = login
        self.registry = registry
        history = HistoryModel(bridge: bridge, login: login, clock: clock, timeZone: timeZone)
        audit = AuditModel(bridge: bridge, openURL: openURL)
    }

    /// A signing or a bulk flow is under way: Sign Credential and Bulk Sign
    /// are both disabled. The core's busy flag is the real guard.
    public var isSigningBusy: Bool { sign.isBusy || bulk.isActive }

    /// The error log's suggested file name, rhg-error-log-YYYY-MM-DD.log, by
    /// today's date in the machine's time zone.
    public var suggestedErrorLogFilename: String {
        "rhg-error-log-\(DisplayDate.ymd(clock(), in: timeZone)).log"
    }

    /// Export Error Log…: writes the diagnostic log to `path`, the file the
    /// operator chose (app.exportErrorLog), and returns the alert saying where
    /// it went or why it failed. The caller shows it over whatever window is
    /// on top, so it appears even while a sheet is up.
    public func exportErrorLog(path: String) async -> AlertState {
        do {
            try await bridge.exportErrorLog(path: path)
        } catch {
            return .error(error)
        }
        return AlertState(
            title: "Error Log Exported",
            message: "Saved to:\n\(path)\n\nYou can attach this file to an email. It contains app diagnostics"
                + " (may include your GitHub username and file paths) \u{2014} no PINs or keys.")
    }

    /// The status bar: "Active keys: N", "Expired (30d): N" and "Version X"
    /// online, "No internet" and "Version X" offline; empty before startup.
    public var statusItems: [String] {
        guard let info else { return [] }
        let version = "Version " + (info.version.hasPrefix("v") ? String(info.version.dropFirst()) : info.version)
        if !info.online {
            return ["No internet", version]
        }
        return ["Active keys: \(info.activeKeys)", "Expired (30d): \(info.recentlyExpired)", version]
    }

    /// The update banner's status slot, from the latest update.status; nil
    /// shows nothing.
    public var updateBanner: UpdateBanner? { updateStatus.flatMap(UpdateBanner.init) }

    /// The "Updated to" notice, from the latest update.updated until the
    /// operator closes it; nil shows nothing.
    public var updatedBanner: UpdatedBanner? { updatedNotice.map(UpdatedBanner.init) }

    /// Closes the "Updated to" notice.
    public func dismissUpdatedNotice() {
        updatedNotice = nil
    }

    /// Restart now: the next quit relaunches the app after the update
    /// installs. The caller then quits; keeping unsubmitted edits at the
    /// discard confirm calls the restart off.
    public func requestRestart() {
        restartRequested = true
    }

    /// Starts the core: listens for its events (buffered since the bridge was
    /// installed), then app.init, sign.honors, auth.state, the registry
    /// (registry.columns, registry.snapshot) and app.start, which loads the
    /// history (history.changed). Ends in `.ready` or `.fatal`. Call once.
    /// The Audit tab's first fetch then runs on its own, so a slow GitHub
    /// never holds startup.
    public func start(dataDir: String? = nil) async {
        guard eventTask == nil else { return }
        let events = bridge.events
        eventTask = Task { [weak self] in
            for await event in events {
                self?.handle(event)
            }
        }
        do {
            info = try await bridge.initApp(dataDir: dataDir)
            try await sign.loadHonors()
            try await login.loadState()
            try await registry.load()
            try await bridge.startApp()
        } catch {
            phase = .fatal(message: error.message + Self.reportSuffix)
            return
        }
        phase = .ready
        Task { await audit.refresh() }
    }

    /// Handles one event, synchronously, so events apply in order and none
    /// waits behind a core call (pin.request least of all). registry.changed
    /// and the history events re-read in their own tasks; each model applies
    /// only its latest read. history.changed clears the selection here, so a
    /// Revoke tapped before its re-read lands has no row to act on.
    private func handle(_ event: BridgeEvent) {
        switch event {
        case .pinRequest(let request): pinPrompt.present(request)
        case .pinDismiss(let dismiss): pinPrompt.dismiss(requestId: dismiss.requestId)
        case .signConnecting: sign.signConnecting()
        case .bulkProgress(let progress): bulk.bulkProgress(progress)
        // The bulk sheet is up from confirm on, so the PIN being resolved
        // changes nothing on screen.
        case .bulkConnecting: break
        case .appInternalError: internalErrorMessage = RPCError.badResponse.message
        case .updateStatus(let status): updateStatus = status
        case .updateUpdated(let notice): updatedNotice = notice
        case .authChanged:
            Task { await login.authChanged() }
            // Whether revoking is available follows the login.
            Task { await history.reread() }
        case .authDeviceCode(let code): login.showDeviceCode(code)
        case .registryChanged: Task { await registry.registryChanged() }
        case .historyChanged:
            history.historyChanged()
            Task { await history.reread() }
        case .historyRevocationsChanged: Task { await history.reread() }
        default: break
        }
    }

    /// The quit sequence: app.canQuit (confirming the discard of unsubmitted
    /// edits), then app.shutdown. Returns whether to terminate: false only
    /// when the operator keeps the edits. Core errors never block quitting.
    /// Concurrent and later calls share the first sequence; shutdown runs once,
    /// relaunching only after `requestRestart()`.
    public func prepareToQuit() async -> Bool {
        if let quitTask {
            return await quitTask.value
        }
        let task = Task { await self.quit() }
        quitTask = task
        let terminate = await task.value
        if !terminate {
            quitTask = nil
            restartRequested = false
        }
        return terminate
    }

    private func quit() async -> Bool {
        if let canQuit = try? await bridge.canQuit(), canQuit.dirty, await !confirmDiscard() {
            return false
        }
        // Read only now, so a Restart now pressed while canQuit ran counts.
        try? await bridge.shutdown(relaunch: restartRequested)
        return true
    }
}
