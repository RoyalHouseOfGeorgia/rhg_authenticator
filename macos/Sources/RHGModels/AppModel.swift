import Foundation
import Observation
import RHGBridge

/// The window's tabs, in the tab picker's order.
public enum AppTab: CaseIterable, Hashable, Sendable {
    case sign
    case history
    case registry
    case audit
    case yubiKey

    /// The tab picker's segment title.
    public var title: String {
        switch self {
        case .sign: AppModel.signTabTitle
        case .history: AppModel.historyTabTitle
        case .registry: AppModel.registryTabTitle
        case .audit: AppModel.auditTabTitle
        case .yubiKey: AppModel.yubiKeyTabTitle
        }
    }
}

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

    /// Help → Export Error Log…, also offered by some alerts.
    nonisolated public static let exportErrorLogTitle = "Export Error Log\u{2026}"
    /// The tab picker's titles, in the tabs' order.
    nonisolated public static let signTabTitle = "Sign"
    nonisolated public static let historyTabTitle = "History"
    nonisolated public static let registryTabTitle = "Registry"
    nonisolated public static let auditTabTitle = "Audit"
    nonisolated public static let yubiKeyTabTitle = "YubiKey"

    /// The quit confirmation with unsubmitted registry edits (`confirmDiscard`).
    nonisolated public static let quitConfirmation = Confirmation(
        title: "Unsubmitted Changes",
        message: "The registry has changes that haven't been submitted for review. If you quit, they'll be lost.",
        confirmTitle: "Discard and Quit", isDestructive: true)

    /// The title of the alert a startup failure shows before quitting.
    nonisolated public static let fatalErrorTitle = "RHG Authenticator Can't Start"
    /// The title of the alert app.internalError shows (`internalErrorMessage`).
    nonisolated public static let internalErrorTitle = "Something Went Wrong"

    /// View → Refresh's title on a tab without a refresh.
    nonisolated public static let refreshMenuTitle = "Refresh"
    /// The documentation Help → RHG Authenticator Help opens.
    nonisolated public static let helpURL = URL(string: "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator#readme")!

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
    /// The tab the window shows.
    public var selectedTab: AppTab = .sign
    /// Bumped by `requestFind()`; the History tab focuses its search field
    /// when it changes.
    public private(set) var findRequests = 0

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

    /// Save SVG / Save PNG, the result's buttons and File's Save QR Code
    /// items alike: a signed result, and no signing under way.
    public var canSaveQR: Bool { sign.result != nil && !isSigningBusy }

    /// View → Refresh's title: the visible tab's refresh button title, or
    /// plain "Refresh" (disabled) on a tab without one (Sign, YubiKey).
    public var refreshTitle: String {
        switch selectedTab {
        case .history: HistoryModel.refreshTitle
        case .registry: RegistryModel.fetchTitle
        case .audit: AuditModel.refreshTitle
        case .sign, .yubiKey: Self.refreshMenuTitle
        }
    }

    /// Whether the visible tab's refresh can run, as its button: History's
    /// Refresh always, Fetch from Server unless a fetch or a submit is under
    /// way, Audit's Refresh unless one is; never on Sign or YubiKey.
    public var canRefresh: Bool {
        switch selectedTab {
        case .history: true
        case .registry: registry.canFetch
        case .audit: audit.canRefresh
        case .sign, .yubiKey: false
        }
    }

    /// View → Refresh (⌘R): what the visible tab's refresh button does
    /// (Fetch from Server asks first when there are unsubmitted edits).
    public func refresh() async {
        guard canRefresh else { return }
        switch selectedTab {
        case .history: await history.refreshTapped()
        case .registry: await registry.fetchTapped()
        case .audit: await audit.refresh()
        case .sign, .yubiKey: break
        }
    }

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
            let result = try await bridge.exportErrorLog(path: path)
            return AlertState(title: result.title, message: result.message)
        } catch {
            return .error(error, title: "Unable to Export Error Log")
        }
    }

    /// The status bar's texts as the core words them (app.init); empty before
    /// startup.
    public var statusItems: [String] { info?.statusItems ?? [] }

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

    /// Find…: shows the History tab, from any tab, and asks it to focus its
    /// search field.
    public func requestFind() {
        selectedTab = .history
        findRequests += 1
    }

    /// Restart Now: the next quit relaunches the app after the update
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
        // Read only now, so a Restart Now pressed while canQuit ran counts.
        try? await bridge.shutdown(relaunch: restartRequested)
        return true
    }
}
