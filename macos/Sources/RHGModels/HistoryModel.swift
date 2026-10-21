import Foundation
import Observation
import RHGBridge

/// The History tab: the issuance log with its search, Refresh, Connect to
/// GitHub, Revoke, Export Issuance Log… and Remove Duplicates…. The core
/// reads, filters, words and revokes; this model shows what it returns.
@MainActor
@Observable
public final class HistoryModel {
    nonisolated public static let searchPlaceholder = "Search by recipient..."
    nonisolated public static let refreshTitle = "Refresh"
    nonisolated public static let connectTitle = "Connect to GitHub"
    nonisolated public static let revokeTitle = "Revoke"
    nonisolated public static let exportTitle = "Export Issuance Log\u{2026}"
    nonisolated public static let removeDuplicatesTitle = "Remove Duplicates\u{2026}"
    nonisolated public static let revocationUnavailableStatus = "Revocation unavailable"

    /// The log as last read, filtered by the search.
    public private(set) var snapshot = HistoryListResult(
        rows: [], loadFailed: false, revocationsUnavailable: false, revocationsLoaded: false, revokeAvailable: false)
    /// The search text; the view changes it with `setQuery(_:)`.
    public private(set) var query = ""
    /// The selected row's index in `snapshot.rows`. An index, not a
    /// credential id: duplicate rows share a payload hash.
    public private(set) var selection: Int?
    /// A revocation is being submitted; Revoke stays disabled.
    public private(set) var isRevoking = false
    /// Ask this; answer with `confirm()` or `dismissConfirmation()`.
    public private(set) var pendingConfirmation: Confirmation?
    /// The alert to show; `alertDismissed()` when the operator closes it.
    public private(set) var alert: AlertState?

    /// The login that Connect to GitHub and a refused revocation start.
    @ObservationIgnored private let login: LoginModel

    @ObservationIgnored private let bridge: any Bridge
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private let timeZone: TimeZone
    @ObservationIgnored private let debounce: Duration
    /// Runs when the pending confirmation is confirmed.
    @ObservationIgnored private var confirmAction: (@MainActor () async -> Void)?
    /// Runs when the alert is dismissed.
    @ObservationIgnored private var alertAction: (@MainActor () async -> Void)?
    /// Counts list reads, so only the latest one is applied.
    @ObservationIgnored private var listReads = 0
    /// The rows on screen are being replaced (history.changed, a new search,
    /// a revocation): the next read applied clears the selection, so a row
    /// picked from the old rows meanwhile is not carried onto the new ones.
    @ObservationIgnored private var rowsReplaced = false
    /// history.changed: the next read applied reports a log that failed to load.
    @ObservationIgnored private var reportLoadFailure = false
    /// The pending debounced search.
    @ObservationIgnored private var searchTask: Task<Void, Never>?

    /// `clock` is now and `timeZone` the machine's zone; `debounce` is how long
    /// the search waits for typing to pause. Tests inject all three.
    public init(
        bridge: any Bridge, login: LoginModel, clock: @escaping () -> Date = Date.init, timeZone: TimeZone = .current,
        debounce: Duration = .milliseconds(200)
    ) {
        self.bridge = bridge
        self.login = login
        self.clock = clock
        self.timeZone = timeZone
        self.debounce = debounce
    }

    /// Connect to GitHub shows without a usable session.
    public var showsConnectButton: Bool { !login.hasUsableSession }

    /// Revoke is enabled for a selected, unrevoked row when the core allows
    /// revoking and no revocation is being submitted.
    public var canRevoke: Bool {
        guard !isRevoking, snapshot.revokeAvailable, let selection, snapshot.rows.indices.contains(selection) else {
            return false
        }
        return !snapshot.rows[selection].revoked
    }

    /// "Revocation unavailable" when the revocation list could not be fetched.
    public var revocationStatus: String {
        snapshot.revocationsUnavailable ? Self.revocationUnavailableStatus : ""
    }

    /// The export's suggested file name, rhg-issuances-YYYY-MM-DD.json, by
    /// today's date in the machine's time zone.
    public var suggestedExportFilename: String {
        "rhg-issuances-\(DisplayDate.ymd(clock(), in: timeZone)).json"
    }

    /// Clears the selection now and once more when the next read lands: the
    /// rows are about to be replaced. Reads already sent are dropped, so only
    /// one sent from now on can land; every caller follows with `reread()`
    /// (directly, through the debounced search, or through AppModel's
    /// history.changed task).
    private func resetSelection() {
        selection = nil
        rowsReplaced = true
        listReads += 1
    }

    /// history.changed: the log was re-read, so its rows may have moved. Call
    /// `reread()` next.
    func historyChanged() {
        resetSelection()
        reportLoadFailure = true
    }

    /// Re-reads the log for the current search (history.changed,
    /// history.revocationsChanged, auth.changed). The selected index stays
    /// while it is in range, unless the rows were replaced meanwhile. Only the
    /// latest read is applied; a failed one keeps the current rows and leaves
    /// a pending replacement and load-failure report to the next read applied.
    func reread() async {
        listReads += 1
        let read = listReads
        let latest = try? await bridge.listHistory(query: query)
        guard read == listReads, let latest else { return }
        if latest != snapshot {
            snapshot = latest
        }
        if rowsReplaced {
            rowsReplaced = false
            selection = nil
        } else if let selection, selection >= snapshot.rows.count {
            self.selection = nil
        }
        // An alert already up keeps its place (and its follow-up); the report
        // waits for a read that lands once it is closed.
        if reportLoadFailure, alert == nil {
            reportLoadFailure = false
            if latest.loadFailed {
                show(AlertState(title: "Error", message: "unable to load history"))
            }
        }
    }

    /// The search text changed: re-reads once typing pauses for `debounce`,
    /// clearing the selection. A newer change supersedes a pending one.
    public func setQuery(_ text: String) {
        guard text != query else { return }
        query = text
        // Any read from now on is for the new search, so its rows reorder.
        resetSelection()
        searchTask?.cancel()
        searchTask = Task { [weak self, debounce] in
            try? await Task.sleep(for: debounce)
            guard !Task.isCancelled, let self else { return }
            await self.reread()
        }
    }

    /// The operator selected a row: shows its record (history.recordText).
    public func select(row: Int) async {
        guard snapshot.rows.indices.contains(row) else { return }
        selection = row
        do {
            let text = try await bridge.recordText(snapshot.rows[row].record)
            show(AlertState(title: "Issuance Record", message: text.detail))
        } catch {
            show(.error(error))
        }
    }

    /// Refresh: re-reads the log and the revocation list (history.refresh);
    /// the results arrive as history.changed and history.revocationsChanged.
    public func refreshTapped() async {
        do {
            try await bridge.refreshHistory()
        } catch {
            show(.error(error))
        }
    }

    /// Connect to GitHub.
    public func connectTapped() async {
        await login.start()
    }

    /// Revoke: asks the core's question about the selected row, then revokes it.
    public func revokeTapped() async {
        guard canRevoke, let selection else { return }
        let record = snapshot.rows[selection].record
        let text: RecordTextResult
        do {
            text = try await bridge.recordText(record)
        } catch {
            show(.error(error))
            return
        }
        let question = Confirmation(
            title: "Confirm Revocation", message: text.revokeConfirm, confirmTitle: Self.revokeTitle,
            isDestructive: true)
        ask(question) { [weak self] in await self?.revoke(record) }
    }

    /// Opens a revocation pull request for `record` (history.revoke) and shows
    /// the outcome the core words.
    private func revoke(_ record: HistoryRecord) async {
        isRevoking = true
        let result: RevokeResult
        do {
            result = try await bridge.revoke(payloadSha256: record.payloadSha256)
        } catch {
            isRevoking = false
            switch error.code {
            case .busy:
                // The running revocation reports its own outcome.
                break
            case .notLoggedIn:
                await login.start()
            case .sessionExpired:
                // The core has logged out; log in again once the alert closes.
                show(AlertState(title: "Session Expired", message: error.message)) { [weak self] in
                    await self?.login.start()
                }
            default:
                show(AlertState(title: "Revocation Failed", message: error.message, offersErrorLogExport: true))
            }
            return
        }
        isRevoking = false
        // The row now reads revoked.
        resetSelection()
        await reread()
        show(AlertState(title: result.title, message: result.message))
    }

    /// Export Issuance Log…: copies the log to `path`, the file the operator
    /// chose (history.exportIssuanceLog), and shows the core's alert saying
    /// where it went.
    public func exportIssuanceLog(path: String) async {
        let result: ExportResult
        do {
            result = try await bridge.exportIssuanceLog(path: path)
        } catch {
            if error.code == .nothingToExport {
                show(AlertState(title: "Nothing to Export", message: error.message))
            } else {
                show(.error(error))
            }
            return
        }
        show(AlertState(title: result.title, message: result.message))
    }

    /// Remove Duplicates…: counts the duplicates (history.duplicatePreview)
    /// and asks the core's question before removing them.
    public func removeDuplicatesTapped() async {
        let preview: DuplicatePreviewResult
        do {
            preview = try await bridge.duplicatePreview()
        } catch {
            showDedupeFailure(error)
            return
        }
        guard preview.count > 0 else {
            showNoDuplicates()
            return
        }
        let question = Confirmation(
            title: "Remove Duplicates", message: preview.confirmMessage,
            confirmTitle: "Remove Entries", cancelTitle: "Cancel", isDestructive: true)
        ask(question) { [weak self] in await self?.removeDuplicates() }
    }

    /// Removes the duplicates (history.removeDuplicates) and shows the core's
    /// report; the list reloads on history.changed.
    private func removeDuplicates() async {
        let result: RemoveDuplicatesResult
        do {
            result = try await bridge.removeDuplicates()
        } catch {
            showDedupeFailure(error)
            return
        }
        guard result.removed > 0 else {
            // The log changed between the preview and the confirm.
            showNoDuplicates()
            return
        }
        show(AlertState(title: "Duplicates Removed", message: result.message))
    }

    private func showDedupeFailure(_ error: RPCError) {
        show(AlertState(title: "Remove Duplicates Failed", message: error.message, offersErrorLogExport: true))
    }

    private func showNoDuplicates() {
        show(AlertState(title: "No Duplicates", message: "The issuance log has no duplicate entries."))
    }

    private func ask(_ question: Confirmation, then action: @escaping @MainActor () async -> Void) {
        pendingConfirmation = question
        confirmAction = action
    }

    private func show(_ state: AlertState, then action: (@MainActor () async -> Void)? = nil) {
        alert = state
        alertAction = action
    }

    /// The pending confirmation was confirmed: runs its action.
    public func confirm() async {
        let action = confirmAction
        pendingConfirmation = nil
        confirmAction = nil
        await action?()
    }

    /// The pending confirmation was declined.
    public func dismissConfirmation() {
        pendingConfirmation = nil
        confirmAction = nil
    }

    /// The operator closed the alert; runs its follow-up, if any.
    public func alertDismissed() async {
        let action = alertAction
        alert = nil
        alertAction = nil
        await action?()
    }
}
