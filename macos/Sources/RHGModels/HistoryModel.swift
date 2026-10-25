import Foundation
import Observation
import RHGBridge

/// The History tab: the issuance log with its search, the selected record's
/// detail, Refresh, Revoke, Delete Entry…, Export Issuance Log… and Remove
/// Duplicates…. The login button (`LoginModel`) sits on this tab too. The core
/// reads, filters, words, revokes and deletes; this model shows what it
/// returns.
@MainActor
@Observable
public final class HistoryModel {
    nonisolated public static let searchPlaceholder = "Search by recipient"
    nonisolated public static let searchTooltip = "Filter the list by recipient (\u{2318}F)"
    nonisolated public static let refreshTitle = "Refresh"
    nonisolated public static let refreshTooltip = "Reread the issuance log and revocations (\u{2318}R)"
    nonisolated public static let revokeTitle = "Revoke"
    nonisolated public static let exportTitle = "Export Issuance Log\u{2026}"
    nonisolated public static let removeDuplicatesTitle = "Remove Duplicates\u{2026}"
    nonisolated public static let deleteTitle = "Delete Entry\u{2026}"
    /// Delete Entry…'s tooltip (`deleteTooltip`), disabled and enabled.
    nonisolated public static let deleteDisabledTooltip = "Select a record to delete it."
    nonisolated public static let deleteEnabledTooltip = "Remove the selected record from the issuance log (\u{232B})"
    /// The detail pane with no record selected.
    nonisolated public static let emptyDetailText = "Select a record to see its details."
    /// Starts the detail pane's text when the core could not word the record.
    nonisolated public static let detailFailedPrefix = "Unable to show this record: "
    /// The delete question's title and buttons.
    nonisolated public static let deleteQuestionTitle = "Delete Issuance Record"
    nonisolated public static let deleteConfirmTitle = "Delete"
    nonisolated public static let revokeInsteadTitle = "Revoke Instead"
    /// The alerts of a deletion that did not happen.
    nonisolated public static let deleteNotFoundTitle = "Record Not Found"
    nonisolated public static let deleteFailedTitle = "Delete Failed"
    nonisolated public static let revocationUnavailableStatus = "Revocation unavailable"
    /// The status line after Remove Duplicates… found none to remove.
    nonisolated public static let noDuplicatesStatus = "The issuance log has no duplicate entries."

    /// The log as last read, filtered by the search.
    public private(set) var snapshot = HistoryListResult(
        rows: [], loadFailed: false, revocationsUnavailable: false, revocationsLoaded: false, revokeAvailable: false)
    /// The search text; the view changes it with `setQuery(_:)`.
    public private(set) var query = ""
    /// The selected row's index in `snapshot.rows`. An index, not a
    /// credential id: duplicate rows share a payload hash.
    public private(set) var selection: Int?
    /// The selected record's detail (history.recordText), or why it could not
    /// be shown; nil shows `emptyDetailText`. The previous detail stays until
    /// the next one arrives.
    public private(set) var selectedDetail: String?
    /// The status line; the login's status texts land here.
    public private(set) var status = ""
    /// A revocation is being submitted; Revoke and Delete Entry… stay disabled.
    public private(set) var isRevoking = false
    /// A deletion is being made; Delete Entry… and Revoke stay disabled.
    public private(set) var isDeleting = false
    /// Ask this; the operator's answer comes back through `answer(_:)`.
    public private(set) var pendingConfirmation: Confirmation?
    /// The alert to show; `alertDismissed()` when the operator closes it.
    public private(set) var alert: AlertState?

    /// The login that a refused revocation starts.
    @ObservationIgnored private let login: LoginModel

    @ObservationIgnored private let bridge: any Bridge
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private let timeZone: TimeZone
    @ObservationIgnored private let debounce: Duration
    /// Runs when the pending confirmation is confirmed.
    @ObservationIgnored private var confirmAction: (@MainActor () async -> Void)?
    /// Runs when the pending confirmation's alternate button is picked.
    @ObservationIgnored private var alternateAction: (@MainActor () async -> Void)?
    /// Runs when the alert is dismissed.
    @ObservationIgnored private var alertAction: (@MainActor () async -> Void)?
    /// Counts list reads, so only the latest one is applied.
    @ObservationIgnored private var listReads = 0
    /// Counts detail reads, so only the latest one is applied (a cleared
    /// selection drops them all).
    @ObservationIgnored private var detailReads = 0
    /// The record whose detail was last asked for (history.recordText), kept
    /// after a failed read so a re-read of the same rows does not ask again.
    @ObservationIgnored private var detailRecord: HistoryRecord?
    /// The rows on screen are being replaced (history.changed, a new search,
    /// a revocation): the next read applied clears the selection if its rows
    /// differ, so a row picked from the old rows meanwhile is not carried
    /// onto the new ones.
    @ObservationIgnored private var rowsReplaced = false
    /// A deletion is pending: the deleted record's position in the rows shown
    /// when it was sent, and those rows. The first read applied that replaces
    /// the rows and holds different rows than those takes it and selects the
    /// row now at that position (clamped to the last). A failed deletion, a
    /// new search or a revocation drops it.
    @ObservationIgnored private var pendingDelete: (position: Int, rows: HistoryListResult)?
    /// A question's text is being read from the core (history.recordText or
    /// history.duplicatePreview): a second Delete, Revoke or Remove Duplicates
    /// tap meanwhile does nothing, so one question cannot replace another.
    @ObservationIgnored private(set) var isAsking = false
    /// The detail read the latest `select(row:)` started; tests await it.
    @ObservationIgnored private(set) var pendingDetail: Task<Void, Never>?
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
        login.addStatusHandler { [weak self] text in self?.status = text }
    }

    /// Revoke is enabled for a selected, unrevoked row when the core allows
    /// revoking and no revocation or deletion is under way.
    public var canRevoke: Bool {
        guard !isRevoking, !isDeleting, snapshot.revokeAvailable, let selection,
            snapshot.rows.indices.contains(selection)
        else {
            return false
        }
        return !snapshot.rows[selection].revoked
    }

    /// Delete Entry… is enabled for a selected row while no revocation or
    /// deletion is under way.
    public var canDelete: Bool {
        guard !isRevoking, !isDeleting, let selection else { return false }
        return snapshot.rows.indices.contains(selection)
    }

    /// Delete Entry…'s tooltip: what it does while enabled, else how to
    /// enable it.
    public var deleteTooltip: String { canDelete ? Self.deleteEnabledTooltip : Self.deleteDisabledTooltip }

    /// "Revocation unavailable" when the revocation list could not be fetched.
    public var revocationStatus: String {
        snapshot.revocationsUnavailable ? Self.revocationUnavailableStatus : ""
    }

    /// The export's suggested file name, rhg-issuances-YYYY-MM-DD.json, by
    /// today's date in the machine's time zone.
    public var suggestedExportFilename: String {
        "rhg-issuances-\(DisplayDate.ymd(clock(), in: timeZone)).json"
    }

    /// No row is selected and no detail shown; detail reads still running
    /// are dropped.
    private func clearSelection() {
        detailReads += 1
        detailRecord = nil
        // Observation notifies on every assignment, so only real changes are
        // made: a search keystroke would otherwise redraw the list and pane.
        if selection != nil {
            selection = nil
        }
        if selectedDetail != nil {
            selectedDetail = nil
        }
    }

    /// The rows are about to be replaced: clears the selection now and once
    /// more when the next read lands with different rows. Reads already sent
    /// are dropped, so only one sent from now on can land; every caller
    /// follows with `reread()` (directly, through the debounced search, or
    /// through AppModel's history.changed task).
    private func resetSelection() {
        clearSelection()
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
    /// history.revocationsChanged, auth.changed). The selected row stays while
    /// it is in range, unless the rows were replaced meanwhile; its detail is
    /// re-read when its record changed. Only the latest read is applied; a
    /// failed one keeps the current rows and leaves a pending replacement and
    /// load-failure report to the next read applied. A read equal to the rows
    /// shown keeps `snapshot`, so the list is not rebuilt. After a deletion,
    /// the first read applied that replaces the rows selects the row that took
    /// the deleted one's place (the last row when it was last; nothing when
    /// the rows are empty) and reads its detail, once its rows differ from
    /// those shown when the deletion was sent.
    func reread() async {
        listReads += 1
        let read = listReads
        let latest = try? await bridge.listHistory(query: query)
        guard read == listReads, let latest else { return }
        // The selection is settled before the rows are shown, so the list
        // never shows a stale selection on the new rows. Rows equal to those
        // shown replace nothing: a row picked meanwhile is the same record.
        let same = latest == snapshot
        let replaced = rowsReplaced
        rowsReplaced = false
        var detailRow: Int?
        if replaced && !same {
            clearSelection()
        }
        if let selection {
            if selection >= latest.rows.count {
                clearSelection()
            } else if latest.rows[selection].record != detailRecord {
                detailRow = selection
            }
        }
        if !same {
            snapshot = latest
        }
        // A replacing read starts with no selection (resetSelection), so the
        // new rows show first with none, then with the row that took the
        // deleted one's place, unless the operator picked a row while the
        // read ran (rows equal to those shown keep it), which wins. Compared
        // with the rows at the deletion, not those shown: a read in between
        // (revocations, login) may already show the rows without the deleted
        // record.
        if replaced, let pending = pendingDelete, latest != pending.rows {
            pendingDelete = nil
            if !latest.rows.isEmpty, selection == nil {
                let next = min(pending.position, latest.rows.count - 1)
                selection = next
                detailRow = next
            }
        }
        // An alert already up keeps its place (and its follow-up); the report
        // waits for a read that lands once it is closed.
        if reportLoadFailure, alert == nil {
            reportLoadFailure = false
            if latest.loadFailed {
                show(AlertState(title: "Unable to Load History", message: "The issuance log couldn't be read."))
            }
        }
        if let detailRow {
            let (read, record) = beginDetailRead(row: detailRow)
            await readDetail(record, read: read)
        }
    }

    /// The search text changed: re-reads once typing pauses for `debounce`,
    /// clearing the selection. A newer change supersedes a pending one.
    public func setQuery(_ text: String) {
        guard text != query else { return }
        query = text
        // Any read from now on is for the new search, so its rows reorder,
        // and they are not the rows a pending deletion was counted in.
        pendingDelete = nil
        resetSelection()
        searchTask?.cancel()
        searchTask = Task { [weak self, debounce] in
            try? await Task.sleep(for: debounce)
            guard !Task.isCancelled, let self else { return }
            await self.reread()
        }
    }

    /// The operator selected a row (mouse or arrow keys): shows its record's
    /// detail (history.recordText) in the detail pane. Nil or out of range
    /// clears the selection; the row already selected changes nothing, so to
    /// retry a failed detail the operator selects another row and comes back.
    /// The selection and the record asked about are settled before this
    /// returns; only the latest selection's reply is applied.
    public func select(row: Int?) {
        guard let row, snapshot.rows.indices.contains(row) else {
            clearSelection()
            return
        }
        guard row != selection else { return }
        selection = row
        let (read, record) = beginDetailRead(row: row)
        pendingDetail = Task { [weak self] in
            await self?.readDetail(record, read: read)
        }
    }

    /// Starts a detail read of `row`'s record: it becomes the latest read and
    /// the record asked about. Returns the read's number and the record.
    private func beginDetailRead(row: Int) -> (read: Int, record: HistoryRecord) {
        detailReads += 1
        let record = snapshot.rows[row].record
        detailRecord = record
        return (detailReads, record)
    }

    /// Reads `record`'s detail (history.recordText) and applies it if `read`
    /// is still the latest detail read.
    private func readDetail(_ record: HistoryRecord, read: Int) async {
        let result: Result<RecordTextResult, RPCError>
        do {
            result = .success(try await bridge.recordText(record))
        } catch {
            result = .failure(error)
        }
        applyDetail(read: read, result: result)
    }

    /// Shows a detail read's reply, unless a newer read or a cleared selection
    /// superseded it. A failure shows the core's error in the detail pane, not
    /// as an alert, so it never replaces an alert or a question on screen.
    private func applyDetail(read: Int, result: Result<RecordTextResult, RPCError>) {
        guard read == detailReads else { return }
        switch result {
        case .success(let text):
            selectedDetail = text.detail
        case .failure(let error):
            selectedDetail = Self.detailFailedPrefix + error.message
        }
    }

    /// Refresh: re-reads the log and the revocation list (history.refresh);
    /// the results arrive as history.changed and history.revocationsChanged.
    public func refreshTapped() async {
        do {
            try await bridge.refreshHistory()
        } catch {
            show(.error(error, title: "Unable to Refresh History"))
        }
    }

    /// No question is up or being prepared: Delete Entry…, Revoke and Remove
    /// Duplicates… may ask theirs.
    private var canAsk: Bool { pendingConfirmation == nil && !isAsking }

    /// Prepares a question (`prepare` reads what the core says and asks it),
    /// one at a time: nothing while another question is up or being
    /// prepared, so a repeated tap or a held Delete key asks once.
    private func asking(_ prepare: () async -> Void) async {
        guard canAsk else { return }
        isAsking = true
        defer { isAsking = false }
        await prepare()
    }

    /// Revoke: asks the core's question about the selected row, then revokes
    /// it.
    public func revokeTapped() async {
        guard canRevoke, let selection else { return }
        await revokeAsking(snapshot.rows[selection].record)
    }

    /// Asks the core's revoke question about `record` (history.recordText),
    /// then revokes it. Revoke and Delete Entry…'s Revoke Instead both come
    /// here.
    private func revokeAsking(_ record: HistoryRecord) async {
        await asking {
            let text: RecordTextResult
            do throws(RPCError) {
                text = try await bridge.recordText(record)
            } catch {
                show(.error(error, title: "Unable to Revoke Record"))
                return
            }
            let question = Confirmation(
                title: "Confirm Revocation", message: text.revokeConfirm, confirmTitle: Self.revokeTitle,
                isDestructive: true)
            ask(question) { [weak self] in await self?.revoke(record) }
        }
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
        // The row now reads revoked. The re-read's rows are not those a
        // deletion whose history.changed never came was counted in.
        pendingDelete = nil
        resetSelection()
        await reread()
        show(AlertState(title: result.title, message: result.message))
    }

    /// Delete Entry… (or the Delete key in the list): asks the core's delete
    /// question about the selected row, offering Revoke Instead when the core
    /// says to, then deletes it. The question holds the record it asked about,
    /// so a history.changed that re-reads the rows meanwhile does not change
    /// what is deleted or revoked.
    public func deleteTapped() async {
        guard canDelete, let selection else { return }
        let record = snapshot.rows[selection].record
        await asking {
            let text: RecordTextResult
            do throws(RPCError) {
                text = try await bridge.recordText(record)
            } catch {
                show(.error(error, title: "Unable to Delete Record"))
                return
            }
            let question = Confirmation(
                title: Self.deleteQuestionTitle, message: text.deleteConfirm, confirmTitle: Self.deleteConfirmTitle,
                alternateTitle: text.offerRevoke ? Self.revokeInsteadTitle : nil, isDestructive: true)
            // Revoke Instead exists only when the core offers it.
            var revokeInstead: (@MainActor () async -> Void)?
            if text.offerRevoke {
                revokeInstead = { [weak self] in await self?.revokeAsking(record) }
            }
            ask(question, then: { [weak self] in await self?.delete(record) }, alternate: revokeInstead)
        }
    }

    /// Deletes `record` from the issuance log (history.deleteEntry) and shows
    /// the core's report; the list reloads on history.changed, and once it
    /// does the row that took the deleted one's place is selected (`reread()`).
    /// A failed deletion selects nothing then.
    private func delete(_ record: HistoryRecord) async {
        // Stored before the call: the core's history.changed may be handled
        // before its reply. None while a replacement is pending (a search or
        // a history.changed still reading): the rows shown are not those the
        // next read replaces.
        if !rowsReplaced, let position = positionOf(record) {
            pendingDelete = (position, snapshot)
        } else {
            pendingDelete = nil
        }
        isDeleting = true
        let result: DeleteEntryResult
        do {
            result = try await bridge.deleteEntry(record)
        } catch {
            isDeleting = false
            pendingDelete = nil
            if error.code == .notFound {
                show(AlertState(title: Self.deleteNotFoundTitle, message: error.message))
            } else {
                show(AlertState(title: Self.deleteFailedTitle, message: error.message, offersErrorLogExport: true))
            }
            return
        }
        isDeleting = false
        show(AlertState(title: result.title, message: result.message))
    }

    /// `record`'s position in the rows shown: the selected row while it still
    /// holds the record (so of identical duplicates the one selected counts),
    /// else the first row holding it; nil when none does (a history.changed
    /// while the question was up can move the rows).
    private func positionOf(_ record: HistoryRecord) -> Int? {
        let rows = snapshot.rows
        if let selection, rows.indices.contains(selection), rows[selection].record == record {
            return selection
        }
        return rows.firstIndex { $0.record == record }
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
                show(.error(error, title: "Unable to Export Issuance Log"))
            }
            return
        }
        show(AlertState(title: result.title, message: result.message))
    }

    /// Remove Duplicates…: counts the duplicates (history.duplicatePreview)
    /// and asks the core's question before removing them.
    public func removeDuplicatesTapped() async {
        await asking {
            let preview: DuplicatePreviewResult
            do throws(RPCError) {
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
    }

    /// Removes the duplicates (history.removeDuplicates) and puts the core's
    /// report on the status line; the list reloads on history.changed.
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
        status = result.message
    }

    private func showDedupeFailure(_ error: RPCError) {
        show(AlertState(title: "Remove Duplicates Failed", message: error.message, offersErrorLogExport: true))
    }

    /// Remove Duplicates… found nothing to remove. Outcomes go to the status
    /// line, not an alert (Windows shows one; a modal for a non-problem is
    /// not the Mac idiom); its failures stay alerts.
    private func showNoDuplicates() {
        status = Self.noDuplicatesStatus
    }

    /// Asks `question`: `action` runs on confirm, `alternate` (if any) on its
    /// alternate button.
    private func ask(
        _ question: Confirmation, then action: @escaping @MainActor () async -> Void,
        alternate: (@MainActor () async -> Void)? = nil
    ) {
        pendingConfirmation = question
        confirmAction = action
        alternateAction = alternate
    }

    private func show(_ state: AlertState, then action: (@MainActor () async -> Void)? = nil) {
        alert = state
        alertAction = action
    }

    /// The pending confirmation was confirmed: runs its action.
    func confirm() async {
        let action = confirmAction
        clearConfirmation()
        await action?()
    }

    /// The pending confirmation's alternate button was picked: runs its
    /// alternate action, which may ask the next question.
    func alternate() async {
        let action = alternateAction
        clearConfirmation()
        await action?()
    }

    /// The pending confirmation was declined.
    func dismissConfirmation() {
        clearConfirmation()
    }

    /// The operator answered the pending confirmation with `choice`.
    public func answer(_ choice: ConfirmChoice) async {
        switch choice {
        case .confirm:
            await confirm()
        case .alternate:
            await alternate()
        case .cancel:
            dismissConfirmation()
        }
    }

    private func clearConfirmation() {
        pendingConfirmation = nil
        confirmAction = nil
        alternateAction = nil
    }

    /// The operator closed the alert; runs its follow-up, if any.
    public func alertDismissed() async {
        let action = alertAction
        alert = nil
        alertAction = nil
        await action?()
    }
}
