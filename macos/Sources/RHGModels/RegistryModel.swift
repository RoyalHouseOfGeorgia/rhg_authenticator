import Foundation
import Observation
import RHGBridge

/// The Registry tab: the edited registry's table, Fetch from Server, Add and
/// Edit Entry, and Submit for Review. The core edits, validates and submits;
/// this model shows what it returns.
@MainActor
@Observable
public final class RegistryModel {
    nonisolated public static let fetchTitle = "Fetch from Server"
    nonisolated public static let fetchTooltip = "Download the latest registry (\u{2318}R)"
    nonisolated public static let submitTitle = "Submit for Review"
    /// The buttons that open the entry sheet (titled `EntryFormModel.addTitle`
    /// / `editTitle`).
    nonisolated public static let addEntryTitle = "Add Entry\u{2026}"
    nonisolated public static let editEntryTitle = "Edit Entry\u{2026}"
    nonisolated public static let editEntryTooltip = "Select an entry to edit it."
    nonisolated public static let loadedStatus = "Loaded from registry server"
    nonisolated public static let fetchingStatus = "Fetching registry\u{2026}"
    nonisolated public static let submittingStatus = "Creating pull request\u{2026}"
    nonisolated public static let submitBusyStatus = "Submit already in progress"
    nonisolated public static let loadFailedStatus = "Failed to load registry"

    /// Fetch from Server with unsubmitted edits.
    nonisolated public static let discardConfirmation = Confirmation(
        title: "Discard Local Edits?",
        message: "This will re-fetch the live registry from the server, discarding your local edits. Continue?",
        confirmTitle: "Discard and Fetch", isDestructive: true)

    /// The table's column count: the core's column set (#, Authority, From,
    /// To, Restrictions, Note, Fingerprint; go/service/registry.go
    /// `registryColumns`) is fixed.
    nonisolated public static let columnCount = 7

    /// The table's column headings.
    public private(set) var columns: [String] = []
    /// The registry as edited.
    public private(set) var snapshot = RegistrySnapshot(entries: [], rows: [], dirty: false, loaded: false)
    /// The selected row's index in the snapshot's entries and rows; cleared by
    /// registry.changed, kept by the model's own re-reads while its row exists.
    public private(set) var selection: Int?
    /// The status line; `login`'s status texts land here too.
    public private(set) var status = ""
    /// The registry is being fetched: the startup load, or Fetch from Server
    /// until its registry.changed (or its failure).
    public private(set) var isFetching = false
    /// Submit for Review's registry.submit is running (not the login it may
    /// start).
    public private(set) var isSubmitting = false
    /// Show the entry sheet while non-nil; its buttons call
    /// `submitEntryForm()` and `cancelEntryForm()`.
    public private(set) var entryForm: EntryFormModel?
    /// Ask this; answer with `confirm()` or `dismissConfirmation()`.
    public private(set) var pendingConfirmation: Confirmation?
    /// The alert to show; `alertDismissed()` when the operator closes it.
    public private(set) var alert: AlertState?

    /// The login that Submit for Review starts without a session.
    @ObservationIgnored private let login: LoginModel

    @ObservationIgnored private let bridge: any Bridge
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private let openURL: @MainActor (URL) -> Void
    /// Runs when the pending confirmation is confirmed.
    @ObservationIgnored private var confirmAction: (@MainActor () async -> Void)?
    /// Runs when the alert is dismissed.
    @ObservationIgnored private var alertAction: (@MainActor () async -> Void)?
    /// Counts snapshot reads, so only the latest one is applied.
    @ObservationIgnored private var snapshotReads = 0

    public init(
        bridge: any Bridge, login: LoginModel, clock: @escaping () -> Date = Date.init,
        openURL: @escaping @MainActor (URL) -> Void = { _ in }
    ) {
        self.bridge = bridge
        self.login = login
        self.clock = clock
        self.openURL = openURL
        login.addStatusHandler { [weak self] text in self?.status = text }
    }

    /// Loads the columns and the registry (registry.columns, registry.snapshot).
    /// The registry may still be loading: app.start finishes it, ending in
    /// registry.changed. A snapshot read overtaken by a newer one (or by
    /// registry.changed) is dropped.
    func load() async throws(RPCError) {
        columns = try await bridge.registryColumns()
        snapshotReads += 1
        let read = snapshotReads
        let latest = try await bridge.registrySnapshot()
        guard read == snapshotReads else { return }
        snapshot = latest
        isFetching = !latest.loaded
        status = latest.loaded ? Self.loadedStatus : Self.fetchingStatus
    }

    /// registry.changed: a fetch (or the startup load) replaced the registry.
    func registryChanged() async {
        isFetching = false
        selection = nil
        guard await refresh() else { return }
        status = snapshot.loaded ? Self.loadedStatus : Self.loadFailedStatus
    }

    /// Re-reads the snapshot, keeping the selection while its row exists. A
    /// failed read keeps the current table. Returns false when a newer read
    /// started meanwhile; its result is then dropped.
    @discardableResult
    private func refresh() async -> Bool {
        snapshotReads += 1
        let read = snapshotReads
        let latest = try? await bridge.registrySnapshot()
        guard read == snapshotReads else { return false }
        if let latest {
            snapshot = latest
            if let selection, selection >= snapshot.rows.count {
                self.selection = nil
            }
        }
        return true
    }

    /// The operator selected a row; nil or out of range clears the selection.
    public func select(row: Int?) {
        guard let row, snapshot.rows.indices.contains(row) else {
            selection = nil
            return
        }
        selection = row
    }

    /// A table cell's text; "" when the row or column is out of range.
    public func cell(row: Int, column: Int) -> String {
        guard snapshot.rows.indices.contains(row), snapshot.rows[row].indices.contains(column) else { return "" }
        return snapshot.rows[row][column]
    }

    /// Copy: a row's `columnCount` cells joined by tabs; "" when the row is
    /// out of range.
    public func copyText(row: Int) -> String {
        guard snapshot.rows.indices.contains(row) else { return "" }
        return (0..<Self.columnCount).map { cell(row: row, column: $0) }.joined(separator: "\t")
    }

    /// A fetch or a submit is running: the spinner shows, and Fetch from
    /// Server and Submit for Review do nothing.
    public var isBusy: Bool { isFetching || isSubmitting }

    /// Fetch from Server is enabled (its button and View → Refresh): not
    /// busy.
    public var canFetch: Bool { !isBusy }

    /// Fetch from Server: asks first when there are unsubmitted edits.
    /// Nothing while busy.
    public func fetchTapped() async {
        guard !isBusy else { return }
        if snapshot.dirty {
            ask(Self.discardConfirmation) { [weak self] in await self?.fetch() }
        } else {
            await fetch()
        }
    }

    /// Re-fetches the registry (registry.fetch); success arrives as
    /// registry.changed.
    private func fetch() async {
        status = Self.fetchingStatus
        isFetching = true
        do {
            try await bridge.fetchRegistry()
        } catch {
            isFetching = false
            status = Self.loadFailedStatus
        }
    }

    /// Add Entry: opens an empty entry sheet; nothing while a fetch is under
    /// way.
    public func addEntryTapped() {
        guard canAddEntry else { return }
        entryForm = EntryFormModel(bridge: bridge, clock: clock)
    }

    /// Add Entry is enabled unless a fetch is under way: the fetched registry
    /// replaces the core's edits, so an entry added meanwhile would be lost.
    public var canAddEntry: Bool { !isFetching }

    /// Edit Entry is enabled while the selected row is an entry and no fetch
    /// is under way
    /// (`editEntryTooltip` says why otherwise).
    public var canEditEntry: Bool {
        guard let selection else { return false }
        return canEditEntry(row: selection)
    }

    /// Whether `row` is an entry that Edit Entry can open now.
    public func canEditEntry(row: Int) -> Bool {
        // A fetch under way replaces the core's edits, and the entry at the
        // row with them.
        !isFetching && snapshot.entries.indices.contains(row)
    }

    /// Edit Entry: opens the selected entry's sheet; nothing without one.
    public func editEntryTapped() {
        guard let selection else { return }
        editEntry(row: selection)
    }

    /// Opens `row`'s entry sheet; nothing when the row is not an entry.
    public func editEntry(row: Int) {
        guard canEditEntry(row: row) else { return }
        entryForm = EntryFormModel(bridge: bridge, index: row, entry: snapshot.entries[row], clock: clock)
    }

    /// Add / Save on the entry sheet: closes it and re-reads the registry once
    /// the core accepts the entry; else the sheet stays with the core's message.
    public func submitEntryForm() async {
        guard let form = entryForm, await form.submit() else { return }
        if entryForm === form {
            entryForm = nil
        }
        await refresh()
    }

    /// Cancel on the entry sheet.
    public func cancelEntryForm() {
        entryForm = nil
    }

    /// Submit for Review: opens a pull request with the edited registry
    /// (registry.submit), logging in first without a session. Nothing with
    /// no entries or while busy.
    public func submitForReview() async {
        guard !isBusy, !snapshot.entries.isEmpty else { return }
        status = Self.submittingStatus
        isSubmitting = true
        let result: SubmitResult
        do {
            result = try await bridge.submitRegistry()
            isSubmitting = false
        } catch {
            isSubmitting = false
            switch error.code {
            case .notLoggedIn:
                await login.start()
            case .busy:
                status = Self.submitBusyStatus
            case .sessionExpired:
                // The core has logged out; log in again once the alert closes.
                status = ""
                show(AlertState(title: "Session Expired", message: error.message)) { [weak self] in
                    await self?.login.start()
                }
            case .registryChanged:
                status = ""
                show(AlertState(title: "Registry Changed", message: error.message))
            default:
                status = ""
                show(AlertState(title: "Submission Failed", message: error.message, offersErrorLogExport: true))
            }
            return
        }
        // The core is clean now but sends no registry.changed for a submit.
        await refresh()
        status = "PR #\(result.prNumber) created"
        if !result.url.isEmpty, let url = URL(string: result.url) {
            let question = Confirmation(
                title: "Pull Request Created", message: "PR #\(result.prNumber) has been created.\n\nOpen in browser?",
                confirmTitle: "Open in Browser", cancelTitle: "Close")
            ask(question) { [weak self] in self?.openURL(url) }
        } else {
            show(AlertState(title: "Pull Request Created", message: "PR #\(result.prNumber) has been created."))
        }
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
