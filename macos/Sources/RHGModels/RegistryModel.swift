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
    nonisolated public static let submitTitle = "Submit for Review"
    nonisolated public static let addEntryTitle = EntryFormModel.addTitle
    nonisolated public static let editEntryTitle = EntryFormModel.editTitle
    nonisolated public static let loadedStatus = "Loaded from registry server"
    nonisolated public static let fetchingStatus = "Fetching..."
    nonisolated public static let loadFailedStatus = "Failed to load registry"

    /// Fetch from Server with unsubmitted edits.
    nonisolated public static let discardConfirmation = Confirmation(
        title: "Discard Local Edits?",
        message: "This will re-fetch the live registry from the server, discarding your local edits. Continue?",
        confirmTitle: "Discard and Fetch", isDestructive: true)

    /// A selected table cell: `row` indexes the snapshot's entries and rows.
    public struct Cell: Sendable, Equatable {
        public var row: Int
        public var column: Int

        public init(row: Int, column: Int) {
            self.row = row
            self.column = column
        }
    }

    /// The table's column headings.
    public private(set) var columns: [String] = []
    /// The registry as edited.
    public private(set) var snapshot = RegistrySnapshot(entries: [], rows: [], dirty: false, loaded: false)
    public private(set) var selection: Cell?
    /// The status line; `login`'s status texts land here too.
    public private(set) var status = ""
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
        login.onStatus = { [weak self] text in self?.status = text }
    }

    /// Loads the columns and the registry (registry.columns, registry.snapshot).
    /// The registry may still be loading: app.start finishes it, ending in
    /// registry.changed.
    func load() async throws(RPCError) {
        columns = try await bridge.registryColumns()
        snapshot = try await bridge.registrySnapshot()
        status = snapshot.loaded ? Self.loadedStatus : Self.fetchingStatus
    }

    /// registry.changed: a fetch (or the startup load) replaced the registry.
    func registryChanged() async {
        selection = nil
        await refresh()
        status = snapshot.loaded ? Self.loadedStatus : Self.loadFailedStatus
    }

    /// Re-reads the snapshot, keeping the selection while its row exists. A
    /// failed read keeps the current table.
    private func refresh() async {
        snapshotReads += 1
        let read = snapshotReads
        guard let latest = try? await bridge.registrySnapshot(), read == snapshotReads else { return }
        snapshot = latest
        if let selection, selection.row >= snapshot.rows.count {
            self.selection = nil
        }
    }

    /// The operator selected a table cell: its text, if any, goes to the
    /// status line.
    public func select(row: Int, column: Int) {
        guard snapshot.rows.indices.contains(row), snapshot.rows[row].indices.contains(column) else { return }
        selection = Cell(row: row, column: column)
        let text = snapshot.rows[row][column]
        if !text.isEmpty {
            status = text
        }
    }

    /// Fetch from Server: asks first when there are unsubmitted edits.
    public func fetchTapped() async {
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
        do {
            try await bridge.fetchRegistry()
        } catch {
            status = Self.loadFailedStatus
        }
    }

    /// Add Entry: opens an empty entry sheet.
    public func addEntryTapped() {
        entryForm = EntryFormModel(bridge: bridge, clock: clock)
    }

    /// Edit Entry: opens the selected entry's sheet, or says none is selected.
    public func editEntryTapped() {
        guard let selection, snapshot.entries.indices.contains(selection.row) else {
            show(AlertState(title: Self.editEntryTitle, message: "No entry selected"))
            return
        }
        entryForm = EntryFormModel(
            bridge: bridge, index: selection.row, entry: snapshot.entries[selection.row], clock: clock)
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
    /// no entries.
    public func submitForReview() async {
        guard !snapshot.entries.isEmpty else { return }
        status = "Creating pull request..."
        let result: SubmitResult
        do {
            result = try await bridge.submitRegistry()
        } catch {
            switch error.code {
            case .notLoggedIn:
                await login.start()
            case .busy:
                status = "Submit already in progress"
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
