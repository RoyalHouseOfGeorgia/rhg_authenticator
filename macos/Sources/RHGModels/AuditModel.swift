import Foundation
import Observation
import RHGBridge

/// The Audit tab: the registry's GitHub commit history; Open on GitHub opens
/// the selected commit's page. The core fetches and words the rows; this
/// model shows them.
@MainActor
@Observable
public final class AuditModel {
    nonisolated public static let refreshTitle = "Refresh"
    nonisolated public static let refreshTooltip = refreshTitle + " (\u{2318}R)"
    nonisolated public static let openTitle = "Open on GitHub"
    nonisolated public static let openTooltip = "Select a commit to open it."
    nonisolated public static let fetchingStatus = "Fetching..."

    public private(set) var rows: [AuditRow] = []
    /// The status line.
    public private(set) var status = ""
    /// A fetch is running; Refresh is disabled.
    public private(set) var isRefreshing = false
    /// The selected row's index in `rows`; cleared when the rows are replaced.
    public private(set) var selection: Int?

    @ObservationIgnored private let bridge: any Bridge
    @ObservationIgnored private let openURL: @MainActor (URL) -> Void

    public init(bridge: any Bridge, openURL: @escaping @MainActor (URL) -> Void = { _ in }) {
        self.bridge = bridge
        self.openURL = openURL
    }

    /// Refresh (and the startup load): fetches the commit history
    /// (audit.commits). Ignored while a fetch runs.
    public func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        let previous = status
        status = Self.fetchingStatus
        defer { isRefreshing = false }
        do {
            let result = try await bridge.auditCommits()
            // The index would point into the old rows.
            selection = nil
            rows = result.rows
            status = result.status
        } catch {
            // busy: a fetch started elsewhere is running and the rows stay
            // as they were, so the status does too.
            status = error.code == .busy ? previous : error.message
        }
    }

    /// The operator selected a row; nil or out of range clears the selection.
    /// Never opens the browser.
    public func select(row: Int?) {
        guard let row, rows.indices.contains(row) else {
            selection = nil
            return
        }
        selection = row
    }

    /// Open on GitHub is enabled while the selected commit has an https URL
    /// with a host (`openTooltip` says why otherwise).
    public var canOpen: Bool { selectedURL != nil }

    /// Open on GitHub: opens the selected commit's page; nothing without one.
    public func openSelected() {
        guard let url = selectedURL else { return }
        openURL(url)
    }

    /// The selected commit's page; nil with none selected, or for anything but
    /// an absolute https URL with a host. The core sends only https github.com
    /// URLs, so this only keeps anything else from reaching the browser.
    private var selectedURL: URL? {
        guard let selection, rows.indices.contains(selection) else { return nil }
        let text = rows[selection].url
        guard !text.isEmpty, let url = URL(string: text), url.scheme?.lowercased() == "https",
            let host = url.host, !host.isEmpty
        else {
            return nil
        }
        return url
    }
}
