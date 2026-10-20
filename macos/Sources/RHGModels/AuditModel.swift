import Foundation
import Observation
import RHGBridge

/// The Audit tab: the registry's GitHub commit history, each row opening its
/// commit page. The core fetches and words the rows; this model shows them.
@MainActor
@Observable
public final class AuditModel {
    nonisolated public static let refreshTitle = "Refresh"
    nonisolated public static let fetchingStatus = "Fetching..."

    public private(set) var rows: [AuditRow] = []
    /// The status line.
    public private(set) var status = ""
    /// A fetch is running; Refresh is disabled.
    public private(set) var isRefreshing = false

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
            rows = result.rows
            status = result.status
        } catch {
            // busy: a fetch started elsewhere is running and the rows stay
            // as they were, so the status does too.
            status = error.code == .busy ? previous : error.message
        }
    }

    /// The operator selected a row: opens its commit page, if it has one.
    /// The core allows only https github.com URLs.
    public func open(row: Int) {
        guard rows.indices.contains(row), !rows[row].url.isEmpty, let url = URL(string: rows[row].url) else { return }
        openURL(url)
    }
}
