import Foundation
import Observation
import RHGBridge

/// Bulk Sign from File: pick a CSV, confirm the plan, sign it with a
/// progress sheet, then show the results. The core plans, signs and words
/// every line; this model shows what it returns.
@MainActor
@Observable
public final class BulkModel {
    nonisolated public static let bulkSignTitle = "Bulk Sign from File\u{2026}"
    /// The confirm and progress sheets' title.
    nonisolated public static let title = "Bulk Sign"
    nonisolated public static let signTitle = "Sign"
    nonisolated public static let cancelTitle = "Cancel"
    nonisolated public static let previewHeading = "First names to be signed:"
    nonisolated public static let invalidToSkipHeading = "Invalid rows (will be skipped):"
    nonisolated public static let resultsTitle = "Bulk Sign \u{2014} Results"
    nonisolated public static let failedHeading = "Failed rows:"
    nonisolated public static let invalidSkippedHeading = "Invalid rows (skipped):"
    nonisolated public static let exportTitle = "Export Results CSV\u{2026}"
    nonisolated public static let regenerateNote = "Re-open the same file to regenerate results later."
    nonisolated public static let closeTitle = "Close"
    nonisolated public static let connectingLabel = "Connecting to YubiKey\u{2026}"
    nonisolated public static let stoppingLabel = "Stopping after current row\u{2026}"

    /// A running bulk.run, as the progress sheet shows it. The sheet stays up
    /// for the whole run, and the PIN prompt stacks on top of it.
    public struct Run: Sendable, Equatable {
        /// The latest bulk.progress; nil before the first.
        public var progress: BulkProgress?
        /// Cancel was pressed: the run stops after its current row.
        public var stopping = false

        public init(progress: BulkProgress? = nil, stopping: Bool = false) {
            self.progress = progress
            self.stopping = stopping
        }

        /// The progress sheet's label.
        public var label: String {
            if stopping {
                return BulkModel.stoppingLabel
            }
            guard let progress else { return BulkModel.connectingLabel }
            return "Signing \(progress.done + 1) of \(progress.total): \(progress.name) \u{2014} touch your YubiKey if it is blinking"
        }

        /// The progress bar, 0...1.
        public var fraction: Double {
            guard let progress, progress.total > 0 else { return 0 }
            return Double(progress.done) / Double(progress.total)
        }

        /// The progress sheet's Cancel button.
        public var isCancelEnabled: Bool { !stopping }
    }

    public enum Phase: Sendable, Equatable {
        case idle
        /// The file picker is open.
        case choosingFile
        /// bulk.load is reading the chosen file; with nothing to sign, bulk.run
        /// then runs here too (no sheet: no card or PIN prompt is involved).
        case loading
        /// Show the confirm sheet for this plan (it has rows to sign).
        case confirming(BulkLoadResult)
        /// bulk.run is running a plan with rows to sign: show the progress
        /// sheet. After a failed run it stays, under the error alert, until
        /// `dismissAlert()`.
        case running(Run)
        /// Show the results sheet.
        case results(plan: BulkLoadResult, outcome: BulkRunResult)
    }

    public private(set) var phase: Phase = .idle
    /// The alert to show; `dismissAlert()` when the operator closes it.
    public private(set) var alert: AlertState?

    @ObservationIgnored private let bridge: any Bridge
    /// bulk.run is in flight.
    @ObservationIgnored private var isRunning = false

    public init(bridge: any Bridge) {
        self.bridge = bridge
    }

    /// A bulk flow is under way, from the file picker opening until the
    /// results are closed or the flow ends: Bulk Sign (and Sign Credential)
    /// are disabled.
    public var isActive: Bool { phase != .idle }

    /// The bulk sheet is up: confirm, progress (from confirm on, so the PIN
    /// prompt stacks on it instead of a closing sheet) or results.
    public var isShowingSheet: Bool {
        switch phase {
        case .confirming, .running, .results: true
        case .idle, .choosingFile, .loading: false
        }
    }

    /// Show the alert over the bulk sheet: an alert on the covered tab would
    /// not show.
    public var isShowingSheetAlert: Bool { alert != nil && isShowingSheet }

    /// Show the alert over the Sign tab: no bulk sheet is up.
    public var isShowingTabAlert: Bool { alert != nil && !isShowingSheet }

    /// The suggested results CSV name; "" without results.
    public var suggestedResultsFilename: String {
        if case .results(_, let outcome) = phase {
            return outcome.resultsFilename
        }
        return ""
    }

    /// Bulk Sign from File: the file picker is about to open. Returns false,
    /// changing nothing, while a flow is under way.
    @discardableResult
    public func begin() -> Bool {
        guard phase == .idle else { return false }
        phase = .choosingFile
        return true
    }

    /// The picker was dismissed without a file.
    public func pickerCancelled() {
        if phase == .choosingFile {
            phase = .idle
        }
    }

    /// The operator chose `path`: plans it (bulk.load), then asks to confirm,
    /// or, with nothing to sign, runs at once without a progress sheet (no
    /// card is touched and no PIN prompt follows).
    public func fileChosen(path: String) async {
        guard phase == .choosingFile else { return }
        phase = .loading
        let plan: BulkLoadResult
        do {
            plan = try await bridge.loadBulk(path: path)
        } catch {
            phase = .idle
            alert = .error(error, title: "Unable to Open File")
            return
        }
        if plan.toSign == 0 {
            await run(plan)
        } else {
            phase = .confirming(plan)
        }
    }

    /// Sign on the confirm sheet.
    public func confirm() async {
        guard case .confirming(let plan) = phase else { return }
        phase = .running(Run())
        await run(plan)
    }

    /// Cancel on the confirm sheet.
    public func cancelConfirm() {
        if case .confirming = phase {
            phase = .idle
        }
    }

    /// Cancel on the progress sheet: the run stops after its current row
    /// (bulk.cancel) and bulk.run returns a cancelled outcome.
    public func cancelRun() async {
        guard isRunning, case .running(var run) = phase, !run.stopping else { return }
        run.stopping = true
        phase = .running(run)
        try? await bridge.cancelBulk()
    }

    /// Close on the results sheet.
    public func closeResults() {
        if case .results = phase {
            phase = .idle
        }
    }

    /// Export Results CSV…: writes the results to `path`, the file the
    /// operator chose. Success shows nothing.
    public func exportResults(path: String) async {
        do {
            try await bridge.exportBulkResults(path: path)
        } catch {
            alert = .error(error, title: "Unable to Export Results")
        }
    }

    /// The operator closed the alert. After a failed run, whose alert shows
    /// over the progress sheet, this also ends the flow.
    public func dismissAlert() {
        alert = nil
        if case .running = phase, !isRunning {
            phase = .idle
        }
    }

    /// bulk.progress: the row about to be signed.
    func bulkProgress(_ progress: BulkProgress) {
        guard case .running(var run) = phase else { return }
        run.progress = progress
        phase = .running(run)
    }

    /// Runs bulk.run, then shows the results. A failure shows its alert
    /// where the flow is: over the progress sheet (closed on dismiss, so the
    /// sheet never closes under a presenting alert), or over the tab when no
    /// sheet is up (nothing to sign).
    private func run(_ plan: BulkLoadResult) async {
        isRunning = true
        defer { isRunning = false }
        do {
            let outcome = try await bridge.runBulk()
            phase = .results(plan: plan, outcome: outcome)
        } catch {
            if !isShowingSheet {
                phase = .idle
            }
            alert = .error(error, title: "Bulk Signing Stopped")
        }
    }
}
