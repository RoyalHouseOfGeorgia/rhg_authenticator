import Foundation
import Observation
import RHGBridge

/// An alert to show: title and message, both display only.
public struct AlertState: Sendable, Equatable {
    public var title: String
    public var message: String

    public init(title: String, message: String) {
        self.title = title
        self.message = message
    }

    /// A core error, shown as-is under the title "Error".
    public static func error(_ error: RPCError) -> AlertState {
        AlertState(title: "Error", message: error.message)
    }
}

/// The "Report Issue" button of a failed signing.
public enum ReportState: Sendable, Equatable {
    /// No button: the last failure offered no report.
    case unavailable
    /// "Report Issue", enabled.
    case available(reportId: String)
    /// "Reporting…", disabled.
    case reporting(reportId: String)
    /// "Issue Reported", disabled for good.
    case reported

    /// The button title; nil when there is no button.
    public var buttonTitle: String? {
        switch self {
        case .unavailable: nil
        case .available: SignModel.reportIssueTitle
        case .reporting: SignModel.reportingTitle
        case .reported: SignModel.issueReportedTitle
        }
    }

    public var isButtonEnabled: Bool {
        if case .available = self { return true }
        return false
    }
}

/// The Sign tab: the credential form, the signing flow and its result. The
/// core validates, normalizes and signs; this model shows what it returns.
@MainActor
@Observable
public final class SignModel {
    nonisolated public static let recipientLabel = "Recipient"
    nonisolated public static let recipientPlaceholder = "Full name of recipient"
    nonisolated public static let honorLabel = "Honor"
    nonisolated public static let honorPlaceholder = "Select honor title"
    nonisolated public static let detailLabel = "Detail"
    nonisolated public static let detailPlaceholder = "Specific distinction or rank"
    nonisolated public static let dateLabel = "Date"
    nonisolated public static let signTitle = "Sign Credential"
    nonisolated public static let printAdvisory = "Print QR at minimum 3\u{00D7}3 cm"
    nonisolated public static let saveSVGTitle = "Save SVG"
    nonisolated public static let savePNGTitle = "Save PNG"
    nonisolated public static let copyURLTitle = "Copy URL"
    nonisolated public static let reportIssueTitle = "Report Issue"
    nonisolated public static let reportingTitle = "Reporting\u{2026}"
    nonisolated public static let issueReportedTitle = "Issue Reported"

    public var recipient = ""
    /// The selected honor title; "" while none is selected.
    public var honor = ""
    public var detail = ""
    /// The credential date; the date picker shows it in UTC.
    public var date: Date

    /// The honor titles to choose from.
    public private(set) var honors: [String] = []
    /// A signing is running: Sign Credential (and Bulk Sign) are disabled.
    public private(set) var isBusy = false
    /// The status line under the buttons.
    public private(set) var status = ""
    /// The last successful signing; its fields are the ones signed (NFC).
    public private(set) var result: SignResult?
    public private(set) var report: ReportState = .unavailable
    /// The alert to show; the view sets it back to nil when dismissed.
    public var alert: AlertState?

    @ObservationIgnored private let bridge: any Bridge
    @ObservationIgnored private let openURL: @MainActor (URL) -> Void

    public init(bridge: any Bridge, clock: () -> Date = Date.init, openURL: @escaping @MainActor (URL) -> Void = { _ in }) {
        self.bridge = bridge
        self.openURL = openURL
        date = clock()
    }

    /// `date` as the signed YYYY-MM-DD: its UTC calendar date, whatever the
    /// machine's time zone or locale.
    public var dateString: String { DisplayDate.ymd(date) }

    /// `date` as shown next to the picker, YYYY-Mon-DD.
    public var displayDate: String { DisplayDate.format(dateString) }

    /// Loads the honor titles (sign.honors).
    public func loadHonors() async throws(RPCError) {
        honors = try await bridge.honors().honors
    }

    /// Sign Credential: validates the form, then signs it. Ignored while busy.
    public func sign() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        result = nil
        report = .unavailable
        let credential = CredentialParams(recipient: recipient, honor: honor, detail: detail, date: dateString)
        do {
            try await bridge.validate(credential)
        } catch {
            status = error.message
            return
        }
        status = "Preparing to sign..."
        let signed: SignResult
        do {
            signed = try await bridge.sign(credential)
        } catch {
            // cancelled: the operator cancelled the PIN prompt.
            status = error.code == .cancelled ? "" : error.message
            if error.offerReport, let reportId = error.reportId {
                report = .available(reportId: reportId)
            }
            return
        }
        if signed.existing {
            status = "Credential previously generated."
            alert = AlertState(title: "Already Issued", message: "Credential previously generated, no new record created.")
        } else if !signed.warning.isEmpty {
            status = signed.warning
            alert = AlertState(title: "Not Recorded", message: signed.warning)
        } else {
            status = "Signed successfully."
        }
        result = signed
    }

    /// sign.connecting: the PIN is resolved and the card is being opened.
    func signConnecting() {
        if isBusy {
            status = "Connecting to YubiKey..."
        }
    }

    /// Report Issue: files the failure (sign.reportError), opening the URL
    /// the core returns, if any. A failure shows the core's message and
    /// leaves the button enabled.
    public func reportIssue() async {
        guard case .available(let reportId) = report else { return }
        report = .reporting(reportId: reportId)
        let filed: Bool
        var failure: RPCError?
        do {
            let outcome = try await bridge.reportError(reportId: reportId)
            if !outcome.url.isEmpty, let url = URL(string: outcome.url) {
                openURL(url)
            }
            filed = outcome.filed
        } catch {
            failure = error
            filed = false
        }
        // A new signing meanwhile replaced the report state (and its alert).
        guard report == .reporting(reportId: reportId) else { return }
        report = filed ? .reported : .available(reportId: reportId)
        if let failure {
            alert = .error(failure)
        }
    }

    /// The suggested file name for saving the result's QR code as `format`.
    public func suggestedFilename(for format: QRFormat) -> String {
        switch format {
        case .svg: result?.svgFilename ?? ""
        case .png: result?.pngFilename ?? ""
        }
    }

    /// Save SVG / Save PNG: writes the result's QR code to `path`, the file
    /// the operator chose.
    public func saveQR(format: QRFormat, path: String) async {
        guard let result else { return }
        do {
            try await bridge.saveQR(url: result.url, format: format, path: path)
        } catch {
            alert = .error(error)
        }
    }
}
