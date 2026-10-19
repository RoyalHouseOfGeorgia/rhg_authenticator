// Result DTOs, one per result shape in the contract
// (go/service/rpc/testdata/contract/methods/<method>/result*.json). Property
// names are the JSON keys; arrays are never null. Strings documented as
// display-only are rendered as given and never compared or parsed.

import Foundation

/// app.init, app.info.
public struct AppInfo: Codable, Sendable, Equatable {
    public var activeKeys: Int
    public var online: Bool
    public var recentlyExpired: Int
    public var version: String

    public init(activeKeys: Int, online: Bool, recentlyExpired: Int, version: String) {
        self.activeKeys = activeKeys
        self.online = online
        self.recentlyExpired = recentlyExpired
        self.version = version
    }
}

/// app.canQuit.
public struct CanQuitResult: Codable, Sendable, Equatable {
    /// Unsubmitted registry edits would be lost.
    public var dirty: Bool

    public init(dirty: Bool) {
        self.dirty = dirty
    }
}

/// sign.honors.
public struct HonorsResult: Codable, Sendable, Equatable {
    public var honors: [String]

    public init(honors: [String]) {
        self.honors = honors
    }
}

/// sign.sign.
public struct SignResult: Codable, Sendable, Equatable {
    /// NFC-normalized, as signed.
    public var recipient: String
    public var honor: String
    public var detail: String
    public var date: String
    /// The verification URL the QR code encodes.
    public var url: String
    public var hash8: String
    /// The credential was already in the issuance log; nothing was signed.
    public var existing: Bool
    /// PNG of the QR code (base64 in JSON).
    public var pngPreview: Data
    /// Display only; "" when there is none.
    public var warning: String
    /// Suggested file names; display only.
    public var svgFilename: String
    public var pngFilename: String

    public init(
        recipient: String, honor: String, detail: String, date: String, url: String, hash8: String,
        existing: Bool, pngPreview: Data, warning: String, svgFilename: String, pngFilename: String
    ) {
        self.recipient = recipient
        self.honor = honor
        self.detail = detail
        self.date = date
        self.url = url
        self.hash8 = hash8
        self.existing = existing
        self.pngPreview = pngPreview
        self.warning = warning
        self.svgFilename = svgFilename
        self.pngFilename = pngFilename
    }
}

/// sign.reportError.
public struct ReportResult: Codable, Sendable, Equatable {
    /// The issue was filed (else `url` is a prefilled browser form).
    public var filed: Bool
    public var url: String

    public init(filed: Bool, url: String) {
        self.filed = filed
        self.url = url
    }
}

/// update.status `state`.
public enum UpdateState: RawRepresentable, Codable, Sendable, Hashable {
    case idle, ready, manualOnly
    case unknown(String)

    public static let known: [UpdateState] = [.idle, .ready, .manualOnly]

    public init(rawValue: String) {
        self = Self.known.first { $0.rawValue == rawValue } ?? .unknown(rawValue)
    }

    public var rawValue: String {
        switch self {
        case .idle: "idle"
        case .ready: "ready"
        case .manualOnly: "manualOnly"
        case .unknown(let raw): raw
        }
    }
}

/// The update offer: update.current `status` and the update.status event.
public struct UpdateStatus: Codable, Sendable, Equatable {
    public var state: UpdateState
    public var version: String
    /// "" unless an https://github.com URL.
    public var releaseUrl: String
    public var moveToApplications: Bool

    public init(state: UpdateState, version: String, releaseUrl: String, moveToApplications: Bool) {
        self.state = state
        self.version = version
        self.releaseUrl = releaseUrl
        self.moveToApplications = moveToApplications
    }
}

/// The "updated to version" notice: update.current `updated` and the
/// update.updated event.
public struct UpdatedNotice: Codable, Sendable, Equatable {
    public var version: String
    /// "" unless an https://github.com URL.
    public var releaseUrl: String

    public init(version: String, releaseUrl: String) {
        self.version = version
        self.releaseUrl = releaseUrl
    }
}

/// update.current.
public struct UpdateCurrentResult: Codable, Sendable, Equatable {
    public var status: UpdateStatus
    /// nil once delivered (or when the app was not just updated).
    public var updated: UpdatedNotice?

    public init(status: UpdateStatus, updated: UpdatedNotice?) {
        self.status = status
        self.updated = updated
    }

    private enum CodingKeys: String, CodingKey {
        case status, updated
    }

    /// Encodes a nil `updated` as null, as the core does.
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(status, forKey: .status)
        try c.encode(updated, forKey: .updated)
    }
}

/// GitHub login state: auth.state, auth.login and the auth.changed event.
public struct AuthState: Codable, Sendable, Equatable {
    public var loggedIn: Bool
    public var offline: Bool
    public var user: String
    /// Display only.
    public var statusText: String

    public init(loggedIn: Bool, offline: Bool, user: String, statusText: String) {
        self.loggedIn = loggedIn
        self.offline = offline
        self.user = user
        self.statusText = statusText
    }
}

/// One row of audit.commits.
public struct AuditRow: Codable, Sendable, Equatable {
    /// Display only.
    public var summary: String
    /// The commit page; "" unless an https github.com URL.
    public var url: String

    public init(summary: String, url: String) {
        self.summary = summary
        self.url = url
    }
}

/// audit.commits.
public struct AuditResult: Codable, Sendable, Equatable {
    public var rows: [AuditRow]
    /// Display only.
    public var status: String

    public init(rows: [AuditRow], status: String) {
        self.rows = rows
        self.status = status
    }
}

/// bulk.load.
public struct BulkLoadResult: Codable, Sendable, Equatable {
    public var toSign: Int
    /// Display only.
    public var countsLine: String
    public var previewNames: [String]
    /// Display only.
    public var invalidLines: [String]

    public init(toSign: Int, countsLine: String, previewNames: [String], invalidLines: [String]) {
        self.toSign = toSign
        self.countsLine = countsLine
        self.previewNames = previewNames
        self.invalidLines = invalidLines
    }
}

/// Why a bulk run ended: bulk.run `stopped`.
public enum BulkStop: RawRepresentable, Codable, Sendable, Hashable {
    case completed, cancelled, failed
    case unknown(String)

    public static let known: [BulkStop] = [.completed, .cancelled, .failed]

    public init(rawValue: String) {
        self = Self.known.first { $0.rawValue == rawValue } ?? .unknown(rawValue)
    }

    public var rawValue: String {
        switch self {
        case .completed: "completed"
        case .cancelled: "cancelled"
        case .failed: "failed"
        case .unknown(let raw): raw
        }
    }
}

/// bulk.run.
public struct BulkRunResult: Codable, Sendable, Equatable {
    public var stopped: BulkStop
    /// Display only.
    public var summaryLine: String
    /// Display only; "" when completed.
    public var stopMessage: String
    /// Display only.
    public var failedLines: [String]
    /// Suggested file name; display only.
    public var resultsFilename: String

    public init(
        stopped: BulkStop, summaryLine: String, stopMessage: String, failedLines: [String],
        resultsFilename: String
    ) {
        self.stopped = stopped
        self.summaryLine = summaryLine
        self.stopMessage = stopMessage
        self.failedLines = failedLines
        self.resultsFilename = resultsFilename
    }
}

/// A signed credential in the issuance log.
public struct HistoryRecord: Codable, Sendable, Equatable {
    /// RFC 3339 UTC.
    public var timestamp: String
    public var recipient: String
    public var honor: String
    public var detail: String
    /// YYYY-MM-DD.
    public var date: String
    /// Hex SHA-256 of the signed payload; the credential's id.
    public var payloadSha256: String
    public var signatureB64url: String

    public init(
        timestamp: String, recipient: String, honor: String, detail: String, date: String,
        payloadSha256: String, signatureB64url: String
    ) {
        self.timestamp = timestamp
        self.recipient = recipient
        self.honor = honor
        self.detail = detail
        self.date = date
        self.payloadSha256 = payloadSha256
        self.signatureB64url = signatureB64url
    }
}

/// One row of history.list.
public struct HistoryRow: Codable, Sendable, Equatable {
    public var record: HistoryRecord
    /// Display only.
    public var summary: String
    public var revoked: Bool

    public init(record: HistoryRecord, summary: String, revoked: Bool) {
        self.record = record
        self.summary = summary
        self.revoked = revoked
    }
}

/// history.list.
public struct HistoryListResult: Codable, Sendable, Equatable {
    /// Newest first, filtered by the query.
    public var rows: [HistoryRow]
    public var loadFailed: Bool
    public var revocationsUnavailable: Bool
    public var revocationsLoaded: Bool
    /// Logged in, online and revocations loaded.
    public var revokeAvailable: Bool

    public init(
        rows: [HistoryRow], loadFailed: Bool, revocationsUnavailable: Bool, revocationsLoaded: Bool,
        revokeAvailable: Bool
    ) {
        self.rows = rows
        self.loadFailed = loadFailed
        self.revocationsUnavailable = revocationsUnavailable
        self.revocationsLoaded = revocationsLoaded
        self.revokeAvailable = revokeAvailable
    }
}

/// history.recordText.
public struct RecordTextResult: Codable, Sendable, Equatable {
    /// Display only.
    public var detail: String
    /// Display only.
    public var revokeConfirm: String

    public init(detail: String, revokeConfirm: String) {
        self.detail = detail
        self.revokeConfirm = revokeConfirm
    }
}

/// history.duplicatePreview.
public struct DuplicatePreviewResult: Codable, Sendable, Equatable {
    public var count: Int

    public init(count: Int) {
        self.count = count
    }
}

/// history.removeDuplicates.
public struct RemoveDuplicatesResult: Codable, Sendable, Equatable {
    public var removed: Int
    /// Path of the backup of the log before removal.
    public var backup: String

    public init(removed: Int, backup: String) {
        self.removed = removed
        self.backup = backup
    }
}

/// The outcome of a history.revoke that did not fail.
public enum RevokeStatus: RawRepresentable, Codable, Sendable, Hashable {
    /// A revocation PR was opened.
    case submitted
    /// Already in the revocation list.
    case alreadyRevoked
    /// A revocation PR is already open.
    case pending
    case unknown(String)

    public static let known: [RevokeStatus] = [.submitted, .alreadyRevoked, .pending]

    public init(rawValue: String) {
        self = Self.known.first { $0.rawValue == rawValue } ?? .unknown(rawValue)
    }

    public var rawValue: String {
        switch self {
        case .submitted: "submitted"
        case .alreadyRevoked: "alreadyRevoked"
        case .pending: "pending"
        case .unknown(let raw): raw
        }
    }
}

/// history.revoke.
public struct RevokeResult: Codable, Sendable, Equatable {
    public var status: RevokeStatus
    /// Submitted only; 0 otherwise.
    public var prNumber: Int
    /// Submitted only; "" otherwise.
    public var url: String
    /// Display only.
    public var title: String
    /// Display only.
    public var message: String

    public init(status: RevokeStatus, prNumber: Int, url: String, title: String, message: String) {
        self.status = status
        self.prNumber = prNumber
        self.url = url
        self.title = title
        self.message = message
    }
}

/// A registry entry as edited: registry.snapshot `entries`.
public struct RegistryEntry: Codable, Sendable, Equatable {
    public var authority: String
    public var from: String
    public var to: String
    public var noExpiry: Bool
    public var publicKey: String
    public var note: String

    public init(authority: String, from: String, to: String, noExpiry: Bool, publicKey: String, note: String) {
        self.authority = authority
        self.from = from
        self.to = to
        self.noExpiry = noExpiry
        self.publicKey = publicKey
        self.note = note
    }
}

/// registry.snapshot.
public struct RegistrySnapshot: Codable, Sendable, Equatable {
    public var entries: [RegistryEntry]
    /// Table cells per entry, in registry.columns order; display only.
    public var rows: [[String]]
    /// Unsubmitted edits.
    public var dirty: Bool
    public var loaded: Bool

    public init(entries: [RegistryEntry], rows: [[String]], dirty: Bool, loaded: Bool) {
        self.entries = entries
        self.rows = rows
        self.dirty = dirty
        self.loaded = loaded
    }
}

/// registry.columns.
public struct ColumnsResult: Codable, Sendable, Equatable {
    /// Display only.
    public var columns: [String]

    public init(columns: [String]) {
        self.columns = columns
    }
}

/// registry.importCertificate, registry.importFromYubiKey.
public struct PublicKeyResult: Codable, Sendable, Equatable {
    /// Base64 Ed25519 public key.
    public var publicKey: String

    public init(publicKey: String) {
        self.publicKey = publicKey
    }
}

/// registry.submit.
public struct SubmitResult: Codable, Sendable, Equatable {
    public var prNumber: Int
    public var url: String

    public init(prNumber: Int, url: String) {
        self.prNumber = prNumber
        self.url = url
    }
}

/// The outcome of yubikey.check: KeyCheck `result`.
public enum KeyCheckResult: RawRepresentable, Codable, Sendable, Hashable {
    /// The key matches a registry entry valid today.
    case found
    /// The key was read but matches no valid entry.
    case notFound
    /// The key could not be read or checked.
    case failed
    case unknown(String)

    public static let known: [KeyCheckResult] = [.found, .notFound, .failed]

    public init(rawValue: String) {
        self = Self.known.first { $0.rawValue == rawValue } ?? .unknown(rawValue)
    }

    public var rawValue: String {
        switch self {
        case .found: "found"
        case .notFound: "notFound"
        case .failed: "failed"
        case .unknown(let raw): raw
        }
    }
}

/// yubikey.check.
public struct KeyCheck: Codable, Sendable, Equatable {
    public var result: KeyCheckResult
    /// Display only.
    public var status: String
    /// Display only.
    public var details: [String]

    public init(result: KeyCheckResult, status: String, details: [String]) {
        self.result = result
        self.status = status
        self.details = details
    }
}
