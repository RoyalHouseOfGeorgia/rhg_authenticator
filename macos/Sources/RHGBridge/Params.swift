// Params DTOs, one per params shape in the contract
// (go/service/rpc/testdata/contract/methods/<method>/params.json). Property
// names are the JSON keys. CanonicalJSON encodes each to the contract's bytes.

/// An empty object, `{}`: the params of a method without params and the
/// result of a void method.
public struct Empty: Codable, Sendable, Equatable {
    public init() {}
}

/// app.init.
public struct AppInitParams: Codable, Sendable, Equatable {
    /// Absolute app data directory; nil uses the platform default.
    public var dataDir: String?

    public init(dataDir: String? = nil) {
        self.dataDir = dataDir
    }
}

/// app.shutdown.
public struct ShutdownParams: Codable, Sendable, Equatable {
    /// Relaunch after applying a ready update ("Restart Now").
    public var relaunch: Bool

    public init(relaunch: Bool) {
        self.relaunch = relaunch
    }
}

/// A file path: app.exportErrorLog, bulk.exportResults, bulk.load,
/// history.exportIssuanceLog, registry.importCertificate.
public struct PathParams: Codable, Sendable, Equatable {
    public var path: String

    public init(path: String) {
        self.path = path
    }
}

/// A credential to validate or sign: sign.validate, sign.sign.
public struct CredentialParams: Codable, Sendable, Equatable {
    public var recipient: String
    public var honor: String
    public var detail: String
    /// YYYY-MM-DD.
    public var date: String

    public init(recipient: String, honor: String, detail: String, date: String) {
        self.recipient = recipient
        self.honor = honor
        self.detail = detail
        self.date = date
    }
}

/// The file format of sign.saveQR.
public enum QRFormat: String, Codable, Sendable {
    case svg, png
}

/// sign.saveQR.
public struct SaveQRParams: Codable, Sendable, Equatable {
    /// The `url` of the SignResult.
    public var url: String
    public var format: QRFormat
    public var path: String

    public init(url: String, format: QRFormat, path: String) {
        self.url = url
        self.format = format
        self.path = path
    }
}

/// sign.reportError.
public struct ReportErrorParams: Codable, Sendable, Equatable {
    /// The `reportId` of an RPCError with `offerReport`.
    public var reportId: String

    public init(reportId: String) {
        self.reportId = reportId
    }
}

/// pin.submit. Its description, debugDescription and mirror redact the PIN,
/// so printing or dumping the params never shows it.
public struct PINSubmitParams: Codable, Sendable, Equatable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public var requestId: UInt64
    public var pin: String
    public var remember: Bool

    public init(requestId: UInt64, pin: String, remember: Bool) {
        self.requestId = requestId
        self.pin = pin
        self.remember = remember
    }

    public var description: String {
        "PINSubmitParams(requestId: \(requestId), pin: <redacted>, remember: \(remember))"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: ["requestId": requestId, "pin": "<redacted>", "remember": remember])
    }
}

/// pin.cancel.
public struct PINCancelParams: Codable, Sendable, Equatable {
    public var requestId: UInt64

    public init(requestId: UInt64) {
        self.requestId = requestId
    }
}

/// history.list.
public struct HistoryListParams: Codable, Sendable, Equatable {
    /// Filter text; "" lists every record.
    public var query: String

    public init(query: String) {
        self.query = query
    }
}

/// history.recordText, history.deleteEntry.
public struct RecordParams: Codable, Sendable, Equatable {
    public var record: HistoryRecord

    public init(record: HistoryRecord) {
        self.record = record
    }
}

/// history.revoke.
public struct RevokeParams: Codable, Sendable, Equatable {
    public var payloadSha256: String

    public init(payloadSha256: String) {
        self.payloadSha256 = payloadSha256
    }
}

/// The registry entry form of registry.addEntry and registry.updateEntry.
public struct EntryForm: Codable, Sendable, Equatable {
    public var authority: String
    /// YYYY-MM-DD.
    public var from: String
    /// YYYY-MM-DD, or "" with `noExpiry`.
    public var to: String
    public var note: String
    public var noExpiry: Bool

    public init(authority: String, from: String, to: String, note: String, noExpiry: Bool) {
        self.authority = authority
        self.from = from
        self.to = to
        self.note = note
        self.noExpiry = noExpiry
    }
}

/// registry.addEntry.
public struct AddEntryParams: Codable, Sendable, Equatable {
    public var form: EntryForm
    /// Base64 Ed25519 public key.
    public var publicKey: String

    public init(form: EntryForm, publicKey: String) {
        self.form = form
        self.publicKey = publicKey
    }
}

/// registry.updateEntry.
public struct UpdateEntryParams: Codable, Sendable, Equatable {
    /// The entry's index in RegistrySnapshot.entries.
    public var index: Int
    public var publicKey: String
    public var form: EntryForm

    public init(index: Int, publicKey: String, form: EntryForm) {
        self.index = index
        self.publicKey = publicKey
        self.form = form
    }
}
