/// The `code` of an error envelope. Hosts branch on it (and on
/// `RPCError.offerReport`), never on the message.
public enum RPCErrorCode: RawRepresentable, Codable, Sendable, Hashable {
    /// The operation was cancelled (the PIN prompt in sign.sign, auth.cancelLogin).
    case cancelled
    /// A host programming error: unknown method, bad params, wrong lifecycle state.
    case input
    /// A conflicting operation is running.
    case busy
    case notLoggedIn
    case sessionExpired
    case registryChanged
    case notFound
    case nothingToExport
    case loginUnavailable
    /// Show the message; there is nothing more specific to do.
    case failed
    /// The core hit a bug; the user should restart.
    case `internal`
    /// A code this build does not know; treat like `failed`.
    case unknown(String)

    /// Every code the contract defines.
    public static let known: [RPCErrorCode] = [
        .cancelled, .input, .busy, .notLoggedIn, .sessionExpired, .registryChanged,
        .notFound, .nothingToExport, .loginUnavailable, .failed, .internal,
    ]

    public init(rawValue: String) {
        self = Self.known.first { $0.rawValue == rawValue } ?? .unknown(rawValue)
    }

    public var rawValue: String {
        switch self {
        case .cancelled: "cancelled"
        case .input: "input"
        case .busy: "busy"
        case .notLoggedIn: "notLoggedIn"
        case .sessionExpired: "sessionExpired"
        case .registryChanged: "registryChanged"
        case .notFound: "notFound"
        case .nothingToExport: "nothingToExport"
        case .loginUnavailable: "loginUnavailable"
        case .failed: "failed"
        case .internal: "internal"
        case .unknown(let raw): raw
        }
    }
}

/// The error of a failed call: the `error` object of an error envelope, or an
/// error the bridge itself raised (see `RPCError.badResponse` and
/// `RPCError.badParams`).
public struct RPCError: Error, Codable, Sendable, Equatable {
    public var code: RPCErrorCode
    /// User-facing text; display only, never compared or parsed.
    public var message: String
    /// Whether the UI offers "Report Issue" (sign.reportError with `reportId`).
    public var offerReport: Bool
    /// Present only when `offerReport` is true.
    public var reportId: String?

    public init(code: RPCErrorCode, message: String, offerReport: Bool = false, reportId: String? = nil) {
        self.code = code
        self.message = message
        self.offerReport = offerReport
        self.reportId = reportId
    }

    private enum CodingKeys: String, CodingKey {
        case code, message, offerReport, reportId
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        code = try c.decode(RPCErrorCode.self, forKey: .code)
        message = try c.decode(String.self, forKey: .message)
        // Always present in the contract; a missing one must not hide the message.
        offerReport = try c.decodeIfPresent(Bool.self, forKey: .offerReport) ?? false
        reportId = try c.decodeIfPresent(String.self, forKey: .reportId)
    }

    /// The core's response could not be decoded (a contract mismatch between
    /// this build and the library). Reported as `internal`: the user can only
    /// restart. Its message is also the app.internalError alert's.
    public static let badResponse = RPCError(
        code: .internal, message: "An internal error occurred — please restart")

    /// The params could not be encoded: a host programming error, like the
    /// core's own `input`.
    public static let badParams = RPCError(code: .input, message: "The request could not be encoded.")
}
