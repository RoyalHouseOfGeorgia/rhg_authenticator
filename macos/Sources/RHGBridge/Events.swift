import Foundation

/// pin.request: prompt for the YubiKey PIN, then answer with pin.submit or
/// pin.cancel.
public struct PINRequest: Codable, Sendable, Equatable {
    public var requestId: UInt64
    /// The initial state of the "remember PIN" checkbox.
    public var rememberDefault: Bool
    /// Cap the PIN to this many UTF-8 bytes (see `truncatePIN`).
    public var maxBytes: Int

    public init(requestId: UInt64, rememberDefault: Bool, maxBytes: Int) {
        self.requestId = requestId
        self.rememberDefault = rememberDefault
        self.maxBytes = maxBytes
    }
}

/// pin.dismiss: the pin.request with this id is withdrawn (timed out,
/// cancelled or shutdown); close its prompt.
public struct PINDismiss: Codable, Sendable, Equatable {
    public var requestId: UInt64

    public init(requestId: UInt64) {
        self.requestId = requestId
    }
}

/// auth.deviceCode: show the GitHub device-flow code.
public struct DeviceCode: Codable, Sendable, Equatable {
    public var userCode: String
    public var verificationUri: String

    public init(userCode: String, verificationUri: String) {
        self.userCode = userCode
        self.verificationUri = verificationUri
    }
}

/// bulk.progress.
public struct BulkProgress: Codable, Sendable, Equatable {
    public var done: Int
    public var total: Int
    /// The recipient being signed; display only.
    public var name: String

    public init(done: Int, total: Int, name: String) {
        self.done = done
        self.total = total
        self.name = name
    }
}

/// An event from the core, `{"event":name,"data":payload}`, with its typed
/// payload.
public enum BridgeEvent: Codable, Sendable, Equatable {
    case appInternalError
    case authChanged(AuthState)
    case authDeviceCode(DeviceCode)
    case bulkConnecting
    case bulkProgress(BulkProgress)
    case historyChanged
    case historyRevocationsChanged
    case pinDismiss(PINDismiss)
    case pinRequest(PINRequest)
    case registryChanged
    case signConnecting
    case updateStatus(UpdateStatus)
    case updateUpdated(UpdatedNotice)
    /// An event this build does not know, or one whose JSON did not decode
    /// (name "" when even the name could not be read). Ignore it.
    case unknown(String)

    /// The event name on the wire.
    public var name: String {
        switch self {
        case .appInternalError: "app.internalError"
        case .authChanged: "auth.changed"
        case .authDeviceCode: "auth.deviceCode"
        case .bulkConnecting: "bulk.connecting"
        case .bulkProgress: "bulk.progress"
        case .historyChanged: "history.changed"
        case .historyRevocationsChanged: "history.revocationsChanged"
        case .pinDismiss: "pin.dismiss"
        case .pinRequest: "pin.request"
        case .registryChanged: "registry.changed"
        case .signConnecting: "sign.connecting"
        case .updateStatus: "update.status"
        case .updateUpdated: "update.updated"
        case .unknown(let name): name
        }
    }

    /// Parses one event as delivered to the event callback. It never fails:
    /// JSON that does not decode becomes `.unknown` (with the name when it
    /// can be read), and nothing of the input is logged.
    public init(json: Data) {
        do {
            self = try JSONDecoder().decode(BridgeEvent.self, from: json)
        } catch {
            let name = try? JSONDecoder().decode(NameOnly.self, from: json).event
            self = .unknown(name ?? "")
        }
    }

    private struct NameOnly: Decodable {
        var event: String
    }

    private enum CodingKeys: String, CodingKey {
        case event, data
    }

    /// Decodes an event strictly: a known event with a payload that does not
    /// decode throws. `init(json:)` is the lenient form for live events.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let name = try c.decode(String.self, forKey: .event)
        func payload<T: Decodable>(_: T.Type) throws -> T { try c.decode(T.self, forKey: .data) }
        switch name {
        case "app.internalError": self = .appInternalError
        case "auth.changed": self = .authChanged(try payload(AuthState.self))
        case "auth.deviceCode": self = .authDeviceCode(try payload(DeviceCode.self))
        case "bulk.connecting": self = .bulkConnecting
        case "bulk.progress": self = .bulkProgress(try payload(BulkProgress.self))
        case "history.changed": self = .historyChanged
        case "history.revocationsChanged": self = .historyRevocationsChanged
        case "pin.dismiss": self = .pinDismiss(try payload(PINDismiss.self))
        case "pin.request": self = .pinRequest(try payload(PINRequest.self))
        case "registry.changed": self = .registryChanged
        case "sign.connecting": self = .signConnecting
        case "update.status": self = .updateStatus(try payload(UpdateStatus.self))
        case "update.updated": self = .updateUpdated(try payload(UpdatedNotice.self))
        default: self = .unknown(name)
        }
    }

    /// Encodes the event as the core does (`data` null for payload-less
    /// events); used to build events in tests and fakes.
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(name, forKey: .event)
        switch self {
        case .authChanged(let p): try c.encode(p, forKey: .data)
        case .authDeviceCode(let p): try c.encode(p, forKey: .data)
        case .bulkProgress(let p): try c.encode(p, forKey: .data)
        case .pinDismiss(let p): try c.encode(p, forKey: .data)
        case .pinRequest(let p): try c.encode(p, forKey: .data)
        case .updateStatus(let p): try c.encode(p, forKey: .data)
        case .updateUpdated(let p): try c.encode(p, forKey: .data)
        case .appInternalError, .bulkConnecting, .historyChanged, .historyRevocationsChanged,
            .registryChanged, .signConnecting, .unknown:
            try c.encodeNil(forKey: .data)
        }
    }
}
