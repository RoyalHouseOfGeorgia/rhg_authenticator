import Foundation
import RHGBridge
import RHGModels

/// A scriptable Bridge: each method answers from its script (a queue of
/// response envelopes, the last one sticky; unscripted methods answer `{}`),
/// every call is recorded with its canonical params, and tests feed the
/// event stream. A `Hold` keeps a call open until the test releases it.
final class FakeBridge: Bridge, @unchecked Sendable {
    typealias Handler = @Sendable () async -> Data

    private let lock = NSLock()
    private var scripts: [String: [Handler]] = [:]
    private var recorded: [(method: String, params: String)] = []
    let events: AsyncStream<BridgeEvent>
    private let sink: AsyncStream<BridgeEvent>.Continuation

    init() {
        (events, sink) = AsyncStream.makeStream(of: BridgeEvent.self)
    }

    // MARK: Scripting

    /// Answers the next call of `method` with `result`.
    func respond<T: Encodable>(_ method: RPCMethod, _ result: T) {
        let data = Self.success(result)
        enqueue(method) { data }
    }

    /// Fails the next call of `method` with `error`.
    func fail(_ method: RPCMethod, _ error: RPCError) {
        let data = Self.failure(error)
        enqueue(method) { data }
    }

    /// Keeps the next call of `method` open until the hold is released.
    func hold(_ method: RPCMethod) -> Hold {
        let hold = Hold()
        enqueue(method) { await hold.wait() }
        return hold
    }

    /// Drops the rest of `method`'s script (its sticky last response too).
    func reset(_ method: RPCMethod) {
        lock.withLock { scripts[method.rawValue] = nil }
    }

    func emit(_ event: BridgeEvent) {
        sink.yield(event)
    }

    private func enqueue(_ method: RPCMethod, _ handler: @escaping Handler) {
        lock.withLock { scripts[method.rawValue, default: []].append(handler) }
    }

    // MARK: Recording

    var calls: [(method: String, params: String)] {
        lock.withLock { recorded }
    }

    var methods: [String] { calls.map(\.method) }

    /// The canonical params JSON of each call of `method`.
    func params(_ method: RPCMethod) -> [String] {
        calls.filter { $0.method == method.rawValue }.map(\.params)
    }

    func count(_ method: RPCMethod) -> Int { params(method).count }

    // MARK: Bridge

    func call<P: Encodable & Sendable, R: Decodable & Sendable>(
        _ method: String, _ params: P
    ) async throws(RPCError) -> R {
        let encoded: Data
        do {
            encoded = try CanonicalJSON.encode(params)
        } catch {
            throw .badParams
        }
        let handler: Handler? = lock.withLock {
            recorded.append((method, String(decoding: encoded, as: UTF8.self)))
            guard var queue = scripts[method], let first = queue.first else { return nil }
            if queue.count > 1 {
                queue.removeFirst()
                scripts[method] = queue
            }
            return first
        }
        let envelope = await handler?() ?? Data(#"{"ok":true,"result":{}}"#.utf8)
        return try RPCEnvelope.decode(envelope)
    }

    // MARK: Envelopes

    static func success<T: Encodable>(_ result: T) -> Data {
        Data(#"{"ok":true,"result":"#.utf8) + (try! CanonicalJSON.encode(result)) + Data("}".utf8)
    }

    static func failure(_ error: RPCError) -> Data {
        Data(#"{"ok":false,"error":"#.utf8) + (try! CanonicalJSON.encode(error)) + Data("}".utf8)
    }
}

/// A call held open by `FakeBridge.hold`; `release` completes it.
final class Hold: Sendable {
    private let stream: AsyncStream<Data>
    private let continuation: AsyncStream<Data>.Continuation

    init() {
        (stream, continuation) = AsyncStream.makeStream(of: Data.self)
    }

    func release<T: Encodable>(_ result: T) {
        release(envelope: FakeBridge.success(result))
    }

    func release(failing error: RPCError) {
        release(envelope: FakeBridge.failure(error))
    }

    func release(envelope: Data) {
        continuation.yield(envelope)
        continuation.finish()
    }

    func wait() async -> Data {
        for await envelope in stream {
            return envelope
        }
        return Data()
    }
}

/// Waits (bounded, about 5 s) until `condition` holds; returns whether it did.
@MainActor
func settle(_ condition: () -> Bool) async -> Bool {
    for _ in 0..<5000 {
        if condition() { return true }
        try? await Task.sleep(nanoseconds: 1_000_000)
    }
    return condition()
}

/// Records the URLs a model opens.
@MainActor
final class URLRecorder {
    var opened: [URL] = []

    var open: @MainActor (URL) -> Void {
        { [self] url in opened.append(url) }
    }
}

let onlineInfo = AppInfo(activeKeys: 3, online: true, recentlyExpired: 1, version: "v1.2.3")

let loggedOut = AuthState(loggedIn: false, offline: false, user: "", statusText: "Not logged in")
let loggedIn = AuthState(loggedIn: true, offline: false, user: "octocat", statusText: "Logged in as @octocat")
let loggedInOffline = AuthState(loggedIn: true, offline: true, user: "octocat", statusText: "Offline")

let registryColumns = ["#", "Authority", "From", "To", "Restrictions", "Note", "Fingerprint"]

/// A registry entry and its table row (the cell texts are the core's).
func registryEntry(_ n: Int, noExpiry: Bool = false, note: String = "") -> (RegistryEntry, [String]) {
    let entry = RegistryEntry(
        authority: "Authority \(n)", from: "2025-01-0\(n)", to: noExpiry ? "" : "2030-12-2\(n)", noExpiry: noExpiry,
        publicKey: "KEY\(n)=", note: note)
    let row = ["\(n)", entry.authority, "2025-Jan-0\(n)", noExpiry ? "(none)" : "2030-Dec-2\(n)", "(none)", note, "fp\(n)"]
    return (entry, row)
}

/// A loaded snapshot of entries 1...count.
func registrySnapshot(count: Int, dirty: Bool = false, loaded: Bool = true) -> RegistrySnapshot {
    let made = (0..<count).map { registryEntry($0 + 1) }
    return RegistrySnapshot(entries: made.map { $0.0 }, rows: made.map { $0.1 }, dirty: dirty, loaded: loaded)
}

/// Scripts the startup reads after sign.honors: auth.state, registry.columns
/// and registry.snapshot.
func scriptStartupRegistry(
    _ fake: FakeBridge, auth: AuthState = loggedOut, snapshot: RegistrySnapshot = registrySnapshot(count: 2)
) {
    fake.respond(.authState, auth)
    fake.respond(.registryColumns, ColumnsResult(columns: registryColumns))
    fake.respond(.registrySnapshot, snapshot)
}

/// An AppModel whose startup succeeded, so its events are being drained.
@MainActor
func startedApp(
    _ fake: FakeBridge, clock: @escaping () -> Date = Date.init, openURL: @escaping @MainActor (URL) -> Void = { _ in }
) async -> AppModel {
    fake.respond(.appInit, onlineInfo)
    fake.respond(.signHonors, HonorsResult(honors: ["Order of Queen Tamar", "Order of the Eagle"]))
    scriptStartupRegistry(fake)
    let app = AppModel(bridge: fake, clock: clock, openURL: openURL)
    await app.start()
    return app
}

func signResult(
    recipient: String = "José", honor: String = "Order of the Eagle", detail: String = "Knight",
    date: String = "2026-01-01", existing: Bool = false, warning: String = ""
) -> SignResult {
    SignResult(
        recipient: recipient, honor: honor, detail: detail, date: date,
        url: "https://verify.royalhouseofgeorgia.ge/?p=abc", existing: existing,
        pngPreview: Data([0x89, 0x50, 0x4E, 0x47]), warning: warning,
        svgFilename: "rhg-0123abcd.svg", pngFilename: "rhg-0123abcd.png")
}
