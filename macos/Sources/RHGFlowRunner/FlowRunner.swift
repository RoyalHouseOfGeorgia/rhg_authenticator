// Test support, never shipped: runs one LiveBridge scenario against the
// rhgfake build of librhgcore, one scenario per process (the core can be
// configured and initialized only once per process). RHGBridgeTests spawns it.
//
//   RHGFlowRunner <scenario>   scenario: offline | online | pinCancel | pinTimeout
//   RHGFlowRunner --version    the core's CLI, handled first as the app does
//
// Prints "ok: <check>" per passed check, then "PASS: <scenario>" and exits 0;
// on the first failure prints "FAIL: <check>: <detail>" and exits 1 (2: usage,
// 3: not the rhgfake library). Never prints params, envelopes or the PIN.

import Foundation
import RHGBridge

@main
enum FlowRunner {
    @MainActor
    static func main() async {
        let args = CommandLine.arguments
        if let code = runMainCLI(args) {
            exit(code)
        }
        guard args.count == 2, let scenario = Scenario(rawValue: args[1]) else {
            let names = Scenario.allCases.map(\.rawValue).joined(separator: " | ")
            emit("usage: RHGFlowRunner \(names)")
            exit(2)
        }
        exit(await Flow(bridge: LiveBridge.install()).run(scenario))
    }
}

enum Scenario: String, CaseIterable {
    /// Registry unreachable: signing is refused before any PIN prompt; a
    /// panic is an internal error and the process stays alive.
    case offline
    /// Registry served: Sign with the PIN submitted, a stale requestId, the
    /// other Sign-tab methods, and the NFC round trip of Georgian and
    /// accented names.
    case online
    /// Registry served: a cancelled PIN prompt cancels the Sign.
    case pinCancel
    /// Registry served, 300 ms PIN timeout: an unanswered prompt is
    /// dismissed and the Sign fails.
    case pinTimeout
}

/// A failed check.
struct Failure: Error {
    let check: String
    let detail: String
}

/// test.configure failed with `input`, most likely because the library is not
/// the rhgfake build (exit 3). `message` is the core's message.
struct NotRHGFake: Error {
    let message: String
}

/// The fake card's PIN (service.FakeCardPIN).
let fakePIN = "123456"

/// test.configure params (rhgfake only; not in the contract).
struct TestConfigureParams: Encodable, Sendable {
    var online: Bool
    var pinTimeoutMs: Int = 0
}

/// How signAnswering answers the Sign's pin.request.
enum PINAnswer {
    case submit
    case cancel
    case ignore
}

/// Records every event from the bridge's stream, in order.
actor EventRecorder {
    private(set) var events: [BridgeEvent] = []

    func append(_ event: BridgeEvent) {
        events.append(event)
    }

    /// The first event at or after index `start` that `match` maps to a value.
    func first<T: Sendable>(from start: Int, _ match: @Sendable (BridgeEvent) -> T?) -> T? {
        events.dropFirst(start).lazy.compactMap(match).first
    }
}

/// The result of a call that ran in its own task.
actor Completion<T: Sendable> {
    private(set) var value: T?

    func set(_ value: T) {
        self.value = value
    }
}

/// One scenario's checks, run in order on the main actor; the bridge calls
/// themselves run on LiveBridge's queue.
@MainActor
final class Flow {
    let bridge: LiveBridge
    let recorder = EventRecorder()
    private var checks = 0

    init(bridge: LiveBridge) {
        self.bridge = bridge
        let events = bridge.events
        Task { [recorder] in
            for await event in events {
                await recorder.append(event)
            }
        }
    }

    /// Runs `scenario` with a fresh data directory, `<tmp>/rhgflow-<uuid>/data`
    /// (files are saved next to it: the core refuses saves into the data
    /// folder), and returns the exit code.
    func run(_ scenario: Scenario) async -> Int32 {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("rhgflow-\(UUID().uuidString)", isDirectory: true)
        let dataDir = root.appendingPathComponent("data", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)
            switch scenario {
            case .offline: try await offline(dataDir: dataDir)
            case .online: try await online(dataDir: dataDir)
            case .pinCancel: try await pinCancel(dataDir: dataDir)
            case .pinTimeout: try await pinTimeout(dataDir: dataDir)
            }
        } catch let notFake as NotRHGFake {
            emit(
                "FAIL: test.configure: input (\(notFake.message)): the library is probably not the rhgfake build: "
                    + "point RHGCORE_LIB_DIR at go/release/rhgcore/rhgfake")
            return 3
        } catch let failure as Failure {
            emit("FAIL: \(failure.check): \(failure.detail)")
            return 1
        } catch {
            emit("FAIL: \(scenario.rawValue): \(error)")
            return 1
        }
        emit("PASS: \(scenario.rawValue) (\(checks) checks)")
        return 0
    }

    // MARK: Scenarios

    func offline(dataDir: URL) async throws {
        let info = try await configureAndInit(online: false, dataDir: dataDir)
        try check(!info.online, "app.init offline", "online \(info.online)")

        let start = await recorder.events.count
        let refused = await signResult(Self.credential("Jane Doe"))
        try expectError(refused, .failed, "sign.sign offline is refused")
        // A pin.request would have been emitted before sign.sign returned;
        // give the consumer task time to record it if there was one.
        try await Task.sleep(for: .milliseconds(300))
        let request = await recorder.first(from: start) { if case .pinRequest(let r) = $0 { r } else { nil } }
        try check(request == nil, "no pin.request when offline", "got one")

        try await expectError(.internal, "test.panic is an internal error") {
            let _: Empty = try await self.bridge.call("test.panic", Empty())
        }
        _ = try await step("app.canQuit after a panic") { try await self.bridge.canQuit() }
        try await shutdownAndCheckClosed()
    }

    func online(dataDir: URL) async throws {
        let info = try await configureAndInit(online: true, dataDir: dataDir)
        try check(info.online && info.activeKeys == 1, "app.init online with the fake card's key",
                  "online \(info.online), activeKeys \(info.activeKeys)")
        try await step("app.start") { try await self.bridge.startApp() }
        let again = try await step("app.info") { try await self.bridge.appInfo() }
        try check(again == info, "app.info matches app.init", "differs")
        let honors = try await step("sign.honors") { try await self.bridge.honors() }
        try check(honors.honors.contains("Ennoblement"), "sign.honors lists Ennoblement", "\(honors.honors.count) honors")
        let update = try await step("update.current") { try await self.bridge.currentUpdate() }
        try check(update.status.state == .idle && update.updated == nil, "update.current is idle",
                  update.status.state.rawValue)
        try await step("sign.validate") { try await self.bridge.validate(Self.credential("Jane Doe")) }
        try await expectError(.failed, "sign.validate without a recipient fails") {
            try await self.bridge.validate(Self.credential(""))
        }

        // Sign with the PIN submitted from the event stream.
        let start = await recorder.events.count
        let (signed, request) = try await signAnswering(Self.credential("Jane Doe"), .submit)
        let result = try signedResult(signed, "sign.sign with the PIN submitted")
        try check(request != nil, "one pin.request", "none")
        try check(result.url.hasPrefix("https://verify.royalhouseofgeorgia.ge/") && !result.existing,
                  "sign.sign returns a new credential's verification URL", "existing \(result.existing)")
        try check(!result.pngPreview.isEmpty, "sign.sign returns a PNG preview", "empty")
        try await waitFor("sign.connecting") { await self.recorder.first(from: start) { $0 == .signConnecting ? true : nil } }
        if let request {
            try await expectError(.input, "pin.submit with a stale requestId") {
                try await self.bridge.submitPIN(requestId: request.requestId, pin: fakePIN, remember: false)
            }
        }

        let svg = dataDir.deletingLastPathComponent().appendingPathComponent("qr.svg")
        try await step("sign.saveQR") { try await self.bridge.saveQR(url: result.url, format: .svg, path: svg.path) }
        try check(FileManager.default.fileExists(atPath: svg.path), "sign.saveQR wrote the file", "missing")
        try await expectError(.notFound, "sign.reportError of an unknown report") {
            _ = try await self.bridge.reportError(reportId: "999")
        }

        try await roundTripNames()

        let quit = try await step("app.canQuit") { try await self.bridge.canQuit() }
        try check(!quit.dirty, "app.canQuit is not dirty", "dirty")
        try await shutdownAndCheckClosed()
    }

    /// Signs Georgian and accented names; the signed recipient must be the
    /// NFC form, compared as UTF-8 bytes (String == ignores normalization).
    func roundTripNames() async throws {
        let georgian = "ნიკოლოზ ბაგრატიონი"
        let nfc = "Jos\u{E9}"
        let nfd = "Jose\u{301}"
        try check(Array(nfc.utf8) != Array(nfd.utf8), "NFC and NFD inputs differ in bytes", "same bytes")

        let signedGeorgian = try signedResult(
            try await signAnswering(Self.credential(georgian), .submit).0, "sign.sign a Georgian name")
        try check(Array(signedGeorgian.recipient.utf8) == Array(georgian.utf8),
                  "Georgian recipient round-trips byte for byte", "bytes differ")

        let signedNFD = try signedResult(try await signAnswering(Self.credential(nfd), .submit).0, "sign.sign an NFD name")
        try check(Array(signedNFD.recipient.utf8) == Array(nfc.utf8), "NFD recipient is signed as NFC bytes",
                  "bytes \(Array(signedNFD.recipient.utf8))")
        try check(!signedNFD.existing, "NFD name is a new credential", "existing")

        let signedNFC = try signedResult(try await signAnswering(Self.credential(nfc), .submit).0, "sign.sign an NFC name")
        try check(Array(signedNFC.recipient.utf8) == Array(nfc.utf8), "NFC recipient is signed as NFC bytes",
                  "bytes \(Array(signedNFC.recipient.utf8))")
        try check(signedNFC.existing && signedNFC.url == signedNFD.url,
                  "NFC name is the NFD name's credential", "existing \(signedNFC.existing)")
    }

    func pinCancel(dataDir: URL) async throws {
        _ = try await configureAndInit(online: true, dataDir: dataDir)
        let (signed, request) = try await signAnswering(Self.credential("Jane Doe"), .cancel)
        try check(request != nil, "one pin.request", "none")
        try expectError(signed, .cancelled, "sign.sign with the PIN cancelled")
        try await shutdownAndCheckClosed()
    }

    func pinTimeout(dataDir: URL) async throws {
        _ = try await configureAndInit(online: true, pinTimeoutMs: 300, dataDir: dataDir)
        let start = await recorder.events.count
        let (signed, request) = try await signAnswering(Self.credential("Jane Doe"), .ignore)
        guard let request else { throw Failure(check: "one pin.request", detail: "none") }
        pass("one pin.request")
        try expectError(signed, .failed, "sign.sign fails when the PIN prompt times out")
        if case .failure(let error) = signed {
            try check(!error.message.contains(fakePIN), "the timeout error holds no PIN", "it does")
        }
        try await waitFor("pin.dismiss withdraws the timed-out request") {
            await self.recorder.first(from: start) {
                if case .pinDismiss(let d) = $0, d.requestId == request.requestId { true } else { nil }
            }
        }
        try await shutdownAndCheckClosed()
    }

    // MARK: Steps

    static func credential(_ recipient: String) -> CredentialParams {
        CredentialParams(recipient: recipient, honor: "Ennoblement", detail: "For service", date: "2026-01-02")
    }

    func configureAndInit(online: Bool, pinTimeoutMs: Int = 0, dataDir: URL) async throws -> AppInfo {
        do throws(RPCError) {
            let _: Empty = try await bridge.call(
                "test.configure", TestConfigureParams(online: online, pinTimeoutMs: pinTimeoutMs))
        } catch {
            // The release build has no test.* methods: unknown method, input.
            if error.code == .input {
                throw NotRHGFake(message: error.message)
            }
            throw Failure(check: "test.configure", detail: "code \(error.code.rawValue)")
        }
        pass("test.configure")
        return try await step("app.init") { try await self.bridge.initApp(dataDir: dataDir.path) }
    }

    /// app.shutdown, then any method but app.canQuit/app.shutdown is refused.
    func shutdownAndCheckClosed() async throws {
        try await step("app.shutdown") { try await self.bridge.shutdown(relaunch: false) }
        try await expectError(.input, "app.info after app.shutdown") { _ = try await self.bridge.appInfo() }
    }

    /// Runs sign.sign in its own task and answers its pin.request (if one
    /// comes: an already-issued credential returns without one).
    func signAnswering(
        _ credential: CredentialParams, _ answer: PINAnswer
    ) async throws -> (Result<SignResult, RPCError>, PINRequest?) {
        let start = await recorder.events.count
        let done = Completion<Result<SignResult, RPCError>>()
        Task { [bridge] in await done.set(await Self.signResult(bridge, credential)) }
        let deadline = ContinuousClock.now + .seconds(30)
        var request: PINRequest?
        while ContinuousClock.now < deadline {
            if let result = await done.value {
                return (result, request)
            }
            if request == nil,
               let r = await recorder.first(from: start, { if case .pinRequest(let r) = $0 { r } else { nil } })
            {
                request = r
                switch answer {
                case .submit:
                    try await step("pin.submit") { try await self.bridge.submitPIN(requestId: r.requestId, pin: fakePIN, remember: false) }
                case .cancel:
                    try await step("pin.cancel") { try await self.bridge.cancelPIN(requestId: r.requestId) }
                case .ignore:
                    break
                }
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw Failure(check: "sign.sign", detail: "no result within 30 s")
    }

    func signResult(_ credential: CredentialParams) async -> Result<SignResult, RPCError> {
        await Self.signResult(bridge, credential)
    }

    static func signResult(_ bridge: LiveBridge, _ credential: CredentialParams) async -> Result<SignResult, RPCError> {
        do throws(RPCError) {
            return .success(try await bridge.sign(credential))
        } catch {
            return .failure(error)
        }
    }

    func signedResult(_ result: Result<SignResult, RPCError>, _ what: String) throws -> SignResult {
        switch result {
        case .success(let value):
            pass(what)
            return value
        case .failure(let error):
            throw Failure(check: what, detail: "code \(error.code.rawValue)")
        }
    }

    @discardableResult
    func step<T>(_ what: String, _ body: () async throws -> T) async throws -> T {
        do {
            let value = try await body()
            pass(what)
            return value
        } catch let error as RPCError {
            throw Failure(check: what, detail: "code \(error.code.rawValue)")
        }
    }

    func expectError(_ code: RPCErrorCode, _ what: String, _ body: () async throws -> Void) async throws {
        do {
            try await body()
        } catch let error as RPCError {
            try check(error.code == code, what, "code \(error.code.rawValue)")
            return
        }
        throw Failure(check: what, detail: "succeeded")
    }

    func expectError<T>(_ result: Result<T, RPCError>, _ code: RPCErrorCode, _ what: String) throws {
        guard case .failure(let error) = result else {
            throw Failure(check: what, detail: "succeeded")
        }
        try check(error.code == code, what, "code \(error.code.rawValue)")
    }

    /// Polls `found` for up to 5 s.
    func waitFor(_ what: String, _ found: () async -> Bool?) async throws {
        let deadline = ContinuousClock.now + .seconds(5)
        while ContinuousClock.now < deadline {
            if await found() == true {
                pass(what)
                return
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw Failure(check: what, detail: "not seen within 5 s")
    }

    func check(_ condition: Bool, _ what: String, _ detail: @autoclosure () -> String) throws {
        guard condition else { throw Failure(check: what, detail: detail()) }
        pass(what)
    }

    func pass(_ what: String) {
        checks += 1
        emit("ok: \(what)")
    }
}

/// Writes one output line unbuffered, so a killed runner leaves every line.
func emit(_ line: String) {
    FileHandle.standardOutput.write(Data((line + "\n").utf8))
}
