import Foundation
import RHGBridge

/// go/service/rpc/testdata/contract, located from this file.
let contractDir: URL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()  // RHGBridgeTests
    .deletingLastPathComponent()  // Tests
    .deletingLastPathComponent()  // macos
    .deletingLastPathComponent()  // repo root
    .appendingPathComponent("go/service/rpc/testdata/contract", isDirectory: true)

func contractFile(_ path: String) throws -> Data {
    try Data(contentsOf: contractDir.appendingPathComponent(path))
}

/// The regular files under `dir`, as paths relative to it, sorted.
func files(under dir: URL) throws -> [String] {
    let base = dir.standardizedFileURL.path
    guard let walker = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: [.isRegularFileKey]) else {
        return []
    }
    var found: [String] = []
    for case let url as URL in walker where try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
        found.append(String(url.standardizedFileURL.path.dropFirst(base.count + 1)))
    }
    return found.sorted()
}

/// `value` in the contract's canonical encoding, with the trailing newline
/// every contract file has.
func canonical<T: Encodable>(_ value: T) throws -> Data {
    try CanonicalJSON.encode(value) + Data("\n".utf8)
}

/// A success envelope around the canonical encoding of `result`.
func successEnvelope<T: Encodable>(_ result: T) throws -> Data {
    Data(#"{"ok":true,"result":"#.utf8) + (try CanonicalJSON.encode(result)) + Data("}\n".utf8)
}

/// A Bridge that records each call's method and canonical params and answers
/// from a table of response envelopes.
final class RecordingBridge: Bridge, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [(method: String, params: Data)] = []
    private let responses: [String: Data]
    let events = AsyncStream<BridgeEvent> { $0.finish() }

    init(responses: [String: Data]) {
        self.responses = responses
    }

    var calls: [(method: String, params: Data)] {
        lock.withLock { recorded }
    }

    func call<P: Encodable & Sendable, R: Decodable & Sendable>(
        _ method: String, _ params: P
    ) async throws(RPCError) -> R {
        let encoded: Data
        do {
            encoded = try CanonicalJSON.encode(params)
        } catch {
            throw .badParams
        }
        lock.withLock { recorded.append((method, encoded)) }
        return try RPCEnvelope.decode(responses[method] ?? Data())
    }
}
