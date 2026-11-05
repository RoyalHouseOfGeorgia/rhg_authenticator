internal import CRHGCore
import Foundation

/// The Bridge to the Go core linked into this process (librhgcore), through
/// its C ABI. There is one per process: `LiveBridge.install()`.
public final class LiveBridge: Bridge {
    private static let shared = LiveBridge()

    /// Calls run here, off the Swift cooperative pool, because RHGCall blocks
    /// (card, network, up to five minutes waiting for a PIN). Concurrent, so
    /// pin.submit and app.canQuit run while sign.sign waits.
    private static let queue = DispatchQueue(label: "rhgcore.call", qos: .userInitiated, attributes: .concurrent)

    private init() {
        _ = eventChannel
        RHGSetEventCallback(deliverEvent)
    }

    /// Registers the event callback (once per process) and returns the
    /// bridge. Call it before app.init: from then on every event is buffered
    /// in `events` until consumed, so none emitted at start-up is lost.
    public static func install() -> LiveBridge {
        shared
    }

    /// Every event since `install()`, unbounded. Single consumer.
    public var events: AsyncStream<BridgeEvent> {
        eventChannel.stream
    }

    public func call<P: Encodable & Sendable, R: Decodable & Sendable>(
        _ method: String, _ params: P
    ) async throws(RPCError) -> R {
        let paramsJSON: String
        do {
            paramsJSON = String(decoding: try CanonicalJSON.encode(params), as: UTF8.self)
        } catch {
            throw .badParams
        }
        let response = await withCheckedContinuation { continuation in
            Self.queue.async {
                continuation.resume(returning: Self.blockingCall(method, paramsJSON))
            }
        }
        return try RPCEnvelope.decode(response)
    }

    /// Runs RHGCall on the current thread and returns the response envelope.
    /// The C strings stay valid for the whole call; Go copies them and does
    /// not write to them.
    private static func blockingCall(_ method: String, _ params: String) -> Data {
        method.withCString { methodC in
            params.withCString { paramsC in
                let response = RHGCall(UnsafeMutablePointer(mutating: methodC), UnsafeMutablePointer(mutating: paramsC))
                defer { RHGFree(response) }
                // Never NULL per the ABI; an empty response decodes as .badResponse.
                guard let response else { return Data() }
                return Data(bytes: response, count: strlen(response))
            }
        }
    }
}

/// The process's event stream, created on first use (by `LiveBridge`'s init,
/// before the callback is registered). Its continuation is thread-safe, and
/// with an unbounded buffer `yield` never blocks the Go thread.
private let eventChannel = AsyncStream.makeStream(of: BridgeEvent.self, bufferingPolicy: .unbounded)

/// The C event callback. It may run on any Go thread, possibly inside an
/// RHGCall on another thread, and must not block: it copies the string (valid
/// only during the call) into an event and yields it, touching no other state.
private func deliverEvent(_ json: UnsafePointer<CChar>?) {
    guard let json else { return }
    eventChannel.continuation.yield(BridgeEvent(json: Data(bytes: json, count: strlen(json))))
}
