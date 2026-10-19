import Foundation
import Observation
import RHGBridge

/// The YubiKey PIN prompt: shown while `request` is non-nil, answered with
/// `submit()` or `cancel()`. The core owns the timeout, the cache and the
/// byte cap; the PIN text is cleared as soon as the prompt is answered or
/// withdrawn, and never appears in the model's description or mirror.
@MainActor
@Observable
public final class PINPromptModel {
    nonisolated public static let title = "YubiKey PIN"
    nonisolated public static let prompt = "Enter your YubiKey PIN to sign:"
    nonisolated public static let placeholder = "YubiKey PIN"
    nonisolated public static let rememberLabel = "Remember PIN for this session"
    nonisolated public static let okTitle = "OK"
    nonisolated public static let cancelTitle = "Cancel"

    /// The pending pin.request; non-nil shows the prompt.
    public private(set) var request: PINRequest?

    /// The "Remember PIN for this session" checkbox, reset to the request's
    /// `rememberDefault` on each request.
    public var remember = false

    private var enteredPIN = ""

    @ObservationIgnored private let bridge: any Bridge

    public init(bridge: any Bridge) {
        self.bridge = bridge
    }

    /// The PIN field, capped to the request's `maxBytes` UTF-8 bytes
    /// (`truncatePIN`); always "" while no request is pending.
    public var pin: String {
        get { enteredPIN }
        set { enteredPIN = request.map { truncatePIN(newValue, maxBytes: $0.maxBytes) } ?? "" }
    }

    /// The hint under the field, e.g. "Up to 8 characters"; "" without a request.
    public var hint: String {
        request.map { "Up to \($0.maxBytes) characters" } ?? ""
    }

    /// Shows `request`, replacing any pending one: the core keeps a single
    /// pending prompt, and the latest id is the live one.
    public func present(_ request: PINRequest) {
        self.request = request
        enteredPIN = ""
        remember = request.rememberDefault
    }

    /// pin.dismiss: closes the prompt if it shows request `requestId`.
    public func dismiss(requestId: UInt64) {
        if request?.requestId == requestId {
            clear()
        }
    }

    /// OK: closes the prompt, then sends the PIN. A failure (a request that
    /// was withdrawn meanwhile) needs no handling: the signing call reports
    /// its own outcome.
    public func submit() async {
        guard let request else { return }
        let pin = enteredPIN
        let remember = remember
        clear()
        try? await bridge.submitPIN(requestId: request.requestId, pin: pin, remember: remember)
    }

    /// Cancel: closes the prompt, then withdraws the request; the signing
    /// call fails with `cancelled`.
    public func cancel() async {
        guard let request else { return }
        clear()
        try? await bridge.cancelPIN(requestId: request.requestId)
    }

    private func clear() {
        enteredPIN = ""
        request = nil
    }
}

extension PINPromptModel: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public nonisolated var description: String { "PINPromptModel(pin: <redacted>)" }
    public nonisolated var debugDescription: String { description }
    public nonisolated var customMirror: Mirror { Mirror(self, children: ["pin": "<redacted>"]) }
}
