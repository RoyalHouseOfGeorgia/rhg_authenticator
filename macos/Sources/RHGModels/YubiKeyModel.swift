import Foundation
import Observation
import RHGBridge

/// The YubiKey tab: looks the inserted key up in the registry. The core reads
/// the card and words the outcome (offline it answers without the card).
@MainActor
@Observable
public final class YubiKeyModel {
    nonisolated public static let checkTitle = "Check YubiKey"
    /// The status line while a check runs.
    nonisolated public static let checkingStatus = "Checking YubiKey\u{2026}"

    /// The status line; "" until the first check.
    public private(set) var status = ""
    /// The key's details, one line each.
    public private(set) var details: [String] = []
    /// A check is running: Check YubiKey is disabled.
    public private(set) var isChecking = false

    @ObservationIgnored private let bridge: any Bridge

    public init(bridge: any Bridge) {
        self.bridge = bridge
    }

    /// Check YubiKey (yubikey.check). Ignored while a check is running.
    public func check() async {
        guard !isChecking else { return }
        isChecking = true
        defer { isChecking = false }
        status = Self.checkingStatus
        details = []
        do {
            let result = try await bridge.checkYubiKey()
            status = result.status
            details = result.details
        } catch {
            status = error.message
        }
    }
}
