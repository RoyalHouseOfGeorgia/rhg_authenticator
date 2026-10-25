import Testing

@testable import RHGModels

@Suite("Confirmation (the question's buttons)")
struct ConfirmationTests {
    func question(destructive: Bool, alternate: Bool) -> RHGModels.Confirmation {
        RHGModels.Confirmation(
            title: "T", message: "M", confirmTitle: "Delete", alternateTitle: alternate ? "Revoke Instead" : nil,
            isDestructive: destructive)
    }

    @Test(
        "the buttons' order: confirm, Cancel, then the alternate, destructive or not",
        arguments: [
            (true, false, [ConfirmChoice.confirm, .cancel]),
            (true, true, [ConfirmChoice.confirm, .cancel, .alternate]),
            (false, false, [ConfirmChoice.confirm, .cancel]),
            (false, true, [ConfirmChoice.confirm, .cancel, .alternate]),
        ])
    func buttonRoles(destructive: Bool, alternate: Bool, roles: [ConfirmChoice]) {
        #expect(question(destructive: destructive, alternate: alternate).buttonRoles == roles)
    }

    @Test(
        "the keys: Cancel has Escape; in a destructive question no other button has a key, so Return destroys nothing",
        arguments: [true, false])
    func keyEquivalents(alternate: Bool) {
        let destructive = question(destructive: true, alternate: alternate)
        #expect(destructive.keyEquivalent(for: .confirm) == "")
        #expect(destructive.keyEquivalent(for: .alternate) == "")
        #expect(destructive.keyEquivalent(for: .cancel) == "\u{1b}")
        #expect(destructive.hasDestructiveAction(for: .confirm))
        #expect(!destructive.hasDestructiveAction(for: .alternate))
        #expect(!destructive.hasDestructiveAction(for: .cancel))
        // Not destructive: confirm keeps NSAlert's Return.
        let plain = question(destructive: false, alternate: alternate)
        #expect(plain.keyEquivalent(for: .confirm) == nil)
        #expect(plain.keyEquivalent(for: .alternate) == nil)
        #expect(plain.keyEquivalent(for: .cancel) == "\u{1b}")
        #expect(!plain.hasDestructiveAction(for: .confirm))
    }

    @Test("each button answers with its role; any other way the question closed is Cancel")
    func choice() {
        let destructive = question(destructive: true, alternate: true)
        #expect(destructive.choice(forButtonAt: 0) == .confirm)
        #expect(destructive.choice(forButtonAt: 1) == .cancel)
        #expect(destructive.choice(forButtonAt: 2) == .alternate)
        #expect(destructive.choice(forButtonAt: 3) == .cancel)
        #expect(destructive.choice(forButtonAt: -1) == .cancel)
        let plainWithAlternate = question(destructive: false, alternate: true)
        #expect(plainWithAlternate.choice(forButtonAt: 0) == .confirm)
        #expect(plainWithAlternate.choice(forButtonAt: 1) == .cancel)
        #expect(plainWithAlternate.choice(forButtonAt: 2) == .alternate)
        let plain = question(destructive: false, alternate: false)
        #expect(plain.choice(forButtonAt: 0) == .confirm)
        #expect(plain.choice(forButtonAt: 1) == .cancel)
        #expect(plain.choice(forButtonAt: 2) == .cancel)
    }
}
