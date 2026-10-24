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
        "the buttons' order: Cancel first in a destructive question, so Return never destroys anything",
        arguments: [
            (true, false, [ConfirmChoice.cancel, .confirm]),
            (true, true, [ConfirmChoice.cancel, .confirm, .alternate]),
            (false, false, [ConfirmChoice.confirm, .cancel]),
            (false, true, [ConfirmChoice.confirm, .alternate, .cancel]),
        ])
    func buttonRoles(destructive: Bool, alternate: Bool, roles: [ConfirmChoice]) {
        #expect(question(destructive: destructive, alternate: alternate).buttonRoles == roles)
    }

    @Test("each button answers with its role; any other way the question closed is Cancel")
    func choice() {
        let destructive = question(destructive: true, alternate: true)
        #expect(destructive.choice(forButtonAt: 0) == .cancel)
        #expect(destructive.choice(forButtonAt: 1) == .confirm)
        #expect(destructive.choice(forButtonAt: 2) == .alternate)
        #expect(destructive.choice(forButtonAt: 3) == .cancel)
        #expect(destructive.choice(forButtonAt: -1) == .cancel)
        let plain = question(destructive: false, alternate: false)
        #expect(plain.choice(forButtonAt: 0) == .confirm)
        #expect(plain.choice(forButtonAt: 1) == .cancel)
        #expect(plain.choice(forButtonAt: 2) == .cancel)
    }
}
