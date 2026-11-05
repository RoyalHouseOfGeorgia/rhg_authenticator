import Foundation
import RHGBridge
import Testing

@testable import RHGModels

@Suite("YubiKeyModel")
@MainActor
struct YubiKeyModelTests {
    @Test("UI copy")
    func copy() {
        #expect(YubiKeyModel.checkTitle == "Check YubiKey")
        #expect(YubiKeyModel.checkingStatus == "Checking YubiKey\u{2026}")
    }

    @Test("a check shows the core's status and details")
    func check() async {
        let result = KeyCheck(outcome: .found, status: "Key found in registry", details: ["Authority: A", "Fingerprint: ae21"])
        let fake = FakeBridge()
        fake.respond(.yubikeyCheck, result)
        let model = YubiKeyModel(bridge: fake)
        #expect(model.status == "" && model.details.isEmpty && !model.isChecking)
        await model.check()
        #expect(model.status == result.status)
        #expect(model.details == result.details)
        #expect(!model.isChecking)
        #expect(fake.params(.yubikeyCheck) == ["{}"])
    }

    @Test("an error shows the core's message without details")
    func error() async {
        let fake = FakeBridge()
        fake.respond(.yubikeyCheck, KeyCheck(outcome: .found, status: "Key found in registry", details: ["Authority: A"]))
        fake.fail(.yubikeyCheck, RPCError(code: .busy, message: "Another YubiKey operation is running."))
        let model = YubiKeyModel(bridge: fake)
        await model.check()
        #expect(model.details == ["Authority: A"])
        await model.check()
        #expect(model.status == "Another YubiKey operation is running.")
        #expect(model.details.isEmpty)
        #expect(!model.isChecking)
    }

    @Test("while checking: checking, details cleared, a second check ignored")
    func checking() async {
        let fake = FakeBridge()
        fake.respond(.yubikeyCheck, KeyCheck(outcome: .notFound, status: "Key NOT found in registry", details: ["F"]))
        let held = fake.hold(.yubikeyCheck)
        let model = YubiKeyModel(bridge: fake)
        await model.check()
        let checking = Task { await model.check() }
        #expect(await settle { fake.count(.yubikeyCheck) == 2 })
        #expect(model.isChecking)
        #expect(model.status == YubiKeyModel.checkingStatus)
        #expect(model.details.isEmpty)
        await model.check()
        #expect(fake.count(.yubikeyCheck) == 2)
        held.release(KeyCheck(outcome: .found, status: "Key found in registry", details: ["A"]))
        await checking.value
        #expect(!model.isChecking)
        #expect(model.status == "Key found in registry")
    }
}
