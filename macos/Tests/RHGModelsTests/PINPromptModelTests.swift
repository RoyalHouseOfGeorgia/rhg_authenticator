import Foundation
import RHGBridge
import Testing

@testable import RHGModels

@Suite("PINPromptModel")
@MainActor
struct PINPromptModelTests {
    func shown(_ fake: FakeBridge, id: UInt64 = 7, rememberDefault: Bool = false, maxBytes: Int = 8) -> PINPromptModel {
        let model = PINPromptModel(bridge: fake)
        model.present(PINRequest(requestId: id, rememberDefault: rememberDefault, maxBytes: maxBytes))
        return model
    }

    @Test("UI copy")
    func copy() {
        #expect(PINPromptModel.title == "YubiKey PIN")
        #expect(PINPromptModel.prompt == "Enter your YubiKey PIN to sign:")
        #expect(PINPromptModel.placeholder == "YubiKey PIN")
        #expect(PINPromptModel.rememberLabel == "Remember PIN for this session")
        #expect(PINPromptModel.okTitle == "Sign")
        #expect(PINPromptModel.cancelTitle == "Cancel")
    }

    @Test("a request shows with its remember default and hint", arguments: [false, true])
    func present(_ rememberDefault: Bool) {
        let model = PINPromptModel(bridge: FakeBridge())
        #expect(model.request == nil)
        #expect(model.hint == "")
        model.present(PINRequest(requestId: 1, rememberDefault: rememberDefault, maxBytes: 8))
        #expect(model.request?.requestId == 1)
        #expect(model.remember == rememberDefault)
        #expect(model.hint == "Up to 8 characters")
        #expect(model.pin == "")
    }

    @Test("without a request the PIN stays empty")
    func noRequest() {
        let model = PINPromptModel(bridge: FakeBridge())
        model.pin = "1234"
        #expect(model.pin == "")
    }

    @Test(
        "the PIN is capped to maxBytes UTF-8 bytes between scalars",
        arguments: [
            ("123456789", 8, "12345678"), ("1234567\u{E9}", 8, "1234567"),
        ])
    func cap(_ typed: String, _ maxBytes: Int, _ kept: String) {
        let model = shown(FakeBridge(), maxBytes: maxBytes)
        model.pin = typed
        #expect(Array(model.pin.utf8) == Array(kept.utf8))
        #expect(model.pin.utf8.count <= maxBytes)
    }

    @Test("submit closes the prompt and clears the PIN before the call returns")
    func submit() async {
        let fake = FakeBridge()
        let held = fake.hold(.pinSubmit)
        let model = shown(fake)
        model.pin = "1234"
        model.remember = true
        let submitting = Task { await model.submit() }
        #expect(await settle { fake.count(.pinSubmit) == 1 })
        #expect(model.pin == "")
        #expect(model.request == nil)
        held.release(Empty())
        await submitting.value
        #expect(fake.params(.pinSubmit) == [#"{"pin":"1234","remember":true,"requestId":7}"#])
        #expect(model.pin == "")
    }

    @Test("a stale submit or cancel (input error) is ignored", arguments: [RPCMethod.pinSubmit, .pinCancel])
    func stale(_ method: RPCMethod) async {
        let fake = FakeBridge()
        fake.fail(method, RPCError(code: .input, message: "no such PIN request"))
        let model = shown(fake)
        model.pin = "1234"
        if method == .pinSubmit {
            await model.submit()
        } else {
            await model.cancel()
        }
        #expect(model.request == nil)
        #expect(model.pin == "")
        #expect(fake.count(method) == 1)
    }

    @Test("cancel closes the prompt, clears the PIN and withdraws the request")
    func cancel() async {
        let fake = FakeBridge()
        let model = shown(fake, id: 12)
        model.pin = "1234"
        await model.cancel()
        #expect(model.request == nil)
        #expect(model.pin == "")
        #expect(fake.methods == ["pin.cancel"])
        #expect(fake.params(.pinCancel) == [#"{"requestId":12}"#])
    }

    @Test("submit and cancel without a request do nothing")
    func noRequestAnswers() async {
        let fake = FakeBridge()
        let model = PINPromptModel(bridge: fake)
        await model.submit()
        await model.cancel()
        #expect(fake.calls.isEmpty)
    }

    @Test("dismiss closes only the matching request, without a call")
    func dismiss() {
        let fake = FakeBridge()
        let model = shown(fake, id: 5)
        model.pin = "1234"
        model.dismiss(requestId: 4)
        #expect(model.request?.requestId == 5)
        #expect(model.pin == "1234")
        model.dismiss(requestId: 5)
        #expect(model.request == nil)
        #expect(model.pin == "")
        #expect(fake.calls.isEmpty)
    }

    @Test("a new request replaces the shown one and resets the form")
    func replace() {
        let model = shown(FakeBridge(), id: 1, rememberDefault: false)
        model.pin = "1234"
        model.remember = true
        model.present(PINRequest(requestId: 2, rememberDefault: false, maxBytes: 8))
        #expect(model.request?.requestId == 2)
        #expect(model.pin == "")
        #expect(model.remember == false)
    }

    @Test("the PIN never appears in the model's description, debug description or dump")
    func redacted() {
        let model = shown(FakeBridge())
        model.pin = "4321"
        var dumped = ""
        dump(model, to: &dumped)
        for text in [String(describing: model), String(reflecting: model), dumped] {
            #expect(!text.contains("4321"))
            #expect(text.contains("<redacted>"))
        }
    }
}
