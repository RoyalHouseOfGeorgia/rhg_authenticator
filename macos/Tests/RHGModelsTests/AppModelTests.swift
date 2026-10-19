import Foundation
import RHGBridge
import Testing

@testable import RHGModels

@Suite("AppModel")
@MainActor
struct AppModelTests {
    @Test("startup online: init, honors, start in order; ready; status bar")
    func startOnline() async {
        let fake = FakeBridge()
        let app = AppModel(bridge: fake)
        #expect(app.phase == .starting)
        #expect(app.statusItems.isEmpty)
        fake.respond(.appInit, onlineInfo)
        fake.respond(.signHonors, HonorsResult(honors: ["A", "B"]))
        await app.start(dataDir: "/data")
        #expect(app.phase == .ready)
        #expect(app.info == onlineInfo)
        #expect(app.statusItems == ["Active keys: 3", "Expired (30d): 1", "Version 1.2.3"])
        #expect(app.sign.honors == ["A", "B"])
        #expect(fake.methods == ["app.init", "sign.honors", "app.start"])
        #expect(fake.params(.appInit) == [#"{"dataDir":"/data"}"#])
    }

    @Test("startup offline: No internet and the version; no data dir sends {}")
    func startOffline() async {
        let fake = FakeBridge()
        fake.respond(.appInit, AppInfo(activeKeys: 0, online: false, recentlyExpired: 0, version: "2.0"))
        fake.respond(.signHonors, HonorsResult(honors: []))
        let app = AppModel(bridge: fake)
        await app.start()
        #expect(app.phase == .ready)
        #expect(app.statusItems == ["No internet", "Version 2.0"])
        #expect(fake.params(.appInit) == ["{}"])
    }

    @Test("only a leading v is stripped from the version")
    func versionPrefix() async {
        let fake = FakeBridge()
        fake.respond(.appInit, AppInfo(activeKeys: 1, online: true, recentlyExpired: 0, version: "vv1"))
        fake.respond(.signHonors, HonorsResult(honors: []))
        let app = AppModel(bridge: fake)
        await app.start()
        #expect(app.statusItems.last == "Version v1")
    }

    @Test("app.init failure is fatal with the report suffix; nothing else is called")
    func initFailure() async {
        let fake = FakeBridge()
        fake.fail(.appInit, RPCError(code: .failed, message: "Could not create the data directory."))
        let app = AppModel(bridge: fake)
        await app.start()
        #expect(
            app.phase
                == .fatal(
                    message: "Could not create the data directory.\n\n"
                        + "Please report this error at https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues"))
        #expect(fake.methods == ["app.init"])
        #expect(app.statusItems.isEmpty)
    }

    @Test("sign.honors failure is fatal; app.start is not called")
    func honorsFailure() async {
        let fake = FakeBridge()
        fake.respond(.appInit, onlineInfo)
        fake.fail(.signHonors, RPCError(code: .internal, message: "honors broke"))
        let app = AppModel(bridge: fake)
        await app.start()
        #expect(app.phase == .fatal(message: "honors broke" + AppModel.reportSuffix))
        #expect(fake.methods == ["app.init", "sign.honors"])
    }

    @Test("app.start failure is fatal")
    func startFailure() async {
        let fake = FakeBridge()
        fake.respond(.appInit, onlineInfo)
        fake.respond(.signHonors, HonorsResult(honors: []))
        fake.fail(.appStart, RPCError(code: .input, message: "not initialized"))
        let app = AppModel(bridge: fake)
        await app.start()
        #expect(app.phase == .fatal(message: "not initialized" + AppModel.reportSuffix))
    }

    @Test("a second start does nothing")
    func startOnce() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        await app.start()
        #expect(fake.count(.appInit) == 1)
    }

    @Test("events emitted before start are delivered once it runs")
    func bufferedEvents() async {
        let fake = FakeBridge()
        fake.emit(.pinRequest(PINRequest(requestId: 4, rememberDefault: true, maxBytes: 8)))
        let app = await startedApp(fake)
        #expect(await settle { app.pinPrompt.request != nil })
        #expect(app.pinPrompt.request?.requestId == 4)
    }

    @Test("app.internalError shows the restart alert")
    func internalError() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        #expect(app.internalErrorMessage == nil)
        fake.emit(.appInternalError)
        #expect(await settle { app.internalErrorMessage != nil })
        #expect(app.internalErrorMessage == "An internal error occurred — please restart")
    }

    @Test("update events are stored; other events are ignored")
    func updateEvents() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        let status = UpdateStatus(
            state: .ready, version: "1.3.0", releaseUrl: "https://github.com/o/r/releases/tag/v1.3.0",
            moveToApplications: false)
        let notice = UpdatedNotice(version: "1.2.3", releaseUrl: "")
        fake.emit(.historyChanged)
        fake.emit(.unknown("future.event"))
        fake.emit(.updateStatus(status))
        fake.emit(.updateUpdated(notice))
        #expect(await settle { app.updatedNotice != nil })
        #expect(app.updateStatus == status)
        #expect(app.updatedNotice == notice)
        #expect(app.phase == .ready)
        #expect(app.internalErrorMessage == nil)
    }

    @Test("pin events reach the PIN prompt")
    func pinEvents() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        fake.emit(.pinRequest(PINRequest(requestId: 9, rememberDefault: false, maxBytes: 8)))
        #expect(await settle { app.pinPrompt.request != nil })
        fake.emit(.pinDismiss(PINDismiss(requestId: 9)))
        #expect(await settle { app.pinPrompt.request == nil })
    }

    // MARK: Quit

    @Test("quit: canQuit, then shutdown with relaunch passed through", arguments: [false, true])
    func quit(relaunch: Bool) async {
        let fake = FakeBridge()
        fake.respond(.appCanQuit, CanQuitResult(dirty: false))
        let app = AppModel(bridge: fake)
        #expect(await app.prepareToQuit(relaunch: relaunch))
        #expect(fake.methods == ["app.canQuit", "app.shutdown"])
        #expect(fake.params(.appShutdown) == [#"{"relaunch":\#(relaunch)}"#])
    }

    @Test("core errors never block quitting")
    func quitErrors() async {
        let fake = FakeBridge()
        fake.fail(.appCanQuit, RPCError(code: .internal, message: "x"))
        fake.fail(.appShutdown, RPCError(code: .internal, message: "y"))
        let app = AppModel(bridge: fake)
        app.confirmDiscard = {
            Issue.record("confirmDiscard asked without dirty edits")
            return false
        }
        #expect(await app.prepareToQuit(relaunch: false))
        #expect(fake.methods == ["app.canQuit", "app.shutdown"])
    }

    @Test("concurrent and later quits share one shutdown")
    func quitIdempotent() async {
        let fake = FakeBridge()
        fake.respond(.appCanQuit, CanQuitResult(dirty: false))
        let held = fake.hold(.appShutdown)
        let app = AppModel(bridge: fake)
        let first = Task { await app.prepareToQuit(relaunch: true) }
        #expect(await settle { fake.count(.appShutdown) == 1 })
        let second = Task { await app.prepareToQuit(relaunch: false) }
        held.release(Empty())
        #expect(await first.value)
        #expect(await second.value)
        #expect(await app.prepareToQuit(relaunch: false))
        #expect(fake.params(.appShutdown) == [#"{"relaunch":true}"#])
        #expect(fake.count(.appCanQuit) == 1)
    }

    @Test("dirty edits: declining keeps the app running; a later quit asks again")
    func quitDirty() async {
        let fake = FakeBridge()
        fake.respond(.appCanQuit, CanQuitResult(dirty: true))
        let app = AppModel(bridge: fake)
        var asked = 0
        app.confirmDiscard = {
            asked += 1
            return asked > 1
        }
        #expect(await app.prepareToQuit(relaunch: false) == false)
        #expect(fake.count(.appShutdown) == 0)
        #expect(await app.prepareToQuit(relaunch: false))
        #expect(asked == 2)
        #expect(fake.count(.appShutdown) == 1)
    }

    @Test("dirty edits: the default confirmDiscard discards")
    func quitDirtyDefault() async {
        let fake = FakeBridge()
        fake.respond(.appCanQuit, CanQuitResult(dirty: true))
        let app = AppModel(bridge: fake)
        #expect(await app.prepareToQuit(relaunch: false))
        #expect(fake.count(.appShutdown) == 1)
    }
}
