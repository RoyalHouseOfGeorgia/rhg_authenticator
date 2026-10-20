import Foundation
import RHGBridge
import Testing

@testable import RHGModels

@Suite("AppModel")
@MainActor
struct AppModelTests {
    @Test("startup online: init, honors, login state, registry, start in order; ready; status bar")
    func startOnline() async {
        let fake = FakeBridge()
        let app = AppModel(bridge: fake)
        #expect(app.phase == .starting)
        #expect(app.statusItems.isEmpty)
        fake.respond(.appInit, onlineInfo)
        fake.respond(.signHonors, HonorsResult(honors: ["A", "B"]))
        scriptStartupRegistry(fake, auth: loggedIn, snapshot: registrySnapshot(count: 1))
        await app.start(dataDir: "/data")
        #expect(app.phase == .ready)
        #expect(app.info == onlineInfo)
        #expect(app.statusItems == ["Active keys: 3", "Expired (30d): 1", "Version 1.2.3"])
        #expect(app.sign.honors == ["A", "B"])
        #expect(app.login.authState == loggedIn)
        #expect(app.registry.columns == registryColumns)
        #expect(app.registry.snapshot == registrySnapshot(count: 1))
        #expect(app.registry.status == "Loaded from registry server")
        #expect(
            fake.methods == [
                "app.init", "sign.honors", "auth.state", "registry.columns", "registry.snapshot", "app.start",
            ])
        #expect(fake.params(.appInit) == [#"{"dataDir":"/data"}"#])
    }

    @Test("startup offline: No internet and the version; no data dir sends {}")
    func startOffline() async {
        let fake = FakeBridge()
        fake.respond(.appInit, AppInfo(activeKeys: 0, online: false, recentlyExpired: 0, version: "2.0"))
        fake.respond(.signHonors, HonorsResult(honors: []))
        scriptStartupRegistry(fake, snapshot: registrySnapshot(count: 0, loaded: false))
        let app = AppModel(bridge: fake)
        await app.start()
        #expect(app.phase == .ready)
        #expect(app.statusItems == ["No internet", "Version 2.0"])
        #expect(app.registry.status == "Fetching...")
        #expect(fake.params(.appInit) == ["{}"])
    }

    @Test("only a leading v is stripped from the version")
    func versionPrefix() async {
        let fake = FakeBridge()
        fake.respond(.appInit, AppInfo(activeKeys: 1, online: true, recentlyExpired: 0, version: "vv1"))
        fake.respond(.signHonors, HonorsResult(honors: []))
        scriptStartupRegistry(fake)
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
        scriptStartupRegistry(fake)
        fake.fail(.appStart, RPCError(code: .input, message: "not initialized"))
        let app = AppModel(bridge: fake)
        await app.start()
        #expect(app.phase == .fatal(message: "not initialized" + AppModel.reportSuffix))
    }

    @Test(
        "auth.state, registry.columns or registry.snapshot failing is fatal; app.start is not called",
        arguments: [RPCMethod.authState, .registryColumns, .registrySnapshot])
    func startupReadFailure(_ failing: RPCMethod) async {
        let fake = FakeBridge()
        fake.respond(.appInit, onlineInfo)
        fake.respond(.signHonors, HonorsResult(honors: []))
        scriptStartupRegistry(fake)
        fake.reset(failing)
        fake.fail(failing, RPCError(code: .internal, message: "read broke"))
        let app = AppModel(bridge: fake)
        await app.start()
        #expect(app.phase == .fatal(message: "read broke" + AppModel.reportSuffix))
        #expect(fake.methods.last == failing.rawValue)
        #expect(fake.count(.appStart) == 0)
    }

    @Test("login status texts land on the Registry tab's status line")
    func loginStatusSink() async {
        let fake = FakeBridge()
        let held = fake.hold(.authLogin)
        let app = await startedApp(fake)
        let login = Task { await app.login.start() }
        #expect(await settle { app.registry.status == "Requesting device code..." })
        held.release(loggedIn)
        await login.value
        #expect(app.registry.status == "Logged in as @octocat")
    }

    @Test("auth and registry events reach the login and the Registry tab, in order")
    func authAndRegistryEvents() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        app.registry.select(row: 0, column: 1)
        #expect(app.registry.selection != nil)
        fake.reset(.registrySnapshot)
        fake.respond(.registrySnapshot, registrySnapshot(count: 3))
        let held = fake.hold(.authLogin)
        let login = Task { await app.login.start() }
        #expect(await settle { fake.count(.authLogin) == 1 })
        fake.emit(.authDeviceCode(DeviceCode(userCode: "ABCD-1234", verificationUri: "https://github.com/login/device")))
        fake.emit(.registryChanged)
        fake.emit(.authChanged(loggedIn))
        #expect(await settle { app.login.authState == loggedIn })
        // registry.changed was handled before the auth.changed that followed it.
        #expect(app.registry.snapshot == registrySnapshot(count: 3))
        #expect(app.registry.selection == nil)
        #expect(app.login.deviceCode?.userCode == "ABCD-1234")
        held.release(loggedIn)
        await login.value
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

    @Test("a pin.request while bulk.run runs shows the PIN prompt")
    func pinDuringBulk() async {
        let fake = FakeBridge()
        fake.respond(.bulkLoad, BulkLoadResult(toSign: 1, countsLine: "", previewNames: ["A"], invalidLines: []))
        let held = fake.hold(.bulkRun)
        let app = await startedApp(fake)
        app.bulk.begin()
        await app.bulk.fileChosen(path: "/in/x.csv")
        let running = Task { await app.bulk.confirm() }
        #expect(await settle { fake.count(.bulkRun) == 1 })
        fake.emit(.pinRequest(PINRequest(requestId: 11, rememberDefault: false, maxBytes: 8)))
        #expect(await settle { app.pinPrompt.request?.requestId == 11 })
        // The progress sheet stays up under the prompt.
        #expect(app.bulk.phase == .running(BulkModel.Run()) && app.bulk.isShowingSheet)
        app.pinPrompt.pin = "123456"
        await app.pinPrompt.submit()
        #expect(fake.params(.pinSubmit) == [#"{"pin":"123456","remember":false,"requestId":11}"#])
        #expect(app.pinPrompt.request == nil)
        let outcome = BulkRunResult(stopped: .completed, summaryLine: "", stopMessage: "", failedLines: [], resultsFilename: "")
        held.release(outcome)
        await running.value
        #expect(app.bulk.phase == .results(plan: BulkLoadResult(toSign: 1, countsLine: "", previewNames: ["A"], invalidLines: []), outcome: outcome))
    }

    // MARK: Error log

    @Test(
        "the error log name is today's date in the machine's time zone",
        arguments: [("UTC", "rhg-error-log-2026-01-01.log"), ("Asia/Tbilisi", "rhg-error-log-2026-01-02.log"),
            ("America/Los_Angeles", "rhg-error-log-2026-01-01.log")])
    func errorLogFilename(_ zone: String, _ name: String) throws {
        let app = AppModel(bridge: FakeBridge(), clock: { lateNewYearsDay }, timeZone: try #require(TimeZone(identifier: zone)))
        #expect(app.suggestedErrorLogFilename == name)
    }

    @Test("error log export: saved-to alert with the path")
    func errorLogExport() async {
        let fake = FakeBridge()
        let app = AppModel(bridge: fake)
        let alert = await app.exportErrorLog(path: "/out/rhg-error-log-2026-01-01.log")
        #expect(fake.params(.appExportErrorLog) == [#"{"path":"/out/rhg-error-log-2026-01-01.log"}"#])
        #expect(
            alert
                == AlertState(
                    title: "Error Log Exported",
                    message: "Saved to:\n/out/rhg-error-log-2026-01-01.log\n\nYou can attach this file to an email. "
                        + "It contains app diagnostics (may include your GitHub username and file paths) — no PINs or keys."))
    }

    @Test("error log export failure shows the core's message")
    func errorLogExportFailure() async {
        let fake = FakeBridge()
        fake.fail(.appExportErrorLog, RPCError(code: .failed, message: "Choose a folder outside the app's data folder."))
        let app = AppModel(bridge: fake)
        let alert = await app.exportErrorLog(path: "/data/x.log")
        #expect(alert == AlertState(title: "Error", message: "Choose a folder outside the app's data folder."))
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

    @Test("Restart now declined, then a plain quit: shutdown once, without relaunch")
    func restartDeclinedThenQuit() async {
        let fake = FakeBridge()
        fake.respond(.appCanQuit, CanQuitResult(dirty: true))
        let app = AppModel(bridge: fake)
        var answers = [false, true]
        app.confirmDiscard = { answers.removeFirst() }
        #expect(await app.prepareToQuit(relaunch: true) == false)
        #expect(fake.count(.appShutdown) == 0)
        #expect(await app.prepareToQuit(relaunch: false))
        #expect(fake.params(.appShutdown) == [#"{"relaunch":false}"#])
        #expect(answers.isEmpty)
    }

    @Test("quit confirmation copy matches the Fyne app")
    func quitCopy() {
        #expect(
            AppModel.quitConfirmation
                == Confirmation(
                    title: "Unsubmitted Changes", message: "The registry has unsubmitted changes. Exit anyway?",
                    confirmTitle: "Exit", cancelTitle: "Cancel", isDestructive: true))
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
