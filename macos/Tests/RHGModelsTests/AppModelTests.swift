import Foundation
import RHGBridge
import Testing

@testable import RHGModels

@Suite("AppModel")
@MainActor
struct AppModelTests {
    @Test("startup online: init, honors, login state, registry, history, start in order; ready; status bar; audit")
    func startOnline() async {
        let fake = FakeBridge()
        let app = AppModel(bridge: fake)
        #expect(app.phase == .starting)
        #expect(app.statusItems.isEmpty)
        fake.respond(.appInit, onlineInfo)
        fake.respond(.signHonors, HonorsResult(honors: ["A", "B"]))
        scriptStartupReads(fake, auth: loggedIn, snapshot: registrySnapshot(count: 1))
        fake.respond(.auditCommits, startupAudit)
        await app.start(dataDir: "/data")
        #expect(app.phase == .ready)
        #expect(app.info == onlineInfo)
        #expect(app.statusItems == ["Active keys: 3", "Expired (30d): 1", "Version 1.2.3"])
        #expect(app.sign.honors == ["A", "B"])
        #expect(app.login.authState == loggedIn)
        #expect(app.registry.columns == registryColumns)
        #expect(app.registry.snapshot == registrySnapshot(count: 1))
        #expect(app.registry.status == "Loaded from registry server")
        #expect(await settle { app.audit.status == "Loaded 0 commits" })
        #expect(
            fake.methods == [
                "app.init", "sign.honors", "auth.state", "registry.columns", "registry.snapshot", "app.start",
                "audit.commits",
            ])
        #expect(fake.params(.appInit) == [#"{"dataDir":"/data"}"#])
    }

    @Test("startup offline: No internet and the version; no data dir sends {}")
    func startOffline() async {
        let fake = FakeBridge()
        fake.respond(.appInit, AppInfo(activeKeys: 0, online: false, recentlyExpired: 0, version: "2.0"))
        fake.respond(.signHonors, HonorsResult(honors: []))
        scriptStartupReads(fake, snapshot: registrySnapshot(count: 0, loaded: false))
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
        scriptStartupReads(fake)
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
        scriptStartupReads(fake)
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
        scriptStartupReads(fake)
        fake.reset(failing)
        fake.fail(failing, RPCError(code: .internal, message: "read broke"))
        let app = AppModel(bridge: fake)
        await app.start()
        #expect(app.phase == .fatal(message: "read broke" + AppModel.reportSuffix))
        #expect(fake.methods.last == failing.rawValue)
        #expect(fake.count(.appStart) == 0)
    }

    @Test("the Audit tab's first fetch runs after ready and does not hold startup; its rows open through the app's opener")
    func auditFirstLoad() async throws {
        let fake = FakeBridge()
        let urls = URLRecorder()
        let commit = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/commit/0123456789012345678901234567890123456789"
        fake.respond(.appInit, onlineInfo)
        fake.respond(.signHonors, HonorsResult(honors: []))
        scriptStartupReads(fake)
        let held = fake.hold(.auditCommits)
        let app = AppModel(bridge: fake, openURL: urls.open)
        await app.start()
        #expect(app.phase == .ready)
        #expect(await settle { fake.count(.auditCommits) == 1 })
        #expect(app.phase == .ready)
        #expect(app.audit.isRefreshing && app.audit.status == "Fetching...")
        held.release(AuditResult(rows: [AuditRow(summary: "c", url: commit)], status: "Loaded 1 commits"))
        #expect(await settle { !app.audit.isRefreshing })
        #expect(app.audit.rows == [AuditRow(summary: "c", url: commit)])
        #expect(app.audit.status == "Loaded 1 commits")
        app.audit.open(row: 0)
        #expect(urls.opened == [try #require(URL(string: commit))])
    }

    @Test("history.changed clears the selection before its re-read lands, then applies it")
    func historyChangedEvent() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        fake.respond(.historyRecordText, RecordTextResult(detail: "d", revokeConfirm: "q"))
        await app.history.select(row: 1)
        #expect(app.history.selection == 1)
        fake.reset(.historyList)
        let held = fake.hold(.historyList)
        fake.emit(.historyChanged)
        #expect(await settle { fake.count(.historyList) == 2 })
        #expect(app.history.selection == nil)
        held.release(historyList(count: 3))
        #expect(await settle { app.history.snapshot == historyList(count: 3) })
        #expect(app.history.selection == nil)
    }

    @Test("history.revocationsChanged re-reads the log keeping the selection")
    func revocationsChangedEvent() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        fake.respond(.historyRecordText, RecordTextResult(detail: "d", revokeConfirm: "q"))
        await app.history.select(row: 1)
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(count: 2, revoked: [1]))
        fake.emit(.historyRevocationsChanged)
        #expect(await settle { app.history.snapshot == historyList(count: 2, revoked: [1]) })
        #expect(app.history.selection == 1)
    }

    @Test("auth.changed updates the login and re-reads the history, whose Revoke gate follows it")
    func authChangedReloadsHistory() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        #expect(app.history.showsConnectButton)
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(count: 2, revokeAvailable: false))
        fake.reset(.authState)
        fake.respond(.authState, loggedIn)
        fake.emit(.authChanged(loggedIn))
        // Two tasks, the login's re-read and the history's: wait for both.
        #expect(await settle { app.history.snapshot.revokeAvailable == false && app.login.authState == loggedIn })
        #expect(!app.history.showsConnectButton)
        #expect(fake.count(.historyList) == 2)
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

    @Test("auth and registry events reach the login and the Registry tab")
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
        fake.reset(.authState)
        fake.respond(.authState, loggedIn)
        fake.emit(.authChanged(loggedOut))
        #expect(await settle { app.login.authState == loggedIn })
        #expect(await settle { app.registry.snapshot == registrySnapshot(count: 3) })
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
        fake.emit(.bulkConnecting)
        fake.emit(.unknown("future.event"))
        fake.emit(.updateStatus(status))
        fake.emit(.updateUpdated(notice))
        #expect(await settle { app.updatedNotice != nil })
        #expect(app.updateStatus == status)
        #expect(app.updatedNotice == notice)
        #expect(app.phase == .ready)
        #expect(app.internalErrorMessage == nil)
    }

    @Test("the banner follows update events: none, then each latest status and notice")
    func updateBanners() async throws {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        #expect(app.updateBanner == nil)
        #expect(app.updatedBanner == nil)
        let url = "https://github.com/o/r/releases/tag/v1.3.0"
        let ready = UpdateStatus(state: .ready, version: "1.3.0", releaseUrl: url, moveToApplications: false)
        let notice = UpdatedNotice(version: "1.2.3", releaseUrl: "")
        fake.emit(.updateStatus(ready))
        fake.emit(.updateUpdated(notice))
        #expect(await settle { app.updatedBanner != nil })
        #expect(app.updateBanner == (try #require(UpdateBanner(ready))))
        #expect(app.updatedBanner == UpdatedBanner(notice))
        // A later notice replaces the earlier one.
        let later = UpdatedNotice(version: "1.3.0", releaseUrl: url)
        fake.emit(.updateUpdated(later))
        #expect(await settle { app.updatedBanner == UpdatedBanner(later) })
        // A later status replaces the offer; idle clears it.
        let manual = UpdateStatus(state: .manualOnly, version: "1.4.0", releaseUrl: url, moveToApplications: true)
        fake.emit(.updateStatus(manual))
        let manualBanner = try #require(UpdateBanner(manual))
        #expect(await settle { app.updateBanner == manualBanner })
        fake.emit(.updateStatus(UpdateStatus(state: .idle, version: "", releaseUrl: "", moveToApplications: false)))
        #expect(await settle { app.updateStatus?.state == .idle })
        #expect(app.updateBanner == nil)
    }

    @Test("closing the Updated notice clears it and leaves the offer")
    func dismissUpdated() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        fake.emit(.updateStatus(UpdateStatus(state: .ready, version: "1.3.0", releaseUrl: "", moveToApplications: false)))
        fake.emit(.updateUpdated(UpdatedNotice(version: "1.2.3", releaseUrl: "")))
        #expect(await settle { app.updatedBanner != nil })
        app.dismissUpdatedNotice()
        #expect(app.updatedNotice == nil)
        #expect(app.updatedBanner == nil)
        #expect(app.updateBanner != nil)
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
        "the error log and issuance export names are today's date in the machine's time zone",
        arguments: [
            ("UTC", "rhg-error-log-2026-01-01.log", "rhg-issuances-2026-01-01.json"),
            ("Asia/Tbilisi", "rhg-error-log-2026-01-02.log", "rhg-issuances-2026-01-02.json"),
            ("America/Los_Angeles", "rhg-error-log-2026-01-01.log", "rhg-issuances-2026-01-01.json"),
        ])
    func errorLogFilename(_ zone: String, _ name: String, _ historyName: String) throws {
        let app = AppModel(bridge: FakeBridge(), clock: { lateNewYearsDay }, timeZone: try #require(TimeZone(identifier: zone)))
        #expect(app.suggestedErrorLogFilename == name)
        // The History tab's export is named by the same clock and zone.
        #expect(app.history.suggestedExportFilename == historyName)
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

    @Test("quit: canQuit, then shutdown, relaunching only after Restart now", arguments: [false, true])
    func quit(relaunch: Bool) async {
        let fake = FakeBridge()
        fake.respond(.appCanQuit, CanQuitResult(dirty: false))
        let app = AppModel(bridge: fake)
        if relaunch {
            app.requestRestart()
        }
        #expect(await app.prepareToQuit())
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
        #expect(await app.prepareToQuit())
        #expect(fake.methods == ["app.canQuit", "app.shutdown"])
    }

    @Test("concurrent and later quits share one shutdown")
    func quitIdempotent() async {
        let fake = FakeBridge()
        fake.respond(.appCanQuit, CanQuitResult(dirty: false))
        let held = fake.hold(.appShutdown)
        let app = AppModel(bridge: fake)
        app.requestRestart()
        let first = Task { await app.prepareToQuit() }
        #expect(await settle { fake.count(.appShutdown) == 1 })
        let second = Task { await app.prepareToQuit() }
        held.release(Empty())
        #expect(await first.value)
        #expect(await second.value)
        #expect(await app.prepareToQuit())
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
        #expect(await app.prepareToQuit() == false)
        #expect(fake.count(.appShutdown) == 0)
        #expect(await app.prepareToQuit())
        #expect(asked == 2)
        #expect(fake.count(.appShutdown) == 1)
    }

    @Test("Restart now pressed while a plain quit checks for edits: that quit relaunches")
    func restartDuringQuit() async {
        let fake = FakeBridge()
        let held = fake.hold(.appCanQuit)
        let app = AppModel(bridge: fake)
        let quit = Task { await app.prepareToQuit() }
        #expect(await settle { fake.count(.appCanQuit) == 1 })
        app.requestRestart()
        held.release(CanQuitResult(dirty: false))
        #expect(await quit.value)
        #expect(fake.params(.appShutdown) == [#"{"relaunch":true}"#])
    }

    @Test("Restart now declined, then a plain quit: shutdown once, without relaunch")
    func restartDeclinedThenQuit() async {
        let fake = FakeBridge()
        fake.respond(.appCanQuit, CanQuitResult(dirty: true))
        let app = AppModel(bridge: fake)
        var answers = [false, true]
        app.confirmDiscard = { answers.removeFirst() }
        app.requestRestart()
        #expect(await app.prepareToQuit() == false)
        #expect(fake.count(.appShutdown) == 0)
        #expect(await app.prepareToQuit())
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
        #expect(await app.prepareToQuit())
        #expect(fake.count(.appShutdown) == 1)
    }
}
