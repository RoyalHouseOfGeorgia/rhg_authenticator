import Foundation
import RHGBridge
import Testing

@testable import RHGModels

@Suite("AppModel")
@MainActor
struct AppModelTests {
    @Test("the tab picker's titles")
    func tabTitles() {
        let titles = [
            AppModel.signTabTitle, AppModel.historyTabTitle, AppModel.registryTabTitle, AppModel.auditTabTitle,
            AppModel.yubiKeyTabTitle,
        ]
        #expect(titles == ["Sign", "History", "Registry", "Audit", "YubiKey"])
        #expect(AppTab.allCases.map(\.title) == titles)
    }

    @Test("the window opens on the Sign tab")
    func defaultTab() {
        let app = AppModel(bridge: FakeBridge())
        #expect(app.selectedTab == .sign)
        #expect(app.findRequests == 0)
    }

    @Test("Find… selects the History tab from any tab and bumps the find counter each time")
    func requestFind() {
        let app = AppModel(bridge: FakeBridge())
        app.selectedTab = .registry
        app.requestFind()
        #expect(app.selectedTab == .history)
        #expect(app.findRequests == 1)
        app.requestFind()
        #expect(app.selectedTab == .history)
        #expect(app.findRequests == 2)
    }

    @Test("Save QR Code: a signed result, and no signing under way")
    func canSaveQR() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        #expect(!app.canSaveQR)
        fake.respond(.signSign, signResult())
        await app.sign.sign()
        #expect(app.canSaveQR)
        app.bulk.begin()
        #expect(!app.canSaveQR)
        app.bulk.pickerCancelled()
        #expect(app.canSaveQR)
    }

    @Test("View → Refresh follows the visible tab: its title, whether it can run, and what it runs")
    func refreshFollowsTab() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        for tab in [AppTab.sign, .yubiKey] {
            app.selectedTab = tab
            #expect(app.refreshTitle == AppModel.refreshMenuTitle)
            #expect(!app.canRefresh)
            await app.refresh()
        }
        #expect(fake.count(.historyRefresh) == 0)
        #expect(fake.count(.registryFetch) == 0)
        #expect(fake.count(.auditCommits) == 1)

        app.selectedTab = .history
        #expect(app.refreshTitle == HistoryModel.refreshTitle)
        #expect(app.canRefresh)
        await app.refresh()
        #expect(fake.count(.historyRefresh) == 1)

        app.selectedTab = .audit
        #expect(app.refreshTitle == AuditModel.refreshTitle)
        fake.reset(.auditCommits)
        let auditHeld = fake.hold(.auditCommits)
        #expect(app.canRefresh)
        let auditRefresh = Task { await app.refresh() }
        #expect(await settle { fake.count(.auditCommits) == 2 })
        #expect(!app.canRefresh)
        await app.refresh()
        #expect(fake.count(.auditCommits) == 2)
        auditHeld.release(startupAudit)
        await auditRefresh.value
        #expect(app.canRefresh)

        app.selectedTab = .registry
        #expect(app.refreshTitle == RegistryModel.fetchTitle)
        let fetchHeld = fake.hold(.registryFetch)
        #expect(app.canRefresh)
        let fetch = Task { await app.refresh() }
        #expect(await settle { fake.count(.registryFetch) == 1 })
        #expect(!app.canRefresh)
        await app.refresh()
        #expect(fake.count(.registryFetch) == 1)
        fetchHeld.release(Empty())
        await fetch.value
        // Fetch from Server stays busy until its registry.changed.
        #expect(!app.canRefresh)
        await app.registry.registryChanged()
        #expect(app.canRefresh)
    }

    @Test("the titles of the alerts the view words")
    func alertTitles() {
        #expect(AppModel.fatalErrorTitle == "RHG Authenticator Can't Start")
        #expect(AppModel.internalErrorTitle == "Something Went Wrong")
    }

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
        #expect(app.statusItems == ["Core keys: three", "Core expired: one", "Core version 1.2.3"])
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

    @Test("startup offline: the core's offline status items; no data dir sends {}")
    func startOffline() async {
        let fake = FakeBridge()
        fake.respond(
            .appInit,
            AppInfo(
                activeKeys: 0, online: false, recentlyExpired: 0, version: "2.0",
                statusItems: ["Core offline", "Core version 2.0"]))
        fake.respond(.signHonors, HonorsResult(honors: []))
        scriptStartupReads(fake, snapshot: registrySnapshot(count: 0, loaded: false))
        let app = AppModel(bridge: fake)
        await app.start()
        #expect(app.phase == .ready)
        #expect(app.statusItems == ["Core offline", "Core version 2.0"])
        #expect(app.registry.status == RegistryModel.fetchingStatus)
        #expect(fake.params(.appInit) == ["{}"])
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
        #expect(app.audit.isRefreshing && app.audit.status == AuditModel.fetchingStatus)
        held.release(AuditResult(rows: [AuditRow(summary: "c", url: commit)], status: "Loaded 1 commits"))
        #expect(await settle { !app.audit.isRefreshing })
        #expect(app.audit.rows == [AuditRow(summary: "c", url: commit)])
        #expect(app.audit.status == "Loaded 1 commits")
        app.audit.select(row: 0)
        app.audit.openSelected()
        #expect(urls.opened == [try #require(URL(string: commit))])
    }

    @Test("history.changed clears the selection before its re-read lands, then applies it")
    func historyChangedEvent() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        fake.respond(.historyRecordText, RecordTextResult(detail: "d", revokeConfirm: "q", deleteConfirm: "dq", offerRevoke: true))
        app.history.select(row: 1)
        await app.history.pendingDetail?.value
        #expect(app.history.selection == 1 && app.history.selectedDetail == "d")
        fake.reset(.historyList)
        let held = fake.hold(.historyList)
        fake.emit(.historyChanged)
        #expect(await settle { fake.count(.historyList) == 2 })
        #expect(app.history.selection == nil && app.history.selectedDetail == nil)
        held.release(historyList(count: 3))
        #expect(await settle { app.history.snapshot == historyList(count: 3) })
        #expect(app.history.selection == nil)
    }

    @Test("history.revocationsChanged re-reads the log keeping the selection")
    func revocationsChangedEvent() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        fake.respond(.historyRecordText, RecordTextResult(detail: "d", revokeConfirm: "q", deleteConfirm: "dq", offerRevoke: true))
        app.history.select(row: 1)
        await app.history.pendingDetail?.value
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
        #expect(!app.login.hasUsableSession)
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(count: 2, revokeAvailable: false))
        fake.reset(.authState)
        fake.respond(.authState, loggedIn)
        fake.emit(.authChanged(loggedIn))
        // Two tasks, the login's re-read and the history's: wait for both.
        #expect(await settle { app.history.snapshot.revokeAvailable == false && app.login.authState == loggedIn })
        #expect(app.login.hasUsableSession)
        #expect(fake.count(.historyList) == 2)
    }

    @Test("the app's one login puts its status texts on the History tab too")
    func loginStatusSink() async {
        let fake = FakeBridge()
        let held = fake.hold(.authLogin)
        let app = await startedApp(fake)
        let login = Task { await app.login.start() }
        // One LoginModel serves both tabs (LoginModelTests covers the routing).
        #expect(await settle { app.history.status == LoginModel.requestingCodeStatus })
        held.release(loggedIn)
        await login.value
        #expect(app.history.status == "Logged in as @octocat")
    }

    @Test("after a confirmed delete, the core's history.changed selects the row in its place and shows its detail")
    func deleteThenHistoryChanged() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        let history = app.history
        fake.respond(
            .historyRecordText,
            RecordTextResult(detail: "Detail of record 1", revokeConfirm: "q", deleteConfirm: "dq", offerRevoke: true))
        history.select(row: 0)
        await history.pendingDetail?.value
        fake.respond(.historyDeleteEntry, DeleteEntryResult(backup: "/b", title: "Deleted", message: "Gone."))
        await history.deleteTapped()
        await history.confirm()
        #expect(fake.count(.historyDeleteEntry) == 1)
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(records: [2]))
        fake.reset(.historyRecordText)
        fake.respond(
            .historyRecordText,
            RecordTextResult(detail: "Detail of record 2", revokeConfirm: "q", deleteConfirm: "dq", offerRevoke: true))
        fake.emit(.historyChanged)
        #expect(await settle { history.selection == 0 && history.selectedDetail == "Detail of record 2" })
        #expect(history.snapshot == historyList(records: [2]))
    }

    @Test("auth and registry events reach the login and the Registry tab")
    func authAndRegistryEvents() async {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        app.registry.select(row: 0)
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

    @Test("update events are stored and the banner follows them: none, then each latest status and notice; other events are ignored")
    func updateBanners() async throws {
        let fake = FakeBridge()
        let app = await startedApp(fake)
        #expect(app.updateBanner == nil)
        #expect(app.updatedBanner == nil)
        let url = "https://github.com/o/r/releases/tag/v1.3.0"
        let ready = UpdateStatus(state: .ready, version: "1.3.0", releaseUrl: url, moveToApplications: false)
        let notice = UpdatedNotice(version: "1.2.3", releaseUrl: "")
        fake.emit(.bulkConnecting)
        fake.emit(.unknown("future.event"))
        fake.emit(.updateStatus(ready))
        fake.emit(.updateUpdated(notice))
        #expect(await settle { app.updatedBanner != nil })
        #expect(app.updateStatus == ready)
        #expect(app.updatedNotice == notice)
        #expect(app.phase == .ready)
        #expect(app.internalErrorMessage == nil)
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

    @Test("error log export: the core's alert, as given")
    func errorLogExport() async {
        let fake = FakeBridge()
        fake.respond(.appExportErrorLog, ExportResult(title: "Core Export Title", message: "Core says: saved it."))
        let app = AppModel(bridge: fake)
        let alert = await app.exportErrorLog(path: "/out/rhg-error-log-2026-01-01.log")
        #expect(fake.params(.appExportErrorLog) == [#"{"path":"/out/rhg-error-log-2026-01-01.log"}"#])
        #expect(alert == AlertState(title: "Core Export Title", message: "Core says: saved it."))
    }

    @Test("error log export failure shows the core's message")
    func errorLogExportFailure() async {
        let fake = FakeBridge()
        fake.fail(.appExportErrorLog, RPCError(code: .failed, message: "Choose a folder outside the app's data folder."))
        let app = AppModel(bridge: fake)
        let alert = await app.exportErrorLog(path: "/data/x.log")
        #expect(alert == AlertState(title: "Unable to Export Error Log", message: "Choose a folder outside the app's data folder."))
    }

    // MARK: Quit

    @Test("quit: canQuit, then shutdown, relaunching only after Restart Now", arguments: [false, true])
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

    @Test("Restart Now pressed while a plain quit checks for edits: that quit relaunches")
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

    @Test("Restart Now declined, then a plain quit: shutdown once, without relaunch")
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

    @Test("quit confirmation copy")
    func quitCopy() {
        #expect(
            AppModel.quitConfirmation
                == Confirmation(
                    title: "Unsubmitted Changes",
                    message:
                        "The registry has changes that haven't been submitted for review. If you quit, they'll be lost.",
                    confirmTitle: "Discard and Quit", cancelTitle: "Cancel", isDestructive: true))
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
