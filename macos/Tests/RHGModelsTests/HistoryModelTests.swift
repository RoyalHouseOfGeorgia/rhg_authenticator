import Foundation
import RHGBridge
import Testing

@testable import RHGModels

@Suite("HistoryModel")
@MainActor
struct HistoryModelTests {
    let recordText = RecordTextResult(
        detail: "Timestamp: 2026-01-02T03:04:05Z\nRecipient: Recipient 2",
        revokeConfirm: "Revoke credential for Recipient 2 dated 2026-Jan-02?\n\nThis cannot be undone.",
        deleteConfirm: "Core asks: delete the record for Recipient 2?", offerRevoke: true)
    /// The record text of a revoked record: no Revoke Instead.
    let revokedText = RecordTextResult(
        detail: "d", revokeConfirm: "q", deleteConfirm: "Core asks: delete the revoked record?", offerRevoke: false)
    let deleted = DeleteEntryResult(
        backup: "/DATA/issuances.json.bak-20260102T030405Z", title: "Core Deleted Title", message: "Core says: deleted.")

    /// The delete question asking `message`, offering Revoke Instead or not.
    func deleteQuestion(_ message: String, offerRevoke: Bool) -> RHGModels.Confirmation {
        Confirmation(
            title: "Delete Issuance Record", message: message, confirmTitle: "Delete", cancelTitle: "Cancel",
            alternateTitle: offerRevoke ? "Revoke Instead" : nil, isDestructive: true)
    }

    /// The revoke question for `recordText`.
    var revokeQuestion: RHGModels.Confirmation {
        Confirmation(
            title: "Confirm Revocation", message: recordText.revokeConfirm, confirmTitle: "Revoke", cancelTitle: "Cancel",
            isDestructive: true)
    }

    /// The canonical params of a call about `record`.
    func recordParams(_ record: HistoryRecord) throws -> String {
        String(decoding: try CanonicalJSON.encode(RecordParams(record: record)), as: UTF8.self)
    }

    /// A model loaded with `list`, its login in `auth`.
    func loaded(
        _ fake: FakeBridge, list: HistoryListResult = historyList(count: 3), auth: AuthState = loggedIn,
        debounce: Duration = .zero
    ) async throws -> HistoryModel {
        fake.respond(.historyList, list)
        let login = LoginModel(bridge: fake)
        await setAuth(login, auth, fake)
        let history = HistoryModel(bridge: fake, login: login, debounce: debounce)
        await history.reread()
        // Later reads answer from each test's own script.
        fake.reset(.historyList)
        return history
    }

    /// `history` with `row` selected (its record alert dismissed).
    func selecting(_ row: Int, in history: HistoryModel, _ fake: FakeBridge) async {
        fake.respond(.historyRecordText, recordText)
        await history.select(row: row)
        await history.alertDismissed()
    }

    @Test("UI copy matches the Fyne app")
    func copy() {
        #expect(HistoryModel.searchPlaceholder == "Search by recipient...")
        #expect(
            [HistoryModel.refreshTitle, HistoryModel.connectTitle, HistoryModel.revokeTitle]
                == ["Refresh", "Connect to GitHub", "Revoke"])
        #expect(HistoryModel.exportTitle == "Export Issuance Log…")
        #expect(HistoryModel.removeDuplicatesTitle == "Remove Duplicates…")
        #expect(HistoryModel.revocationUnavailableStatus == "Revocation unavailable")
        #expect(HistoryModel.deleteTitle == "Delete Entry…")
        #expect(HistoryModel.deleteTooltip == "Select a record to delete it.")
        #expect(
            [HistoryModel.deleteQuestionTitle, HistoryModel.deleteConfirmTitle, HistoryModel.revokeInsteadTitle]
                == ["Delete Issuance Record", "Delete", "Revoke Instead"])
        #expect([HistoryModel.deleteNotFoundTitle, HistoryModel.deleteFailedTitle] == ["Record Not Found", "Delete Failed"])
    }

    // MARK: Reads

    @Test("before load: no rows, nothing selected, nothing to revoke")
    func initial() {
        let history = HistoryModel(bridge: FakeBridge(), login: LoginModel(bridge: FakeBridge()))
        #expect(history.snapshot.rows.isEmpty && !history.snapshot.revokeAvailable)
        #expect(history.query == "" && history.selection == nil && !history.isRevoking && !history.isDeleting)
        #expect(history.alert == nil && history.pendingConfirmation == nil)
        #expect(!history.canRevoke && !history.canDelete)
        // The default clock is now.
        #expect(history.suggestedExportFilename.hasPrefix("rhg-issuances-20"))
    }

    @Test("the first read is for the empty query")
    func load() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        #expect(history.snapshot == historyList(count: 3))
        #expect(fake.params(.historyList) == [#"{"query":""}"#])
        #expect(history.selection == nil && history.alert == nil)
        #expect(history.revocationStatus == "")
    }

    @Test("history.changed clears the selection and applies the re-read log")
    func historyChanged() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        #expect(history.selection == 1)
        fake.respond(.historyList, historyList(count: 4))
        history.historyChanged()
        await history.reread()
        #expect(history.selection == nil)
        #expect(history.snapshot == historyList(count: 4))
        #expect(history.alert == nil)
    }

    @Test("history.changed with a log that failed to load: unable to load history")
    func historyChangedLoadFailed() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        fake.respond(.historyList, historyList(count: 0, loadFailed: true))
        history.historyChanged()
        await history.reread()
        #expect(history.alert == AlertState(title: "Error", message: "unable to load history"))
        await history.alertDismissed()
        #expect(history.alert == nil)
    }

    @Test("revocations and auth changes re-read the log, keeping the selection")
    func keepSelection() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(2, in: history, fake)
        fake.respond(.historyList, historyList(count: 3, revoked: [3]))
        await history.reread()
        #expect(history.snapshot == historyList(count: 3, revoked: [3]))
        #expect(history.selection == 2)
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(count: 3, revokeAvailable: false))
        await history.reread()
        #expect(history.snapshot == historyList(count: 3, revokeAvailable: false))
        #expect(history.selection == 2)
    }

    @Test("a read with fewer rows than the selected index clears the selection")
    func selectionOutOfRange() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(2, in: history, fake)
        fake.respond(.historyList, historyList(count: 2))
        await history.reread()
        #expect(history.selection == nil)
    }

    @Test("a failed read keeps the rows; the next read applied still replaces them and reports a failed load")
    func readFailure() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        fake.fail(.historyList, RPCError(code: .internal, message: "x"))
        history.historyChanged()
        await history.reread()
        #expect(history.snapshot == historyList(count: 3))
        #expect(history.alert == nil)
        await selecting(1, in: history, fake)
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(count: 3, loadFailed: true))
        await history.reread()
        #expect(history.selection == nil)
        #expect(history.alert == AlertState(title: "Error", message: "unable to load history"))
    }

    @Test("an older read finishing last is dropped, its load failure included")
    func staleRead() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        let first = fake.hold(.historyList)
        fake.respond(.historyList, historyList(count: 4))
        history.historyChanged()
        let older = Task { await history.reread() }
        #expect(await settle { fake.count(.historyList) == 2 })
        await history.reread()
        #expect(history.snapshot == historyList(count: 4))
        first.release(historyList(count: 0, loadFailed: true))
        await older.value
        #expect(history.snapshot == historyList(count: 4))
        #expect(history.alert == nil)
    }

    @Test("a load failure landing under another alert waits until that alert is closed")
    func loadFailureUnderAlert() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        fake.respond(.historyRecordText, recordText)
        await history.select(row: 1)
        let recordAlert = AlertState(title: "Issuance Record", message: recordText.detail)
        #expect(history.alert == recordAlert)
        fake.respond(.historyList, historyList(count: 0, loadFailed: true))
        history.historyChanged()
        await history.reread()
        #expect(history.alert == recordAlert)
        await history.alertDismissed()
        await history.reread()
        #expect(history.alert == AlertState(title: "Error", message: "unable to load history"))
    }

    @Test("history.changed overtaken by a newer read: the newer read reports the load failure")
    func loadFailureOnNewerRead() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        let first = fake.hold(.historyList)
        fake.respond(.historyList, historyList(count: 0, loadFailed: true))
        history.historyChanged()
        let older = Task { await history.reread() }
        #expect(await settle { fake.count(.historyList) == 2 })
        await history.reread()
        #expect(history.alert == AlertState(title: "Error", message: "unable to load history"))
        first.release(historyList(count: 3))
        await older.value
        #expect(history.snapshot == historyList(count: 0, loadFailed: true))
    }

    @Test("a row picked from the old rows while history.changed re-reads is not carried onto the new ones")
    func selectDuringReplacingRead() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        let held = fake.hold(.historyList)
        history.historyChanged()
        let read = Task { await history.reread() }
        #expect(await settle { fake.count(.historyList) == 2 })
        await selecting(1, in: history, fake)
        held.release(historyList(count: 3))
        await read.value
        #expect(history.selection == nil)
    }

    @Test("Revocation unavailable shows while the revocation list could not be fetched")
    func revocationStatus() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake, list: historyList(count: 1, revocationsUnavailable: true, revokeAvailable: false))
        #expect(history.revocationStatus == "Revocation unavailable")
        fake.respond(.historyList, historyList(count: 1))
        await history.reread()
        #expect(history.revocationStatus == "")
    }

    // MARK: Search

    @Test("typing re-reads once it pauses, sending only the latest query, with the selection reset")
    func debounce() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake, debounce: .milliseconds(50))
        await selecting(0, in: history, fake)
        fake.respond(.historyList, historyList(count: 1))
        history.setQuery("R")
        history.setQuery("Re")
        #expect(history.query == "Re")
        #expect(await settle { history.snapshot == historyList(count: 1) })
        #expect(history.selection == nil)
        #expect(fake.params(.historyList) == [#"{"query":""}"#, #"{"query":"Re"}"#])
    }

    @Test("an unchanged query neither searches nor clears the selection")
    func sameQuery() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        history.setQuery("")
        #expect(history.selection == 1)
        // A search task, had one started, would run in this yield.
        await Task.yield()
        #expect(fake.count(.historyList) == 1)
    }

    @Test("a newer query supersedes a read in flight for the older one")
    func supersededResult() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake, debounce: .seconds(60))
        let first = fake.hold(.historyList)
        fake.respond(.historyList, historyList(count: 1))
        history.setQuery("R")
        let older = Task { await history.reread() }
        #expect(await settle { fake.count(.historyList) == 2 })
        history.setQuery("Re")
        await history.reread()
        #expect(history.snapshot == historyList(count: 1))
        first.release(historyList(count: 2))
        await older.value
        #expect(history.snapshot == historyList(count: 1))
        #expect(fake.params(.historyList).suffix(2) == [#"{"query":"R"}"#, #"{"query":"Re"}"#])
    }

    @Test("a read sent before the search changed is dropped, so a row picked meanwhile is not carried onto the new rows")
    func readSentBeforeQueryChange() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake, debounce: .seconds(60))
        let held = fake.hold(.historyList)
        fake.respond(.historyList, historyList(count: 3, revoked: [1]))
        let stale = Task { await history.reread() }
        #expect(await settle { fake.count(.historyList) == 2 })
        history.setQuery("R")
        held.release(historyList(count: 2))
        await stale.value
        #expect(history.snapshot == historyList(count: 3))
        await selecting(1, in: history, fake)
        // The search's own read lands.
        await history.reread()
        #expect(history.snapshot == historyList(count: 3, revoked: [1]))
        #expect(history.selection == nil)
    }

    @Test("a read for a new query before its search runs clears the selection")
    func readForNewQuery() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake, debounce: .seconds(60))
        await selecting(1, in: history, fake)
        fake.respond(.historyList, historyList(count: 3))
        history.setQuery("Recipient")
        await history.reread()
        // The search itself still waits: a search task that did not would run
        // in this yield and send a third read.
        await Task.yield()
        #expect(fake.count(.historyList) == 2)
        #expect(fake.params(.historyList).last == #"{"query":"Recipient"}"#)
        #expect(history.selection == nil)
    }

    // MARK: Selection

    @Test("selecting a row shows its record; out of range is ignored")
    func select() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        fake.respond(.historyRecordText, recordText)
        await history.select(row: 1)
        #expect(history.selection == 1)
        #expect(history.alert == AlertState(title: "Issuance Record", message: recordText.detail))
        let params = try #require(fake.params(.historyRecordText).first)
        #expect(params.contains(#""payloadSha256":"\#(historyRecord(2).payloadSha256)""#))
        await history.select(row: 3)
        await history.select(row: -1)
        #expect(history.selection == 1)
        #expect(fake.count(.historyRecordText) == 1)
    }

    @Test("a record text failure shows the core's error")
    func selectFailure() async throws {
        let fake = FakeBridge()
        fake.fail(.historyRecordText, RPCError(code: .failed, message: "no such record"))
        let history = try await loaded(fake)
        await history.select(row: 0)
        #expect(history.selection == 0)
        #expect(history.alert == AlertState(title: "Error", message: "no such record"))
    }

    @Test("duplicate rows sharing a hash are selected by index")
    func duplicateRows() async throws {
        let fake = FakeBridge()
        let row = historyRow(2)
        let list = HistoryListResult(
            rows: [row, row], loadFailed: false, revocationsUnavailable: false, revocationsLoaded: true, revokeAvailable: true)
        let history = try await loaded(fake, list: list)
        await selecting(1, in: history, fake)
        #expect(history.selection == 1)
        #expect(history.canRevoke)
    }

    // MARK: Gates

    @Test("Connect to GitHub shows logged out or offline")
    func connectButton() async throws {
        #expect(try await loaded(FakeBridge(), auth: loggedOut).showsConnectButton)
        #expect(try await loaded(FakeBridge(), auth: loggedInOffline).showsConnectButton)
        #expect(try await loaded(FakeBridge(), auth: loggedIn).showsConnectButton == false)
    }

    @Test("Revoke needs a selected, unrevoked row and the core's go-ahead")
    func canRevoke() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake, list: historyList(count: 2, revoked: [2]))
        #expect(!history.canRevoke)
        await selecting(0, in: history, fake)
        #expect(history.canRevoke)
        await selecting(1, in: history, fake)
        #expect(!history.canRevoke)
        let unavailable = try await loaded(fake, list: historyList(count: 2, revokeAvailable: false))
        await selecting(0, in: unavailable, fake)
        #expect(!unavailable.canRevoke)
    }

    @Test("Connect to GitHub starts the login")
    func connect() async throws {
        let fake = FakeBridge()
        fake.respond(.authLogin, loggedIn)
        let history = try await loaded(fake, auth: loggedOut)
        await history.connectTapped()
        #expect(fake.count(.authLogin) == 1)
    }

    // MARK: Refresh

    @Test("Refresh asks the core; the results arrive as events")
    func refresh() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await history.refreshTapped()
        #expect(fake.params(.historyRefresh) == ["{}"])
        #expect(history.alert == nil)
        #expect(fake.count(.historyList) == 1)
    }

    @Test("a failed Refresh shows the core's error")
    func refreshFailure() async throws {
        let fake = FakeBridge()
        fake.fail(.historyRefresh, RPCError(code: .internal, message: "x"))
        let history = try await loaded(fake)
        await history.refreshTapped()
        #expect(history.alert == AlertState(title: "Error", message: "x"))
    }

    // MARK: Revoke

    @Test("Revoke asks the core's question, revokes the row's hash, re-reads with the selection reset and shows the outcome")
    func revoke() async throws {
        let outcome = RevokeResult(
            status: .submitted, prNumber: 43, url: "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/pull/43",
            title: "Revocation Submitted",
            message: "Pull request #43 created:\nhttps://github.com/RoyalHouseOfGeorgia/rhg_authenticator/pull/43")
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        await history.revokeTapped()
        #expect(
            history.pendingConfirmation
                == Confirmation(
                    title: "Confirm Revocation", message: recordText.revokeConfirm, confirmTitle: "Revoke",
                    cancelTitle: "Cancel", isDestructive: true))
        #expect(fake.count(.historyRevoke) == 0)
        fake.respond(.historyRevoke, outcome)
        fake.respond(.historyList, historyList(count: 3, revoked: [2]))
        await history.confirm()
        #expect(history.pendingConfirmation == nil)
        #expect(fake.params(.historyRevoke) == [#"{"payloadSha256":"\#(historyRecord(2).payloadSha256)"}"#])
        #expect(history.snapshot == historyList(count: 3, revoked: [2]))
        #expect(history.selection == nil)
        #expect(!history.isRevoking)
        #expect(history.alert == AlertState(title: outcome.title, message: outcome.message))
        await history.alertDismissed()
        #expect(fake.count(.authLogin) == 0)
    }

    @Test("Revoke while it cannot revoke calls nothing")
    func revokeGated() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await history.revokeTapped()
        #expect(history.pendingConfirmation == nil)
        #expect(fake.count(.historyRecordText) == 0)
    }

    @Test("a record text failure on Revoke shows the error and asks nothing")
    func revokeTextFailure() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(0, in: history, fake)
        fake.reset(.historyRecordText)
        fake.fail(.historyRecordText, RPCError(code: .failed, message: "bad record"))
        await history.revokeTapped()
        #expect(history.pendingConfirmation == nil)
        #expect(history.alert == AlertState(title: "Error", message: "bad record"))
    }

    @Test("Revoke declined: nothing is revoked")
    func revokeDeclined() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(0, in: history, fake)
        await history.revokeTapped()
        history.dismissConfirmation()
        #expect(history.pendingConfirmation == nil)
        await history.confirm()
        #expect(fake.count(.historyRevoke) == 0)
    }

    @Test("Revoke stays disabled while a revocation is being submitted")
    func revoking() async throws {
        let fake = FakeBridge()
        let held = fake.hold(.historyRevoke)
        let history = try await loaded(fake)
        await selecting(0, in: history, fake)
        await history.revokeTapped()
        let confirm = Task { await history.confirm() }
        #expect(await settle { fake.count(.historyRevoke) == 1 })
        #expect(history.isRevoking && !history.canRevoke)
        await history.revokeTapped()
        #expect(fake.count(.historyRecordText) == 2)
        held.release(failing: RPCError(code: .failed, message: "x"))
        await confirm.value
        #expect(!history.isRevoking && history.canRevoke)
    }

    @Test("busy: nothing shows; the running revocation reports itself")
    func revokeBusy() async throws {
        let fake = FakeBridge()
        fake.fail(.historyRevoke, RPCError(code: .busy, message: "Another operation is in progress."))
        let history = try await loaded(fake)
        await selecting(0, in: history, fake)
        await history.revokeTapped()
        await history.confirm()
        #expect(history.alert == nil && !history.isRevoking)
        #expect(history.selection == 0)
        #expect(fake.count(.authLogin) == 0)
    }

    @Test("not logged in: Revoke starts the login")
    func revokeNotLoggedIn() async throws {
        let fake = FakeBridge()
        fake.fail(.historyRevoke, RPCError(code: .notLoggedIn, message: "Not logged in to GitHub."))
        fake.respond(.authLogin, loggedIn)
        let history = try await loaded(fake)
        await selecting(0, in: history, fake)
        await history.revokeTapped()
        await history.confirm()
        #expect(fake.methods.suffix(2) == ["history.revoke", "auth.login"])
        #expect(history.alert == nil && !history.isRevoking)
    }

    @Test("session expired: the alert, then the login only once it is dismissed")
    func revokeSessionExpired() async throws {
        let fake = FakeBridge()
        let message = "Your GitHub session expired. Please log in again."
        fake.fail(.historyRevoke, RPCError(code: .sessionExpired, message: message))
        fake.respond(.authLogin, loggedIn)
        let history = try await loaded(fake)
        await selecting(0, in: history, fake)
        await history.revokeTapped()
        await history.confirm()
        #expect(history.alert == AlertState(title: "Session Expired", message: message))
        #expect(fake.count(.authLogin) == 0)
        await history.alertDismissed()
        #expect(history.alert == nil)
        #expect(fake.count(.authLogin) == 1)
        await history.alertDismissed()
        #expect(fake.count(.authLogin) == 1)
    }

    @Test(
        "any other failure: Revocation Failed offering the error log",
        arguments: [RPCErrorCode.failed, .internal, .input, .unknown("future")])
    func revokeFailed(_ code: RPCErrorCode) async throws {
        let fake = FakeBridge()
        fake.fail(.historyRevoke, RPCError(code: code, message: "GitHub returned an error."))
        let history = try await loaded(fake)
        await selecting(0, in: history, fake)
        await history.revokeTapped()
        await history.confirm()
        #expect(
            history.alert
                == AlertState(title: "Revocation Failed", message: "GitHub returned an error.", offersErrorLogExport: true))
        #expect(!history.isRevoking && history.selection == 0)
        await history.alertDismissed()
        #expect(fake.count(.authLogin) == 0)
    }

    // MARK: Export

    @Test(
        "the export name is today's date in the machine's time zone",
        arguments: [("UTC", "rhg-issuances-2026-01-01.json"), ("Asia/Tbilisi", "rhg-issuances-2026-01-02.json"),
            ("America/Los_Angeles", "rhg-issuances-2026-01-01.json")])
    func exportFilename(_ zone: String, _ name: String) throws {
        let history = HistoryModel(
            bridge: FakeBridge(), login: LoginModel(bridge: FakeBridge()), clock: { lateNewYearsDay },
            timeZone: try #require(TimeZone(identifier: zone)))
        #expect(history.suggestedExportFilename == name)
    }

    @Test("export: the core's alert, as given")
    func export() async throws {
        let fake = FakeBridge()
        fake.respond(.historyExportIssuanceLog, ExportResult(title: "Core Log Title", message: "Core says: copied."))
        let history = try await loaded(fake)
        await history.exportIssuanceLog(path: "/out/rhg-issuances-2026-01-01.json")
        #expect(fake.params(.historyExportIssuanceLog) == [#"{"path":"/out/rhg-issuances-2026-01-01.json"}"#])
        #expect(history.alert == AlertState(title: "Core Log Title", message: "Core says: copied."))
    }

    @Test("export with nothing signed: Nothing to Export with the core's message")
    func exportNothing() async throws {
        let fake = FakeBridge()
        let message = "No credentials have been signed on this computer yet."
        fake.fail(.historyExportIssuanceLog, RPCError(code: .nothingToExport, message: message))
        let history = try await loaded(fake)
        await history.exportIssuanceLog(path: "/out/x.json")
        #expect(history.alert == AlertState(title: "Nothing to Export", message: message))
    }

    @Test("any other export failure shows the core's error")
    func exportFailure() async throws {
        let fake = FakeBridge()
        fake.fail(.historyExportIssuanceLog, RPCError(code: .failed, message: "Choose a folder outside the app's data folder."))
        let history = try await loaded(fake)
        await history.exportIssuanceLog(path: "/data/x.json")
        #expect(history.alert == AlertState(title: "Error", message: "Choose a folder outside the app's data folder."))
    }

    // MARK: Remove Duplicates

    @Test("a failed preview: Remove Duplicates Failed offering the error log")
    func dedupePreviewFailure() async throws {
        let fake = FakeBridge()
        fake.fail(.historyDuplicatePreview, RPCError(code: .failed, message: "unreadable log"))
        let history = try await loaded(fake)
        await history.removeDuplicatesTapped()
        #expect(
            history.alert == AlertState(title: "Remove Duplicates Failed", message: "unreadable log", offersErrorLogExport: true))
        #expect(history.pendingConfirmation == nil)
    }

    @Test("no duplicates: No Duplicates, nothing asked")
    func dedupeNone() async throws {
        let fake = FakeBridge()
        fake.respond(.historyDuplicatePreview, DuplicatePreviewResult(count: 0, confirmMessage: ""))
        let history = try await loaded(fake)
        await history.removeDuplicatesTapped()
        #expect(history.alert == AlertState(title: "No Duplicates", message: "The issuance log has no duplicate entries."))
        #expect(history.pendingConfirmation == nil)
        #expect(fake.count(.historyRemoveDuplicates) == 0)
    }

    @Test("duplicates found: the core's question, then its report; the list waits for history.changed")
    func dedupeConfirmed() async throws {
        let fake = FakeBridge()
        fake.respond(.historyDuplicatePreview, DuplicatePreviewResult(count: 2, confirmMessage: "Core asks: remove two?"))
        fake.respond(
            .historyRemoveDuplicates,
            RemoveDuplicatesResult(removed: 2, backup: "/DATA/issuances.json.bak", message: "Core says: two gone."))
        let history = try await loaded(fake)
        await history.removeDuplicatesTapped()
        #expect(
            history.pendingConfirmation
                == Confirmation(
                    title: "Remove Duplicates", message: "Core asks: remove two?",
                    confirmTitle: "Remove Entries", cancelTitle: "Cancel", isDestructive: true))
        #expect(fake.count(.historyRemoveDuplicates) == 0)
        await history.confirm()
        #expect(fake.params(.historyRemoveDuplicates) == ["{}"])
        #expect(history.alert == AlertState(title: "Duplicates Removed", message: "Core says: two gone."))
        #expect(fake.count(.historyList) == 1)
    }

    @Test("duplicates found, declined: nothing is removed")
    func dedupeDeclined() async throws {
        let fake = FakeBridge()
        fake.respond(.historyDuplicatePreview, DuplicatePreviewResult(count: 1, confirmMessage: "Core asks: remove one?"))
        let history = try await loaded(fake)
        await history.removeDuplicatesTapped()
        history.dismissConfirmation()
        await history.confirm()
        #expect(fake.count(.historyRemoveDuplicates) == 0)
        #expect(history.alert == nil)
    }

    @Test("the log changed after the preview: removed 0 is No Duplicates")
    func dedupeRemovedNone() async throws {
        let fake = FakeBridge()
        fake.respond(.historyDuplicatePreview, DuplicatePreviewResult(count: 1, confirmMessage: "Core asks: remove one?"))
        fake.respond(.historyRemoveDuplicates, RemoveDuplicatesResult(removed: 0, backup: "", message: ""))
        let history = try await loaded(fake)
        await history.removeDuplicatesTapped()
        await history.confirm()
        #expect(history.alert == AlertState(title: "No Duplicates", message: "The issuance log has no duplicate entries."))
    }

    @Test("a failed removal: Remove Duplicates Failed offering the error log")
    func dedupeRemoveFailure() async throws {
        let fake = FakeBridge()
        fake.respond(.historyDuplicatePreview, DuplicatePreviewResult(count: 1, confirmMessage: "Core asks: remove one?"))
        fake.fail(.historyRemoveDuplicates, RPCError(code: .failed, message: "backup failed"))
        let history = try await loaded(fake)
        await history.removeDuplicatesTapped()
        await history.confirm()
        #expect(
            history.alert == AlertState(title: "Remove Duplicates Failed", message: "backup failed", offersErrorLogExport: true))
    }

    // MARK: Delete

    @Test("Delete Entry… needs a selected row in range, revoked or not")
    func canDelete() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake, list: historyList(count: 2, revoked: [2], revokeAvailable: false))
        #expect(!history.canDelete)
        await selecting(0, in: history, fake)
        #expect(history.canDelete)
        await selecting(1, in: history, fake)
        #expect(history.canDelete)
        fake.respond(.historyList, historyList(count: 1))
        history.historyChanged()
        await history.reread()
        #expect(!history.canDelete)
    }

    @Test("Delete Entry… while it cannot delete calls nothing")
    func deleteGated() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await history.deleteTapped()
        #expect(history.pendingConfirmation == nil)
        #expect(fake.count(.historyRecordText) == 0)
    }

    @Test("an unrevoked record: the core's question with Revoke Instead; Delete deletes the record and shows the core's report")
    func deleteConfirmed() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        await history.deleteTapped()
        #expect(fake.params(.historyRecordText).last == (try recordParams(historyRecord(2))))
        #expect(history.pendingConfirmation == deleteQuestion(recordText.deleteConfirm, offerRevoke: true))
        #expect(fake.count(.historyDeleteEntry) == 0)
        fake.respond(.historyDeleteEntry, deleted)
        await history.confirm()
        #expect(history.pendingConfirmation == nil)
        #expect(fake.params(.historyDeleteEntry) == [try recordParams(historyRecord(2))])
        #expect(history.alert == AlertState(title: "Core Deleted Title", message: "Core says: deleted."))
        #expect(!history.isDeleting)
        // The list reloads on the core's history.changed, not here.
        #expect(fake.count(.historyList) == 1)
        #expect(fake.count(.historyRevoke) == 0)
        await history.alternate()
        #expect(fake.count(.historyRecordText) == 2)
    }

    @Test("Revoke Instead asks the revoke question for the same record, and Revoke revokes it")
    func revokeInstead() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        await history.deleteTapped()
        await history.alternate()
        #expect(fake.params(.historyRecordText).suffix(2) == [try recordParams(historyRecord(2)), try recordParams(historyRecord(2))])
        #expect(history.pendingConfirmation == revokeQuestion)
        #expect(fake.count(.historyDeleteEntry) == 0)
        let outcome = RevokeResult(status: .submitted, prNumber: 43, url: "u", title: "Core Revoked", message: "Core says: PR.")
        fake.respond(.historyRevoke, outcome)
        await history.confirm()
        #expect(fake.params(.historyRevoke) == [#"{"payloadSha256":"\#(historyRecord(2).payloadSha256)"}"#])
        #expect(fake.count(.historyDeleteEntry) == 0)
        #expect(history.alert == AlertState(title: "Core Revoked", message: "Core says: PR."))
    }

    @Test("Revoke Instead, then Cancel: nothing is revoked or deleted")
    func revokeInsteadDeclined() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        await history.deleteTapped()
        await history.alternate()
        history.dismissConfirmation()
        #expect(history.pendingConfirmation == nil)
        await history.confirm()
        await history.alternate()
        #expect(fake.count(.historyRevoke) == 0 && fake.count(.historyDeleteEntry) == 0)
    }

    @Test("a record text failure on Revoke Instead shows the error and asks nothing")
    func revokeInsteadTextFailure() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        await history.deleteTapped()
        fake.reset(.historyRecordText)
        fake.fail(.historyRecordText, RPCError(code: .failed, message: "bad record"))
        await history.alternate()
        #expect(history.pendingConfirmation == nil)
        #expect(history.alert == AlertState(title: "Error", message: "bad record"))
    }

    @Test("Delete declined: nothing is deleted, revoked or asked")
    func deleteDeclined() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        await history.deleteTapped()
        history.dismissConfirmation()
        #expect(history.pendingConfirmation == nil)
        await history.confirm()
        await history.alternate()
        #expect(fake.count(.historyDeleteEntry) == 0 && fake.count(.historyRevoke) == 0)
        #expect(fake.count(.historyRecordText) == 2)
        #expect(history.pendingConfirmation == nil && history.alert == nil)
    }

    @Test("a revoked record: the core's question without Revoke Instead")
    func deleteRevoked() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake, list: historyList(count: 2, revoked: [2]))
        await selecting(1, in: history, fake)
        fake.reset(.historyRecordText)
        fake.respond(.historyRecordText, revokedText)
        await history.deleteTapped()
        #expect(history.pendingConfirmation == deleteQuestion(revokedText.deleteConfirm, offerRevoke: false))
        #expect(history.pendingConfirmation?.alternateTitle == nil)
        fake.respond(.historyDeleteEntry, deleted)
        await history.confirm()
        #expect(fake.params(.historyDeleteEntry) == [try recordParams(historyRecord(2))])
        #expect(fake.count(.historyRevoke) == 0)
    }

    @Test("without Revoke Instead, alternate() only closes the question")
    func deleteRevokedAlternate() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake, list: historyList(count: 2, revoked: [2]))
        await selecting(1, in: history, fake)
        fake.reset(.historyRecordText)
        fake.respond(.historyRecordText, revokedText)
        await history.deleteTapped()
        let reads = fake.count(.historyRecordText)
        await history.alternate()
        #expect(history.pendingConfirmation == nil && history.alert == nil)
        // No revoke question was asked: that would read the record text again.
        #expect(fake.count(.historyRecordText) == reads)
        #expect(fake.count(.historyRevoke) == 0 && fake.count(.historyDeleteEntry) == 0)
    }

    @Test("Revoke Instead while logged out: the revocation starts the login")
    func revokeInsteadLoggedOut() async throws {
        let fake = FakeBridge()
        fake.fail(.historyRevoke, RPCError(code: .notLoggedIn, message: "Not logged in to GitHub."))
        fake.respond(.authLogin, loggedIn)
        let history = try await loaded(fake, auth: loggedOut)
        await selecting(1, in: history, fake)
        await history.deleteTapped()
        await history.alternate()
        await history.confirm()
        #expect(fake.methods.suffix(2) == ["history.revoke", "auth.login"])
        #expect(history.alert == nil && !history.isRevoking)
        #expect(fake.count(.historyDeleteEntry) == 0)
    }

    @Test("Revoke Instead before the revocation list loaded: Revocation Failed with the core's message")
    func revokeInsteadRevocationsNotLoaded() async throws {
        let fake = FakeBridge()
        let message = "Core says: the revocation list has not loaded."
        fake.fail(.historyRevoke, RPCError(code: .failed, message: message))
        let history = try await loaded(fake, list: historyList(count: 3, revocationsUnavailable: true, revokeAvailable: false))
        await selecting(1, in: history, fake)
        #expect(!history.canRevoke)
        await history.deleteTapped()
        await history.alternate()
        await history.confirm()
        #expect(history.alert == AlertState(title: "Revocation Failed", message: message, offersErrorLogExport: true))
        #expect(!history.isRevoking)
    }

    @Test("history.changed while the question is pending: Delete still deletes the record asked about")
    func deleteAfterHistoryChanged() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        await history.deleteTapped()
        fake.respond(.historyList, historyList(count: 1))
        history.historyChanged()
        await history.reread()
        #expect(history.selection == nil && history.snapshot == historyList(count: 1))
        #expect(history.pendingConfirmation == deleteQuestion(recordText.deleteConfirm, offerRevoke: true))
        fake.respond(.historyDeleteEntry, deleted)
        await history.confirm()
        #expect(fake.params(.historyDeleteEntry) == [try recordParams(historyRecord(2))])
    }

    @Test("history.changed while the question is pending: Revoke Instead still revokes the record asked about")
    func revokeInsteadAfterHistoryChanged() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        await history.deleteTapped()
        fake.respond(.historyList, historyList(count: 1))
        history.historyChanged()
        await history.reread()
        #expect(history.selection == nil)
        await history.alternate()
        #expect(fake.params(.historyRecordText).last == (try recordParams(historyRecord(2))))
        #expect(history.pendingConfirmation == revokeQuestion)
        await history.confirm()
        #expect(fake.params(.historyRevoke) == [#"{"payloadSha256":"\#(historyRecord(2).payloadSha256)"}"#])
    }

    @Test("not found: Record Not Found with the core's message")
    func deleteNotFound() async throws {
        let fake = FakeBridge()
        let message = "This record is no longer in the issuance log."
        fake.fail(.historyDeleteEntry, RPCError(code: .notFound, message: message))
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        await history.deleteTapped()
        await history.confirm()
        #expect(history.alert == AlertState(title: "Record Not Found", message: message))
        #expect(!history.isDeleting && history.canDelete)
    }

    @Test(
        "any other failure: Delete Failed with the core's message, offering the error log",
        arguments: [RPCErrorCode.failed, .internal, .input, .busy, .unknown("future")])
    func deleteFailed(_ code: RPCErrorCode) async throws {
        let fake = FakeBridge()
        fake.fail(.historyDeleteEntry, RPCError(code: code, message: "Core says: backup failed."))
        let history = try await loaded(fake)
        await selecting(1, in: history, fake)
        await history.deleteTapped()
        await history.confirm()
        #expect(
            history.alert == AlertState(title: "Delete Failed", message: "Core says: backup failed.", offersErrorLogExport: true))
        #expect(!history.isDeleting)
    }

    @Test("a record text failure on Delete Entry… shows the error and asks nothing")
    func deleteTextFailure() async throws {
        let fake = FakeBridge()
        let history = try await loaded(fake)
        await selecting(0, in: history, fake)
        fake.reset(.historyRecordText)
        fake.fail(.historyRecordText, RPCError(code: .failed, message: "bad record"))
        await history.deleteTapped()
        #expect(history.pendingConfirmation == nil)
        #expect(history.alert == AlertState(title: "Error", message: "bad record"))
    }

    @Test("Delete Entry… and Revoke stay disabled while a deletion is being made")
    func deleting() async throws {
        let fake = FakeBridge()
        let held = fake.hold(.historyDeleteEntry)
        let history = try await loaded(fake)
        await selecting(0, in: history, fake)
        await history.deleteTapped()
        let confirm = Task { await history.confirm() }
        #expect(await settle { fake.count(.historyDeleteEntry) == 1 })
        #expect(history.isDeleting && !history.canDelete && !history.canRevoke)
        await history.deleteTapped()
        await history.revokeTapped()
        #expect(fake.count(.historyRecordText) == 2)
        held.release(deleted)
        await confirm.value
        #expect(!history.isDeleting && history.canDelete && history.canRevoke)
    }

    @Test("Delete Entry… stays disabled while a revocation started from Revoke Instead is submitted")
    func revokingDisablesDelete() async throws {
        let fake = FakeBridge()
        let held = fake.hold(.historyRevoke)
        let history = try await loaded(fake)
        await selecting(0, in: history, fake)
        await history.deleteTapped()
        await history.alternate()
        let confirm = Task { await history.confirm() }
        #expect(await settle { fake.count(.historyRevoke) == 1 })
        #expect(history.isRevoking && !history.canDelete && !history.canRevoke)
        await history.deleteTapped()
        #expect(fake.count(.historyRecordText) == 3)
        held.release(failing: RPCError(code: .failed, message: "x"))
        await confirm.value
        #expect(!history.isRevoking && history.canDelete)
    }
}
