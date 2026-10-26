import Foundation
import Observation
import RHGBridge
import Testing

@testable import RHGModels

/// Whether an observed property changed since `watch` started tracking it.
final class ChangeFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    var changed: Bool { lock.withLock { value } }

    func set() {
        lock.withLock { value = true }
    }
}

/// Tracks the observable properties `read` reads; the flag is set on their
/// first change.
@MainActor
func watch(_ read: () -> Void) -> ChangeFlag {
    let flag = ChangeFlag()
    withObservationTracking(read) { flag.set() }
    return flag
}

/// The tests named after a Windows HistoryViewModelTests test port it, with
/// one Mac difference: a failed detail read shows the core's error in the
/// detail pane (`detailFailedPrefix`), never as an alert.
@Suite("HistoryModel")
@MainActor
struct HistoryModelTests {
    let deleted = DeleteEntryResult(
        backup: "/data/issuances.json.bak", title: "Core Deleted Title", message: "Core says: deleted it.")
    let submitted = RevokeResult(
        status: .submitted, prNumber: 12, url: "https://github.com/x/pull/12", title: "Revocation Submitted",
        message: "PR #12 opened.")

    /// The core's texts for `historyRecord(n)`.
    func text(_ n: Int, offerRevoke: Bool = true) -> RecordTextResult {
        RecordTextResult(
            detail: "Detail of record \(n)", revokeConfirm: "Revoke the credential of Recipient \(n)?",
            deleteConfirm: "Delete the record of Recipient \(n)?", offerRevoke: offerRevoke)
    }

    /// The delete question the core's text for record `n` asks.
    func deleteQuestion(_ n: Int, offerRevoke: Bool = true) -> RHGModels.Confirmation {
        Confirmation(
            title: "Delete Issuance Record", message: "Delete the record of Recipient \(n)?", confirmTitle: "Delete",
            cancelTitle: "Cancel", alternateTitle: offerRevoke ? "Revoke Instead" : nil, isDestructive: true)
    }

    /// The revoke question the core's text for record `n` asks.
    func revokeQuestion(_ n: Int) -> RHGModels.Confirmation {
        Confirmation(
            title: "Confirm Revocation", message: "Revoke the credential of Recipient \(n)?", confirmTitle: "Revoke",
            cancelTitle: "Cancel", isDestructive: true)
    }

    /// The canonical params of a call about `historyRecord(n)`.
    func recordParams(_ n: Int) throws -> String {
        String(decoding: try CanonicalJSON.encode(RecordParams(record: historyRecord(n))), as: UTF8.self)
    }

    /// The canonical params of history.revoke for `historyRecord(n)`.
    func revokeParams(_ n: Int) -> String {
        #"{"payloadSha256":"\#(historyRecord(n).payloadSha256)"}"#
    }

    /// A model nothing has been read into, its login in `auth`.
    func model(_ fake: FakeBridge, auth: AuthState = loggedIn, debounce: Duration = .zero) async -> HistoryModel {
        let login = LoginModel(bridge: fake)
        await setAuth(login, auth, fake)
        return HistoryModel(bridge: fake, login: login, debounce: debounce)
    }

    /// history.changed as AppModel handles it: the selection is cleared at
    /// once, then the log re-read.
    func changed(_ history: HistoryModel) async {
        history.historyChanged()
        await history.reread()
    }

    /// history.changed whose re-read runs in a task, returned once its
    /// history.list call is sent (the `count`th).
    func changing(_ history: HistoryModel, _ fake: FakeBridge, count: Int) async -> Task<Void, Never> {
        history.historyChanged()
        let task = Task { await history.reread() }
        #expect(await settle { fake.count(.historyList) == count })
        return task
    }

    /// A model whose first rows (default records 1 to 3) landed through
    /// history.changed; later reads answer from each test's own script.
    func loaded(
        _ fake: FakeBridge, list: HistoryListResult = historyList(records: [1, 2, 3]), auth: AuthState = loggedIn,
        debounce: Duration = .zero
    ) async -> HistoryModel {
        fake.respond(.historyList, list)
        let history = await model(fake, auth: auth, debounce: debounce)
        await changed(history)
        fake.reset(.historyList)
        return history
    }

    /// A loaded model with `row` (holding record `row + 1`) selected and its
    /// detail shown; later record texts answer from each test's own script.
    func selected(
        _ row: Int, _ fake: FakeBridge, list: HistoryListResult = historyList(records: [1, 2, 3]),
        auth: AuthState = loggedIn, debounce: Duration = .zero
    ) async -> HistoryModel {
        let history = await loaded(fake, list: list, auth: auth, debounce: debounce)
        fake.respond(.historyRecordText, text(row + 1))
        history.select(row: row)
        await history.pendingDetail?.value
        fake.reset(.historyRecordText)
        #expect(history.selectedDetail == "Detail of record \(row + 1)")
        return history
    }

    /// A model with `row` of `list` (row n holding record n + 1) deleted; its
    /// history.changed is not raised yet.
    func deletedRow(
        _ row: Int, _ fake: FakeBridge, list: HistoryListResult = historyList(records: [1, 2, 3])
    ) async -> HistoryModel {
        let history = await selected(row, fake, list: list)
        fake.respond(.historyRecordText, text(row + 1))
        fake.respond(.historyDeleteEntry, deleted)
        await history.deleteTapped()
        await history.confirm()
        fake.reset(.historyRecordText)
        #expect(fake.count(.historyDeleteEntry) == 1)
        return history
    }

    @Test("UI copy")
    func copy() {
        #expect(HistoryModel.searchPlaceholder == "Search by recipient")
        #expect([HistoryModel.refreshTitle, HistoryModel.revokeTitle] == ["Refresh", "Revoke"])
        #expect(HistoryModel.exportTitle == "Export Issuance Log…")
        #expect(HistoryModel.removeDuplicatesTitle == "Remove Duplicates…")
        #expect(HistoryModel.deleteTitle == "Delete Entry…")
        #expect(HistoryModel.emptyDetailText == "Select a record to see its details.")
        #expect(HistoryModel.detailFailedPrefix == "Unable to show this record: ")
    }

    @Test("tooltips")
    func tooltips() {
        #expect(HistoryModel.refreshTooltip == "Reread the issuance log and revocations (\u{2318}R)")
        #expect(HistoryModel.searchTooltip == "Filter the list by recipient (\u{2318}F)")
        #expect(HistoryModel.noDuplicatesStatus == "The issuance log has no duplicate entries.")
    }

    @Test("ANewModelIsEmptyAndNotLoaded")
    func aNewModelIsEmptyAndNotLoaded() {
        let fake = FakeBridge()
        let history = HistoryModel(bridge: fake, login: LoginModel(bridge: fake))
        #expect(history.snapshot.rows.isEmpty && !history.snapshot.revocationsLoaded)
        #expect(history.query == "" && history.selection == nil && history.selectedDetail == nil)
        #expect(history.status == "" && history.revocationStatus == "")
        #expect(!history.isRevoking && !history.isDeleting && !history.isAsking)
        #expect(history.pendingDetail == nil && history.alert == nil && history.pendingConfirmation == nil)
        #expect(!history.canRevoke && !history.canDelete)
        #expect(fake.calls.isEmpty)
        // The default clock is now.
        #expect(history.suggestedExportFilename.hasPrefix("rhg-issuances-20"))
    }

    // MARK: Reads

    @Test("HistoryChangedReadsTheLogForTheQuery")
    func historyChangedReadsTheLogForTheQuery() async {
        let fake = FakeBridge()
        let history = await model(fake)
        fake.respond(.historyList, historyList(records: [1, 2]))
        await changed(history)
        #expect(history.snapshot == historyList(records: [1, 2]))
        #expect(fake.params(.historyList) == [#"{"query":""}"#])
        #expect(history.alert == nil)
    }

    @Test("AReReadWithTheSameRowsKeepsTheSnapshot")
    func aReReadWithTheSameRowsKeepsTheSnapshot() async {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        let flag = watch { _ = history.snapshot }
        fake.respond(.historyList, historyList(records: [1, 2, 3]))
        await history.reread()
        #expect(!flag.changed)
        #expect(history.selection == 1)
        #expect(history.selectedDetail == "Detail of record 2")
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(records: [1, 2, 3], revoked: [2]))
        await history.reread()
        #expect(history.snapshot.rows[1].revoked)
        #expect(flag.changed)
    }

    @Test("HistoryChangedClearsTheSelectionEvenWhenTheRowStillExists")
    func historyChangedClearsTheSelectionEvenWhenTheRowStillExists() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.respond(.historyList, historyList(records: [1, 2, 3]))
        history.historyChanged()
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
        await history.reread()
        #expect(history.selection == nil)
        #expect(fake.count(.historyRecordText) == 1)  // the selection's only
    }

    @Test("ARowPickedBeforeHistoryChangedsReadLandsIsClearedWhenTheRowsDiffer")
    func aRowPickedBeforeHistoryChangedsReadLandsIsClearedWhenTheRowsDiffer() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        let read = fake.hold(.historyList)
        let changed = await changing(history, fake, count: 2)
        fake.respond(.historyRecordText, text(2))
        history.select(row: 1)
        await history.pendingDetail?.value
        #expect(history.selection == 1)
        read.release(historyList(records: [4, 1, 2, 3]))
        await changed.value
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
    }

    @Test("ARowPickedBeforeHistoryChangedsReadLandsSurvivesTheSameRows")
    func aRowPickedBeforeHistoryChangedsReadLandsSurvivesTheSameRows() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        let read = fake.hold(.historyList)
        let changed = await changing(history, fake, count: 2)
        fake.respond(.historyRecordText, text(2))
        history.select(row: 1)
        await history.pendingDetail?.value
        let flag = watch { _ = history.snapshot }
        read.release(historyList(records: [1, 2, 3]))
        await changed.value
        #expect(!flag.changed)
        #expect(history.selection == 1)
        #expect(history.selectedDetail == "Detail of record 2")
        #expect(fake.count(.historyRecordText) == 1)  // the pick's only
    }

    @Test("AReReadKeepsASelectionInRangeWithoutReReadingAnUnchangedRecord")
    func aReReadKeepsASelectionInRangeWithoutReReadingAnUnchangedRecord() async {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        let list = historyList(records: [1, 2, 3], revoked: [2])
        fake.respond(.historyList, list)
        await history.reread()
        #expect(history.snapshot == list)
        #expect(history.selection == 1)
        #expect(history.selectedDetail == "Detail of record 2")
        #expect(fake.count(.historyRecordText) == 1)  // the selection's only
    }

    @Test("AReReadDropsASelectionOutOfRange")
    func aReReadDropsASelectionOutOfRange() async {
        let fake = FakeBridge()
        let history = await selected(2, fake)
        fake.respond(.historyList, historyList(records: [1, 2]))
        await history.reread()
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
    }

    @Test("AKeptRowWhoseRecordChangedHasItsDetailReRead")
    func aKeptRowWhoseRecordChangedHasItsDetailReRead() async throws {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.respond(.historyList, historyList(records: [4, 1, 2, 3]))
        fake.respond(.historyRecordText, text(4))
        await history.reread()
        #expect(history.selection == 0)
        #expect(history.selectedDetail == "Detail of record 4")
        #expect(fake.params(.historyRecordText) == [try recordParams(1), try recordParams(4)])
    }

    // Mac: a failed detail shows the core's error in the pane, not an alert.
    @Test("AFailedDetailIsNotAskedForAgainByAReReadOfTheSameRecord")
    func aFailedDetailIsNotAskedForAgainByAReReadOfTheSameRecord() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        fake.fail(.historyRecordText, RPCError(code: .failed, message: "no"))
        history.select(row: 0)
        await history.pendingDetail?.value
        // The pane shows the core's error; no alert.
        #expect(history.selectedDetail == HistoryModel.detailFailedPrefix + "no")
        #expect(history.alert == nil)
        fake.respond(.historyList, historyList(records: [1, 2, 3]))
        await history.reread()
        #expect(history.selection == 0)
        #expect(fake.count(.historyRecordText) == 1)
        #expect(history.selectedDetail == HistoryModel.detailFailedPrefix + "no")
        #expect(history.alert == nil)
    }

    @Test("AnOlderReadFinishingLastIsDropped")
    func anOlderReadFinishingLastIsDropped() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        let older = fake.hold(.historyList)
        fake.respond(.historyList, historyList(records: [1]))
        let first = Task { await history.reread() }
        #expect(await settle { fake.count(.historyList) == 2 })
        await history.reread()
        #expect(history.snapshot == historyList(records: [1]))
        older.release(historyList(records: [1, 2, 3, 4]))
        await first.value
        #expect(history.snapshot == historyList(records: [1]))
    }

    @Test("AFailedReadKeepsTheRowsAndLeavesThePendingClearAndReportToTheNextRead")
    func aFailedReadKeepsTheRowsAndLeavesThePendingClearAndReportToTheNextRead() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        let before = history.snapshot
        fake.fail(.historyList, RPCError(code: .internal, message: "x"))
        await changed(history)
        #expect(history.snapshot == before)
        #expect(history.alert == nil)
        fake.respond(.historyRecordText, text(1))
        history.select(row: 0)
        await history.pendingDetail?.value
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(records: [], loadFailed: true))
        await history.reread()  // as history.revocationsChanged does
        #expect(history.selection == nil)
        #expect(history.alert == AlertState(title: "Unable to Load History", message: "The issuance log couldn't be read."))
    }

    @Test("TheLoadFailureIsReportedOncePerHistoryChanged")
    func theLoadFailureIsReportedOncePerHistoryChanged() async {
        let fake = FakeBridge()
        fake.respond(.historyList, historyList(records: [], loadFailed: true))
        let history = await model(fake)
        await changed(history)
        #expect(history.alert == AlertState(title: "Unable to Load History", message: "The issuance log couldn't be read."))
        await history.alertDismissed()
        await history.reread()
        #expect(history.alert == nil)
        await changed(history)
        #expect(history.alert == AlertState(title: "Unable to Load History", message: "The issuance log couldn't be read."))
    }

    @Test("AFailedLoadIsNotReportedWithoutHistoryChangedNorAfterALoadThatWorked")
    func aFailedLoadIsNotReportedWithoutHistoryChangedNorAfterALoadThatWorked() async {
        let fake = FakeBridge()
        fake.respond(.historyList, historyList(records: [], loadFailed: true))
        let history = await model(fake)
        await history.reread()  // revocationsChanged, auth.changed: not armed
        #expect(history.snapshot.loadFailed)
        #expect(history.alert == nil)
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(records: [1]))
        fake.respond(.historyList, historyList(records: [], loadFailed: true))
        await changed(history)  // consumes the report: the log loaded
        #expect(history.alert == nil)
        await history.reread()
        #expect(history.snapshot.loadFailed)
        #expect(history.alert == nil)
    }

    @Test("RevocationStatusFollowsTheSnapshot")
    func revocationStatusFollowsTheSnapshot() async {
        let fake = FakeBridge()
        let history = await loaded(fake, list: historyList(records: [1], revocationsUnavailable: true))
        #expect(history.revocationStatus == "Revocation unavailable")
        fake.respond(.historyList, historyList(records: [1]))
        await history.reread()
        #expect(history.revocationStatus == "")
    }

    @Test("an older read finishing last is dropped, its load failure included")
    func staleRead() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        let first = fake.hold(.historyList)
        fake.respond(.historyList, historyList(count: 4))
        let older = await changing(history, fake, count: 2)
        await history.reread()
        #expect(history.snapshot == historyList(count: 4))
        first.release(historyList(count: 0, loadFailed: true))
        await older.value
        #expect(history.snapshot == historyList(count: 4))
        #expect(history.alert == nil)
    }

    @Test("a load failure landing under another alert waits until that alert is closed")
    func loadFailureUnderAlert() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        fake.fail(.historyRefresh, RPCError(code: .busy, message: "Already refreshing."))
        await history.refreshTapped()
        let blocking = AlertState(title: "Unable to Refresh History", message: "Already refreshing.")
        #expect(history.alert == blocking)
        fake.respond(.historyList, historyList(count: 0, loadFailed: true))
        await changed(history)
        #expect(history.alert == blocking)
        await history.alertDismissed()
        await history.reread()
        #expect(history.alert == AlertState(title: "Unable to Load History", message: "The issuance log couldn't be read."))
    }

    @Test("history.changed overtaken by a newer read: the newer read reports the load failure")
    func loadFailureOnNewerRead() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        let first = fake.hold(.historyList)
        fake.respond(.historyList, historyList(count: 0, loadFailed: true))
        let older = await changing(history, fake, count: 2)
        await history.reread()
        #expect(history.alert == AlertState(title: "Unable to Load History", message: "The issuance log couldn't be read."))
        first.release(historyList(count: 3))
        await older.value
        #expect(history.snapshot == historyList(count: 0, loadFailed: true))
    }

    // MARK: Search

    @Test("ASearchReadsOnceTypingPausesAndClearsTheSelectionAtOnce")
    func aSearchReadsOnceTypingPausesAndClearsTheSelectionAtOnce() async {
        let fake = FakeBridge()
        let history = await selected(1, fake, debounce: .milliseconds(50))
        let filtered = historyList(records: [2])
        fake.respond(.historyList, filtered)
        history.setQuery("Recipient 2")
        #expect(history.query == "Recipient 2")
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
        #expect(await settle { history.snapshot == filtered })
        #expect(fake.params(.historyList) == [#"{"query":""}"#, #"{"query":"Recipient 2"}"#])
        #expect(history.selection == nil)
    }

    @Test("SettingTheSameQueryDoesNothing")
    func settingTheSameQueryDoesNothing() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        history.setQuery("")
        #expect(history.selection == 0)
        #expect(history.selectedDetail == "Detail of record 1")
        // A search task, had one started, would run in this yield.
        await Task.yield()
        #expect(fake.count(.historyList) == 1)  // the load's only
    }

    @Test("AQueryChangeDropsAReadAlreadySentAndARowPickedMeanwhile")
    func aQueryChangeDropsAReadAlreadySentAndARowPickedMeanwhile() async {
        let fake = FakeBridge()
        let history = await loaded(fake, debounce: .seconds(60))
        let older = fake.hold(.historyList)
        let newer = historyList(records: [3])
        fake.respond(.historyList, newer)
        let reread = Task { await history.reread() }
        #expect(await settle { fake.count(.historyList) == 2 })
        history.setQuery("3")
        // A row picked from the old rows before the search's read lands.
        fake.respond(.historyRecordText, text(1))
        history.select(row: 0)
        await history.pendingDetail?.value
        #expect(history.selection == 0)
        older.release(historyList(records: [1, 2]))
        await reread.value
        #expect(history.snapshot.rows.count == 3)
        // The search's own read (its debounce never fires in this test).
        await history.reread()
        #expect(history.snapshot == newer)
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
    }

    @Test("typing re-reads once it pauses, sending only the latest query, with the selection reset")
    func debounce() async {
        let fake = FakeBridge()
        let history = await selected(0, fake, debounce: .milliseconds(50))
        fake.respond(.historyList, historyList(count: 1))
        history.setQuery("R")
        history.setQuery("Re")
        #expect(history.query == "Re")
        #expect(await settle { history.snapshot == historyList(count: 1) })
        #expect(history.selection == nil)
        #expect(fake.params(.historyList) == [#"{"query":""}"#, #"{"query":"Re"}"#])
    }

    @Test("a newer query supersedes a read in flight for the older one")
    func supersededResult() async {
        let fake = FakeBridge()
        let history = await loaded(fake, debounce: .seconds(60))
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

    @Test("a read for a new query before its search runs leaves the selection cleared")
    func readForNewQuery() async {
        let fake = FakeBridge()
        let history = await selected(1, fake, debounce: .seconds(60))
        fake.respond(.historyList, historyList(count: 3))
        history.setQuery("Recipient")
        await history.reread()
        // The search itself still waits: a search task that did not would run
        // in this yield and send a third read.
        await Task.yield()
        #expect(fake.count(.historyList) == 2)
        #expect(fake.params(.historyList).last == #"{"query":"Recipient"}"#)
        #expect(history.selection == nil && history.selectedDetail == nil)
    }

    // MARK: Selection

    @Test("SelectingARowShowsItsDetail")
    func selectingARowShowsItsDetail() async throws {
        let fake = FakeBridge()
        let history = await loaded(fake)
        fake.respond(.historyRecordText, text(2))
        history.select(row: 1)
        #expect(history.selection == 1)
        await history.pendingDetail?.value
        #expect(history.selectedDetail == "Detail of record 2")
        #expect(fake.params(.historyRecordText) == [try recordParams(2)])
        #expect(history.alert == nil)
    }

    @Test("TheDetailStaysUntilTheNextRowsDetailArrives")
    func theDetailStaysUntilTheNextRowsDetailArrives() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        let held = fake.hold(.historyRecordText)
        history.select(row: 1)
        #expect(history.selection == 1)
        #expect(history.selectedDetail == "Detail of record 1")
        held.release(text(2))
        await history.pendingDetail?.value
        #expect(history.selectedDetail == "Detail of record 2")
    }

    @Test("TheLatestSelectionWinsItsRepliesAndFailuresIncluded")
    func theLatestSelectionWinsItsRepliesAndFailuresIncluded() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        let first = fake.hold(.historyRecordText)
        let second = fake.hold(.historyRecordText)
        fake.respond(.historyRecordText, text(3))
        history.select(row: 0)
        let one = history.pendingDetail
        #expect(await settle { fake.count(.historyRecordText) == 1 })
        history.select(row: 1)
        let two = history.pendingDetail
        #expect(await settle { fake.count(.historyRecordText) == 2 })
        history.select(row: 2)
        await history.pendingDetail?.value
        #expect(history.selectedDetail == "Detail of record 3")
        first.release(text(1))
        second.release(failing: RPCError(code: .failed, message: "stale"))
        await one?.value
        await two?.value
        #expect(history.selection == 2)
        #expect(history.selectedDetail == "Detail of record 3")
        #expect(history.alert == nil)
    }

    @Test("NoRowOrOneOutOfRangeClearsTheSelection", arguments: [nil, -1, 3] as [Int?])
    func noRowOrOneOutOfRangeClearsTheSelection(_ row: Int?) async {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        history.select(row: row)
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
        #expect(fake.count(.historyRecordText) == 1)  // the first selection's only
    }

    @Test("ClearingTheSelectionDropsADetailReadStillRunning")
    func clearingTheSelectionDropsADetailReadStillRunning() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        let held = fake.hold(.historyRecordText)
        history.select(row: 0)
        let pending = history.pendingDetail
        history.select(row: nil)
        held.release(text(1))
        await pending?.value
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
    }

    @Test("duplicate rows sharing a hash are selected by index")
    func duplicateRows() async {
        let fake = FakeBridge()
        let history = await selected(1, fake, list: historyList(records: [2, 2]))
        #expect(history.selection == 1)
        #expect(history.canRevoke)
    }

    @Test("re-selecting the selected row makes no call, also after a failed detail")
    func reselectingTheSelectedRow() async {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        history.select(row: 1)
        // Awaits whatever detail read is latest: a new one would run here.
        await history.pendingDetail?.value
        #expect(fake.count(.historyRecordText) == 1)
        #expect(history.selectedDetail == "Detail of record 2")
        fake.fail(.historyRecordText, RPCError(code: .failed, message: "no"))
        history.select(row: 0)
        await history.pendingDetail?.value
        #expect(history.selectedDetail == HistoryModel.detailFailedPrefix + "no")
        history.select(row: 0)
        await history.pendingDetail?.value
        #expect(fake.count(.historyRecordText) == 2)
        #expect(history.selection == 0)
        #expect(history.selectedDetail == HistoryModel.detailFailedPrefix + "no")
    }

    @Test("a row selected just before history.changed shows no detail once its read lands")
    func selectThenHistoryChanged() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        fake.respond(.historyRecordText, text(2))
        history.select(row: 1)
        history.historyChanged()
        await history.pendingDetail?.value
        #expect(fake.count(.historyRecordText) == 1)
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
    }

    @Test("a failed detail read leaves another alert up, and that alert's follow-up still runs")
    func failedDetailUnderAnAlert() async {
        let fake = FakeBridge()
        let message = "Your GitHub session expired. Please log in again."
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        fake.fail(.historyRevoke, RPCError(code: .sessionExpired, message: message))
        fake.respond(.authLogin, loggedIn)
        await history.revokeTapped()
        await history.confirm()
        let sessionExpired = AlertState(title: "Session Expired", message: message)
        #expect(history.alert == sessionExpired)
        fake.reset(.historyRecordText)
        fake.fail(.historyRecordText, RPCError(code: .failed, message: "cannot word it"))
        history.select(row: 1)
        await history.pendingDetail?.value
        #expect(history.alert == sessionExpired)
        #expect(history.selectedDetail == HistoryModel.detailFailedPrefix + "cannot word it")
        #expect(fake.count(.authLogin) == 0)
        await history.alertDismissed()
        #expect(fake.count(.authLogin) == 1)
    }

    // MARK: Refresh

    @Test("Refresh asks the core; the results arrive as events")
    func refresh() async {
        let fake = FakeBridge()
        let history = await loaded(fake)
        await history.refreshTapped()
        #expect(fake.params(.historyRefresh) == ["{}"])
        #expect(history.alert == nil)
        #expect(fake.count(.historyList) == 1)
    }

    @Test("a failed Refresh shows the core's error")
    func refreshFailure() async {
        let fake = FakeBridge()
        fake.fail(.historyRefresh, RPCError(code: .internal, message: "x"))
        let history = await loaded(fake)
        await history.refreshTapped()
        #expect(history.alert == AlertState(title: "Unable to Refresh History", message: "x"))
    }

    // MARK: Revoke

    @Test("RevokeNeedsASelectedUnrevokedRowAndTheCoresGoAhead")
    func revokeNeedsASelectedUnrevokedRowAndTheCoresGoAhead() async {
        let fake = FakeBridge()
        let history = await loaded(fake, list: historyList(records: [1, 2], revoked: [2]))
        #expect(!history.canRevoke)
        await history.revokeTapped()  // ignored
        #expect(fake.count(.historyRecordText) == 0)
        #expect(history.pendingConfirmation == nil)

        fake.respond(.historyRecordText, text(2))
        history.select(row: 1)
        await history.pendingDetail?.value
        #expect(!history.canRevoke)  // already revoked

        history.select(row: 0)
        await history.pendingDetail?.value
        #expect(history.canRevoke)

        let flag = watch { _ = history.canRevoke }
        fake.respond(.historyList, historyList(records: [1, 2], revoked: [2], revokeAvailable: false))
        await history.reread()
        #expect(history.selection == 0)
        #expect(flag.changed)
        #expect(!history.canRevoke)  // logged out, offline or no revocation list
    }

    @Test("RevokeIsDisabledWhileARevocationRuns")
    func revokeIsDisabledWhileARevocationRuns() async {
        let fake = FakeBridge()
        let held = fake.hold(.historyRevoke)
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        await history.revokeTapped()
        let revoking = Task { await history.confirm() }
        #expect(await settle { fake.count(.historyRevoke) == 1 })
        #expect(history.isRevoking)
        #expect(!history.canRevoke)
        fake.respond(.historyList, historyList(records: [1, 2, 3], revoked: [1]))
        held.release(submitted)
        await revoking.value
        #expect(!history.isRevoking)
    }

    @Test("ConfirmedRevokeOpensThePullRequestReReadsAndShowsTheCoresOutcome")
    func confirmedRevokeOpensThePullRequestReReadsAndShowsTheCoresOutcome() async throws {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        let revoked = historyList(records: [1, 2, 3], revoked: [1])
        fake.respond(.historyList, revoked)
        fake.respond(.historyRevoke, submitted)
        await history.revokeTapped()
        #expect(history.pendingConfirmation == revokeQuestion(1))
        #expect(fake.count(.historyRevoke) == 0)
        await history.confirm()
        #expect(history.pendingConfirmation == nil)
        #expect(fake.params(.historyRecordText) == [try recordParams(1), try recordParams(1)])
        #expect(fake.params(.historyRevoke) == [revokeParams(1)])
        #expect(history.snapshot == revoked)
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
        #expect(!history.isRevoking)
        #expect(history.alert == AlertState(title: "Revocation Submitted", message: "PR #12 opened."))
        await history.alertDismissed()
        #expect(fake.count(.authLogin) == 0)
    }

    @Test("ASuccessfulRevocationWhoseReReadFailsStillShowsTheCoresOutcome")
    func aSuccessfulRevocationWhoseReReadFailsStillShowsTheCoresOutcome() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        let shown = history.snapshot
        fake.respond(.historyRecordText, text(1))
        fake.fail(.historyList, RPCError(code: .internal, message: "x"))
        fake.respond(.historyRevoke, submitted)
        await history.revokeTapped()
        await history.confirm()
        #expect(history.snapshot == shown)
        #expect(history.selection == nil)
        #expect(!history.isRevoking)
        #expect(history.alert == AlertState(title: "Revocation Submitted", message: "PR #12 opened."))
    }

    @Test("ARecordTextFailureBeforeRevokingShowsTheCoresErrorAndAsksNothing")
    func aRecordTextFailureBeforeRevokingShowsTheCoresErrorAndAsksNothing() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.fail(.historyRecordText, RPCError(code: .failed, message: "no text"))
        await history.revokeTapped()
        #expect(history.pendingConfirmation == nil)
        #expect(fake.count(.historyRevoke) == 0)
        #expect(history.alert == AlertState(title: "Unable to Revoke Record", message: "no text"))
        #expect(!history.isAsking)
    }

    @Test("ABusyRevocationShowsNothing")
    func aBusyRevocationShowsNothing() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        fake.fail(.historyRevoke, RPCError(code: .busy, message: "busy"))
        await history.revokeTapped()
        await history.confirm()
        #expect(history.alert == nil)
        #expect(!history.isRevoking)
        #expect(fake.count(.authLogin) == 0)
        #expect(history.selection == 0)
    }

    @Test("NotLoggedInStartsTheLoginWhoseStatusTextsShowOnHistory")
    func notLoggedInStartsTheLoginWhoseStatusTextsShowOnHistory() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        fake.fail(.historyRevoke, RPCError(code: .notLoggedIn, message: "Not logged in to GitHub."))
        fake.respond(.authLogin, loggedIn)
        await history.revokeTapped()
        await history.confirm()
        #expect(fake.methods.suffix(2) == ["history.revoke", "auth.login"])
        #expect(!history.isRevoking)
        #expect(history.status == "Logged in as @octocat")
        #expect(history.alert == nil)
    }

    @Test("SessionExpiredShowsTheAlertThenLogsInOnlyOnceItIsDismissed")
    func sessionExpiredShowsTheAlertThenLogsInOnlyOnceItIsDismissed() async {
        let fake = FakeBridge()
        let message = "Your GitHub session expired. Please log in again."
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        fake.fail(.historyRevoke, RPCError(code: .sessionExpired, message: message))
        fake.respond(.authLogin, loggedIn)
        await history.revokeTapped()
        await history.confirm()
        #expect(history.alert == AlertState(title: "Session Expired", message: message))
        #expect(fake.count(.authLogin) == 0)
        await history.alertDismissed()
        #expect(history.alert == nil)
        #expect(fake.count(.authLogin) == 1)
        #expect(history.status == "Logged in as @octocat")
        await history.alertDismissed()
        #expect(fake.count(.authLogin) == 1)
    }

    @Test(
        "AnyOtherRevocationFailureShowsRevocationFailedOfferingTheErrorLog",
        arguments: [RPCErrorCode.failed, .unknown("future")])
    func anyOtherRevocationFailureShowsRevocationFailedOfferingTheErrorLog(_ code: RPCErrorCode) async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        fake.fail(.historyRevoke, RPCError(code: code, message: "GitHub returned an error."))
        await history.revokeTapped()
        await history.confirm()
        #expect(
            history.alert
                == AlertState(title: "Revocation Failed", message: "GitHub returned an error.", offersErrorLogExport: true))
        #expect(!history.isRevoking && history.selection == 0)
        await history.alertDismissed()
        #expect(fake.count(.authLogin) == 0)
    }

    @Test("a confirmed revoke drops a detail read still running")
    func confirmedRevokeDropsADetailRead() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        // Enqueued first: the selection's detail read takes the hold, the
        // revoke question the reply after it.
        let held = fake.hold(.historyRecordText)
        fake.respond(.historyRecordText, text(2))
        history.select(row: 1)
        let detail = history.pendingDetail
        #expect(await settle { fake.count(.historyRecordText) == 2 })
        fake.respond(.historyList, historyList(records: [1, 2, 3], revoked: [2]))
        fake.respond(.historyRevoke, submitted)
        await history.revokeTapped()
        #expect(history.pendingConfirmation == revokeQuestion(2))
        await history.confirm()
        #expect(history.selection == nil && history.selectedDetail == nil)
        held.release(text(2))
        await detail?.value
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
    }

    @Test("a deletion whose history.changed never came is not taken by a revocation's re-read")
    func revokeDropsAPendingDelete() async {
        let fake = FakeBridge()
        let history = await deletedRow(1, fake)
        // The deletion's history.changed is lost; record 1 is revoked next.
        // Its re-read differs from the rows the deletion was counted in, so
        // a pending deletion still held would select row 1.
        fake.respond(.historyRecordText, text(2))
        fake.respond(.historyList, historyList(records: [1, 3], revoked: [3]))
        fake.respond(.historyRevoke, submitted)
        history.select(row: 0)
        await history.pendingDetail?.value
        await history.revokeTapped()
        await history.confirm()
        #expect(fake.count(.historyRevoke) == 1)
        #expect(history.snapshot == historyList(records: [1, 3], revoked: [3]))
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
    }

    // MARK: Delete

    @Test("DeleteEntryNeedsASelectedRowRevokedOrNotWithRevokingUnavailable")
    func deleteEntryNeedsASelectedRowRevokedOrNotWithRevokingUnavailable() async {
        let fake = FakeBridge()
        let history = await loaded(fake, list: historyList(records: [1, 2], revoked: [2], revokeAvailable: false))
        #expect(!history.canDelete)
        await history.deleteTapped()  // ignored
        #expect(fake.count(.historyRecordText) == 0)
        #expect(history.pendingConfirmation == nil)

        fake.respond(.historyRecordText, text(2, offerRevoke: false))
        history.select(row: 1)
        await history.pendingDetail?.value
        #expect(history.canDelete)  // revoked, revoking unavailable: still deletable
        #expect(!history.canRevoke)

        fake.respond(.historyList, historyList(records: [1]))
        await history.reread()  // the selected row is gone
        #expect(history.selection == nil)
        #expect(!history.canDelete)
    }

    @Test("Delete Entry's tooltip: how to enable it while disabled, what it does while enabled")
    func deleteTooltip() async {
        let fake = FakeBridge()
        let held = fake.hold(.historyDeleteEntry)
        let history = await loaded(fake, list: historyList(records: [1, 2, 3]))
        #expect(history.deleteTooltip == "Select a record to delete it.")
        fake.respond(.historyRecordText, text(1))
        history.select(row: 0)
        await history.pendingDetail?.value
        #expect(history.deleteTooltip == "Remove the selected record from the issuance log (\u{232B})")
        await history.deleteTapped()
        let deleting = Task { await history.confirm() }
        #expect(await settle { fake.count(.historyDeleteEntry) == 1 })
        // A deletion under way disables Delete Entry… with a row selected.
        #expect(history.deleteTooltip == HistoryModel.deleteDisabledTooltip)
        held.release(deleted)
        await deleting.value
        #expect(history.deleteTooltip == HistoryModel.deleteEnabledTooltip)
        history.select(row: nil)
        #expect(history.deleteTooltip == HistoryModel.deleteDisabledTooltip)
    }

    @Test("ASnapshotChangeReRaisesDeleteEntrysCanExecute")
    func aSnapshotChangeReRaisesDeleteEntrysCanExecute() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        let flag = watch { _ = history.canDelete }
        fake.respond(.historyList, historyList(records: [1, 2, 3], revoked: [1]))
        await history.reread()
        #expect(history.selection == 0)
        #expect(flag.changed)
        #expect(history.canDelete)
    }

    @Test("DeleteEntryIsDisabledWhileARevocationRuns")
    func deleteEntryIsDisabledWhileARevocationRuns() async {
        let fake = FakeBridge()
        let held = fake.hold(.historyRevoke)
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        await history.revokeTapped()
        let revoking = Task { await history.confirm() }
        #expect(await settle { fake.count(.historyRevoke) == 1 })
        #expect(history.isRevoking)
        #expect(history.selection == 0)
        #expect(!history.canDelete)
        fake.respond(.historyList, historyList(records: [1, 2, 3], revoked: [1]))
        held.release(submitted)
        await revoking.value
        #expect(!history.isRevoking)
        #expect(fake.count(.historyDeleteEntry) == 0)
    }

    @Test("RevokeAndDeleteEntryAreDisabledWhileADeletionRuns")
    func revokeAndDeleteEntryAreDisabledWhileADeletionRuns() async {
        let fake = FakeBridge()
        let held = fake.hold(.historyDeleteEntry)
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        #expect(history.canRevoke)
        await history.deleteTapped()
        let deleting = Task { await history.confirm() }
        #expect(await settle { fake.count(.historyDeleteEntry) == 1 })
        #expect(history.isDeleting)
        #expect(history.selection == 0)
        #expect(!history.canRevoke)
        #expect(!history.canDelete)
        await history.revokeTapped()  // ignored
        await history.deleteTapped()  // ignored
        #expect(fake.count(.historyRevoke) == 0)
        #expect(fake.count(.historyRecordText) == 2)
        held.release(deleted)
        await deleting.value
        #expect(!history.isDeleting)
        #expect(history.canRevoke)
        #expect(history.canDelete)
    }

    @Test("DeleteEntryIsDisabledWhileARevokeInsteadRuns")
    func deleteEntryIsDisabledWhileARevokeInsteadRuns() async {
        let fake = FakeBridge()
        let held = fake.hold(.historyRevoke)
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        await history.deleteTapped()
        await history.alternate()
        let revoking = Task { await history.confirm() }
        #expect(await settle { fake.count(.historyRevoke) == 1 })
        #expect(history.isRevoking)
        #expect(!history.isDeleting)
        #expect(!history.canDelete)
        #expect(!history.canRevoke)
        await history.deleteTapped()  // ignored
        #expect(fake.count(.historyRecordText) == 3)
        fake.respond(.historyList, historyList(records: [1, 2, 3], revoked: [1]))
        held.release(submitted)
        await revoking.value
        #expect(!history.isRevoking)
        #expect(fake.count(.historyDeleteEntry) == 0)
    }

    @Test("ARevokedRecordsQuestionHasTwoButtons")
    func aRevokedRecordsQuestionHasTwoButtons() async {
        let fake = FakeBridge()
        let history = await selected(0, fake, list: historyList(records: [1, 2], revoked: [1]))
        fake.respond(.historyRecordText, text(1, offerRevoke: false))
        await history.deleteTapped()
        #expect(history.pendingConfirmation == deleteQuestion(1, offerRevoke: false))
        #expect(history.pendingConfirmation?.alternateTitle == nil)
    }

    @Test("WithoutRevokeInsteadAnAlternateAnswerDoesNothing")
    func withoutRevokeInsteadAnAlternateAnswerDoesNothing() async {
        let fake = FakeBridge()
        let history = await selected(0, fake, list: historyList(records: [1, 2], revoked: [1]))
        fake.respond(.historyRecordText, text(1, offerRevoke: false))
        await history.deleteTapped()
        await history.alternate()
        #expect(history.pendingConfirmation == nil)
        // No revoke question was asked: that would read the record text again.
        #expect(fake.count(.historyRecordText) == 2)
        #expect(fake.count(.historyRevoke) == 0)
        #expect(fake.count(.historyDeleteEntry) == 0)
        #expect(history.alert == nil)
    }

    @Test("ConfirmedDeleteDeletesTheRecordAndShowsTheCoresAlert")
    func confirmedDeleteDeletesTheRecordAndShowsTheCoresAlert() async throws {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        fake.respond(.historyRecordText, text(2))
        fake.respond(.historyDeleteEntry, deleted)
        await history.deleteTapped()
        #expect(fake.count(.historyDeleteEntry) == 0)
        await history.confirm()
        #expect(history.pendingConfirmation == nil)
        #expect(fake.params(.historyDeleteEntry) == [try recordParams(2)])
        #expect(history.alert == AlertState(title: "Core Deleted Title", message: "Core says: deleted it."))
        #expect(!history.isDeleting)
        #expect(fake.count(.historyRevoke) == 0)
        // The list reloads on the core's history.changed, not here.
        #expect(fake.count(.historyList) == 1)  // the load's only
        // The question is gone: its alternate has nothing to run.
        await history.alternate()
        #expect(fake.count(.historyRecordText) == 2)
    }

    @Test("answering the delete question routes each button: confirm deletes, alternate asks to revoke, cancel ends it")
    func answerRoutesEachButton() async throws {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        fake.respond(.historyDeleteEntry, deleted)

        await history.deleteTapped()
        await history.answer(.cancel)
        #expect(history.pendingConfirmation == nil)
        #expect(fake.count(.historyDeleteEntry) == 0)

        await history.deleteTapped()
        await history.answer(.alternate)
        #expect(history.pendingConfirmation == revokeQuestion(1))
        await history.answer(.cancel)
        #expect(fake.count(.historyRevoke) == 0)

        await history.deleteTapped()
        await history.answer(.confirm)
        #expect(history.pendingConfirmation == nil)
        #expect(fake.params(.historyDeleteEntry) == [try recordParams(1)])
        #expect(fake.count(.historyRevoke) == 0)
    }

    @Test("RevokeInsteadRevokesTheCapturedRecordAfterTheRevokeQuestion")
    func revokeInsteadRevokesTheCapturedRecordAfterTheRevokeQuestion() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        let revoked = historyList(records: [1, 2, 3], revoked: [1])
        fake.respond(.historyList, revoked)
        fake.respond(.historyRevoke, submitted)
        await history.deleteTapped()
        #expect(history.pendingConfirmation == deleteQuestion(1))
        await history.alternate()
        #expect(history.pendingConfirmation == revokeQuestion(1))
        await history.confirm()
        #expect(fake.params(.historyRevoke) == [revokeParams(1)])
        #expect(fake.count(.historyDeleteEntry) == 0)
        #expect(history.snapshot == revoked)
        #expect(!history.isRevoking)
        #expect(history.alert == AlertState(title: "Revocation Submitted", message: "PR #12 opened."))
    }

    @Test("RevokeInsteadWhileLoggedOutStartsTheLogin")
    func revokeInsteadWhileLoggedOutStartsTheLogin() async {
        let fake = FakeBridge()
        let history = await selected(
            0, fake, list: historyList(records: [1, 2, 3], revokeAvailable: false), auth: loggedOut)
        #expect(!history.canRevoke)
        fake.respond(.historyRecordText, text(1))
        fake.fail(.historyRevoke, RPCError(code: .notLoggedIn, message: "Not logged in to GitHub."))
        fake.respond(.authLogin, loggedIn)
        await history.deleteTapped()
        await history.alternate()
        await history.confirm()
        #expect(fake.methods.suffix(2) == ["history.revoke", "auth.login"])
        #expect(!history.isRevoking)
        #expect(history.status == "Logged in as @octocat")
        #expect(history.alert == nil)
        #expect(fake.count(.historyDeleteEntry) == 0)
    }

    @Test("HistoryChangedWhileTheQuestionIsOpenStillDeletesTheCapturedRecord")
    func historyChangedWhileTheQuestionIsOpenStillDeletesTheCapturedRecord() async throws {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        fake.respond(.historyRecordText, text(2))
        fake.respond(.historyDeleteEntry, deleted)
        await history.deleteTapped()
        let moved = historyList(records: [4, 1, 2, 3])
        fake.respond(.historyList, moved)
        await changed(history)
        #expect(history.pendingConfirmation == deleteQuestion(2))
        await history.confirm()
        #expect(history.snapshot == moved)
        #expect(history.selection == nil)
        #expect(fake.params(.historyDeleteEntry) == [try recordParams(2)])
        #expect(history.alert == AlertState(title: "Core Deleted Title", message: "Core says: deleted it."))
        // The deletion's own history.changed: the record was found in the
        // moved rows, so the row now in its place is selected.
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(records: [4, 1, 3]))
        await changed(history)
        #expect(history.selection == 2)
    }

    @Test("HistoryChangedWhileTheQuestionIsOpenStillRevokesTheCapturedRecord")
    func historyChangedWhileTheQuestionIsOpenStillRevokesTheCapturedRecord() async throws {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        fake.respond(.historyRecordText, text(2))
        fake.respond(.historyRevoke, submitted)
        await history.deleteTapped()
        fake.respond(.historyList, historyList(records: [4, 1, 2, 3]))
        await changed(history)
        #expect(history.selection == nil)
        await history.alternate()
        #expect(history.pendingConfirmation == revokeQuestion(2))
        await history.confirm()
        #expect(fake.params(.historyRevoke) == [revokeParams(2)])
        #expect(
            fake.params(.historyRecordText) == [try recordParams(2), try recordParams(2), try recordParams(2)])
        #expect(history.alert == AlertState(title: "Revocation Submitted", message: "PR #12 opened."))
    }

    @Test("ARecordNoLongerInTheLogShowsRecordNotFound")
    func aRecordNoLongerInTheLogShowsRecordNotFound() async {
        let fake = FakeBridge()
        let message = "This record is no longer in the issuance log."
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        fake.fail(.historyDeleteEntry, RPCError(code: .notFound, message: message))
        await history.deleteTapped()
        await history.confirm()
        #expect(history.alert == AlertState(title: "Record Not Found", message: message))
        #expect(history.alert?.offersErrorLogExport == false)
        #expect(!history.isDeleting && history.canDelete)
    }

    @Test(
        "AnyOtherDeleteFailureShowsDeleteFailedOfferingTheErrorLog",
        arguments: [RPCErrorCode.failed, .busy, .unknown("future")])
    func anyOtherDeleteFailureShowsDeleteFailedOfferingTheErrorLog(_ code: RPCErrorCode) async {
        let fake = FakeBridge()
        let message = "Could not delete the record. The issuance log was not changed."
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        fake.fail(.historyDeleteEntry, RPCError(code: code, message: message))
        await history.deleteTapped()
        await history.confirm()
        #expect(history.alert == AlertState(title: "Delete Failed", message: message, offersErrorLogExport: true))
        #expect(!history.isDeleting)
        #expect(history.canDelete)
    }

    @Test("ARecordTextFailureBeforeDeletingShowsTheCoresErrorAndAsksNothing")
    func aRecordTextFailureBeforeDeletingShowsTheCoresErrorAndAsksNothing() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.fail(.historyRecordText, RPCError(code: .failed, message: "no text"))
        await history.deleteTapped()
        #expect(history.pendingConfirmation == nil)
        #expect(fake.count(.historyDeleteEntry) == 0)
        #expect(history.alert == AlertState(title: "Unable to Delete Record", message: "no text"))
        #expect(!history.isAsking)
    }

    @Test("a record text failure on Revoke Instead shows the error and asks nothing")
    func revokeInsteadTextFailure() async {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        fake.respond(.historyRecordText, text(2))
        await history.deleteTapped()
        fake.reset(.historyRecordText)
        fake.fail(.historyRecordText, RPCError(code: .failed, message: "bad record"))
        await history.alternate()
        #expect(history.pendingConfirmation == nil)
        #expect(history.alert == AlertState(title: "Unable to Revoke Record", message: "bad record"))
        #expect(!history.isAsking)
    }

    @Test("Delete declined: nothing is deleted, revoked or asked")
    func deleteDeclined() async {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        fake.respond(.historyRecordText, text(2))
        await history.deleteTapped()
        history.dismissConfirmation()
        #expect(history.pendingConfirmation == nil)
        await history.confirm()
        await history.alternate()
        #expect(fake.count(.historyDeleteEntry) == 0 && fake.count(.historyRevoke) == 0)
        #expect(fake.count(.historyRecordText) == 2)
        #expect(history.pendingConfirmation == nil && history.alert == nil)
    }

    // MARK: The row in a deleted row's place

    @Test("AfterADeletionTheRowInItsPlaceIsSelectedWithItsDetail")
    func afterADeletionTheRowInItsPlaceIsSelectedWithItsDetail() async throws {
        let fake = FakeBridge()
        let history = await deletedRow(1, fake)
        fake.respond(.historyRecordText, text(3))
        fake.respond(.historyList, historyList(records: [1, 3]))
        await changed(history)
        #expect(history.selection == 1)
        #expect(fake.params(.historyRecordText).last == (try recordParams(3)))
        #expect(history.selectedDetail == "Detail of record 3")
    }

    @Test("AfterDeletingTheLastRowTheNewLastRowIsSelected")
    func afterDeletingTheLastRowTheNewLastRowIsSelected() async {
        let fake = FakeBridge()
        let history = await deletedRow(2, fake)
        fake.respond(.historyList, historyList(records: [1, 2]))
        await changed(history)
        #expect(history.selection == 1)
    }

    @Test("AfterDeletingTheOnlyRowNothingIsSelected")
    func afterDeletingTheOnlyRowNothingIsSelected() async {
        let fake = FakeBridge()
        let history = await deletedRow(0, fake, list: historyList(records: [1]))
        let empty = historyList(records: [])
        fake.respond(.historyList, empty)
        await changed(history)
        #expect(history.snapshot == empty)
        #expect(history.selection == nil)
        #expect(history.selectedDetail == nil)
        // Taken by that read: a later issuance selects nothing.
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(records: [5]))
        await changed(history)
        #expect(history.selection == nil)
    }

    @Test("ARereadShowingTheDeletionFirstStillSelectsTheRowInItsPlace")
    func aRereadShowingTheDeletionFirstStillSelectsTheRowInItsPlace() async throws {
        // A revocations or login re-read lands after the core's write but
        // before its history.changed: that one then reads the same rows.
        let fake = FakeBridge()
        let history = await deletedRow(1, fake)
        fake.respond(.historyRecordText, text(3))
        let rows = historyList(records: [1, 3])
        fake.respond(.historyList, rows)
        await history.reread()
        #expect(history.snapshot == rows)
        await changed(history)
        #expect(history.selection == 1)
        #expect(fake.params(.historyRecordText).last == (try recordParams(3)))
        #expect(history.selectedDetail == "Detail of record 3")
        // Taken: a later change selects nothing.
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(records: [1, 3, 4]))
        await changed(history)
        #expect(history.selection == nil)
    }

    @Test("AHistoryChangedStillHoldingTheDeletedRecordDoesNotTakeItsPlace")
    func aHistoryChangedStillHoldingTheDeletedRecordDoesNotTakeItsPlace() async {
        // An unrelated history.changed read before the core's write.
        let fake = FakeBridge()
        let history = await deletedRow(1, fake)
        fake.respond(.historyList, historyList(records: [1, 2, 3]))
        await changed(history)
        #expect(history.selection == nil)
        fake.reset(.historyList)
        fake.respond(.historyList, historyList(records: [1, 3]))
        await changed(history)
        #expect(history.selection == 1)
    }

    @Test("ADeletionDuringAPendingSearchSelectsNothingAfterIt")
    func aDeletionDuringAPendingSearchSelectsNothingAfterIt() async {
        // A row picked from the old rows while the search waits for typing to
        // pause: its position is not in the rows the search reads.
        let fake = FakeBridge()
        let history = await selected(1, fake, debounce: .seconds(60))
        history.setQuery("Recipient")
        fake.respond(.historyRecordText, text(2))
        history.select(row: 1)
        await history.pendingDetail?.value
        #expect(history.selection == 1)
        fake.respond(.historyDeleteEntry, deleted)
        await history.deleteTapped()
        await history.confirm()
        #expect(fake.count(.historyDeleteEntry) == 1)
        let rows = historyList(records: [1, 3])
        fake.respond(.historyList, rows)
        await changed(history)
        #expect(history.snapshot == rows)
        #expect(history.selection == nil)
    }

    @Test("HistoryChangedBeforeTheDeleteReplyStillSelectsTheRowInItsPlace")
    func historyChangedBeforeTheDeleteReplyStillSelectsTheRowInItsPlace() async throws {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        fake.respond(.historyRecordText, text(2))
        let held = fake.hold(.historyDeleteEntry)
        await history.deleteTapped()
        let deleting = Task { await history.confirm() }
        #expect(await settle { fake.count(.historyDeleteEntry) == 1 })
        fake.reset(.historyRecordText)
        fake.respond(.historyRecordText, text(3))
        fake.respond(.historyList, historyList(records: [1, 3]))
        await changed(history)
        held.release(deleted)
        await deleting.value
        #expect(history.selection == 1)
        #expect(fake.params(.historyRecordText).last == (try recordParams(3)))
        #expect(history.selectedDetail == "Detail of record 3")
    }

    @Test("DeletingTheLaterOfTwoIdenticalDuplicatesKeepsTheSelectionInPlace")
    func deletingTheLaterOfTwoIdenticalDuplicatesKeepsTheSelectionInPlace() async throws {
        // The first identical copy is row 0: the first-match rule alone would give 0.
        let fake = FakeBridge()
        let history = await deletedRow(1, fake, list: historyList(records: [2, 2, 3]))
        #expect(fake.params(.historyDeleteEntry) == [try recordParams(2)])
        fake.respond(.historyList, historyList(records: [2, 3]))
        await changed(history)
        #expect(history.selection == 1)
    }

    @Test("OnlyTheAppliedReadAfterADeletionTakesItsPlace")
    func onlyTheAppliedReadAfterADeletionTakesItsPlace() async {
        let fake = FakeBridge()
        let history = await deletedRow(3, fake, list: historyList(records: [1, 2, 3, 4, 5]))
        let shown = history.snapshot
        let superseded = fake.hold(.historyList)
        let latest = fake.hold(.historyList)
        let first = await changing(history, fake, count: 2)
        let second = await changing(history, fake, count: 3)
        superseded.release(historyList(records: [1, 2]))
        await first.value
        #expect(history.snapshot == shown)
        #expect(history.selection == nil)
        let rows = historyList(records: [1, 2, 3, 5])
        latest.release(rows)
        await second.value
        #expect(history.snapshot == rows)
        #expect(history.selection == 3)
    }

    @Test("AFailedDeletionSelectsNothingOnTheNextHistoryChanged", arguments: [RPCErrorCode.notFound, .failed])
    func aFailedDeletionSelectsNothingOnTheNextHistoryChanged(_ code: RPCErrorCode) async {
        let fake = FakeBridge()
        let history = await selected(1, fake)
        fake.respond(.historyRecordText, text(2))
        fake.fail(.historyDeleteEntry, RPCError(code: code, message: "no"))
        await history.deleteTapped()
        await history.confirm()
        let rows = historyList(records: [1, 3])
        fake.respond(.historyList, rows)
        await changed(history)
        #expect(history.snapshot == rows)
        #expect(history.selection == nil)
    }

    @Test("ASearchChangedWhileDeletingSelectsNothingAfterIt")
    func aSearchChangedWhileDeletingSelectsNothingAfterIt() async {
        let fake = FakeBridge()
        let history = await selected(1, fake, debounce: .seconds(60))
        fake.respond(.historyRecordText, text(2))
        let held = fake.hold(.historyDeleteEntry)
        await history.deleteTapped()
        let deleting = Task { await history.confirm() }
        #expect(await settle { fake.count(.historyDeleteEntry) == 1 })
        history.setQuery("Recipient")
        held.release(deleted)
        await deleting.value
        let rows = historyList(records: [1, 3])
        fake.respond(.historyList, rows)
        await changed(history)
        #expect(history.snapshot == rows)
        #expect(history.selection == nil)
    }

    // MARK: One question at a time

    @Test("a second Delete or Revoke tap while a question is up does nothing")
    func secondTapWhileAQuestionIsUp() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        await history.deleteTapped()
        #expect(history.pendingConfirmation == deleteQuestion(1))
        // A held Delete key repeats.
        await history.deleteTapped()
        await history.revokeTapped()
        await history.removeDuplicatesTapped()
        #expect(fake.count(.historyRecordText) == 2)
        #expect(fake.count(.historyDuplicatePreview) == 0)
        #expect(history.pendingConfirmation == deleteQuestion(1))
    }

    @Test("a second Delete or Revoke tap while a question is being prepared does nothing")
    func secondTapWhileAQuestionIsPrepared() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        // The question takes the hold; a tap the gate let through would get
        // the reply after it at once and be counted, rather than wait.
        let held = fake.hold(.historyRecordText)
        fake.respond(.historyRecordText, text(1))
        let asking = Task { await history.revokeTapped() }
        #expect(await settle { fake.count(.historyRecordText) == 2 })
        #expect(history.isAsking)
        await history.deleteTapped()
        await history.revokeTapped()
        #expect(fake.count(.historyRecordText) == 2)
        held.release(text(1))
        await asking.value
        #expect(!history.isAsking)
        #expect(history.pendingConfirmation == revokeQuestion(1))
    }

    @Test("a Delete or Revoke tap while Revoke Instead prepares its question does nothing")
    func secondTapDuringRevokeInstead() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        fake.respond(.historyRecordText, text(1))
        await history.deleteTapped()
        fake.reset(.historyRecordText)
        let held = fake.hold(.historyRecordText)
        fake.respond(.historyRecordText, text(1))
        let alternate = Task { await history.alternate() }
        #expect(await settle { fake.count(.historyRecordText) == 3 })
        #expect(history.pendingConfirmation == nil)
        await history.deleteTapped()
        await history.revokeTapped()
        await history.removeDuplicatesTapped()
        #expect(fake.count(.historyRecordText) == 3)
        #expect(fake.count(.historyDuplicatePreview) == 0)
        held.release(text(1))
        await alternate.value
        #expect(history.pendingConfirmation == revokeQuestion(1))
    }

    @Test("Remove Duplicates while a delete question is being prepared does nothing, and the reverse")
    func removeDuplicatesAndDeleteDoNotOverlap() async {
        let fake = FakeBridge()
        let history = await selected(0, fake)
        let heldText = fake.hold(.historyRecordText)
        fake.respond(.historyRecordText, text(1))
        let deleting = Task { await history.deleteTapped() }
        #expect(await settle { fake.count(.historyRecordText) == 2 })
        await history.removeDuplicatesTapped()
        #expect(fake.count(.historyDuplicatePreview) == 0)
        heldText.release(text(1))
        await deleting.value
        #expect(history.pendingConfirmation == deleteQuestion(1))
        history.dismissConfirmation()

        let heldPreview = fake.hold(.historyDuplicatePreview)
        fake.respond(.historyDuplicatePreview, DuplicatePreviewResult(count: 1, confirmMessage: "Core asks: remove one?"))
        let previewing = Task { await history.removeDuplicatesTapped() }
        #expect(await settle { fake.count(.historyDuplicatePreview) == 1 })
        await history.deleteTapped()
        await history.revokeTapped()
        #expect(fake.count(.historyRecordText) == 2)
        heldPreview.release(DuplicatePreviewResult(count: 1, confirmMessage: "Core asks: remove one?"))
        await previewing.value
        #expect(history.pendingConfirmation?.title == "Remove Duplicates")
    }

    // MARK: Export

    @Test("export: the core's alert, as given")
    func export() async {
        let fake = FakeBridge()
        fake.respond(.historyExportIssuanceLog, ExportResult(title: "Core Log Title", message: "Core says: copied."))
        let history = await loaded(fake)
        await history.exportIssuanceLog(path: "/out/rhg-issuances-2026-01-01.json")
        #expect(fake.params(.historyExportIssuanceLog) == [#"{"path":"/out/rhg-issuances-2026-01-01.json"}"#])
        #expect(history.alert == AlertState(title: "Core Log Title", message: "Core says: copied."))
    }

    @Test("export with nothing signed: Nothing to Export with the core's message")
    func exportNothing() async {
        let fake = FakeBridge()
        let message = "No credentials have been signed on this computer yet."
        fake.fail(.historyExportIssuanceLog, RPCError(code: .nothingToExport, message: message))
        let history = await loaded(fake)
        await history.exportIssuanceLog(path: "/out/x.json")
        #expect(history.alert == AlertState(title: "Nothing to Export", message: message))
    }

    @Test("any other export failure shows the core's error")
    func exportFailure() async {
        let fake = FakeBridge()
        fake.fail(.historyExportIssuanceLog, RPCError(code: .failed, message: "Choose a folder outside the app's data folder."))
        let history = await loaded(fake)
        await history.exportIssuanceLog(path: "/data/x.json")
        #expect(
            history.alert
                == AlertState(title: "Unable to Export Issuance Log", message: "Choose a folder outside the app's data folder."))
    }

    // MARK: Remove Duplicates

    @Test("a failed preview: Remove Duplicates Failed offering the error log")
    func dedupePreviewFailure() async {
        let fake = FakeBridge()
        fake.fail(.historyDuplicatePreview, RPCError(code: .failed, message: "unreadable log"))
        let history = await loaded(fake)
        await history.removeDuplicatesTapped()
        #expect(
            history.alert == AlertState(title: "Remove Duplicates Failed", message: "unreadable log", offersErrorLogExport: true))
        #expect(history.pendingConfirmation == nil)
        #expect(!history.isAsking)
    }

    @Test("no duplicates: the status line says so, no alert, nothing asked")
    func dedupeNone() async {
        let fake = FakeBridge()
        fake.respond(.historyDuplicatePreview, DuplicatePreviewResult(count: 0, confirmMessage: ""))
        let history = await loaded(fake)
        await history.removeDuplicatesTapped()
        #expect(history.status == HistoryModel.noDuplicatesStatus)
        #expect(history.alert == nil)
        #expect(history.pendingConfirmation == nil)
        #expect(fake.count(.historyRemoveDuplicates) == 0)
    }

    @Test("duplicates found: the core's question, then its report on the status line; the list waits for history.changed")
    func dedupeConfirmed() async {
        let fake = FakeBridge()
        fake.respond(.historyDuplicatePreview, DuplicatePreviewResult(count: 2, confirmMessage: "Core asks: remove two?"))
        fake.respond(
            .historyRemoveDuplicates,
            RemoveDuplicatesResult(removed: 2, backup: "/DATA/issuances.json.bak", message: "Core says: two gone."))
        let history = await loaded(fake)
        await history.removeDuplicatesTapped()
        #expect(
            history.pendingConfirmation
                == Confirmation(
                    title: "Remove Duplicates", message: "Core asks: remove two?",
                    confirmTitle: "Remove Entries", cancelTitle: "Cancel", isDestructive: true))
        #expect(fake.count(.historyRemoveDuplicates) == 0)
        await history.confirm()
        #expect(fake.params(.historyRemoveDuplicates) == ["{}"])
        #expect(history.status == "Core says: two gone.")
        #expect(history.alert == nil)
        #expect(fake.count(.historyList) == 1)
    }

    @Test("the log changed after the preview: removed 0 says there are no duplicates, no alert")
    func dedupeRemovedNone() async {
        let fake = FakeBridge()
        fake.respond(.historyDuplicatePreview, DuplicatePreviewResult(count: 1, confirmMessage: "Core asks: remove one?"))
        fake.respond(.historyRemoveDuplicates, RemoveDuplicatesResult(removed: 0, backup: "", message: ""))
        let history = await loaded(fake)
        await history.removeDuplicatesTapped()
        await history.confirm()
        #expect(history.status == HistoryModel.noDuplicatesStatus)
        #expect(history.alert == nil)
    }

    @Test("a failed removal: Remove Duplicates Failed offering the error log")
    func dedupeRemoveFailure() async {
        let fake = FakeBridge()
        fake.respond(.historyDuplicatePreview, DuplicatePreviewResult(count: 1, confirmMessage: "Core asks: remove one?"))
        fake.fail(.historyRemoveDuplicates, RPCError(code: .failed, message: "backup failed"))
        let history = await loaded(fake)
        await history.removeDuplicatesTapped()
        await history.confirm()
        #expect(
            history.alert == AlertState(title: "Remove Duplicates Failed", message: "backup failed", offersErrorLogExport: true))
    }
}
