import Foundation
import RHGBridge
import Testing

@testable import RHGModels

func bulkPlan(toSign: Int = 2, invalid: [String] = ["line 4: honor: not one of the allowed honor titles"]) -> BulkLoadResult {
    BulkLoadResult(
        toSign: toSign, countsLine: "3 rows: \(toSign) to sign, 0 already issued, \(invalid.count) invalid",
        previewNames: Array(["Jane Doe", "Carol White"].prefix(toSign)), invalidLines: invalid)
}

func bulkOutcome(_ stopped: BulkStop = .completed, stopMessage: String = "", failed: [String] = []) -> BulkRunResult {
    BulkRunResult(
        stopped: stopped, summaryLine: "Processed 3 rows: 2 successful (2 newly signed, 0 already issued), 1 invalid, 0 failed/not attempted.",
        stopMessage: stopMessage, failedLines: failed, resultsFilename: "rhg-bulk-results-2026-01-02-030405.csv")
}

@Suite("BulkModel")
@MainActor
struct BulkModelTests {
    /// The running phase's state; nil when not running.
    func run(_ model: BulkModel) -> BulkModel.Run? {
        if case .running(let run) = model.phase { return run }
        return nil
    }

    @Test("UI copy matches the Fyne app")
    func copy() {
        #expect(Array(BulkModel.bulkSignTitle.utf8) == Array("Bulk Sign from File".utf8) + [0xE2, 0x80, 0xA6])
        #expect([BulkModel.title, BulkModel.signTitle, BulkModel.cancelTitle] == ["Bulk Sign", "Sign", "Cancel"])
        #expect(BulkModel.previewHeading == "First names to be signed:")
        #expect(BulkModel.invalidToSkipHeading == "Invalid rows (will be skipped):")
        #expect(Array(BulkModel.resultsTitle.utf8) == Array("Bulk Sign ".utf8) + [0xE2, 0x80, 0x94] + Array(" Results".utf8))
        #expect(BulkModel.failedHeading == "Failed rows:")
        #expect(BulkModel.invalidSkippedHeading == "Invalid rows (skipped):")
        #expect(Array(BulkModel.exportTitle.utf8) == Array("Export Results CSV".utf8) + [0xE2, 0x80, 0xA6])
        #expect(BulkModel.regenerateNote == "Re-open the same file to regenerate results later.")
        #expect(BulkModel.closeTitle == "Close")
        #expect(BulkModel.connectingLabel == "Connecting to YubiKey...")
        #expect(Array(BulkModel.stoppingLabel.utf8) == Array("Stopping after current row".utf8) + [0xE2, 0x80, 0xA6])
    }

    @Test("happy path: load, confirm, run with progress, results, close")
    func happyPath() async {
        let fake = FakeBridge()
        let plan = bulkPlan()
        fake.respond(.bulkLoad, plan)
        let held = fake.hold(.bulkRun)
        let app = await startedApp(fake)
        let model = app.bulk
        #expect(model.phase == .idle && !model.isActive && !app.isSigningBusy)

        #expect(model.begin())
        #expect(model.phase == .choosingFile && model.isActive && app.isSigningBusy)
        #expect(!model.isShowingSheet)
        await model.fileChosen(path: "/in/bulk.csv")
        #expect(model.phase == .confirming(plan))
        #expect(app.isSigningBusy && model.isShowingSheet)
        #expect(fake.params(.bulkLoad) == [#"{"path":"/in/bulk.csv"}"#])
        #expect(model.suggestedResultsFilename == "")

        let running = Task { await model.confirm() }
        #expect(await settle { fake.count(.bulkRun) == 1 })
        #expect(run(model) == BulkModel.Run())
        #expect(model.isShowingSheet)  // from confirm on, so the PIN prompt stacks on it
        #expect(run(model)?.label == "Connecting to YubiKey...")
        #expect(run(model)?.fraction == 0)
        #expect(run(model)?.isCancelEnabled == true)

        fake.emit(.bulkProgress(BulkProgress(done: 0, total: 2, name: "Jane Doe")))
        #expect(await settle { run(model)?.progress != nil })
        #expect(run(model)?.label == "Signing 1 of 2: Jane Doe \u{2014} touch your YubiKey if it is blinking")
        #expect(run(model)?.fraction == 0)
        fake.emit(.bulkProgress(BulkProgress(done: 1, total: 2, name: "Carol White")))
        #expect(await settle { run(model)?.progress?.done == 1 })
        #expect(run(model)?.label == "Signing 2 of 2: Carol White \u{2014} touch your YubiKey if it is blinking")
        #expect(run(model)?.fraction == 0.5)
        #expect(app.isSigningBusy)

        let outcome = bulkOutcome()
        held.release(outcome)
        await running.value
        #expect(model.phase == .results(plan: plan, outcome: outcome))
        #expect(model.suggestedResultsFilename == "rhg-bulk-results-2026-01-02-030405.csv")
        #expect(app.isSigningBusy && model.isShowingSheet)
        #expect(model.alert == nil)
        #expect(fake.count(.bulkCancel) == 0)

        model.closeResults()
        #expect(model.phase == .idle && !app.isSigningBusy && !model.isShowingSheet)
        #expect(fake.params(.bulkRun) == ["{}"])
    }

    @Test("nothing to sign: runs at once, without the confirm step or a progress sheet")
    func nothingToSign() async {
        let fake = FakeBridge()
        let plan = bulkPlan(toSign: 0)
        fake.respond(.bulkLoad, plan)
        let held = fake.hold(.bulkRun)
        let model = BulkModel(bridge: fake)
        model.begin()
        let loading = Task { await model.fileChosen(path: "/in/done.csv") }
        #expect(await settle { fake.count(.bulkRun) == 1 })
        #expect(model.phase == .loading && !model.isShowingSheet && model.isActive)
        await model.cancelRun()  // no progress sheet, no Cancel
        let outcome = bulkOutcome()
        held.release(outcome)
        await loading.value
        #expect(model.phase == .results(plan: plan, outcome: outcome))
        #expect(fake.methods == ["bulk.load", "bulk.run"])
    }

    @Test("nothing to sign, run error: the alert shows over the tab and the flow ends")
    func nothingToSignRunError() async {
        let fake = FakeBridge()
        fake.respond(.bulkLoad, bulkPlan(toSign: 0))
        fake.fail(.bulkRun, RPCError(code: .busy, message: "Another operation is in progress."))
        let model = BulkModel(bridge: fake)
        model.begin()
        await model.fileChosen(path: "/in/done.csv")
        #expect(model.phase == .idle)
        #expect(model.isShowingTabAlert && !model.isShowingSheetAlert)
        #expect(model.alert == AlertState(title: "Error", message: "Another operation is in progress."))
    }

    @Test("a load error shows the core's message and ends the flow")
    func loadError() async {
        let fake = FakeBridge()
        fake.fail(.bulkLoad, RPCError(code: .failed, message: "Could not open the CSV file."))
        let model = BulkModel(bridge: fake)
        model.begin()
        await model.fileChosen(path: "/in/x.csv")
        #expect(model.phase == .idle && !model.isActive)
        #expect(model.alert == AlertState(title: "Error", message: "Could not open the CSV file."))
        #expect(model.isShowingTabAlert && !model.isShowingSheetAlert)
        #expect(fake.count(.bulkRun) == 0)
        model.dismissAlert()
        #expect(model.alert == nil && model.phase == .idle)
    }

    @Test("a run error shows the core's message over the progress sheet; dismissing it ends the flow")
    func runError() async {
        let fake = FakeBridge()
        fake.respond(.bulkLoad, bulkPlan())
        fake.fail(
            .bulkRun,
            RPCError(code: .failed, message: "Registry unavailable — cannot sign offline.", offerReport: true, reportId: "9"))
        let model = BulkModel(bridge: fake)
        model.begin()
        await model.fileChosen(path: "/in/x.csv")
        await model.confirm()
        // The sheet stays up under the alert, so it never closes while the
        // alert presents; no report is offered.
        #expect(run(model) == BulkModel.Run())
        #expect(model.isShowingSheetAlert && !model.isShowingTabAlert)
        #expect(model.alert == AlertState(title: "Error", message: "Registry unavailable — cannot sign offline."))
        await model.cancelRun()  // the run is over: nothing to cancel
        #expect(fake.count(.bulkCancel) == 0)
        model.dismissAlert()
        #expect(model.phase == .idle && model.alert == nil && !model.isActive)
    }

    @Test("cancel mid-run: bulk.cancel, Stopping label kept through later progress, cancelled results")
    func cancelMidRun() async {
        let fake = FakeBridge()
        let plan = bulkPlan()
        fake.respond(.bulkLoad, plan)
        let held = fake.hold(.bulkRun)
        let app = await startedApp(fake)
        let model = app.bulk
        model.begin()
        await model.fileChosen(path: "/in/x.csv")
        let running = Task { await model.confirm() }
        #expect(await settle { fake.count(.bulkRun) == 1 })
        fake.emit(.bulkProgress(BulkProgress(done: 0, total: 3, name: "Jane Doe")))
        #expect(await settle { run(model)?.progress != nil })

        await model.cancelRun()
        #expect(fake.count(.bulkCancel) == 1)
        #expect(run(model)?.stopping == true)
        #expect(run(model)?.label == "Stopping after current row\u{2026}")
        #expect(run(model)?.isCancelEnabled == false)
        await model.cancelRun()  // ignored while stopping
        #expect(fake.count(.bulkCancel) == 1)

        fake.emit(.bulkProgress(BulkProgress(done: 1, total: 3, name: "Carol White")))
        #expect(await settle { run(model)?.progress?.done == 1 })
        #expect(run(model)?.label == "Stopping after current row\u{2026}")
        #expect(abs((run(model)?.fraction ?? 0) - 1.0 / 3.0) < 1e-9)

        let outcome = bulkOutcome(.cancelled, stopMessage: "Cancelled.")
        held.release(outcome)
        await running.value
        #expect(model.phase == .results(plan: plan, outcome: outcome))
    }

    @Test("a bulk.cancel failure is ignored: the run reports its own outcome")
    func cancelFailure() async {
        let fake = FakeBridge()
        fake.respond(.bulkLoad, bulkPlan())
        fake.fail(.bulkCancel, RPCError(code: .internal, message: "x"))
        let held = fake.hold(.bulkRun)
        let model = BulkModel(bridge: fake)
        model.begin()
        await model.fileChosen(path: "/in/x.csv")
        let running = Task { await model.confirm() }
        #expect(await settle { fake.count(.bulkRun) == 1 })
        await model.cancelRun()
        #expect(model.alert == nil)
        #expect(run(model)?.stopping == true)
        held.release(bulkOutcome(.cancelled))
        await running.value
        #expect(model.alert == nil)
    }

    @Test("progress events outside a run are ignored")
    func eventsOutsideRun() async {
        let fake = FakeBridge()
        fake.respond(.bulkLoad, bulkPlan())
        let held = fake.hold(.bulkRun)
        let app = await startedApp(fake)
        let model = app.bulk

        fake.emit(.bulkProgress(BulkProgress(done: 0, total: 2, name: "Jane Doe")))
        fake.emit(.appInternalError)  // a marker: events are handled in order
        #expect(await settle { app.internalErrorMessage != nil })
        #expect(model.phase == .idle)

        model.begin()
        await model.fileChosen(path: "/in/x.csv")
        let running = Task { await model.confirm() }
        #expect(await settle { fake.count(.bulkRun) == 1 })
        fake.emit(.bulkProgress(BulkProgress(done: 0, total: 2, name: "Jane Doe")))
        #expect(await settle { run(model)?.progress != nil })
        held.release(bulkOutcome())
        await running.value

        app.internalErrorMessage = nil
        fake.emit(.bulkProgress(BulkProgress(done: 1, total: 2, name: "Carol White")))
        fake.emit(.appInternalError)
        #expect(await settle { app.internalErrorMessage != nil })
        #expect(model.phase == .results(plan: bulkPlan(), outcome: bulkOutcome()))
    }

    @Test("a progress fraction with total 0 is 0")
    func zeroTotal() {
        #expect(BulkModel.Run(progress: BulkProgress(done: 0, total: 0, name: "")).fraction == 0)
    }

    @Test("picker and confirm cancels end the flow without calling the core")
    func cancels() async {
        let fake = FakeBridge()
        fake.respond(.bulkLoad, bulkPlan())
        let model = BulkModel(bridge: fake)
        #expect(model.begin())
        #expect(!model.begin())  // ignored while under way
        #expect(model.phase == .choosingFile)
        model.pickerCancelled()
        #expect(model.phase == .idle)

        model.begin()
        await model.fileChosen(path: "/in/x.csv")
        model.cancelConfirm()
        #expect(model.phase == .idle)
        #expect(fake.methods == ["bulk.load"])
    }

    @Test("actions out of their phase are ignored")
    func outOfPhase() async {
        let fake = FakeBridge()
        let model = BulkModel(bridge: fake)
        await model.fileChosen(path: "/in/x.csv")
        await model.confirm()
        await model.cancelRun()
        model.pickerCancelled()
        model.cancelConfirm()
        model.closeResults()
        #expect(model.phase == .idle)
        #expect(fake.methods.isEmpty)

        fake.respond(.bulkLoad, bulkPlan())
        model.begin()
        await model.fileChosen(path: "/in/x.csv")
        model.pickerCancelled()
        model.closeResults()
        #expect(model.phase == .confirming(bulkPlan()))
    }

    @Test("export: sends the chosen path; success shows nothing")
    func exportSuccess() async {
        let fake = FakeBridge()
        let model = BulkModel(bridge: fake)
        await model.exportResults(path: "/out/results.csv")
        #expect(model.alert == nil)
        #expect(fake.params(.bulkExportResults) == [#"{"path":"/out/results.csv"}"#])
    }

    @Test("export failure shows the core's message over the results sheet, which stays")
    func exportFailure() async {
        let fake = FakeBridge()
        let plan = bulkPlan(toSign: 0)
        fake.respond(.bulkLoad, plan)
        fake.respond(.bulkRun, bulkOutcome())
        fake.fail(.bulkExportResults, RPCError(code: .busy, message: "Another YubiKey operation is running."))
        let model = BulkModel(bridge: fake)
        model.begin()
        await model.fileChosen(path: "/in/done.csv")
        await model.exportResults(path: "/out/results.csv")
        #expect(model.alert == AlertState(title: "Error", message: "Another YubiKey operation is running."))
        #expect(model.isShowingSheetAlert && !model.isShowingTabAlert)
        model.dismissAlert()
        #expect(model.alert == nil && model.phase == .results(plan: plan, outcome: bulkOutcome()))
    }

    @Test("isSigningBusy: a signing or a bulk flow, without coupling the two")
    func sharedBusy() async {
        let fake = FakeBridge()
        let held = fake.hold(.signSign)
        let app = await startedApp(fake)
        let signing = Task { await app.sign.sign() }
        #expect(await settle { fake.count(.signSign) == 1 })
        #expect(app.isSigningBusy && !app.bulk.isActive)
        held.release(signResult())
        await signing.value
        #expect(!app.isSigningBusy)
        app.bulk.begin()
        #expect(app.isSigningBusy && !app.sign.isBusy)
        app.bulk.pickerCancelled()
        #expect(!app.isSigningBusy)
    }
}
