import Foundation
import RHGBridge
import Testing

@testable import RHGModels

/// 2026-01-01T23:30:00Z.
let lateNewYearsDay = Date(timeIntervalSince1970: 1_767_310_200)

@Suite("SignModel")
@MainActor
struct SignModelTests {
    /// A model whose form is filled in, with the clock at `lateNewYearsDay`.
    func filledModel(_ fake: FakeBridge, openURL: @escaping @MainActor (URL) -> Void = { _ in }) -> SignModel {
        let model = SignModel(bridge: fake, clock: { lateNewYearsDay }, openURL: openURL)
        model.recipient = "Jose\u{301}"  // NFD; the core signs NFC
        model.honor = "Order of the Eagle"
        model.detail = "Knight"
        return model
    }

    let credentialJSON =
        #"{"date":"2026-01-01","detail":"Knight","honor":"Order of the Eagle","recipient":"Jose\#u{301}"}"#

    @Test("UI copy matches the Fyne app")
    func copy() {
        #expect(SignModel.honorPlaceholder == "Select honor title")
        #expect(SignModel.recipientPlaceholder == "Full name of recipient")
        #expect(SignModel.detailPlaceholder == "Specific distinction or rank")
        #expect(SignModel.signTitle == "Sign Credential")
        let advisory: [UInt8] = Array("Print QR at minimum 3".utf8) + [0xC3, 0x97] + Array("3 cm".utf8)  // U+00D7
        #expect(Array(SignModel.printAdvisory.utf8) == advisory)
        #expect([SignModel.saveSVGTitle, SignModel.savePNGTitle, SignModel.copyURLTitle] == ["Save SVG", "Save PNG", "Copy URL"])
        let reporting: [UInt8] = Array("Reporting".utf8) + [0xE2, 0x80, 0xA6]  // U+2026
        #expect(Array(SignModel.reportingTitle.utf8) == reporting)
    }

    @Test("a validation error shows the core's message and never signs")
    func validationError() async {
        let fake = FakeBridge()
        fake.fail(.signValidate, RPCError(code: .failed, message: "Recipient name is required."))
        let model = filledModel(fake)
        await model.sign()
        #expect(model.status == "Recipient name is required.")
        #expect(!model.isBusy)
        #expect(model.result == nil)
        #expect(fake.methods == ["sign.validate"])
        #expect(fake.params(.signValidate) == [credentialJSON])
    }

    @Test("success: the result holds the signed (NFC) fields, not the form text")
    func success() async {
        let fake = FakeBridge()
        let signed = signResult()
        fake.respond(.signSign, signed)
        let model = filledModel(fake)
        await model.sign()
        #expect(model.status == "Signed successfully.")
        #expect(model.alert == nil)
        #expect(!model.isBusy)
        #expect(model.result == signed)
        #expect(Array(model.result!.recipient.utf8) == Array("Jos\u{E9}".utf8))
        #expect(Array(model.result!.recipient.utf8) != Array(model.recipient.utf8))
        #expect(fake.methods == ["sign.validate", "sign.sign"])
        #expect(fake.params(.signSign) == [credentialJSON])
        #expect(model.report == .unavailable)
    }

    @Test("an existing credential: status and Already Issued alert")
    func existing() async {
        let fake = FakeBridge()
        fake.respond(.signSign, signResult(existing: true, warning: "ignored"))
        let model = filledModel(fake)
        await model.sign()
        #expect(model.status == "Credential previously generated.")
        #expect(
            model.alert
                == AlertState(title: "Already Issued", message: "Credential previously generated, no new record created."))
        #expect(model.result?.existing == true)
    }

    @Test("a warning: status and Not Recorded alert")
    func warning() async {
        let fake = FakeBridge()
        fake.respond(.signSign, signResult(warning: "Signed, but the issuance log could not be written."))
        let model = filledModel(fake)
        await model.sign()
        #expect(model.status == "Signed, but the issuance log could not be written.")
        #expect(
            model.alert == AlertState(title: "Not Recorded", message: "Signed, but the issuance log could not be written."))
        #expect(model.result != nil)
    }

    @Test("an error without offerReport shows its message, no report button")
    func plainError() async {
        let fake = FakeBridge()
        fake.fail(.signSign, RPCError(code: .failed, message: "No YubiKey detected."))
        let model = filledModel(fake)
        await model.sign()
        #expect(model.status == "No YubiKey detected.")
        #expect(model.report == .unavailable)
        #expect(model.report.buttonTitle == nil)
        #expect(!model.report.isButtonEnabled)
        #expect(model.result == nil)
        #expect(!model.isBusy)
    }

    @Test("a cancelled PIN prompt clears the status")
    func cancelled() async {
        let fake = FakeBridge()
        fake.fail(.signSign, RPCError(code: .cancelled, message: "cancelled"))
        let model = filledModel(fake)
        await model.sign()
        #expect(model.status == "")
        #expect(!model.isBusy)
    }

    @Test("Report Issue: reporting, then filed (Issue Reported, disabled for good)")
    func reportFiled() async {
        let fake = FakeBridge()
        let urls = URLRecorder()
        fake.fail(.signSign, RPCError(code: .failed, message: "Signing failed.", offerReport: true, reportId: "r1"))
        let held = fake.hold(.signReportError)
        let model = filledModel(fake, openURL: urls.open)
        await model.sign()
        #expect(model.status == "Signing failed.")
        #expect(model.report == .available(reportId: "r1"))
        #expect(model.report.buttonTitle == "Report Issue")
        #expect(model.report.isButtonEnabled)

        let reporting = Task { await model.reportIssue() }
        #expect(await settle { fake.count(.signReportError) == 1 })
        #expect(model.report == .reporting(reportId: "r1"))
        #expect(model.report.buttonTitle == "Reporting\u{2026}")
        #expect(!model.report.isButtonEnabled)
        await model.reportIssue()  // ignored while reporting
        held.release(ReportResult(filed: true, url: ""))
        await reporting.value

        #expect(model.report == .reported)
        #expect(model.report.buttonTitle == "Issue Reported")
        #expect(!model.report.isButtonEnabled)
        #expect(urls.opened.isEmpty)
        await model.reportIssue()
        #expect(fake.params(.signReportError) == [#"{"reportId":"r1"}"#])
    }

    @Test("Report Issue not filed: opens the core's URL and re-enables")
    func reportBrowserForm() async {
        let fake = FakeBridge()
        let urls = URLRecorder()
        fake.fail(.signSign, RPCError(code: .failed, message: "m", offerReport: true, reportId: "r2"))
        let form = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues/new?title=Sign%20failure"
        fake.respond(.signReportError, ReportResult(filed: false, url: form))
        let model = filledModel(fake, openURL: urls.open)
        await model.sign()
        await model.reportIssue()
        #expect(urls.opened == [URL(string: form)!])
        #expect(model.report == .available(reportId: "r2"))
        #expect(model.report.buttonTitle == "Report Issue")
    }

    @Test("without an openURL hook a returned URL is dropped", arguments: [false, true])
    func reportDefaultOpenURL(viaApp: Bool) async {
        let fake = FakeBridge()
        fake.fail(.signSign, RPCError(code: .failed, message: "m", offerReport: true, reportId: "r5"))
        fake.respond(.signReportError, ReportResult(filed: false, url: "https://github.com/o/r/issues/new"))
        let model = viaApp ? AppModel(bridge: fake).sign : SignModel(bridge: fake)
        await model.sign()
        await model.reportIssue()
        #expect(model.report == .available(reportId: "r5"))
    }

    @Test("Report Issue failure re-enables without opening anything")
    func reportFailure() async {
        let fake = FakeBridge()
        let urls = URLRecorder()
        fake.fail(.signSign, RPCError(code: .failed, message: "m", offerReport: true, reportId: "r3"))
        fake.fail(.signReportError, RPCError(code: .failed, message: "offline"))
        let model = filledModel(fake, openURL: urls.open)
        await model.sign()
        await model.reportIssue()
        #expect(urls.opened.isEmpty)
        #expect(model.report == .available(reportId: "r3"))
    }

    @Test("a new signing during a report keeps its own report state")
    func reportOverlappedBySign() async {
        let fake = FakeBridge()
        fake.fail(.signSign, RPCError(code: .failed, message: "m", offerReport: true, reportId: "r4"))
        let held = fake.hold(.signReportError)
        let model = filledModel(fake)
        await model.sign()
        let reporting = Task { await model.reportIssue() }
        #expect(await settle { fake.count(.signReportError) == 1 })
        fake.fail(.signValidate, RPCError(code: .failed, message: "invalid"))
        await model.sign()
        #expect(model.report == .unavailable)
        held.release(ReportResult(filed: false, url: ""))
        await reporting.value
        #expect(model.report == .unavailable)
    }

    @Test("busy: a second sign is ignored; connecting shows only while busy")
    func busyAndConnecting() async {
        let fake = FakeBridge()
        let held = fake.hold(.signSign)
        let app = await startedApp(fake, clock: { lateNewYearsDay })
        let model = app.sign
        model.honor = "Order of the Eagle"
        let signing = Task { await model.sign() }
        #expect(await settle { fake.count(.signSign) == 1 })
        #expect(model.isBusy)
        #expect(model.status == "Preparing to sign...")
        await model.sign()
        #expect(fake.count(.signValidate) == 1)

        fake.emit(.signConnecting)
        #expect(await settle { model.status == "Connecting to YubiKey..." })
        held.release(signResult())
        await signing.value
        #expect(!model.isBusy)
        #expect(model.status == "Signed successfully.")
        #expect(fake.count(.signSign) == 1)

        // A late connecting event is ignored (events are handled in order).
        fake.emit(.signConnecting)
        fake.emit(.appInternalError)
        #expect(await settle { app.internalErrorMessage != nil })
        #expect(model.status == "Signed successfully.")
    }

    @Test("a new signing clears the previous result")
    func clearsResult() async {
        let fake = FakeBridge()
        fake.respond(.signSign, signResult())
        let model = filledModel(fake)
        await model.sign()
        #expect(model.result != nil)
        fake.fail(.signValidate, RPCError(code: .failed, message: "invalid"))
        await model.sign()
        #expect(model.result == nil)
    }

    // MARK: Dates

    @Test("the date defaults to the clock's UTC calendar date, whatever the zone")
    func utcDate() throws {
        let fake = FakeBridge()
        let model = SignModel(bridge: fake, clock: { lateNewYearsDay })
        #expect(model.dateString == "2026-01-01")
        #expect(model.displayDate == "2026-Jan-01")

        // 2026-01-02T01:30 in Tbilisi (+04:00) is still 2026-01-01 in UTC.
        var tbilisi = Calendar(identifier: .gregorian)
        tbilisi.timeZone = try #require(TimeZone(identifier: "Asia/Tbilisi"))
        let local = try #require(tbilisi.date(from: DateComponents(year: 2026, month: 1, day: 2, hour: 1, minute: 30)))
        model.date = local
        #expect(tbilisi.component(.day, from: local) == 2)
        #expect(model.dateString == "2026-01-01")
    }

    @Test("the default clock is now")
    func defaultClock() {
        let model = SignModel(bridge: FakeBridge())
        #expect(abs(model.date.timeIntervalSinceNow) < 60)
        #expect(model.dateString == DisplayDate.ymd(Date()))
    }

    @Test(
        "DisplayDate formats YYYY-MM-DD as YYYY-Mon-DD",
        arguments: [
            ("2026-01-02", "2026-Jan-02"), ("2026-02-28", "2026-Feb-28"), ("2026-03-15", "2026-Mar-15"),
            ("2026-04-01", "2026-Apr-01"), ("2026-05-01", "2026-May-01"), ("2026-06-01", "2026-Jun-01"),
            ("2026-07-01", "2026-Jul-01"), ("2026-08-01", "2026-Aug-01"), ("2026-09-01", "2026-Sep-01"),
            ("2026-10-19", "2026-Oct-19"), ("2026-11-01", "2026-Nov-01"), ("2026-12-31", "2026-Dec-31"),
        ])
    func displayDate(_ ymd: String, _ shown: String) {
        #expect(DisplayDate.format(ymd) == shown)
    }

    @Test(
        "DisplayDate leaves other text unchanged",
        arguments: ["", "2026-01", "2026-13-01", "2026-00-01", "2026-1-02", "26-01-02", "2026-+1-02", "abcd-01-02",
            "2026-01-02-03", "2026/01/02", "２０２６-01-02"])
    func displayDateInvalid(_ text: String) {
        #expect(DisplayDate.format(text) == text)
    }

    // MARK: Saving

    @Test("save: sends the result's URL; suggested names come from the result")
    func saveSuccess() async {
        let fake = FakeBridge()
        fake.respond(.signSign, signResult())
        let model = filledModel(fake)
        #expect(model.suggestedFilename(for: .svg) == "")
        #expect(model.suggestedFilename(for: .png) == "")
        await model.saveQR(format: .svg, path: "/out/a.svg")
        #expect(fake.count(.signSaveQR) == 0)

        await model.sign()
        #expect(model.suggestedFilename(for: .svg) == "rhg-0123abcd.svg")
        #expect(model.suggestedFilename(for: .png) == "rhg-0123abcd.png")
        await model.saveQR(format: .png, path: "/out/a.png")
        #expect(model.alert == nil)
        #expect(
            fake.params(.signSaveQR)
                == [#"{"format":"png","path":"/out/a.png","url":"https://verify.royalhouseofgeorgia.ge/?p=abc"}"#])
    }

    @Test("save failure shows the core's message", arguments: [QRFormat.svg, .png])
    func saveFailure(_ format: QRFormat) async {
        let fake = FakeBridge()
        fake.respond(.signSign, signResult())
        fake.fail(.signSaveQR, RPCError(code: .failed, message: "Choose a folder outside the app's data folder."))
        let model = filledModel(fake)
        await model.sign()
        await model.saveQR(format: format, path: "/out/a")
        #expect(model.alert == AlertState(title: "Error", message: "Choose a folder outside the app's data folder."))
    }

    @Test("loadHonors fills the picker")
    func loadHonors() async throws {
        let fake = FakeBridge()
        fake.respond(.signHonors, HonorsResult(honors: ["X"]))
        let model = SignModel(bridge: fake)
        try await model.loadHonors()
        #expect(model.honors == ["X"])
    }
}
