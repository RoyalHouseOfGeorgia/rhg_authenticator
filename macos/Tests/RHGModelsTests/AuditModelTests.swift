import Foundation
import RHGBridge
import Testing

@testable import RHGModels

@Suite("AuditModel")
@MainActor
struct AuditModelTests {
    let commitURL = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/commit/0123456789012345678901234567890123456789"

    @Test("UI copy matches the Fyne app")
    func copy() {
        #expect(AuditModel.refreshTitle == "Refresh")
        #expect(AuditModel.fetchingStatus == "Fetching...")
        #expect(AuditModel.openTitle == "Open on GitHub")
    }

    @Test("tooltips")
    func tooltips() {
        #expect(AuditModel.openTooltip == "Select a commit to open it.")
        #expect(AuditModel.refreshTooltip == "Refresh (\u{2318}R)")
    }

    /// A model whose fetch returned rows with `urls`, and its URL recorder.
    func loaded(_ urls: [String]) async -> (AuditModel, URLRecorder, FakeBridge) {
        let fake = FakeBridge()
        let rows = urls.enumerated().map { AuditRow(summary: "commit \($0.offset)", url: $0.element) }
        fake.respond(.auditCommits, AuditResult(rows: rows, status: "s"))
        let recorder = URLRecorder()
        let audit = AuditModel(bridge: fake, openURL: recorder.open)
        await audit.refresh()
        fake.reset(.auditCommits)
        return (audit, recorder, fake)
    }

    @Test("before a fetch: no rows, no status")
    func initial() {
        let audit = AuditModel(bridge: FakeBridge())
        #expect(audit.rows.isEmpty && audit.status == "" && !audit.isRefreshing)
        #expect(audit.selection == nil && !audit.canOpen)
    }

    @Test("Refresh: Fetching... while it runs, then the rows and the core's status")
    func refresh() async {
        let fake = FakeBridge()
        let held = fake.hold(.auditCommits)
        let audit = AuditModel(bridge: fake)
        let running = Task { await audit.refresh() }
        #expect(await settle { fake.count(.auditCommits) == 1 })
        #expect(audit.isRefreshing && audit.status == "Fetching...")
        let rows = [AuditRow(summary: "2026-Jan-02  Jane Doe — Add key for A", url: commitURL)]
        held.release(AuditResult(rows: rows, status: "Loaded 1 commits"))
        await running.value
        #expect(audit.rows == rows)
        #expect(audit.status == "Loaded 1 commits")
        #expect(!audit.isRefreshing)
        #expect(fake.params(.auditCommits) == ["{}"])
    }

    @Test("Refresh while a fetch runs is ignored")
    func refreshWhileRefreshing() async {
        let fake = FakeBridge()
        let held = fake.hold(.auditCommits)
        let audit = AuditModel(bridge: fake)
        let running = Task { await audit.refresh() }
        #expect(await settle { fake.count(.auditCommits) == 1 })
        await audit.refresh()
        #expect(fake.count(.auditCommits) == 1)
        held.release(AuditResult(rows: [], status: "Loaded 0 commits"))
        await running.value
        #expect(audit.status == "Loaded 0 commits")
    }

    @Test("a failed fetch shows the core's message and keeps the rows")
    func refreshFailure() async {
        let fake = FakeBridge()
        let rows = [AuditRow(summary: "c", url: commitURL)]
        fake.respond(.auditCommits, AuditResult(rows: rows, status: "Loaded 1 commits"))
        fake.fail(.auditCommits, RPCError(code: .failed, message: "GitHub API error: 503"))
        let audit = AuditModel(bridge: fake)
        await audit.refresh()
        await audit.refresh()
        #expect(audit.status == "GitHub API error: 503")
        #expect(audit.rows == rows)
        #expect(!audit.isRefreshing)
    }

    @Test("busy: the rows and status stay as they were; Refresh is enabled again")
    func refreshBusy() async {
        let fake = FakeBridge()
        fake.respond(.auditCommits, AuditResult(rows: [], status: "Loaded 0 commits"))
        fake.fail(.auditCommits, RPCError(code: .busy, message: "Another operation is in progress."))
        let audit = AuditModel(bridge: fake)
        await audit.refresh()
        await audit.refresh()
        #expect(audit.status == "Loaded 0 commits")
        #expect(!audit.isRefreshing)
    }

    @Test("selecting a row selects it and never opens the browser; nil or out of range clears")
    func select() async {
        let (audit, urls, _) = await loaded([commitURL, commitURL])
        audit.select(row: 1)
        #expect(audit.selection == 1)
        audit.select(row: 0)
        #expect(audit.selection == 0)
        #expect(urls.opened.isEmpty)
        for row in [nil, -1, 2] as [Int?] {
            audit.select(row: 0)
            audit.select(row: row)
            #expect(audit.selection == nil)
        }
        #expect(urls.opened.isEmpty)
    }

    @Test(
        "Open on GitHub is enabled only for an absolute https URL with a host",
        arguments: [
            ("", false), ("http://github.com/x", false), ("https://", false), ("github.com/x", false),
            ("https://github.com/o/r/commit/abc", true), ("HTTPS://github.com/o/r/commit/abc", true),
        ])
    func canOpen(_ url: String, _ enabled: Bool) async throws {
        let (audit, urls, _) = await loaded([url])
        #expect(!audit.canOpen)
        audit.select(row: 0)
        #expect(audit.canOpen == enabled)
        audit.openSelected()
        #expect(urls.opened == (enabled ? [try #require(URL(string: url))] : []))
    }

    @Test("Open on GitHub opens the selected commit's page; nothing without a selection")
    func openSelected() async throws {
        let other = "https://github.com/o/r/commit/def"
        let (audit, urls, _) = await loaded([commitURL, other])
        audit.openSelected()
        #expect(urls.opened.isEmpty)
        audit.select(row: 1)
        audit.openSelected()
        #expect(urls.opened == [try #require(URL(string: other))])
    }

    @Test("a successful Refresh clears the selection before replacing the rows; a failed one keeps it")
    func refreshSelection() async {
        let (audit, _, fake) = await loaded([commitURL, commitURL])
        audit.select(row: 1)
        fake.fail(.auditCommits, RPCError(code: .failed, message: "GitHub API error: 503"))
        await audit.refresh()
        #expect(audit.selection == 1 && audit.canOpen)
        fake.reset(.auditCommits)
        fake.respond(.auditCommits, AuditResult(rows: [AuditRow(summary: "c", url: commitURL)], status: "Loaded 1 commits"))
        await audit.refresh()
        #expect(audit.selection == nil && !audit.canOpen)
        #expect(audit.rows.count == 1)
    }
}
