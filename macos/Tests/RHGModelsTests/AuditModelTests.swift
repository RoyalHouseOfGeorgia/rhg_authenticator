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
    }

    @Test("before a fetch: no rows, no status")
    func initial() {
        let audit = AuditModel(bridge: FakeBridge())
        #expect(audit.rows.isEmpty && audit.status == "" && !audit.isRefreshing)
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

    @Test("selecting a row opens its commit page; no URL or out of range opens nothing")
    func open() async throws {
        let fake = FakeBridge()
        fake.respond(
            .auditCommits,
            AuditResult(rows: [AuditRow(summary: "a", url: commitURL), AuditRow(summary: "b", url: "")], status: "s"))
        let urls = URLRecorder()
        let audit = AuditModel(bridge: fake, openURL: urls.open)
        await audit.refresh()
        audit.open(row: 1)
        audit.open(row: 2)
        audit.open(row: -1)
        #expect(urls.opened.isEmpty)
        audit.open(row: 0)
        #expect(urls.opened == [try #require(URL(string: commitURL))])
    }
}
