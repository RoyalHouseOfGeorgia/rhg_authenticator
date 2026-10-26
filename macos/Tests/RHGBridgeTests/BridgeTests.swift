import Foundation
import RHGBridge
import Testing

@Suite("Envelopes and errors")
struct EnvelopeTests {
    @Test("an unknown error code decodes, keeping its raw value")
    func unknownCode() throws {
        let data = Data(#"{"ok":false,"error":{"code":"brandNew","message":"m","offerReport":false}}"#.utf8)
        let error = try #require(throws: RPCError.self) { _ = try RPCEnvelope.decode(data, as: Empty.self) }
        #expect(error.code == .unknown("brandNew"))
        #expect(error.code.rawValue == "brandNew")
        #expect(error.message == "m")
    }

    @Test("missing reportId is nil; missing offerReport is false")
    func optionalErrorFields() throws {
        let data = Data(#"{"ok":false,"error":{"code":"failed","message":"m"}}"#.utf8)
        let error = try #require(throws: RPCError.self) { _ = try RPCEnvelope.decode(data, as: Empty.self) }
        #expect(error == RPCError(code: .failed, message: "m"))
        #expect(error.reportId == nil && !error.offerReport)
    }

    @Test(
        "an undecodable response is badResponse",
        arguments: [
            "", "not json", "[]", #"{"result":{}}"#, #"{"ok":true}"#, #"{"ok":false}"#,
            #"{"ok":true,"result":{"dirty":"yes"}}"#, #"{"ok":false,"error":{"code":"failed"}}"#,
        ])
    func badResponse(_ body: String) throws {
        let error = try #require(throws: RPCError.self) {
            _ = try RPCEnvelope.decode(Data(body.utf8), as: CanQuitResult.self)
        }
        #expect(error == .badResponse)
        #expect(error.code == .internal && !error.offerReport)
    }

    @Test("CanonicalJSON sorts keys and escapes neither slashes nor non-ASCII")
    func canonicalEncoding() throws {
        let params = SaveQRParams(url: "https://x/ნ?a=é", format: .png, path: "/OUT/a.png")
        let json = String(decoding: try CanonicalJSON.encode(params), as: UTF8.self)
        #expect(json == #"{"format":"png","path":"/OUT/a.png","url":"https://x/ნ?a=é"}"#)
    }

    @Test("a nil update notice encodes as null, as the core sends it")
    func updatedNull() throws {
        let result = UpdateCurrentResult(
            status: UpdateStatus(state: .idle, version: "", releaseUrl: "", moveToApplications: false), updated: nil)
        let json = String(decoding: try CanonicalJSON.encode(result), as: UTF8.self)
        #expect(json.hasSuffix(#""updated":null}"#))
        #expect(try RPCEnvelope.decode(Data((#"{"ok":true,"result":"# + json + "}").utf8), as: UpdateCurrentResult.self) == result)
    }
}

@Suite("Result enums")
struct ResultEnumTests {
    @Test("unknown values decode to .unknown and keep their raw value")
    func unknownValues() throws {
        let decoder = JSONDecoder()
        let raw = Data(#""later""#.utf8)
        #expect(try decoder.decode(UpdateState.self, from: raw) == .unknown("later"))
        #expect(try decoder.decode(BulkStop.self, from: raw) == .unknown("later"))
        #expect(try decoder.decode(RevokeStatus.self, from: raw) == .unknown("later"))
        #expect(try decoder.decode(KeyCheckResult.self, from: raw) == .unknown("later"))
        #expect(UpdateState.unknown("later").rawValue == "later")
        #expect(BulkStop.unknown("later").rawValue == "later")
        #expect(RevokeStatus.unknown("later").rawValue == "later")
        #expect(KeyCheckResult.unknown("later").rawValue == "later")
    }
}

@Suite("Events")
struct EventTests {
    @Test("an unknown event name decodes to .unknown(name) with data null on re-encode")
    func unknownEvent() throws {
        let event = BridgeEvent(json: Data(#"{"event":"new.thing","data":{"x":1}}"#.utf8))
        #expect(event == .unknown("new.thing"))
        #expect(event.name == "new.thing")
        #expect(try CanonicalJSON.encode(event) == Data(#"{"data":null,"event":"new.thing"}"#.utf8))
    }

    @Test(
        "malformed event JSON never crashes and becomes .unknown",
        arguments: [
            ("", ""), ("{", ""), ("[]", ""), (#"{"data":null}"#, ""), (#"{"event":7}"#, ""),
            (#"{"event":"pin.request","data":null}"#, "pin.request"),
            (#"{"event":"pin.request","data":{"requestId":"x"}}"#, "pin.request"),
            (#"{"event":"update.status"}"#, "update.status"),
        ])
    func malformedEvent(_ json: String, _ name: String) {
        #expect(BridgeEvent(json: Data(json.utf8)) == .unknown(name))
    }

    @Test("a known event with a bad payload throws in the strict decoder")
    func strictDecode() {
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(BridgeEvent.self, from: Data(#"{"event":"pin.dismiss","data":{}}"#.utf8))
        }
    }
}

@Suite("PIN handling")
struct PINTests {
    @Test("truncatePIN cuts between scalars, counting UTF-8 bytes")
    func truncation() {
        // A decomposed é: the combining mark (2 bytes) does not fit.
        #expect(Array(truncatePIN("123456e\u{301}", maxBytes: 8).utf8) == Array("123456e".utf8))
        // A precomposed é (2 bytes) fits exactly.
        #expect(Array(truncatePIN("123456\u{E9}", maxBytes: 8).utf8) == Array("123456\u{E9}".utf8))
        // A flag is two 4-byte scalars and one Character: only the first fits.
        #expect(Array(truncatePIN("\u{1F1EC}\u{1F1EA}", maxBytes: 7).utf8) == Array("\u{1F1EC}".utf8))
        #expect(truncatePIN("1234", maxBytes: -1).isEmpty)
    }

    @Test("pin.submit params never print, debug-print or dump the PIN")
    func redaction() {
        let params = PINSubmitParams(requestId: 7, pin: "secret-987", remember: true)
        var dumped = ""
        dump(params, to: &dumped)
        for text in [String(describing: params), String(reflecting: params), "\(params)", dumped] {
            #expect(!text.contains("secret-987"))
            #expect(text.contains("<redacted>"))
        }
        #expect(params.description.contains("requestId: 7"))
    }
}

@Suite("Typed Bridge helpers")
struct HelperTests {
    /// Each helper's method and canonical params, answered with the
    /// contract's result.json for that method.
    @Test("each helper sends its method and contract-shaped params and decodes the contract result")
    func helpers() async throws {
        var responses: [String: Data] = [:]
        for method in RPCMethod.allCases {
            responses[method.rawValue] = try contractFile("methods/\(method.rawValue)/result.json")
        }
        let bridge = RecordingBridge(responses: responses)
        let credential = CredentialParams(recipient: "Jane Doe", honor: "Ennoblement", detail: "For service", date: "2026-01-02")
        let signURL = try JSONDecoder().decode(
            SaveQRParams.self, from: contractFile("methods/sign.saveQR/params.json")
        ).url

        #expect(try await bridge.initApp(dataDir: "/DATA").activeKeys == 1)
        try await bridge.startApp()
        #expect(try await bridge.appInfo().version == "dev")
        #expect(try await bridge.canQuit().dirty)
        try await bridge.shutdown(relaunch: false)
        #expect(try await bridge.honors().honors.contains("Ennoblement"))
        try await bridge.validate(credential)
        #expect(try await bridge.sign(credential).existing)
        try await bridge.saveQR(url: signURL, format: .svg, path: "/OUT/rhg-credential-2026-01-02-da93dff4-min3cm.svg")
        #expect(try await bridge.reportError(reportId: "1").filed)
        try await bridge.submitPIN(requestId: 1, pin: "123456", remember: true)
        try await bridge.cancelPIN(requestId: 2)
        #expect(try await bridge.currentUpdate().status.state == .ready)
        #expect(try await bridge.loadBulk(path: "/OUT/bulk.csv").toSign == 1)
        #expect(try await bridge.runBulk().stopped == .completed)
        try await bridge.cancelBulk()
        try await bridge.exportBulkResults(path: "/OUT/bulk-results.csv")
        #expect(try await bridge.checkYubiKey().outcome == .found)
        // Display strings are render-only (contract README): check shapes, not text.
        #expect(try await !bridge.exportErrorLog(path: "/OUT/error-log.txt").message.isEmpty)
        #expect(try await bridge.registryColumns().count == 7)
        let snapshot = try await bridge.registrySnapshot()
        #expect(snapshot.entries.count == 2 && snapshot.rows.count == 2 && snapshot.dirty && snapshot.loaded)
        try await bridge.fetchRegistry()
        try await bridge.addEntry(
            form: EntryForm(authority: "New Authority", from: "2026-01-01", to: "", note: "Second key", noExpiry: true),
            publicKey: "JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0=")
        try await bridge.updateEntry(
            index: 0, publicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
            form: EntryForm(authority: "A", from: "2025-01-01", to: "2030-12-31", note: "", noExpiry: false))
        #expect(try await bridge.importCertificate(path: "/OUT/certificate.pem") == "JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0=")
        #expect(try await bridge.importFromYubiKey() == "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
        #expect(try await bridge.submitRegistry().prNumber == 42)
        #expect(try await bridge.authState() == AuthState(loggedIn: false, offline: false, user: "", statusText: "Not logged in"))
        #expect(try await bridge.login().user == "octocat")
        try await bridge.cancelLogin()
        try await bridge.logout()
        try await bridge.refreshHistory()
        #expect(try await bridge.listHistory(query: "").rows.count == 4)
        let record = try JSONDecoder().decode(
            RecordParams.self, from: contractFile("methods/history.recordText/params.json")
        ).record
        #expect(try await !bridge.recordText(record).revokeConfirm.isEmpty)
        #expect(try await bridge.revoke(payloadSha256: String(repeating: "0", count: 63) + "2").status == .submitted)
        #expect(try await !bridge.exportIssuanceLog(path: "/OUT/issuances-export.json").title.isEmpty)
        #expect(try await bridge.duplicatePreview().count == 1)
        #expect(try await bridge.removeDuplicates().removed == 1)
        let deleted = try JSONDecoder().decode(
            RecordParams.self, from: contractFile("methods/history.deleteEntry/params.json")
        ).record
        #expect(try await !bridge.deleteEntry(deleted).backup.isEmpty)
        #expect(try await bridge.auditCommits().rows.count == 1)

        let expected: [RPCMethod] = [
            .appInit, .appStart, .appInfo, .appCanQuit, .appShutdown, .signHonors, .signValidate, .signSign,
            .signSaveQR, .signReportError, .pinSubmit, .pinCancel, .updateCurrent, .bulkLoad, .bulkRun, .bulkCancel,
            .bulkExportResults, .yubikeyCheck, .appExportErrorLog, .registryColumns, .registrySnapshot, .registryFetch,
            .registryAddEntry, .registryUpdateEntry, .registryImportCertificate, .registryImportFromYubiKey,
            .registrySubmit, .authState, .authLogin, .authCancelLogin, .authLogout, .historyRefresh, .historyList,
            .historyRecordText, .historyRevoke, .historyExportIssuanceLog, .historyDuplicatePreview,
            .historyRemoveDuplicates, .historyDeleteEntry, .auditCommits,
        ]
        let calls = bridge.calls
        #expect(calls.map(\.method) == expected.map(\.rawValue))
        for (call, method) in zip(calls, expected) {
            let file = try contractFile("methods/\(method.rawValue)/params.json")
            #expect(call.params + Data("\n".utf8) == file, "\(method.rawValue) params")
        }
    }
}

/// The memberwise inits (used by fakes) assign each argument to its own field:
/// each DTO built from the contract's values equals the decoded contract file.
@Suite("DTO initializers")
struct InitializerTests {
    private func result<R: Decodable>(_ path: String, as _: R.Type = R.self) throws -> R {
        try RPCEnvelope.decode(contractFile("methods/\(path)"))
    }

    @Test("result inits match the contract results")
    func resultInits() throws {
        let info: AppInfo = try result("app.info/result.json")
        #expect(info == AppInfo(activeKeys: 1, online: true, recentlyExpired: 0, version: "dev", statusItems: info.statusItems))
        #expect(info.statusItems.count == 3)
        for method in ["app.exportErrorLog", "history.exportIssuanceLog"] {
            let export: ExportResult = try result("\(method)/result.json")
            #expect(export == ExportResult(title: export.title, message: export.message))
            #expect(!export.title.isEmpty && !export.message.isEmpty, "\(method)")
        }
        #expect(try result("app.canQuit/result.json") == CanQuitResult(dirty: true))
        let honors: HonorsResult = try result("sign.honors/result.json")
        #expect(honors.honors.count == 7 && honors.honors.last == "Other")
        let signed: SignResult = try result("sign.sign/result.json")
        #expect(
            signed
                == SignResult(
                    recipient: "Jane Doe", honor: "Ennoblement", detail: "For service", date: "2026-01-02", url: signed.url,
                    existing: true, pngPreview: Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
                    warning: "", svgFilename: "rhg-credential-2026-01-02-da93dff4-min3cm.svg",
                    pngFilename: "rhg-credential-2026-01-02-da93dff4-2048px.png"))
        let report: ReportResult = try result("sign.reportError/result.json")
        #expect(report == ReportResult(filed: true, url: report.url))
        let audit: AuditResult = try result("audit.commits/result.json")
        #expect(audit.rows.count == 1 && !audit.rows[0].summary.isEmpty && !audit.status.isEmpty)
        let load: BulkLoadResult = try result("bulk.load/result.json")
        #expect(load == BulkLoadResult(toSign: 1, countsLine: load.countsLine, previewNames: ["Carol White"], invalidLines: load.invalidLines))
        let run: BulkRunResult = try result("bulk.run/result.failed.json")
        #expect(
            run
                == BulkRunResult(
                    stopped: .failed, summaryLine: run.summaryLine, stopMessage: run.stopMessage, failedLines: run.failedLines,
                    resultsFilename: "rhg-bulk-results-2026-01-02-030405.csv"))
        let list: HistoryListResult = try result("history.list/result.json")
        let last = list.rows[3]
        let rebuilt = HistoryRow(
            record: HistoryRecord(
                timestamp: "2026-01-02T03:04:05Z", recipient: "Alice Smith", honor: "Ennoblement", detail: "For service",
                date: "2026-01-02", payloadSha256: last.record.payloadSha256, signatureB64url: last.record.signatureB64url),
            summary: last.summary, revoked: true)
        #expect(last == rebuilt)
        #expect(
            list
                == HistoryListResult(
                    rows: list.rows, loadFailed: false, revocationsUnavailable: false, revocationsLoaded: true, revokeAvailable: false))
        let text: RecordTextResult = try result("history.recordText/result.json")
        // Each field holds its own key's text, whatever the wording.
        struct RawText: Decodable {
            let detail, revokeConfirm, deleteConfirm: String
            let offerRevoke: Bool
        }
        struct RawEnvelope: Decodable { let result: RawText }
        let raw = try JSONDecoder().decode(
            RawEnvelope.self, from: contractFile("methods/history.recordText/result.json")
        ).result
        #expect(!text.detail.isEmpty && text.detail == raw.detail)
        #expect(!text.revokeConfirm.isEmpty && text.revokeConfirm == raw.revokeConfirm)
        #expect(!text.deleteConfirm.isEmpty && text.deleteConfirm == raw.deleteConfirm)
        #expect(
            text
                == RecordTextResult(
                    detail: raw.detail, revokeConfirm: raw.revokeConfirm, deleteConfirm: raw.deleteConfirm,
                    offerRevoke: raw.offerRevoke))
        let deleted: DeleteEntryResult = try result("history.deleteEntry/result.json")
        #expect(
            deleted
                == DeleteEntryResult(
                    backup: "/DATA/issuances.json.bak-20260102T030405Z", title: deleted.title, message: deleted.message))
        #expect(!deleted.title.isEmpty && !deleted.message.isEmpty && deleted.title != deleted.message)
        let preview: DuplicatePreviewResult = try result("history.duplicatePreview/result.json")
        #expect(preview == DuplicatePreviewResult(count: 1, confirmMessage: preview.confirmMessage))
        #expect(!preview.confirmMessage.isEmpty)
        let removed: RemoveDuplicatesResult = try result("history.removeDuplicates/result.json")
        #expect(
            removed
                == RemoveDuplicatesResult(
                    removed: 1, backup: "/DATA/issuances.json.bak-20260102T030405Z", message: removed.message))
        #expect(!removed.message.isEmpty)
        let revoke: RevokeResult = try result("history.revoke/result.json")
        #expect(revoke == RevokeResult(status: .submitted, prNumber: 43, url: revoke.url, title: revoke.title, message: revoke.message))
        let snapshot: RegistrySnapshot = try result("registry.snapshot/result.json")
        #expect(
            snapshot.entries[0]
                == RegistryEntry(
                    authority: "A", from: "2025-01-01", to: "2030-12-31", noExpiry: false,
                    publicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", note: ""))
        #expect(snapshot == RegistrySnapshot(entries: snapshot.entries, rows: snapshot.rows, dirty: true, loaded: true))
        let columns: ColumnsResult = try result("registry.columns/result.json")
        #expect(columns == ColumnsResult(columns: columns.columns))
        #expect(
            try result("registry.importCertificate/result.json")
                == PublicKeyResult(publicKey: "JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0="))
        let submit: SubmitResult = try result("registry.submit/result.json")
        #expect(submit == SubmitResult(prNumber: 42, url: submit.url))
        let check: KeyCheck = try result("yubikey.check/result.notFound.json")
        #expect(check == KeyCheck(outcome: .notFound, status: "Key NOT found in registry", details: check.details))
    }
}
