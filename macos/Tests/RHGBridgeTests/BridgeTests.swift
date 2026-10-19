import Foundation
import RHGBridge
import Testing

@Suite("Envelopes and errors")
struct EnvelopeTests {
    @Test("ok:true with {} decodes as Empty")
    func emptyResult() throws {
        let result = try RPCEnvelope.decode(Data(#"{"ok":true,"result":{}}"#.utf8), as: Empty.self)
        #expect(result == Empty())
    }

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

    @Test("every known code round-trips through its raw value")
    func knownCodes() {
        #expect(RPCErrorCode.known.count == 11)
        for code in RPCErrorCode.known {
            #expect(RPCErrorCode(rawValue: code.rawValue) == code)
        }
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

    @Test("a result that does not match the DTO is badResponse")
    func resultMismatch() throws {
        let data = Data(#"{"ok":true,"result":{}}"#.utf8)
        #expect(throws: RPCError.badResponse) { _ = try RPCEnvelope.decode(data, as: AppInfo.self) }
    }

    @Test("CanonicalJSON sorts keys and escapes neither slashes nor non-ASCII")
    func canonicalEncoding() throws {
        let params = SaveQRParams(url: "https://x/ნ?a=é", format: .png, path: "/OUT/a.png")
        let json = String(decoding: try CanonicalJSON.encode(params), as: UTF8.self)
        #expect(json == #"{"format":"png","path":"/OUT/a.png","url":"https://x/ნ?a=é"}"#)
    }

    @Test("an omitted dataDir is absent from app.init params")
    func appInitDefault() throws {
        #expect(try CanonicalJSON.encode(AppInitParams()) == Data("{}".utf8))
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

    @Test("known values round-trip through their raw value")
    func knownValues() {
        for v in UpdateState.known { #expect(UpdateState(rawValue: v.rawValue) == v) }
        for v in BulkStop.known { #expect(BulkStop(rawValue: v.rawValue) == v) }
        for v in RevokeStatus.known { #expect(RevokeStatus(rawValue: v.rawValue) == v) }
        for v in KeyCheckResult.known { #expect(KeyCheckResult(rawValue: v.rawValue) == v) }
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

    @Test("every event's name and payload survive an encode/decode round trip")
    func roundTrip() throws {
        let status = UpdateStatus(state: .ready, version: "1", releaseUrl: "u", moveToApplications: true)
        let events: [BridgeEvent] = [
            .appInternalError, .authChanged(AuthState(loggedIn: true, offline: false, user: "u", statusText: "s")),
            .authDeviceCode(DeviceCode(userCode: "A-B", verificationUri: "v")), .bulkConnecting,
            .bulkProgress(BulkProgress(done: 1, total: 2, name: "n")), .historyChanged, .historyRevocationsChanged,
            .pinDismiss(PINDismiss(requestId: 4)), .pinRequest(PINRequest(requestId: 4, rememberDefault: false, maxBytes: 8)),
            .registryChanged, .signConnecting, .updateStatus(status),
            .updateUpdated(UpdatedNotice(version: "1", releaseUrl: "u")),
        ]
        for event in events {
            #expect(BridgeEvent(json: try CanonicalJSON.encode(event)) == event, "\(event.name)")
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

        let expected: [RPCMethod] = [
            .appInit, .appStart, .appInfo, .appCanQuit, .appShutdown, .signHonors, .signValidate, .signSign,
            .signSaveQR, .signReportError, .pinSubmit, .pinCancel, .updateCurrent,
        ]
        let calls = bridge.calls
        #expect(calls.map(\.method) == expected.map(\.rawValue))
        for (call, method) in zip(calls, expected) {
            let file = try contractFile("methods/\(method.rawValue)/params.json")
            #expect(call.params + Data("\n".utf8) == file, "\(method.rawValue) params")
        }
    }

    @Test("a helper rethrows the error envelope")
    func helperError() async throws {
        let bridge = RecordingBridge(responses: ["sign.sign": try contractFile("errors/failed-with-report.json")])
        let credential = CredentialParams(recipient: "", honor: "", detail: "", date: "")
        do {
            _ = try await bridge.sign(credential)
            Issue.record("sign succeeded")
        } catch {
            #expect(error.code == .failed && error.offerReport && error.reportId == "1")
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

    private func params<P: Decodable>(_ method: String, as _: P.Type = P.self) throws -> P {
        try JSONDecoder().decode(P.self, from: contractFile("methods/\(method)/params.json"))
    }

    @Test("params inits match the contract params")
    func paramsInits() throws {
        let record = try params("history.recordText", as: RecordParams.self).record
        #expect(try params("bulk.load") == PathParams(path: "/OUT/bulk.csv"))
        #expect(try params("history.list") == HistoryListParams(query: ""))
        #expect(try params("history.revoke") == RevokeParams(payloadSha256: String(repeating: "0", count: 63) + "2"))
        #expect(try params("history.recordText") == RecordParams(record: record))
        let key = "JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0="
        #expect(
            try params("registry.addEntry")
                == AddEntryParams(
                    form: EntryForm(authority: "New Authority", from: "2026-01-01", to: "", note: "Second key", noExpiry: true),
                    publicKey: key))
        #expect(
            try params("registry.updateEntry")
                == UpdateEntryParams(
                    index: 0, publicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
                    form: EntryForm(authority: "A", from: "2025-01-01", to: "2030-12-31", note: "", noExpiry: false)))
    }

    @Test("result inits match the contract results")
    func resultInits() throws {
        #expect(try result("app.info/result.json") == AppInfo(activeKeys: 1, online: true, recentlyExpired: 0, version: "dev"))
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
        #expect(audit == AuditResult(rows: [AuditRow(summary: audit.rows[0].summary, url: audit.rows[0].url)], status: "Loaded 1 commits"))
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
        #expect(
            text
                == RecordTextResult(
                    detail: "Timestamp: 2026-01-02T03:04:05Z\nRecipient: Alice Smith\nHonor: Ennoblement\nDetail: For service\n"
                        + "Date: 2026-Jan-02\nPayload SHA-256: " + String(repeating: "0", count: 63) + "1\nSignature: "
                        + String(repeating: "A", count: 86),
                    revokeConfirm: "Revoke credential for Alice Smith dated 2026-Jan-02?\n\nThis cannot be undone."))
        #expect(try result("history.duplicatePreview/result.json") == DuplicatePreviewResult(count: 1))
        #expect(
            try result("history.removeDuplicates/result.json")
                == RemoveDuplicatesResult(removed: 1, backup: "/DATA/issuances.json.bak-20260102T030405Z"))
        let revoke: RevokeResult = try result("history.revoke/result.json")
        #expect(revoke == RevokeResult(status: .submitted, prNumber: 43, url: revoke.url, title: "Revocation Submitted", message: revoke.message))
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
