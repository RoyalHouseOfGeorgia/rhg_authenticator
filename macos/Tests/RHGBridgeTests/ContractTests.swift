import Foundation
import RHGBridge
import Testing

/// How one method's contract files are checked: `params` decodes a params
/// file and re-encodes it canonically; `result` decodes a success envelope,
/// re-encodes it, and returns the result enum's raw value and whether it is
/// a known case (nil for a method without a result enum).
struct MethodContract {
    let params: (Data) throws -> Data
    let result: (Data) throws -> (encoded: Data, enumValue: (raw: String, known: Bool)?)

    init<P: Codable, R: Codable>(
        _: P.Type, _: R.Type, enumValue: @escaping (R) -> (raw: String, known: Bool)? = { _ in nil }
    ) {
        params = { data in try canonical(try JSONDecoder().decode(P.self, from: data)) }
        result = { data in
            let decoded = try RPCEnvelope.decode(data, as: R.self)
            return (try successEnvelope(decoded), enumValue(decoded))
        }
    }

    /// The DTOs of each method. The switch is exhaustive, so a method added
    /// to RPCMethod without DTOs does not compile.
    static func of(_ method: RPCMethod) -> MethodContract {
        switch method {
        case .appCanQuit: MethodContract(Empty.self, CanQuitResult.self)
        case .appExportErrorLog: MethodContract(PathParams.self, Empty.self)
        case .appInfo: MethodContract(Empty.self, AppInfo.self)
        case .appInit: MethodContract(AppInitParams.self, AppInfo.self)
        case .appShutdown: MethodContract(ShutdownParams.self, Empty.self)
        case .appStart: MethodContract(Empty.self, Empty.self)
        case .auditCommits: MethodContract(Empty.self, AuditResult.self)
        case .authCancelLogin: MethodContract(Empty.self, Empty.self)
        case .authLogin: MethodContract(Empty.self, AuthState.self)
        case .authLogout: MethodContract(Empty.self, Empty.self)
        case .authState: MethodContract(Empty.self, AuthState.self)
        case .bulkCancel: MethodContract(Empty.self, Empty.self)
        case .bulkExportResults: MethodContract(PathParams.self, Empty.self)
        case .bulkLoad: MethodContract(PathParams.self, BulkLoadResult.self)
        case .bulkRun:
            MethodContract(Empty.self, BulkRunResult.self) {
                ($0.stopped.rawValue, BulkStop.known.contains($0.stopped))
            }
        case .historyDuplicatePreview: MethodContract(Empty.self, DuplicatePreviewResult.self)
        case .historyExportIssuanceLog: MethodContract(PathParams.self, Empty.self)
        case .historyList: MethodContract(HistoryListParams.self, HistoryListResult.self)
        case .historyRecordText: MethodContract(RecordParams.self, RecordTextResult.self)
        case .historyRefresh: MethodContract(Empty.self, Empty.self)
        case .historyRemoveDuplicates: MethodContract(Empty.self, RemoveDuplicatesResult.self)
        case .historyRevoke:
            MethodContract(RevokeParams.self, RevokeResult.self) {
                ($0.status.rawValue, RevokeStatus.known.contains($0.status))
            }
        case .pinCancel: MethodContract(PINCancelParams.self, Empty.self)
        case .pinSubmit: MethodContract(PINSubmitParams.self, Empty.self)
        case .registryAddEntry: MethodContract(AddEntryParams.self, Empty.self)
        case .registryColumns: MethodContract(Empty.self, ColumnsResult.self)
        case .registryFetch: MethodContract(Empty.self, Empty.self)
        case .registryImportCertificate: MethodContract(PathParams.self, PublicKeyResult.self)
        case .registryImportFromYubiKey: MethodContract(Empty.self, PublicKeyResult.self)
        case .registrySnapshot: MethodContract(Empty.self, RegistrySnapshot.self)
        case .registrySubmit: MethodContract(Empty.self, SubmitResult.self)
        case .registryUpdateEntry: MethodContract(UpdateEntryParams.self, Empty.self)
        case .signHonors: MethodContract(Empty.self, HonorsResult.self)
        case .signReportError: MethodContract(ReportErrorParams.self, ReportResult.self)
        case .signSaveQR: MethodContract(SaveQRParams.self, Empty.self)
        case .signSign: MethodContract(CredentialParams.self, SignResult.self)
        case .signValidate: MethodContract(CredentialParams.self, Empty.self)
        case .updateCurrent:
            MethodContract(Empty.self, UpdateCurrentResult.self) {
                ($0.status.state.rawValue, UpdateState.known.contains($0.status.state))
            }
        case .yubikeyCheck:
            MethodContract(Empty.self, KeyCheck.self) {
                ($0.result.rawValue, KeyCheckResult.known.contains($0.result))
            }
        }
    }
}

@Suite("Contract files")
struct ContractTests {
    @Test("methods/index.json lists exactly the RPCMethod cases")
    func methodIndexMatches() throws {
        let index = try JSONDecoder().decode([String: String].self, from: contractFile("methods/index.json"))
        #expect(Set(index.keys) == Set(RPCMethod.allCases.map(\.rawValue)))
    }

    @Test("every methods/ file decodes, and re-encodes to the same bytes")
    func methodFiles() throws {
        let methodsDir = contractDir.appendingPathComponent("methods")
        let all = try files(under: methodsDir).filter { $0 != "index.json" }
        #expect(all.count >= RPCMethod.allCases.count * 2)
        var enumValues: [RPCMethod: Set<String>] = [:]
        for path in all {
            let parts = path.split(separator: "/").map(String.init)
            try #require(parts.count == 2, "unexpected file \(path)")
            let method = try #require(RPCMethod(rawValue: parts[0]), "no RPCMethod for \(parts[0])")
            let contract = MethodContract.of(method)
            let data = try Data(contentsOf: methodsDir.appendingPathComponent(path))
            switch parts[1] {
            case "params.json":
                #expect(try contract.params(data) == data, "params bytes differ: \(path)")
            case "result.json":
                let (encoded, value) = try contract.result(data)
                #expect(encoded == data, "result bytes differ: \(path)")
                if let value {
                    #expect(value.known, "unknown enum value in \(path)")
                    enumValues[method, default: []].insert(value.raw)
                }
            default:
                // result.<value>.json: the result enum's other values.
                let name = parts[1]
                try #require(name.hasPrefix("result.") && name.hasSuffix(".json"), "unexpected file \(path)")
                let expected = String(name.dropFirst("result.".count).dropLast(".json".count))
                let (encoded, value) = try contract.result(data)
                #expect(encoded == data, "result bytes differ: \(path)")
                let found = try #require(value, "\(path) has no result enum in its DTO")
                #expect(found.raw == expected && found.known, "\(path) decodes as \(found.raw)")
                enumValues[method, default: []].insert(found.raw)
            }
        }
        // Each result enum's Swift cases are exactly the contract's values.
        #expect(enumValues[.bulkRun] == Set(BulkStop.known.map(\.rawValue)))
        #expect(enumValues[.historyRevoke] == Set(RevokeStatus.known.map(\.rawValue)))
        #expect(enumValues[.yubikeyCheck] == Set(KeyCheckResult.known.map(\.rawValue)))
    }

    @Test("every methods/<method> directory has params.json and result.json")
    func everyMethodHasFiles() throws {
        let all = Set(try files(under: contractDir.appendingPathComponent("methods")))
        for method in RPCMethod.allCases {
            #expect(all.contains("\(method.rawValue)/params.json"), "\(method.rawValue)")
            #expect(all.contains("\(method.rawValue)/result.json"), "\(method.rawValue)")
        }
    }

    @Test("every errors/ file decodes as its RPCError and re-encodes to the same bytes")
    func errorFiles() throws {
        let errorsDir = contractDir.appendingPathComponent("errors")
        var codes: Set<String> = []
        for name in try files(under: errorsDir) {
            let data = try Data(contentsOf: errorsDir.appendingPathComponent(name))
            let error = try #require(throws: RPCError.self) { _ = try RPCEnvelope.decode(data, as: Empty.self) }
            #expect(RPCErrorCode.known.contains(error.code), "\(name)")
            let encoded = Data(#"{"error":"#.utf8) + (try CanonicalJSON.encode(error)) + Data(#","ok":false}\#n"#.utf8)
            #expect(encoded == data, "error bytes differ: \(name)")
            if name == "failed-with-report.json" {
                #expect(error.code == .failed && error.offerReport && error.reportId == "1")
            } else {
                #expect(name == error.code.rawValue + ".json")
                #expect(!error.offerReport && error.reportId == nil, "\(name)")
                codes.insert(error.code.rawValue)
            }
        }
        #expect(codes == Set(RPCErrorCode.known.map(\.rawValue)))
    }

    @Test("every events/ file decodes as its BridgeEvent and re-encodes to the same bytes")
    func eventFiles() throws {
        let eventsDir = contractDir.appendingPathComponent("events")
        var names: Set<String> = []
        var states: Set<String> = []
        for file in try files(under: eventsDir) {
            let data = try Data(contentsOf: eventsDir.appendingPathComponent(file))
            let event = try JSONDecoder().decode(BridgeEvent.self, from: data)
            #expect(BridgeEvent(json: data) == event, "\(file)")
            #expect(try canonical(event) == data, "event bytes differ: \(file)")
            let stem = String(file.dropLast(".json".count))
            if case .updateStatus(let status) = event {
                #expect(stem == "update.status.\(status.state.rawValue)")
                #expect(UpdateState.known.contains(status.state))
                states.insert(status.state.rawValue)
            } else {
                #expect(stem == event.name)
            }
            if case .unknown = event {
                Issue.record("\(file) decodes as an unknown event")
            }
            names.insert(event.name)
        }
        let allEvents = [
            "app.internalError", "auth.changed", "auth.deviceCode", "bulk.connecting", "bulk.progress",
            "history.changed", "history.revocationsChanged", "pin.dismiss", "pin.request", "registry.changed",
            "sign.connecting", "update.status", "update.updated",
        ]
        #expect(names == Set(allEvents))
        #expect(states == Set(UpdateState.known.map(\.rawValue)))
    }

    @Test("pin-truncation.json: every case, compared as UTF-8 bytes")
    func pinTruncation() throws {
        struct Case: Decodable {
            var input: String
            var maxBytes: Int
            var output: String
        }
        let cases = try JSONDecoder().decode([Case].self, from: contractFile("pin-truncation.json"))
        #expect(cases.count >= 10)
        for c in cases {
            let got = truncatePIN(c.input, maxBytes: c.maxBytes)
            #expect(Array(got.utf8) == Array(c.output.utf8), "input bytes \(Array(c.input.utf8)), maxBytes \(c.maxBytes)")
        }
    }
}
