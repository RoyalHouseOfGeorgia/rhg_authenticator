/// The core's method surface. `LiveBridge` calls the Go core through its C
/// ABI; tests substitute a fake. Typed helpers live in an extension, so a
/// fake implements only `call` and `events`.
public protocol Bridge: Sendable {
    /// Calls `method` with `params` and returns its decoded result. Failures
    /// are always `RPCError`: the core's error envelope, `.badParams` or
    /// `.badResponse`. A call may block for minutes (card, network, a PIN
    /// prompt) without blocking the caller's thread; it cannot be cancelled
    /// from Swift (cancel the operation through the core, e.g. pin.cancel).
    func call<P: Encodable & Sendable, R: Decodable & Sendable>(
        _ method: String, _ params: P
    ) async throws(RPCError) -> R

    /// Every event the core emits, in order. Single consumer: iterate it
    /// from one task only.
    var events: AsyncStream<BridgeEvent> { get }
}

/// Every method in the contract (methods/index.json).
public enum RPCMethod: String, CaseIterable, Sendable {
    case appCanQuit = "app.canQuit"
    case appExportErrorLog = "app.exportErrorLog"
    case appInfo = "app.info"
    case appInit = "app.init"
    case appShutdown = "app.shutdown"
    case appStart = "app.start"
    case auditCommits = "audit.commits"
    case authCancelLogin = "auth.cancelLogin"
    case authLogin = "auth.login"
    case authLogout = "auth.logout"
    case authState = "auth.state"
    case bulkCancel = "bulk.cancel"
    case bulkExportResults = "bulk.exportResults"
    case bulkLoad = "bulk.load"
    case bulkRun = "bulk.run"
    case historyDuplicatePreview = "history.duplicatePreview"
    case historyExportIssuanceLog = "history.exportIssuanceLog"
    case historyList = "history.list"
    case historyRecordText = "history.recordText"
    case historyRefresh = "history.refresh"
    case historyRemoveDuplicates = "history.removeDuplicates"
    case historyRevoke = "history.revoke"
    case pinCancel = "pin.cancel"
    case pinSubmit = "pin.submit"
    case registryAddEntry = "registry.addEntry"
    case registryColumns = "registry.columns"
    case registryFetch = "registry.fetch"
    case registryImportCertificate = "registry.importCertificate"
    case registryImportFromYubiKey = "registry.importFromYubiKey"
    case registrySnapshot = "registry.snapshot"
    case registrySubmit = "registry.submit"
    case registryUpdateEntry = "registry.updateEntry"
    case signHonors = "sign.honors"
    case signReportError = "sign.reportError"
    case signSaveQR = "sign.saveQR"
    case signSign = "sign.sign"
    case signValidate = "sign.validate"
    case updateCurrent = "update.current"
    case yubikeyCheck = "yubikey.check"
}

extension Bridge {
    public func call<P: Encodable & Sendable, R: Decodable & Sendable>(
        _ method: RPCMethod, _ params: P
    ) async throws(RPCError) -> R {
        try await call(method.rawValue, params)
    }

    /// Calls a void method.
    func callVoid<P: Encodable & Sendable>(_ method: RPCMethod, _ params: P) async throws(RPCError) {
        let _: Empty = try await call(method, params)
    }

    /// app.init. Install the event callback first (`LiveBridge.install()`).
    public func initApp(dataDir: String? = nil) async throws(RPCError) -> AppInfo {
        try await call(.appInit, AppInitParams(dataDir: dataDir))
    }

    /// app.start, once the UI listens for events.
    public func startApp() async throws(RPCError) {
        try await callVoid(.appStart, Empty())
    }

    public func appInfo() async throws(RPCError) -> AppInfo {
        try await call(.appInfo, Empty())
    }

    public func canQuit() async throws(RPCError) -> CanQuitResult {
        try await call(.appCanQuit, Empty())
    }

    public func shutdown(relaunch: Bool) async throws(RPCError) {
        try await callVoid(.appShutdown, ShutdownParams(relaunch: relaunch))
    }

    public func honors() async throws(RPCError) -> HonorsResult {
        try await call(.signHonors, Empty())
    }

    public func validate(_ credential: CredentialParams) async throws(RPCError) {
        try await callVoid(.signValidate, credential)
    }

    /// sign.sign; emits pin.request (answer with `submitPIN` or `cancelPIN`)
    /// and sign.connecting while it runs.
    public func sign(_ credential: CredentialParams) async throws(RPCError) -> SignResult {
        try await call(.signSign, credential)
    }

    public func saveQR(url: String, format: QRFormat, path: String) async throws(RPCError) {
        try await callVoid(.signSaveQR, SaveQRParams(url: url, format: format, path: path))
    }

    public func reportError(reportId: String) async throws(RPCError) -> ReportResult {
        try await call(.signReportError, ReportErrorParams(reportId: reportId))
    }

    public func submitPIN(requestId: UInt64, pin: String, remember: Bool) async throws(RPCError) {
        try await callVoid(.pinSubmit, PINSubmitParams(requestId: requestId, pin: pin, remember: remember))
    }

    public func cancelPIN(requestId: UInt64) async throws(RPCError) {
        try await callVoid(.pinCancel, PINCancelParams(requestId: requestId))
    }

    public func currentUpdate() async throws(RPCError) -> UpdateCurrentResult {
        try await call(.updateCurrent, Empty())
    }

    /// bulk.load: reads and plans the bulk CSV at `path` for `runBulk`.
    public func loadBulk(path: String) async throws(RPCError) -> BulkLoadResult {
        try await call(.bulkLoad, PathParams(path: path))
    }

    /// bulk.run: signs the loaded plan. With rows to sign it emits pin.request
    /// (answer with `submitPIN` or `cancelPIN`), then bulk.connecting and one
    /// bulk.progress per row; with nothing to sign it returns at once, with no
    /// prompt or events. A cancelled run (`cancelBulk` or the PIN prompt)
    /// succeeds with `stopped` `.cancelled`.
    public func runBulk() async throws(RPCError) -> BulkRunResult {
        try await call(.bulkRun, Empty())
    }

    /// bulk.cancel: stops a running bulk.run after its current row.
    public func cancelBulk() async throws(RPCError) {
        try await callVoid(.bulkCancel, Empty())
    }

    /// bulk.exportResults: writes the last plan's per-row results as CSV to `path`.
    public func exportBulkResults(path: String) async throws(RPCError) {
        try await callVoid(.bulkExportResults, PathParams(path: path))
    }

    /// yubikey.check: reads the inserted key and looks it up in the registry.
    public func checkYubiKey() async throws(RPCError) -> KeyCheck {
        try await call(.yubikeyCheck, Empty())
    }

    /// app.exportErrorLog: writes the diagnostic log to `path` and returns
    /// the alert saying where it went.
    public func exportErrorLog(path: String) async throws(RPCError) -> ExportResult {
        try await call(.appExportErrorLog, PathParams(path: path))
    }

    /// registry.columns: the registry table's column headings; display only.
    public func registryColumns() async throws(RPCError) -> [String] {
        let result: ColumnsResult = try await call(.registryColumns, Empty())
        return result.columns
    }

    /// registry.snapshot: the registry as edited, with its table cells.
    public func registrySnapshot() async throws(RPCError) -> RegistrySnapshot {
        try await call(.registrySnapshot, Empty())
    }

    /// registry.fetch: re-fetches the live registry, discarding local edits.
    /// Success arrives as the registry.changed event.
    public func fetchRegistry() async throws(RPCError) {
        try await callVoid(.registryFetch, Empty())
    }

    /// registry.addEntry: appends an entry for `publicKey` (base64 Ed25519).
    public func addEntry(form: EntryForm, publicKey: String) async throws(RPCError) {
        try await callVoid(.registryAddEntry, AddEntryParams(form: form, publicKey: publicKey))
    }

    /// registry.updateEntry: replaces the entry at `index` of the snapshot,
    /// which must still hold `publicKey`.
    public func updateEntry(index: Int, publicKey: String, form: EntryForm) async throws(RPCError) {
        try await callVoid(.registryUpdateEntry, UpdateEntryParams(index: index, publicKey: publicKey, form: form))
    }

    /// registry.importCertificate: the public key of the certificate at `path`.
    public func importCertificate(path: String) async throws(RPCError) -> String {
        let result: PublicKeyResult = try await call(.registryImportCertificate, PathParams(path: path))
        return result.publicKey
    }

    /// registry.importFromYubiKey: the inserted YubiKey's public key.
    public func importFromYubiKey() async throws(RPCError) -> String {
        let result: PublicKeyResult = try await call(.registryImportFromYubiKey, Empty())
        return result.publicKey
    }

    /// registry.submit: opens a pull request with the edited registry.
    public func submitRegistry() async throws(RPCError) -> SubmitResult {
        try await call(.registrySubmit, Empty())
    }

    /// history.refresh: re-reads the issuance log (history.changed) and
    /// refetches the revocation list (history.revocationsChanged).
    public func refreshHistory() async throws(RPCError) {
        try await callVoid(.historyRefresh, Empty())
    }

    /// history.list: the issuance log, newest first, filtered by `query`.
    public func listHistory(query: String) async throws(RPCError) -> HistoryListResult {
        try await call(.historyList, HistoryListParams(query: query))
    }

    /// history.recordText: `record`'s detail text and revoke question.
    public func recordText(_ record: HistoryRecord) async throws(RPCError) -> RecordTextResult {
        try await call(.historyRecordText, RecordParams(record: record))
    }

    /// history.revoke: opens a revocation pull request for the credential.
    public func revoke(payloadSha256: String) async throws(RPCError) -> RevokeResult {
        try await call(.historyRevoke, RevokeParams(payloadSha256: payloadSha256))
    }

    /// history.exportIssuanceLog: copies the issuance log to `path` and
    /// returns the alert saying where it went.
    public func exportIssuanceLog(path: String) async throws(RPCError) -> ExportResult {
        try await call(.historyExportIssuanceLog, PathParams(path: path))
    }

    /// history.duplicatePreview: how many duplicate entries removeDuplicates
    /// would remove, and the question to ask before removing them.
    public func duplicatePreview() async throws(RPCError) -> DuplicatePreviewResult {
        try await call(.historyDuplicatePreview, Empty())
    }

    /// history.removeDuplicates: backs up the issuance log, then removes its
    /// duplicate entries; emits history.changed.
    public func removeDuplicates() async throws(RPCError) -> RemoveDuplicatesResult {
        try await call(.historyRemoveDuplicates, Empty())
    }

    /// audit.commits: the registry's GitHub commit history.
    public func auditCommits() async throws(RPCError) -> AuditResult {
        try await call(.auditCommits, Empty())
    }

    /// auth.state: the GitHub login state.
    public func authState() async throws(RPCError) -> AuthState {
        try await call(.authState, Empty())
    }

    /// auth.login: reconnects an offline session or runs the GitHub device
    /// flow, emitting auth.deviceCode, and returns once a token arrives or the
    /// login is cancelled (`cancelLogin`).
    public func login() async throws(RPCError) -> AuthState {
        try await call(.authLogin, Empty())
    }

    /// auth.cancelLogin: stops a running auth.login, which fails `cancelled`.
    public func cancelLogin() async throws(RPCError) {
        try await callVoid(.authCancelLogin, Empty())
    }

    /// auth.logout: clears the saved session.
    public func logout() async throws(RPCError) {
        try await callVoid(.authLogout, Empty())
    }
}
