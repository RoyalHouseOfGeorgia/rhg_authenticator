using System.Text.Json.Serialization.Metadata;
using System.Threading.Channels;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// The core's method surface. <see cref="LiveBridge"/> calls the Go core
/// through its C ABI; tests substitute a fake. The typed methods are default
/// implementations over <see cref="CallAsync"/>, so a fake implements only
/// <see cref="CallAsync"/> and <see cref="Events"/> (or overrides any typed
/// method). Every failure is an <see cref="RpcException"/>: the core's error
/// envelope, <see cref="RpcException.BadParams"/> or
/// <see cref="RpcException.BadResponse"/>. A call may take minutes (card,
/// network, a PIN prompt) without blocking the caller's thread; it cannot be
/// cancelled from .NET (cancel the operation through the core, e.g. pin.cancel).
/// </summary>
public interface IBridge
{
    /// <summary>
    /// Every event the core emits, in order. Single consumer: read it from one
    /// loop only.
    /// </summary>
    ChannelReader<BridgeEvent> Events { get; }

    /// <summary>
    /// Calls <paramref name="method"/> with <paramref name="parameters"/>
    /// (sent in <see cref="CanonicalJson"/> form) and returns its decoded result.
    /// </summary>
    Task<TResult> CallAsync<TParams, TResult>(
        string method, TParams parameters, JsonTypeInfo<TParams> paramsTypeInfo, JsonTypeInfo<TResult> resultTypeInfo);

    /// <summary>app.init. <see cref="LiveBridge.Install"/> must have run first, so no event is lost.</summary>
    Task<AppInfo> InitAppAsync(string? dataDir = null)
    {
        return Call(RpcMethod.AppInit, new AppInitParams(dataDir), Json.AppInitParams, Json.AppInfo);
    }

    /// <summary>app.start, once the UI listens for events.</summary>
    Task StartAppAsync()
    {
        return CallVoid(RpcMethod.AppStart);
    }

    /// <summary>app.info.</summary>
    Task<AppInfo> AppInfoAsync()
    {
        return Call(RpcMethod.AppInfo, Json.AppInfo);
    }

    /// <summary>app.canQuit.</summary>
    Task<CanQuitResult> CanQuitAsync()
    {
        return Call(RpcMethod.AppCanQuit, Json.CanQuitResult);
    }

    /// <summary>app.shutdown; <paramref name="relaunch"/> after applying a ready update.</summary>
    Task ShutdownAsync(bool relaunch)
    {
        return CallVoid(RpcMethod.AppShutdown, new ShutdownParams(relaunch), Json.ShutdownParams);
    }

    /// <summary>sign.honors.</summary>
    Task<HonorsResult> HonorsAsync()
    {
        return Call(RpcMethod.SignHonors, Json.HonorsResult);
    }

    /// <summary>sign.validate.</summary>
    Task ValidateAsync(CredentialParams credential)
    {
        return CallVoid(RpcMethod.SignValidate, credential, Json.CredentialParams);
    }

    /// <summary>
    /// sign.sign; emits pin.request (answer with <see cref="SubmitPinAsync"/> or
    /// <see cref="CancelPinAsync"/>) and sign.connecting while it runs.
    /// </summary>
    Task<SignResult> SignAsync(CredentialParams credential)
    {
        return Call(RpcMethod.SignSign, credential, Json.CredentialParams, Json.SignResult);
    }

    /// <summary>sign.saveQR: writes the QR code of <paramref name="url"/> to <paramref name="path"/>.</summary>
    Task SaveQrAsync(string url, QrFormat format, string path)
    {
        return CallVoid(RpcMethod.SignSaveQr, new SaveQrParams(url, format, path), Json.SaveQrParams);
    }

    /// <summary>sign.reportError: files (or prepares) the issue of an error offering a report.</summary>
    Task<ReportResult> ReportErrorAsync(string reportId)
    {
        return Call(RpcMethod.SignReportError, new ReportErrorParams(reportId), Json.ReportErrorParams, Json.ReportResult);
    }

    /// <summary>pin.submit.</summary>
    Task SubmitPinAsync(ulong requestId, string pin, bool remember)
    {
        return CallVoid(RpcMethod.PinSubmit, new PinSubmitParams(requestId, pin, remember), Json.PinSubmitParams);
    }

    /// <summary>pin.cancel.</summary>
    Task CancelPinAsync(ulong requestId)
    {
        return CallVoid(RpcMethod.PinCancel, new PinCancelParams(requestId), Json.PinCancelParams);
    }

    /// <summary>update.current.</summary>
    Task<UpdateCurrentResult> CurrentUpdateAsync()
    {
        return Call(RpcMethod.UpdateCurrent, Json.UpdateCurrentResult);
    }

    /// <summary>bulk.load: reads and plans the bulk CSV at <paramref name="path"/> for <see cref="RunBulkAsync"/>.</summary>
    Task<BulkLoadResult> LoadBulkAsync(string path)
    {
        return Call(RpcMethod.BulkLoad, new PathParams(path), Json.PathParams, Json.BulkLoadResult);
    }

    /// <summary>
    /// bulk.run: signs the loaded plan. With rows to sign it emits pin.request,
    /// then bulk.connecting and one bulk.progress per row; with nothing to sign
    /// it returns at once. A cancelled run (<see cref="CancelBulkAsync"/> or the
    /// PIN prompt) succeeds with <see cref="BulkStop.Cancelled"/>.
    /// </summary>
    Task<BulkRunResult> RunBulkAsync()
    {
        return Call(RpcMethod.BulkRun, Json.BulkRunResult);
    }

    /// <summary>bulk.cancel: stops a running bulk.run after its current row.</summary>
    Task CancelBulkAsync()
    {
        return CallVoid(RpcMethod.BulkCancel);
    }

    /// <summary>bulk.exportResults: writes the last plan's per-row results as CSV to <paramref name="path"/>.</summary>
    Task ExportBulkResultsAsync(string path)
    {
        return CallVoid(RpcMethod.BulkExportResults, new PathParams(path), Json.PathParams);
    }

    /// <summary>yubikey.check: reads the inserted key and looks it up in the registry.</summary>
    Task<KeyCheck> CheckYubiKeyAsync()
    {
        return Call(RpcMethod.YubikeyCheck, Json.KeyCheck);
    }

    /// <summary>app.exportErrorLog: writes the diagnostic log to <paramref name="path"/>; returns the alert.</summary>
    Task<ExportResult> ExportErrorLogAsync(string path)
    {
        return Call(RpcMethod.AppExportErrorLog, new PathParams(path), Json.PathParams, Json.ExportResult);
    }

    /// <summary>registry.columns: the registry table's column headings; display only.</summary>
    async Task<IReadOnlyList<string>> RegistryColumnsAsync()
    {
        return (await Call(RpcMethod.RegistryColumns, Json.ColumnsResult).ConfigureAwait(false)).Columns;
    }

    /// <summary>registry.snapshot: the registry as edited, with its table cells.</summary>
    Task<RegistrySnapshot> RegistrySnapshotAsync()
    {
        return Call(RpcMethod.RegistrySnapshot, Json.RegistrySnapshot);
    }

    /// <summary>registry.fetch: re-fetches the live registry, discarding local edits; success arrives as registry.changed.</summary>
    Task FetchRegistryAsync()
    {
        return CallVoid(RpcMethod.RegistryFetch);
    }

    /// <summary>registry.addEntry: appends an entry for <paramref name="publicKey"/> (base64 Ed25519).</summary>
    Task AddEntryAsync(EntryForm form, string publicKey)
    {
        return CallVoid(RpcMethod.RegistryAddEntry, new AddEntryParams(form, publicKey), Json.AddEntryParams);
    }

    /// <summary>registry.updateEntry: replaces the entry at <paramref name="index"/>, which must still hold <paramref name="publicKey"/>.</summary>
    Task UpdateEntryAsync(int index, string publicKey, EntryForm form)
    {
        return CallVoid(RpcMethod.RegistryUpdateEntry, new UpdateEntryParams(index, publicKey, form), Json.UpdateEntryParams);
    }

    /// <summary>registry.importCertificate: the public key of the certificate at <paramref name="path"/>.</summary>
    async Task<string> ImportCertificateAsync(string path)
    {
        var result = await Call(RpcMethod.RegistryImportCertificate, new PathParams(path), Json.PathParams, Json.PublicKeyResult)
            .ConfigureAwait(false);
        return result.PublicKey;
    }

    /// <summary>registry.importFromYubiKey: the inserted YubiKey's public key.</summary>
    async Task<string> ImportFromYubiKeyAsync()
    {
        return (await Call(RpcMethod.RegistryImportFromYubiKey, Json.PublicKeyResult).ConfigureAwait(false)).PublicKey;
    }

    /// <summary>registry.submit: opens a pull request with the edited registry.</summary>
    Task<SubmitResult> SubmitRegistryAsync()
    {
        return Call(RpcMethod.RegistrySubmit, Json.SubmitResult);
    }

    /// <summary>history.refresh: re-reads the issuance log (history.changed) and refetches the revocation list (history.revocationsChanged).</summary>
    Task RefreshHistoryAsync()
    {
        return CallVoid(RpcMethod.HistoryRefresh);
    }

    /// <summary>history.list: the issuance log, newest first, filtered by <paramref name="query"/>.</summary>
    Task<HistoryListResult> ListHistoryAsync(string query)
    {
        return Call(RpcMethod.HistoryList, new HistoryListParams(query), Json.HistoryListParams, Json.HistoryListResult);
    }

    /// <summary>history.recordText: <paramref name="record"/>'s detail text and its revoke and delete questions.</summary>
    Task<RecordTextResult> RecordTextAsync(HistoryRecord record)
    {
        return Call(RpcMethod.HistoryRecordText, new RecordParams(record), Json.RecordParams, Json.RecordTextResult);
    }

    /// <summary>history.revoke: opens a revocation pull request for the credential.</summary>
    Task<RevokeResult> RevokeAsync(string payloadSha256)
    {
        return Call(RpcMethod.HistoryRevoke, new RevokeParams(payloadSha256), Json.RevokeParams, Json.RevokeResult);
    }

    /// <summary>history.exportIssuanceLog: copies the issuance log to <paramref name="path"/>; returns the alert.</summary>
    Task<ExportResult> ExportIssuanceLogAsync(string path)
    {
        return Call(RpcMethod.HistoryExportIssuanceLog, new PathParams(path), Json.PathParams, Json.ExportResult);
    }

    /// <summary>history.duplicatePreview: how many duplicates removeDuplicates would remove, and the question to ask first.</summary>
    Task<DuplicatePreviewResult> DuplicatePreviewAsync()
    {
        return Call(RpcMethod.HistoryDuplicatePreview, Json.DuplicatePreviewResult);
    }

    /// <summary>history.removeDuplicates: backs up the issuance log, then removes its duplicates; emits history.changed.</summary>
    Task<RemoveDuplicatesResult> RemoveDuplicatesAsync()
    {
        return Call(RpcMethod.HistoryRemoveDuplicates, Json.RemoveDuplicatesResult);
    }

    /// <summary>
    /// history.deleteEntry: backs up the issuance log, then deletes
    /// <paramref name="record"/> (as history.list returned it); emits
    /// history.changed, also when the record is no longer in the log
    /// (<see cref="RpcErrorCode.NotFound"/>).
    /// </summary>
    Task<DeleteEntryResult> DeleteEntryAsync(HistoryRecord record)
    {
        return Call(RpcMethod.HistoryDeleteEntry, new RecordParams(record), Json.RecordParams, Json.DeleteEntryResult);
    }

    /// <summary>audit.commits: the registry's GitHub commit history.</summary>
    Task<AuditResult> AuditCommitsAsync()
    {
        return Call(RpcMethod.AuditCommits, Json.AuditResult);
    }

    /// <summary>auth.state: the GitHub login state.</summary>
    Task<AuthState> AuthStateAsync()
    {
        return Call(RpcMethod.AuthState, Json.AuthState);
    }

    /// <summary>
    /// auth.login: reconnects an offline session or runs the GitHub device flow,
    /// emitting auth.deviceCode, and returns once a token arrives or the login
    /// is cancelled (<see cref="CancelLoginAsync"/>).
    /// </summary>
    Task<AuthState> LoginAsync()
    {
        return Call(RpcMethod.AuthLogin, Json.AuthState);
    }

    /// <summary>auth.cancelLogin: stops a running auth.login, which fails <see cref="RpcErrorCode.Cancelled"/>.</summary>
    Task CancelLoginAsync()
    {
        return CallVoid(RpcMethod.AuthCancelLogin);
    }

    /// <summary>auth.logout: clears the saved session.</summary>
    Task LogoutAsync()
    {
        return CallVoid(RpcMethod.AuthLogout);
    }

    private static BridgeJsonContext Json => BridgeJsonContext.Default;

    private Task<TResult> Call<TParams, TResult>(
        string method, TParams parameters, JsonTypeInfo<TParams> paramsTypeInfo, JsonTypeInfo<TResult> resultTypeInfo)
    {
        return CallAsync(method, parameters, paramsTypeInfo, resultTypeInfo);
    }

    private Task<TResult> Call<TResult>(string method, JsonTypeInfo<TResult> resultTypeInfo)
    {
        return CallAsync(method, Empty.Value, Json.Empty, resultTypeInfo);
    }

    private Task CallVoid<TParams>(string method, TParams parameters, JsonTypeInfo<TParams> paramsTypeInfo)
    {
        return CallAsync(method, parameters, paramsTypeInfo, Json.Empty);
    }

    private Task CallVoid(string method)
    {
        return CallAsync(method, Empty.Value, Json.Empty, Json.Empty);
    }
}
