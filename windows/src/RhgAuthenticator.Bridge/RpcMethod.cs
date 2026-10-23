namespace RhgAuthenticator.Bridge;

/// <summary>Every method name in the contract (methods/index.json).</summary>
public static class RpcMethod
{
#pragma warning disable CS1591 // Each constant is its method's wire name.
    public const string AppCanQuit = "app.canQuit";
    public const string AppExportErrorLog = "app.exportErrorLog";
    public const string AppInfo = "app.info";
    public const string AppInit = "app.init";
    public const string AppShutdown = "app.shutdown";
    public const string AppStart = "app.start";
    public const string AuditCommits = "audit.commits";
    public const string AuthCancelLogin = "auth.cancelLogin";
    public const string AuthLogin = "auth.login";
    public const string AuthLogout = "auth.logout";
    public const string AuthState = "auth.state";
    public const string BulkCancel = "bulk.cancel";
    public const string BulkExportResults = "bulk.exportResults";
    public const string BulkLoad = "bulk.load";
    public const string BulkRun = "bulk.run";
    public const string HistoryDeleteEntry = "history.deleteEntry";
    public const string HistoryDuplicatePreview = "history.duplicatePreview";
    public const string HistoryExportIssuanceLog = "history.exportIssuanceLog";
    public const string HistoryList = "history.list";
    public const string HistoryRecordText = "history.recordText";
    public const string HistoryRefresh = "history.refresh";
    public const string HistoryRemoveDuplicates = "history.removeDuplicates";
    public const string HistoryRevoke = "history.revoke";
    public const string PinCancel = "pin.cancel";
    public const string PinSubmit = "pin.submit";
    public const string RegistryAddEntry = "registry.addEntry";
    public const string RegistryColumns = "registry.columns";
    public const string RegistryFetch = "registry.fetch";
    public const string RegistryImportCertificate = "registry.importCertificate";
    public const string RegistryImportFromYubiKey = "registry.importFromYubiKey";
    public const string RegistrySnapshot = "registry.snapshot";
    public const string RegistrySubmit = "registry.submit";
    public const string RegistryUpdateEntry = "registry.updateEntry";
    public const string SignHonors = "sign.honors";
    public const string SignReportError = "sign.reportError";
    public const string SignSaveQr = "sign.saveQR";
    public const string SignSign = "sign.sign";
    public const string SignValidate = "sign.validate";
    public const string UpdateCurrent = "update.current";
    public const string YubikeyCheck = "yubikey.check";
#pragma warning restore CS1591

    /// <summary>Every method, in contract order.</summary>
    public static IReadOnlyList<string> All { get; } =
    [
        AppCanQuit, AppExportErrorLog, AppInfo, AppInit, AppShutdown, AppStart, AuditCommits, AuthCancelLogin,
        AuthLogin, AuthLogout, AuthState, BulkCancel, BulkExportResults, BulkLoad, BulkRun, HistoryDeleteEntry,
        HistoryDuplicatePreview, HistoryExportIssuanceLog, HistoryList, HistoryRecordText, HistoryRefresh, HistoryRemoveDuplicates,
        HistoryRevoke, PinCancel, PinSubmit, RegistryAddEntry, RegistryColumns, RegistryFetch,
        RegistryImportCertificate, RegistryImportFromYubiKey, RegistrySnapshot, RegistrySubmit, RegistryUpdateEntry,
        SignHonors, SignReportError, SignSaveQr, SignSign, SignValidate, UpdateCurrent, YubikeyCheck,
    ];
}
