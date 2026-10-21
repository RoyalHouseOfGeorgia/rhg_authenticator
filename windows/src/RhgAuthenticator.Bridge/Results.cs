using System.Text.Json.Serialization;

namespace RhgAuthenticator.Bridge;

// Result DTOs, one per result shape in the contract
// (go/service/rpc/testdata/contract/methods/<method>/result*.json). Property
// names are the JSON keys in camelCase; every field is required and arrays are
// never null; unknown fields are ignored (the contract is additive). Strings
// documented as display-only are rendered as given and never compared or
// parsed. Records compare collections by reference.

/// <summary>app.init, app.info.</summary>
/// <param name="ActiveKeys">Registry keys valid today.</param>
/// <param name="Online">The registry was reachable.</param>
/// <param name="RecentlyExpired">Keys expired in the last 30 days.</param>
/// <param name="Version">The core's version.</param>
/// <param name="StatusItems">The status bar's texts, in order; display only.</param>
public sealed record AppInfo(
    int ActiveKeys, bool Online, int RecentlyExpired, string Version, IReadOnlyList<string> StatusItems);

/// <summary>app.exportErrorLog, history.exportIssuanceLog: the alert saying where the file went.</summary>
/// <param name="Title">Display only.</param>
/// <param name="Message">Display only.</param>
public sealed record ExportResult(string Title, string Message);

/// <summary>app.canQuit.</summary>
/// <param name="Dirty">Unsubmitted registry edits would be lost.</param>
public sealed record CanQuitResult(bool Dirty);

/// <summary>sign.honors.</summary>
/// <param name="Honors">The honor titles to choose from; display and send as given.</param>
public sealed record HonorsResult(IReadOnlyList<string> Honors);

/// <summary>sign.sign.</summary>
/// <param name="Recipient">NFC-normalized, as signed.</param>
/// <param name="Honor">As signed.</param>
/// <param name="Detail">As signed.</param>
/// <param name="Date">As signed, YYYY-MM-DD.</param>
/// <param name="Url">The verification URL the QR code encodes.</param>
/// <param name="Existing">The credential was already in the issuance log; nothing was signed.</param>
/// <param name="PngPreview">PNG of the QR code (base64 in JSON).</param>
/// <param name="Warning">Display only; "" when there is none.</param>
/// <param name="SvgFilename">Suggested file name; display only.</param>
/// <param name="PngFilename">Suggested file name; display only.</param>
public sealed record SignResult(
    string Recipient,
    string Honor,
    string Detail,
    string Date,
    string Url,
    bool Existing,
    byte[] PngPreview,
    string Warning,
    string SvgFilename,
    string PngFilename);

/// <summary>sign.reportError.</summary>
/// <param name="Filed">The issue was filed (else <paramref name="Url"/> is a prefilled browser form).</param>
/// <param name="Url">The issue, or the form to open.</param>
public sealed record ReportResult(bool Filed, string Url);

/// <summary>update.status <c>state</c>.</summary>
[JsonConverter(typeof(WireEnumConverter<UpdateState>))]
public enum UpdateState
{
    /// <summary>A value this build does not know.</summary>
    Unknown = 0,

    /// <summary>No update to offer.</summary>
    Idle,

    /// <summary>An update is downloaded and installs on quit.</summary>
    Ready,

    /// <summary>An update exists but must be installed by hand.</summary>
    ManualOnly,
}

/// <summary>The update offer: update.current <c>status</c> and the update.status event.</summary>
/// <param name="State">What to offer.</param>
/// <param name="Version">The offered version; "" when idle.</param>
/// <param name="ReleaseUrl">"" unless an https://github.com URL.</param>
/// <param name="MoveToApplications">macOS only: the app must be moved to /Applications to update.</param>
public sealed record UpdateStatus(UpdateState State, string Version, string ReleaseUrl, bool MoveToApplications);

/// <summary>The "updated to version" notice: update.current <c>updated</c> and the update.updated event.</summary>
/// <param name="Version">The version now running.</param>
/// <param name="ReleaseUrl">"" unless an https://github.com URL.</param>
public sealed record UpdatedNotice(string Version, string ReleaseUrl);

/// <summary>update.current.</summary>
/// <param name="Status">The update offer.</param>
/// <param name="Updated">Null once delivered (or when the app was not just updated); encoded as null.</param>
public sealed record UpdateCurrentResult(UpdateStatus Status, UpdatedNotice? Updated);

/// <summary>GitHub login state: auth.state, auth.login and the auth.changed event.</summary>
/// <param name="LoggedIn">A GitHub session is active.</param>
/// <param name="Offline">Logged in from a saved session that could not be checked.</param>
/// <param name="User">The GitHub user name; "" when logged out.</param>
/// <param name="StatusText">Display only.</param>
public sealed record AuthState(bool LoggedIn, bool Offline, string User, string StatusText);

/// <summary>One row of audit.commits.</summary>
/// <param name="Summary">Display only.</param>
/// <param name="Url">The commit page; "" unless an https github.com URL.</param>
public sealed record AuditRow(string Summary, string Url);

/// <summary>audit.commits.</summary>
/// <param name="Rows">Newest first.</param>
/// <param name="Status">Display only.</param>
public sealed record AuditResult(IReadOnlyList<AuditRow> Rows, string Status);

/// <summary>bulk.load.</summary>
/// <param name="ToSign">Rows bulk.run would sign.</param>
/// <param name="CountsLine">Display only.</param>
/// <param name="PreviewNames">The recipients to sign, in order.</param>
/// <param name="InvalidLines">Display only.</param>
public sealed record BulkLoadResult(
    int ToSign, string CountsLine, IReadOnlyList<string> PreviewNames, IReadOnlyList<string> InvalidLines);

/// <summary>Why a bulk run ended: bulk.run <c>stopped</c>.</summary>
[JsonConverter(typeof(WireEnumConverter<BulkStop>))]
public enum BulkStop
{
    /// <summary>A value this build does not know.</summary>
    Unknown = 0,

    /// <summary>Every row was attempted.</summary>
    Completed,

    /// <summary>Cancelled (bulk.cancel or the PIN prompt).</summary>
    Cancelled,

    /// <summary>A failure stopped the run.</summary>
    Failed,
}

/// <summary>bulk.run.</summary>
/// <param name="Stopped">Why the run ended.</param>
/// <param name="SummaryLine">Display only.</param>
/// <param name="StopMessage">Display only; "" when completed.</param>
/// <param name="FailedLines">Display only.</param>
/// <param name="ResultsFilename">Suggested file name; display only.</param>
public sealed record BulkRunResult(
    BulkStop Stopped, string SummaryLine, string StopMessage, IReadOnlyList<string> FailedLines, string ResultsFilename);

/// <summary>A signed credential in the issuance log.</summary>
/// <param name="Timestamp">RFC 3339 UTC.</param>
/// <param name="Recipient">As signed.</param>
/// <param name="Honor">As signed.</param>
/// <param name="Detail">As signed.</param>
/// <param name="Date">YYYY-MM-DD.</param>
/// <param name="PayloadSha256">Hex SHA-256 of the signed payload; the credential's id.</param>
/// <param name="SignatureB64url">The signature, base64url.</param>
public sealed record HistoryRecord(
    string Timestamp,
    string Recipient,
    string Honor,
    string Detail,
    string Date,
    string PayloadSha256,
    string SignatureB64url);

/// <summary>One row of history.list.</summary>
/// <param name="Record">The record; pass it to history.recordText.</param>
/// <param name="Summary">Display only.</param>
/// <param name="Revoked">The credential is in the revocation list.</param>
public sealed record HistoryRow(HistoryRecord Record, string Summary, bool Revoked);

/// <summary>history.list.</summary>
/// <param name="Rows">Newest first, filtered by the query.</param>
/// <param name="LoadFailed">The issuance log could not be read.</param>
/// <param name="RevocationsUnavailable">The revocation list could not be fetched.</param>
/// <param name="RevocationsLoaded">The revocation list has been fetched.</param>
/// <param name="RevokeAvailable">Logged in, online and revocations loaded.</param>
public sealed record HistoryListResult(
    IReadOnlyList<HistoryRow> Rows,
    bool LoadFailed,
    bool RevocationsUnavailable,
    bool RevocationsLoaded,
    bool RevokeAvailable);

/// <summary>history.recordText.</summary>
/// <param name="Detail">Display only.</param>
/// <param name="RevokeConfirm">Display only.</param>
public sealed record RecordTextResult(string Detail, string RevokeConfirm);

/// <summary>history.duplicatePreview.</summary>
/// <param name="Count">Duplicate entries history.removeDuplicates would remove.</param>
/// <param name="ConfirmMessage">The question to ask before removing them; display only, "" when count is 0.</param>
public sealed record DuplicatePreviewResult(int Count, string ConfirmMessage);

/// <summary>history.removeDuplicates.</summary>
/// <param name="Removed">Entries removed.</param>
/// <param name="Backup">Path of the backup of the log before removal.</param>
/// <param name="Message">Display only; "" when removed is 0.</param>
public sealed record RemoveDuplicatesResult(int Removed, string Backup, string Message);

/// <summary>The outcome of a history.revoke that did not fail.</summary>
[JsonConverter(typeof(WireEnumConverter<RevokeStatus>))]
public enum RevokeStatus
{
    /// <summary>A value this build does not know.</summary>
    Unknown = 0,

    /// <summary>A revocation PR was opened.</summary>
    Submitted,

    /// <summary>Already in the revocation list.</summary>
    AlreadyRevoked,

    /// <summary>A revocation PR is already open.</summary>
    Pending,
}

/// <summary>history.revoke.</summary>
/// <param name="Status">The outcome.</param>
/// <param name="PrNumber">Submitted only; 0 otherwise.</param>
/// <param name="Url">Submitted only; "" otherwise.</param>
/// <param name="Title">Display only.</param>
/// <param name="Message">Display only.</param>
public sealed record RevokeResult(RevokeStatus Status, int PrNumber, string Url, string Title, string Message);

/// <summary>A registry entry as edited: registry.snapshot <c>entries</c>.</summary>
/// <param name="Authority">The key holder.</param>
/// <param name="From">YYYY-MM-DD.</param>
/// <param name="To">YYYY-MM-DD, or "" with <paramref name="NoExpiry"/>.</param>
/// <param name="NoExpiry">The key never expires.</param>
/// <param name="PublicKey">Base64 Ed25519 public key.</param>
/// <param name="Note">Free text.</param>
public sealed record RegistryEntry(string Authority, string From, string To, bool NoExpiry, string PublicKey, string Note);

/// <summary>registry.snapshot.</summary>
/// <param name="Entries">The entries, in registry order.</param>
/// <param name="Rows">Table cells per entry, in registry.columns order; display only.</param>
/// <param name="Dirty">Unsubmitted edits.</param>
/// <param name="Loaded">The registry has been fetched.</param>
public sealed record RegistrySnapshot(
    IReadOnlyList<RegistryEntry> Entries, IReadOnlyList<IReadOnlyList<string>> Rows, bool Dirty, bool Loaded);

/// <summary>registry.columns.</summary>
/// <param name="Columns">Display only.</param>
public sealed record ColumnsResult(IReadOnlyList<string> Columns);

/// <summary>registry.importCertificate, registry.importFromYubiKey.</summary>
/// <param name="PublicKey">Base64 Ed25519 public key.</param>
public sealed record PublicKeyResult(string PublicKey);

/// <summary>registry.submit.</summary>
/// <param name="PrNumber">The pull request opened.</param>
/// <param name="Url">Its page.</param>
public sealed record SubmitResult(int PrNumber, string Url);

/// <summary>The outcome of yubikey.check: <see cref="KeyCheck.Outcome"/>.</summary>
[JsonConverter(typeof(WireEnumConverter<KeyCheckOutcome>))]
public enum KeyCheckOutcome
{
    /// <summary>A value this build does not know.</summary>
    Unknown = 0,

    /// <summary>The key matches a registry entry valid today.</summary>
    Found,

    /// <summary>The key was read but matches no valid entry.</summary>
    NotFound,

    /// <summary>The key could not be read or checked.</summary>
    Failed,
}

/// <summary>yubikey.check.</summary>
/// <param name="Outcome">The outcome.</param>
/// <param name="Status">Display only.</param>
/// <param name="Details">Display only.</param>
public sealed record KeyCheck(KeyCheckOutcome Outcome, string Status, IReadOnlyList<string> Details);
