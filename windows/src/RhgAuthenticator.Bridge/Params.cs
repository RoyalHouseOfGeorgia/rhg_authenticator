using System.Text;
using System.Text.Json.Serialization;

namespace RhgAuthenticator.Bridge;

// Params DTOs, one per params shape in the contract
// (go/service/rpc/testdata/contract/methods/<method>/params.json). Property
// names are the JSON keys in camelCase. CanonicalJson encodes each to the
// contract's bytes.

/// <summary>
/// An empty object, <c>{}</c>: the params of a method without params and the
/// result of a void method.
/// </summary>
public sealed record Empty
{
    /// <summary>The one value.</summary>
    public static readonly Empty Value = new();
}

/// <summary>app.init.</summary>
/// <param name="DataDir">Absolute app data directory; null (omitted) uses the platform default.</param>
public sealed record AppInitParams(
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? DataDir = null);

/// <summary>app.shutdown.</summary>
/// <param name="Relaunch">Relaunch after applying a ready update ("Restart now").</param>
public sealed record ShutdownParams(bool Relaunch);

/// <summary>
/// A file path: app.exportErrorLog, bulk.exportResults, bulk.load,
/// history.exportIssuanceLog, registry.importCertificate.
/// </summary>
/// <param name="Path">The file's full path.</param>
public sealed record PathParams(string Path);

/// <summary>A credential to validate or sign: sign.validate, sign.sign.</summary>
/// <param name="Recipient">The recipient's name.</param>
/// <param name="Honor">One of sign.honors.</param>
/// <param name="Detail">Free text.</param>
/// <param name="Date">YYYY-MM-DD.</param>
public sealed record CredentialParams(string Recipient, string Honor, string Detail, string Date);

/// <summary>The file format of sign.saveQR.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<QrFormat>))]
public enum QrFormat
{
    /// <summary>Scalable vector graphics.</summary>
    [JsonStringEnumMemberName("svg")]
    Svg,

    /// <summary>A PNG image.</summary>
    [JsonStringEnumMemberName("png")]
    Png,
}

/// <summary>sign.saveQR.</summary>
/// <param name="Url">The <see cref="SignResult.Url"/>.</param>
/// <param name="Format">The file format.</param>
/// <param name="Path">The file's full path.</param>
public sealed record SaveQrParams(string Url, QrFormat Format, string Path);

/// <summary>sign.reportError.</summary>
/// <param name="ReportId">The <see cref="RpcException.ReportId"/> of an error offering a report.</param>
public sealed record ReportErrorParams(string ReportId);

/// <summary>pin.submit. Its <see cref="object.ToString"/> redacts the PIN.</summary>
/// <param name="RequestId">The <see cref="PinRequest.RequestId"/> answered.</param>
/// <param name="Pin">The PIN, capped with <see cref="PinTruncation.Truncate"/>.</param>
/// <param name="Remember">Cache the PIN for later signs.</param>
public sealed record PinSubmitParams(ulong RequestId, string Pin, bool Remember)
{
    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append($"RequestId = {RequestId}, Pin = <redacted>, Remember = {Remember}");
        return true;
    }
}

/// <summary>pin.cancel.</summary>
/// <param name="RequestId">The <see cref="PinRequest.RequestId"/> cancelled.</param>
public sealed record PinCancelParams(ulong RequestId);

/// <summary>history.list.</summary>
/// <param name="Query">Filter text; "" lists every record.</param>
public sealed record HistoryListParams(string Query);

/// <summary>history.recordText, history.deleteEntry.</summary>
/// <param name="Record">A record exactly as history.list returned it.</param>
public sealed record RecordParams(HistoryRecord Record);

/// <summary>history.revoke.</summary>
/// <param name="PayloadSha256">The credential's <see cref="HistoryRecord.PayloadSha256"/>.</param>
public sealed record RevokeParams(string PayloadSha256);

/// <summary>The registry entry form of registry.addEntry and registry.updateEntry.</summary>
/// <param name="Authority">The key holder.</param>
/// <param name="From">YYYY-MM-DD.</param>
/// <param name="To">YYYY-MM-DD, or "" with <paramref name="NoExpiry"/>.</param>
/// <param name="Note">Free text.</param>
/// <param name="NoExpiry">The key never expires.</param>
public sealed record EntryForm(string Authority, string From, string To, string Note, bool NoExpiry);

/// <summary>registry.addEntry.</summary>
/// <param name="Form">The entry.</param>
/// <param name="PublicKey">Base64 Ed25519 public key.</param>
public sealed record AddEntryParams(EntryForm Form, string PublicKey);

/// <summary>registry.updateEntry.</summary>
/// <param name="Index">The entry's index in <see cref="RegistrySnapshot.Entries"/>.</param>
/// <param name="PublicKey">The key the entry must still hold.</param>
/// <param name="Form">The replacement entry.</param>
public sealed record UpdateEntryParams(int Index, string PublicKey, EntryForm Form);
