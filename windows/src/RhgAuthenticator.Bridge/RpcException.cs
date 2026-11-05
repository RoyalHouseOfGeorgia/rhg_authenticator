using System.Text.Json.Serialization;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// The <c>code</c> of an error envelope. Hosts branch on it (and on
/// <see cref="RpcException.OfferReport"/>), never on the message.
/// </summary>
[JsonConverter(typeof(WireEnumConverter<RpcErrorCode>))]
public enum RpcErrorCode
{
    /// <summary>A code this build does not know; treat like <see cref="Failed"/>.</summary>
    Unknown = 0,

    /// <summary>The operation was cancelled (the PIN prompt in sign.sign, auth.cancelLogin).</summary>
    Cancelled,

    /// <summary>A host programming error: unknown method, bad params, wrong lifecycle state.</summary>
    Input,

    /// <summary>A conflicting operation is running.</summary>
    Busy,

    /// <summary>The method needs a GitHub login.</summary>
    NotLoggedIn,

    /// <summary>The GitHub session expired; log in again.</summary>
    SessionExpired,

    /// <summary>The registry changed on GitHub since it was loaded.</summary>
    RegistryChanged,

    /// <summary>The thing asked for no longer exists (e.g. a report id).</summary>
    NotFound,

    /// <summary>There is nothing to export.</summary>
    NothingToExport,

    /// <summary>GitHub login is not available on this computer.</summary>
    LoginUnavailable,

    /// <summary>Show the message; there is nothing more specific to do.</summary>
    Failed,

    /// <summary>The core hit a bug; the user should restart.</summary>
    Internal,
}

/// <summary>
/// The error of a failed call: the <c>error</c> object of an error envelope,
/// or one the bridge itself raised (<see cref="BadResponse"/>,
/// <see cref="BadParams"/>). <see cref="Exception.Message"/> is user-facing
/// text: display only, never compared or parsed.
/// </summary>
public sealed class RpcException : Exception
{
    /// <summary>The message of <see cref="BadResponse"/>; also the app.internalError alert's.</summary>
    public const string BadResponseMessage = "An internal error occurred — please restart";

    /// <summary>The message of <see cref="BadParams"/>.</summary>
    public const string BadParamsMessage = "The request could not be encoded.";

    /// <summary>Creates an error with a known <paramref name="code"/>.</summary>
    public RpcException(RpcErrorCode code, string message, bool offerReport = false, string? reportId = null)
        : this(WireEnum.NameOf(code), message, offerReport, reportId)
    {
    }

    /// <summary>Creates an error from the envelope's raw <paramref name="rawCode"/>.</summary>
    public RpcException(string rawCode, string message, bool offerReport = false, string? reportId = null)
        : base(message)
    {
        ArgumentNullException.ThrowIfNull(rawCode);
        RawCode = rawCode;
        Code = WireEnum.Parse<RpcErrorCode>(rawCode);
        OfferReport = offerReport;
        ReportId = reportId;
    }

    /// <summary>The error code; <see cref="RpcErrorCode.Unknown"/> for one this build does not know.</summary>
    public RpcErrorCode Code { get; }

    /// <summary>The code as sent, kept for an unknown code.</summary>
    public string RawCode { get; }

    /// <summary>Whether the UI offers "Report Issue" (sign.reportError with <see cref="ReportId"/>).</summary>
    public bool OfferReport { get; }

    /// <summary>Present only when <see cref="OfferReport"/> is true.</summary>
    public string? ReportId { get; }

    /// <summary>
    /// The core's response could not be decoded (a contract mismatch between
    /// this build and the library). Reported as <c>internal</c>: the user can
    /// only restart.
    /// </summary>
    public static RpcException BadResponse()
    {
        return new RpcException(RpcErrorCode.Internal, BadResponseMessage);
    }

    /// <summary>The params could not be encoded: a host programming error, like the core's <c>input</c>.</summary>
    public static RpcException BadParams()
    {
        return new RpcException(RpcErrorCode.Input, BadParamsMessage);
    }
}

/// <summary>The <c>error</c> object of an error envelope, as on the wire.</summary>
internal sealed record RpcErrorPayload(
    string Code,
    string Message,
    bool OfferReport = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ReportId = null)
{
    public RpcException ToException()
    {
        return new RpcException(Code, Message, OfferReport, ReportId);
    }

    public static RpcErrorPayload From(RpcException error)
    {
        return new RpcErrorPayload(error.RawCode, error.Message, error.OfferReport, error.ReportId);
    }
}
