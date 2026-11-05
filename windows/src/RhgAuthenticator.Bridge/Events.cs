using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;

namespace RhgAuthenticator.Bridge;

/// <summary>pin.request: prompt for the YubiKey PIN, then answer with pin.submit or pin.cancel.</summary>
/// <param name="RequestId">Pass to pin.submit or pin.cancel.</param>
/// <param name="RememberDefault">The initial state of the "remember PIN" checkbox.</param>
/// <param name="MaxBytes">Cap the PIN to this many UTF-8 bytes (<see cref="PinTruncation.Truncate"/>).</param>
public sealed record PinRequest(ulong RequestId, bool RememberDefault, int MaxBytes);

/// <summary>pin.dismiss: the pin.request with this id is withdrawn (timed out, cancelled or shutdown); close its prompt.</summary>
/// <param name="RequestId">The withdrawn request.</param>
public sealed record PinDismiss(ulong RequestId);

/// <summary>auth.deviceCode: show the GitHub device-flow code.</summary>
/// <param name="UserCode">The code to enter.</param>
/// <param name="VerificationUri">Where to enter it.</param>
public sealed record DeviceCode(string UserCode, string VerificationUri);

/// <summary>bulk.progress.</summary>
/// <param name="Done">Rows finished.</param>
/// <param name="Total">Rows to sign.</param>
/// <param name="Name">The recipient being signed; display only.</param>
public sealed record BulkProgress(int Done, int Total, string Name);

/// <summary>
/// An event from the core, <c>{"event":name,"data":payload}</c>, with its typed
/// payload. Match on the nested records; ignore <see cref="Unknown"/>.
/// </summary>
public abstract record BridgeEvent
{
    private protected BridgeEvent()
    {
    }

    /// <summary>The event name on the wire.</summary>
    public abstract string Name { get; }

    /// <summary>app.internalError: the core hit a bug; show the restart alert.</summary>
    public sealed record AppInternalError : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "app.internalError";
    }

    /// <summary>auth.changed: the login state changed (payloads may arrive out of order: call auth.state).</summary>
    /// <param name="State">The new state.</param>
    public sealed record AuthChanged(AuthState State) : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "auth.changed";
    }

    /// <summary>auth.deviceCode: show the device-flow code.</summary>
    /// <param name="Code">The code and where to enter it.</param>
    public sealed record AuthDeviceCode(DeviceCode Code) : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "auth.deviceCode";
    }

    /// <summary>bulk.connecting: the bulk run is opening the YubiKey.</summary>
    public sealed record BulkConnecting : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "bulk.connecting";
    }

    /// <summary>bulk.progress: one row of the bulk run is being signed.</summary>
    /// <param name="Progress">Rows done and the current recipient.</param>
    public sealed record BulkProgressed(BulkProgress Progress) : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "bulk.progress";
    }

    /// <summary>history.changed: re-read history.list.</summary>
    public sealed record HistoryChanged : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "history.changed";
    }

    /// <summary>history.revocationsChanged: re-read history.list.</summary>
    public sealed record HistoryRevocationsChanged : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "history.revocationsChanged";
    }

    /// <summary>pin.dismiss: close the prompt of the withdrawn request.</summary>
    /// <param name="Dismiss">The withdrawn request.</param>
    public sealed record PinDismissed(PinDismiss Dismiss) : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "pin.dismiss";
    }

    /// <summary>pin.request: prompt for the PIN.</summary>
    /// <param name="Request">The prompt to show.</param>
    public sealed record PinRequested(PinRequest Request) : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "pin.request";
    }

    /// <summary>registry.changed: re-read registry.snapshot.</summary>
    public sealed record RegistryChanged : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "registry.changed";
    }

    /// <summary>sign.connecting: sign.sign is opening the YubiKey.</summary>
    public sealed record SignConnecting : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "sign.connecting";
    }

    /// <summary>update.status: the update offer changed.</summary>
    /// <param name="Status">The new offer.</param>
    public sealed record UpdateStatusChanged(UpdateStatus Status) : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "update.status";
    }

    /// <summary>update.updated: show the "updated to version" notice.</summary>
    /// <param name="Notice">The version now running.</param>
    public sealed record UpdateUpdated(UpdatedNotice Notice) : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => "update.updated";
    }

    /// <summary>
    /// An event this build does not know, or one whose JSON did not decode
    /// (name "" when even the name could not be read). Ignore it.
    /// </summary>
    /// <param name="EventName">The name, as sent.</param>
    public sealed record Unknown(string EventName) : BridgeEvent
    {
        /// <inheritdoc />
        public override string Name => EventName;
    }

    /// <summary>
    /// Parses one event as delivered to the event callback. It never fails:
    /// JSON that does not decode becomes <see cref="Unknown"/> (with the name
    /// when it can be read), and nothing of the input is logged.
    /// </summary>
    public static BridgeEvent Parse(ReadOnlySpan<byte> utf8Json)
    {
        try
        {
            return ParseStrict(utf8Json);
        }
        catch (JsonException)
        {
            return new Unknown(NameOrEmpty(utf8Json));
        }
    }

    /// <summary>
    /// Parses an event strictly: a known event whose payload does not decode,
    /// or JSON that is not an event, throws <see cref="JsonException"/>. An
    /// unknown name is <see cref="Unknown"/>. <see cref="Parse"/> is the lenient
    /// form for live events.
    /// </summary>
    public static BridgeEvent ParseStrict(ReadOnlySpan<byte> utf8Json)
    {
        var envelope = JsonSerializer.Deserialize(utf8Json, WireJsonContext.Default.EventEnvelope)
            ?? throw new JsonException("An event is an object.");
        var data = envelope.Data;
        return envelope.Event switch
        {
            "app.internalError" => new AppInternalError(),
            "auth.changed" => new AuthChanged(Payload(data, BridgeJsonContext.Default.AuthState)),
            "auth.deviceCode" => new AuthDeviceCode(Payload(data, BridgeJsonContext.Default.DeviceCode)),
            "bulk.connecting" => new BulkConnecting(),
            "bulk.progress" => new BulkProgressed(Payload(data, BridgeJsonContext.Default.BulkProgress)),
            "history.changed" => new HistoryChanged(),
            "history.revocationsChanged" => new HistoryRevocationsChanged(),
            "pin.dismiss" => new PinDismissed(Payload(data, BridgeJsonContext.Default.PinDismiss)),
            "pin.request" => new PinRequested(Payload(data, BridgeJsonContext.Default.PinRequest)),
            "registry.changed" => new RegistryChanged(),
            "sign.connecting" => new SignConnecting(),
            "update.status" => new UpdateStatusChanged(Payload(data, BridgeJsonContext.Default.UpdateStatus)),
            "update.updated" => new UpdateUpdated(Payload(data, BridgeJsonContext.Default.UpdatedNotice)),
            var name => new Unknown(name),
        };
    }

    /// <summary>
    /// Encodes the event canonically, as the core does (<c>data</c> null for
    /// payload-less and unknown events); for tests and fakes.
    /// </summary>
    internal string ToJson()
    {
        var data = this switch
        {
            AuthChanged e => JsonSerializer.SerializeToNode(e.State, BridgeJsonContext.Default.AuthState),
            AuthDeviceCode e => JsonSerializer.SerializeToNode(e.Code, BridgeJsonContext.Default.DeviceCode),
            BulkProgressed e => JsonSerializer.SerializeToNode(e.Progress, BridgeJsonContext.Default.BulkProgress),
            PinDismissed e => JsonSerializer.SerializeToNode(e.Dismiss, BridgeJsonContext.Default.PinDismiss),
            PinRequested e => JsonSerializer.SerializeToNode(e.Request, BridgeJsonContext.Default.PinRequest),
            UpdateStatusChanged e => JsonSerializer.SerializeToNode(e.Status, BridgeJsonContext.Default.UpdateStatus),
            UpdateUpdated e => JsonSerializer.SerializeToNode(e.Notice, BridgeJsonContext.Default.UpdatedNotice),
            _ => null,
        };
        var node = new JsonObject { ["event"] = Name, ["data"] = data };
        return System.Text.Encoding.UTF8.GetString(CanonicalJson.EncodeNode(node));
    }

    private static T Payload<T>(JsonElement? data, JsonTypeInfo<T> typeInfo)
    {
        if (data is not { } element)
        {
            throw new JsonException("The event has no payload.");
        }
        return element.Deserialize(typeInfo) ?? throw new JsonException("The event's payload is null.");
    }

    private static string NameOrEmpty(ReadOnlySpan<byte> utf8Json)
    {
        try
        {
            return JsonSerializer.Deserialize(utf8Json, WireJsonContext.Default.EventName)?.Event ?? "";
        }
        catch (JsonException)
        {
            return "";
        }
    }
}

/// <summary>An event's wire form, <c>{"event":name,"data":payload}</c>.</summary>
internal sealed record EventEnvelope(string Event, JsonElement? Data = null);

/// <summary>Just an event's name, read when its payload does not decode.</summary>
internal sealed record EventName(string Event);
