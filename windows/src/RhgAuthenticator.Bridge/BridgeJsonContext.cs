using System.Text.Json.Serialization;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// System.Text.Json metadata for every contract DTO: camelCase names, every
/// constructor parameter without a default required, and nullable annotations
/// enforced, so a result missing a field or holding a null where none is
/// allowed fails to decode (<see cref="RpcException.BadResponse"/>). Unknown
/// fields are ignored.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true)]
[JsonSerializable(typeof(Empty))]
[JsonSerializable(typeof(AppInitParams))]
[JsonSerializable(typeof(ShutdownParams))]
[JsonSerializable(typeof(PathParams))]
[JsonSerializable(typeof(CredentialParams))]
[JsonSerializable(typeof(SaveQrParams))]
[JsonSerializable(typeof(ReportErrorParams))]
[JsonSerializable(typeof(PinSubmitParams))]
[JsonSerializable(typeof(PinCancelParams))]
[JsonSerializable(typeof(HistoryListParams))]
[JsonSerializable(typeof(RecordParams))]
[JsonSerializable(typeof(RevokeParams))]
[JsonSerializable(typeof(AddEntryParams))]
[JsonSerializable(typeof(UpdateEntryParams))]
[JsonSerializable(typeof(AppInfo))]
[JsonSerializable(typeof(ExportResult))]
[JsonSerializable(typeof(CanQuitResult))]
[JsonSerializable(typeof(HonorsResult))]
[JsonSerializable(typeof(SignResult))]
[JsonSerializable(typeof(ReportResult))]
[JsonSerializable(typeof(UpdateCurrentResult))]
[JsonSerializable(typeof(AuthState))]
[JsonSerializable(typeof(AuditResult))]
[JsonSerializable(typeof(BulkLoadResult))]
[JsonSerializable(typeof(BulkRunResult))]
[JsonSerializable(typeof(HistoryListResult))]
[JsonSerializable(typeof(RecordTextResult))]
[JsonSerializable(typeof(DuplicatePreviewResult))]
[JsonSerializable(typeof(RemoveDuplicatesResult))]
[JsonSerializable(typeof(RevokeResult))]
[JsonSerializable(typeof(RegistrySnapshot))]
[JsonSerializable(typeof(ColumnsResult))]
[JsonSerializable(typeof(PublicKeyResult))]
[JsonSerializable(typeof(SubmitResult))]
[JsonSerializable(typeof(KeyCheck))]
[JsonSerializable(typeof(PinRequest))]
[JsonSerializable(typeof(PinDismiss))]
[JsonSerializable(typeof(DeviceCode))]
[JsonSerializable(typeof(BulkProgress))]
[JsonSerializable(typeof(UpdateStatus))]
[JsonSerializable(typeof(UpdatedNotice))]
[JsonSerializable(typeof(UpdateState))]
[JsonSerializable(typeof(BulkStop))]
[JsonSerializable(typeof(RevokeStatus))]
[JsonSerializable(typeof(KeyCheckOutcome))]
[JsonSerializable(typeof(RpcErrorCode))]
[JsonSerializable(typeof(QrFormat))]
public sealed partial class BridgeJsonContext : JsonSerializerContext
{
}

/// <summary>The wire forms of envelopes and events, with <see cref="BridgeJsonContext"/>'s options.</summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true)]
[JsonSerializable(typeof(RpcErrorPayload))]
[JsonSerializable(typeof(EventEnvelope))]
[JsonSerializable(typeof(EventName))]
internal sealed partial class WireJsonContext : JsonSerializerContext
{
}
