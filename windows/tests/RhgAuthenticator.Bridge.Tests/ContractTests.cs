using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace RhgAuthenticator.Bridge.Tests;

/// <summary>
/// How one method's contract files are checked: <see cref="Params"/> decodes a
/// params file and re-encodes it canonically; <see cref="Result"/> decodes a
/// success envelope, re-encodes it, and returns the result enum's wire value
/// and whether it is a known member (null for a method without a result enum).
/// </summary>
internal sealed record MethodContract(
    Func<byte[], byte[]> Params,
    Func<byte[], (byte[] Encoded, (string Raw, bool Known)? EnumValue)> Result)
{
    private static BridgeJsonContext Json => BridgeJsonContext.Default;

    private static MethodContract Of<TParams, TResult>(
        JsonTypeInfo<TParams> paramsInfo, JsonTypeInfo<TResult> resultInfo,
        Func<TResult, (string, bool)>? enumValue = null)
    {
        return new MethodContract(
            data => Support.Canonical(JsonSerializer.Deserialize(data, paramsInfo)!, paramsInfo),
            data =>
            {
                var decoded = RpcEnvelope.Decode(data, resultInfo);
                return (Support.SuccessEnvelope(decoded, resultInfo), enumValue?.Invoke(decoded));
            });
    }

    private static (string, bool) Wire<TEnum>(TEnum value)
        where TEnum : struct, Enum
    {
        return (WireEnum.NameOf(value), WireEnum.Known<TEnum>().Contains(value));
    }

    /// <summary>The DTOs of each method.</summary>
    public static IReadOnlyDictionary<string, MethodContract> All { get; } = new Dictionary<string, MethodContract>
    {
        [RpcMethod.AppCanQuit] = Of(Json.Empty, Json.CanQuitResult),
        [RpcMethod.AppExportErrorLog] = Of(Json.PathParams, Json.ExportResult),
        [RpcMethod.AppInfo] = Of(Json.Empty, Json.AppInfo),
        [RpcMethod.AppInit] = Of(Json.AppInitParams, Json.AppInfo),
        [RpcMethod.AppShutdown] = Of(Json.ShutdownParams, Json.Empty),
        [RpcMethod.AppStart] = Of(Json.Empty, Json.Empty),
        [RpcMethod.AuditCommits] = Of(Json.Empty, Json.AuditResult),
        [RpcMethod.AuthCancelLogin] = Of(Json.Empty, Json.Empty),
        [RpcMethod.AuthLogin] = Of(Json.Empty, Json.AuthState),
        [RpcMethod.AuthLogout] = Of(Json.Empty, Json.Empty),
        [RpcMethod.AuthState] = Of(Json.Empty, Json.AuthState),
        [RpcMethod.BulkCancel] = Of(Json.Empty, Json.Empty),
        [RpcMethod.BulkExportResults] = Of(Json.PathParams, Json.Empty),
        [RpcMethod.BulkLoad] = Of(Json.PathParams, Json.BulkLoadResult),
        [RpcMethod.BulkRun] = Of(Json.Empty, Json.BulkRunResult, r => Wire(r.Stopped)),
        [RpcMethod.HistoryDeleteEntry] = Of(Json.RecordParams, Json.DeleteEntryResult),
        [RpcMethod.HistoryDuplicatePreview] = Of(Json.Empty, Json.DuplicatePreviewResult),
        [RpcMethod.HistoryExportIssuanceLog] = Of(Json.PathParams, Json.ExportResult),
        [RpcMethod.HistoryList] = Of(Json.HistoryListParams, Json.HistoryListResult),
        [RpcMethod.HistoryRecordText] = Of(Json.RecordParams, Json.RecordTextResult),
        [RpcMethod.HistoryRefresh] = Of(Json.Empty, Json.Empty),
        [RpcMethod.HistoryRemoveDuplicates] = Of(Json.Empty, Json.RemoveDuplicatesResult),
        [RpcMethod.HistoryRevoke] = Of(Json.RevokeParams, Json.RevokeResult, r => Wire(r.Status)),
        [RpcMethod.PinCancel] = Of(Json.PinCancelParams, Json.Empty),
        [RpcMethod.PinSubmit] = Of(Json.PinSubmitParams, Json.Empty),
        [RpcMethod.RegistryAddEntry] = Of(Json.AddEntryParams, Json.Empty),
        [RpcMethod.RegistryColumns] = Of(Json.Empty, Json.ColumnsResult),
        [RpcMethod.RegistryFetch] = Of(Json.Empty, Json.Empty),
        [RpcMethod.RegistryImportCertificate] = Of(Json.PathParams, Json.PublicKeyResult),
        [RpcMethod.RegistryImportFromYubiKey] = Of(Json.Empty, Json.PublicKeyResult),
        [RpcMethod.RegistrySnapshot] = Of(Json.Empty, Json.RegistrySnapshot),
        [RpcMethod.RegistrySubmit] = Of(Json.Empty, Json.SubmitResult),
        [RpcMethod.RegistryUpdateEntry] = Of(Json.UpdateEntryParams, Json.Empty),
        [RpcMethod.SignHonors] = Of(Json.Empty, Json.HonorsResult),
        [RpcMethod.SignReportError] = Of(Json.ReportErrorParams, Json.ReportResult),
        [RpcMethod.SignSaveQr] = Of(Json.SaveQrParams, Json.Empty),
        [RpcMethod.SignSign] = Of(Json.CredentialParams, Json.SignResult),
        [RpcMethod.SignValidate] = Of(Json.CredentialParams, Json.Empty),
        [RpcMethod.UpdateCurrent] = Of(Json.Empty, Json.UpdateCurrentResult, r => Wire(r.Status.State)),
        [RpcMethod.YubikeyCheck] = Of(Json.Empty, Json.KeyCheck, r => Wire(r.Outcome)),
    };
}

public sealed class ContractTests
{
    private static string MethodsDir => Path.Combine(Support.ContractDir, "methods");

    [Fact]
    public void MethodIndexListsExactlyTheRpcMethods()
    {
        var index = JsonSerializer.Deserialize<Dictionary<string, string>>(Support.ContractFile("methods/index.json"))!;
        Assert.Equal(index.Keys.Order(StringComparer.Ordinal), RpcMethod.All.Order(StringComparer.Ordinal));
        Assert.Equal(RpcMethod.All.Order(StringComparer.Ordinal), MethodContract.All.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(RpcMethod.All.Count, RpcMethod.All.Distinct().Count());
    }

    [Fact]
    public void EveryMethodFileDecodesAndReencodesToTheSameBytes()
    {
        var all = Support.FilesUnder(MethodsDir).Where(f => f != "index.json").ToList();
        Assert.True(all.Count >= RpcMethod.All.Count * 2);
        var enumValues = new Dictionary<string, HashSet<string>>();
        foreach (var path in all)
        {
            var parts = path.Split('/');
            Assert.Equal(2, parts.Length);
            var contract = MethodContract.All[parts[0]];
            var data = File.ReadAllBytes(Path.Combine(MethodsDir, path));
            switch (parts[1])
            {
                case "params.json":
                    Assert.True(data.AsSpan().SequenceEqual(contract.Params(data)), $"params bytes differ: {path}");
                    break;
                case "result.json":
                    {
                        var (encoded, value) = contract.Result(data);
                        Assert.True(data.AsSpan().SequenceEqual(encoded), $"result bytes differ: {path}");
                        if (value is { } v)
                        {
                            Assert.True(v.Known, $"unknown enum value in {path}");
                            enumValues.TryAdd(parts[0], []);
                            enumValues[parts[0]].Add(v.Raw);
                        }
                        break;
                    }
                default:
                    {
                        // result.<value>.json: the result enum's other values.
                        var name = parts[1];
                        Assert.StartsWith("result.", name, StringComparison.Ordinal);
                        Assert.EndsWith(".json", name, StringComparison.Ordinal);
                        var expected = name["result.".Length..^".json".Length];
                        var (encoded, value) = contract.Result(data);
                        Assert.True(data.AsSpan().SequenceEqual(encoded), $"result bytes differ: {path}");
                        Assert.NotNull(value);
                        Assert.Equal(expected, value.Value.Raw);
                        Assert.True(value.Value.Known);
                        enumValues.TryAdd(parts[0], []);
                        enumValues[parts[0]].Add(value.Value.Raw);
                        break;
                    }
            }
        }
        // Each result enum's members are exactly the contract's values.
        Assert.Equal(WireNames<BulkStop>(), enumValues[RpcMethod.BulkRun]);
        Assert.Equal(WireNames<RevokeStatus>(), enumValues[RpcMethod.HistoryRevoke]);
        Assert.Equal(WireNames<KeyCheckOutcome>(), enumValues[RpcMethod.YubikeyCheck]);
    }

    [Fact]
    public void EveryErrorFileDecodesAsItsRpcExceptionAndReencodes()
    {
        var errorsDir = Path.Combine(Support.ContractDir, "errors");
        var codes = new HashSet<string>();
        foreach (var name in Support.FilesUnder(errorsDir))
        {
            var data = File.ReadAllBytes(Path.Combine(errorsDir, name));
            var error = Assert.Throws<RpcException>(() => RpcEnvelope.Decode(data, BridgeJsonContext.Default.Empty));
            Assert.NotEqual(RpcErrorCode.Unknown, error.Code);
            byte[] encoded = [.. "{\"error\":"u8,
                .. CanonicalJson.EncodeToUtf8(RpcErrorPayload.From(error), WireJsonContext.Default.RpcErrorPayload),
                .. ",\"ok\":false}\n"u8];
            Assert.True(data.AsSpan().SequenceEqual(encoded), $"error bytes differ: {name}");
            Assert.False(string.IsNullOrEmpty(error.Message));
            if (name == "failed-with-report.json")
            {
                Assert.Equal(RpcErrorCode.Failed, error.Code);
                Assert.True(error.OfferReport);
                Assert.Equal("1", error.ReportId);
            }
            else
            {
                Assert.Equal(error.RawCode + ".json", name);
                Assert.False(error.OfferReport, name);
                Assert.Null(error.ReportId);
                codes.Add(error.RawCode);
            }
        }
        Assert.Equal(WireNames<RpcErrorCode>(), codes);
    }

    [Fact]
    public void EveryEventFileDecodesAsItsBridgeEventAndReencodes()
    {
        var eventsDir = Path.Combine(Support.ContractDir, "events");
        var names = new HashSet<string>();
        var states = new HashSet<string>();
        foreach (var file in Support.FilesUnder(eventsDir))
        {
            var data = File.ReadAllBytes(Path.Combine(eventsDir, file));
            var e = BridgeEvent.ParseStrict(data);
            Assert.Equal(e, BridgeEvent.Parse(data));
            Assert.True(data.AsSpan().SequenceEqual(Support.Utf8(e.ToJson() + "\n")), $"event bytes differ: {file}");
            Assert.IsNotType<BridgeEvent.Unknown>(e);
            var stem = file[..^".json".Length];
            if (e is BridgeEvent.UpdateStatusChanged { Status: var status })
            {
                Assert.Equal($"update.status.{WireEnum.NameOf(status.State)}", stem);
                Assert.NotEqual(UpdateState.Unknown, status.State);
                states.Add(WireEnum.NameOf(status.State));
            }
            else
            {
                Assert.Equal(e.Name, stem);
            }
            names.Add(e.Name);
        }
        string[] allEvents =
        [
            "app.internalError", "auth.changed", "auth.deviceCode", "bulk.connecting", "bulk.progress",
            "history.changed", "history.revocationsChanged", "pin.dismiss", "pin.request", "registry.changed",
            "sign.connecting", "update.status", "update.updated",
        ];
        Assert.Equal(allEvents.ToHashSet(), names);
        Assert.Equal(WireNames<UpdateState>(), states);
    }

    [Fact]
    public void EventFilesHoldTheirPayloads()
    {
        BridgeEvent Event(string name)
        {
            return BridgeEvent.ParseStrict(Support.ContractFile($"events/{name}.json"));
        }

        Assert.Equal(
            new BridgeEvent.AuthChanged(new AuthState(true, false, "octocat", "Logged in as @octocat")), Event("auth.changed"));
        Assert.Equal(
            new BridgeEvent.AuthDeviceCode(new DeviceCode("ABCD-1234", "https://github.com/login/device")), Event("auth.deviceCode"));
        Assert.Equal(new BridgeEvent.BulkProgressed(new BulkProgress(1, 3, "Jane Doe")), Event("bulk.progress"));
        Assert.Equal(new BridgeEvent.PinDismissed(new PinDismiss(3)), Event("pin.dismiss"));
        Assert.Equal(new BridgeEvent.PinRequested(new PinRequest(1, true, 8)), Event("pin.request"));
        var ready = Assert.IsType<BridgeEvent.UpdateStatusChanged>(Event("update.status.ready")).Status;
        Assert.Equal(new UpdateStatus(UpdateState.Ready, "9.9.9", ready.ReleaseUrl, false), ready);
        Assert.StartsWith("https://github.com/", ready.ReleaseUrl, StringComparison.Ordinal);
        var manual = Assert.IsType<BridgeEvent.UpdateStatusChanged>(Event("update.status.manualOnly")).Status;
        Assert.Equal(UpdateState.ManualOnly, manual.State);
        Assert.True(manual.MoveToApplications);
        var updated = Assert.IsType<BridgeEvent.UpdateUpdated>(Event("update.updated")).Notice;
        Assert.Equal("9.9.8", updated.Version);
        Assert.IsType<BridgeEvent.AppInternalError>(Event("app.internalError"));
        Assert.IsType<BridgeEvent.BulkConnecting>(Event("bulk.connecting"));
        Assert.IsType<BridgeEvent.HistoryChanged>(Event("history.changed"));
        Assert.IsType<BridgeEvent.HistoryRevocationsChanged>(Event("history.revocationsChanged"));
        Assert.IsType<BridgeEvent.RegistryChanged>(Event("registry.changed"));
        Assert.IsType<BridgeEvent.SignConnecting>(Event("sign.connecting"));
    }

    private sealed record PinCase(string Input, int MaxBytes, string Output);

    [Fact]
    public void PinTruncationMatchesEveryContractCaseAsUtf8Bytes()
    {
        var cases = JsonSerializer.Deserialize<List<PinCase>>(
            Support.ContractFile("pin-truncation.json"), new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        Assert.True(cases.Count >= 10);
        foreach (var c in cases)
        {
            var got = PinTruncation.Truncate(c.Input, c.MaxBytes);
            Assert.True(Support.Utf8(got).AsSpan().SequenceEqual(Support.Utf8(c.Output)),
                $"input {Convert.ToHexString(Support.Utf8(c.Input))}, maxBytes {c.MaxBytes}");
        }
    }

    private static HashSet<string> WireNames<TEnum>()
        where TEnum : struct, Enum
    {
        return [.. WireEnum.Known<TEnum>().Select(WireEnum.NameOf)];
    }
}
