using System.Text.Json;

namespace RhgAuthenticator.Bridge.Tests;

/// <summary>Each typed IBridge method sends its contract method and params and decodes the contract result.</summary>
public sealed class HelperTests
{
    private static BridgeJsonContext Json => BridgeJsonContext.Default;

    [Fact]
    public async Task EachHelperSendsContractParamsAndDecodesTheContractResult()
    {
        var responses = RpcMethod.All.ToDictionary(m => m, m => Support.ContractFile($"methods/{m}/result.json"));
        var recording = new RecordingBridge(responses);
        IBridge bridge = recording;
        var credential = new CredentialParams("Jane Doe", "Ennoblement", "For service", "2026-01-02");
        var signUrl = JsonSerializer.Deserialize(Support.ContractFile("methods/sign.saveQR/params.json"), Json.SaveQrParams)!.Url;
        var record = JsonSerializer.Deserialize(Support.ContractFile("methods/history.recordText/params.json"), Json.RecordParams)!.Record;
        var deleted = JsonSerializer.Deserialize(Support.ContractFile("methods/history.deleteEntry/params.json"), Json.RecordParams)!.Record;
        const string certKey = "JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0=";
        const string yubiKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

        Assert.Equal(1, (await bridge.InitAppAsync("/DATA")).ActiveKeys);
        await bridge.StartAppAsync();
        Assert.Equal("dev", (await bridge.AppInfoAsync()).Version);
        Assert.True((await bridge.CanQuitAsync()).Dirty);
        await bridge.ShutdownAsync(relaunch: false);
        Assert.Contains("Ennoblement", (await bridge.HonorsAsync()).Honors);
        await bridge.ValidateAsync(credential);
        Assert.True((await bridge.SignAsync(credential)).Existing);
        await bridge.SaveQrAsync(signUrl, QrFormat.Svg, "/OUT/rhg-credential-2026-01-02-da93dff4-min3cm.svg");
        Assert.True((await bridge.ReportErrorAsync("1")).Filed);
        await bridge.SubmitPinAsync(1, "123456", remember: true);
        await bridge.CancelPinAsync(2);
        Assert.Equal(UpdateState.Ready, (await bridge.CurrentUpdateAsync()).Status.State);
        Assert.Equal(1, (await bridge.LoadBulkAsync("/OUT/bulk.csv")).ToSign);
        Assert.Equal(BulkStop.Completed, (await bridge.RunBulkAsync()).Stopped);
        await bridge.CancelBulkAsync();
        await bridge.ExportBulkResultsAsync("/OUT/bulk-results.csv");
        Assert.Equal(KeyCheckOutcome.Found, (await bridge.CheckYubiKeyAsync()).Outcome);
        // Display strings are render-only (contract README): check shapes, not text.
        Assert.NotEmpty((await bridge.ExportErrorLogAsync("/OUT/error-log.txt")).Message);
        Assert.Equal(7, (await bridge.RegistryColumnsAsync()).Count);
        var snapshot = await bridge.RegistrySnapshotAsync();
        Assert.True(snapshot.Entries.Count == 2 && snapshot.Rows.Count == 2 && snapshot.Dirty && snapshot.Loaded);
        await bridge.FetchRegistryAsync();
        await bridge.AddEntryAsync(new EntryForm("New Authority", "2026-01-01", "", "Second key", true), certKey);
        await bridge.UpdateEntryAsync(0, yubiKey, new EntryForm("A", "2025-01-01", "2030-12-31", "", false));
        Assert.Equal(certKey, await bridge.ImportCertificateAsync("/OUT/certificate.pem"));
        Assert.Equal(yubiKey, await bridge.ImportFromYubiKeyAsync());
        Assert.Equal(42, (await bridge.SubmitRegistryAsync()).PrNumber);
        Assert.Equal(new AuthState(false, false, "", "Not logged in"), await bridge.AuthStateAsync());
        Assert.Equal("octocat", (await bridge.LoginAsync()).User);
        await bridge.CancelLoginAsync();
        await bridge.LogoutAsync();
        await bridge.RefreshHistoryAsync();
        Assert.Equal(4, (await bridge.ListHistoryAsync("")).Rows.Count);
        var text = await bridge.RecordTextAsync(record);
        Assert.True(text.RevokeConfirm.Length > 0 && text.DeleteConfirm.Length > 0 && !text.OfferRevoke);
        Assert.Equal("/DATA/issuances.json.bak-20260102T030405Z", (await bridge.DeleteEntryAsync(deleted)).Backup);
        Assert.Equal(RevokeStatus.Submitted, (await bridge.RevokeAsync(new string('0', 63) + "2")).Status);
        Assert.NotEmpty((await bridge.ExportIssuanceLogAsync("/OUT/issuances-export.json")).Title);
        Assert.Equal(1, (await bridge.DuplicatePreviewAsync()).Count);
        Assert.Equal(1, (await bridge.RemoveDuplicatesAsync()).Removed);
        Assert.Single((await bridge.AuditCommitsAsync()).Rows);

        string[] expected =
        [
            RpcMethod.AppInit, RpcMethod.AppStart, RpcMethod.AppInfo, RpcMethod.AppCanQuit, RpcMethod.AppShutdown,
            RpcMethod.SignHonors, RpcMethod.SignValidate, RpcMethod.SignSign, RpcMethod.SignSaveQr,
            RpcMethod.SignReportError, RpcMethod.PinSubmit, RpcMethod.PinCancel, RpcMethod.UpdateCurrent,
            RpcMethod.BulkLoad, RpcMethod.BulkRun, RpcMethod.BulkCancel, RpcMethod.BulkExportResults,
            RpcMethod.YubikeyCheck, RpcMethod.AppExportErrorLog, RpcMethod.RegistryColumns, RpcMethod.RegistrySnapshot,
            RpcMethod.RegistryFetch, RpcMethod.RegistryAddEntry, RpcMethod.RegistryUpdateEntry,
            RpcMethod.RegistryImportCertificate, RpcMethod.RegistryImportFromYubiKey, RpcMethod.RegistrySubmit,
            RpcMethod.AuthState, RpcMethod.AuthLogin, RpcMethod.AuthCancelLogin, RpcMethod.AuthLogout,
            RpcMethod.HistoryRefresh, RpcMethod.HistoryList, RpcMethod.HistoryRecordText,
            RpcMethod.HistoryDeleteEntry, RpcMethod.HistoryRevoke, RpcMethod.HistoryExportIssuanceLog, RpcMethod.HistoryDuplicatePreview, RpcMethod.HistoryRemoveDuplicates,
            RpcMethod.AuditCommits,
        ];
        var calls = recording.Calls;
        Assert.Equal(expected, calls.Select(c => c.Method));
        Assert.Equal(RpcMethod.All.Order(StringComparer.Ordinal), expected.Order(StringComparer.Ordinal));
        foreach (var (call, method) in calls.Zip(expected))
        {
            Assert.Equal(Support.ContractFile($"methods/{method}/params.json"), Support.Utf8(call.Params + "\n"));
        }
    }

    [Fact]
    public async Task HelperRethrowsTheErrorEnvelope()
    {
        IBridge bridge = new RecordingBridge(new Dictionary<string, byte[]>
        {
            [RpcMethod.SignSign] = Support.ContractFile("errors/failed-with-report.json"),
        });
        var error = await Assert.ThrowsAsync<RpcException>(() => bridge.SignAsync(new CredentialParams("", "", "", "")));
        Assert.Equal(RpcErrorCode.Failed, error.Code);
        Assert.True(error.OfferReport);
        Assert.Equal("1", error.ReportId);
    }

    [Fact]
    public void ResultSpotChecks()
    {
        T Result<T>(string path, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info)
        {
            return RpcEnvelope.Decode(Support.ContractFile($"methods/{path}"), info);
        }

        var info = Result("app.info/result.json", Json.AppInfo);
        Assert.Equal(3, info.StatusItems.Count);
        Assert.All(info.StatusItems, item => Assert.NotEmpty(item));
        Assert.Equal(info.StatusItems, Result("app.init/result.json", Json.AppInfo).StatusItems);
        foreach (var method in new[] { "app.exportErrorLog", "history.exportIssuanceLog" })
        {
            var export = Result($"{method}/result.json", Json.ExportResult);
            Assert.NotEmpty(export.Title);
            Assert.Contains("/OUT/", export.Message, StringComparison.Ordinal);
        }
        var preview = Result("history.duplicatePreview/result.json", Json.DuplicatePreviewResult);
        Assert.Equal(1, preview.Count);
        Assert.NotEmpty(preview.ConfirmMessage);
        var removed = Result("history.removeDuplicates/result.json", Json.RemoveDuplicatesResult);
        Assert.Equal(new RemoveDuplicatesResult(1, "/DATA/issuances.json.bak-20260102T030405Z", removed.Message), removed);
        Assert.NotEmpty(removed.Message);
        var signed = Result("sign.sign/result.json", Json.SignResult);
        Assert.Equal(("Jane Doe", "rhg-credential-2026-01-02-da93dff4-2048px.png", "rhg-credential-2026-01-02-da93dff4-min3cm.svg", ""),
            (signed.Recipient, signed.PngFilename, signed.SvgFilename, signed.Warning));
        var run = Result("bulk.run/result.failed.json", Json.BulkRunResult);
        Assert.Equal((BulkStop.Failed, "rhg-bulk-results-2026-01-02-030405.csv"), (run.Stopped, run.ResultsFilename));
        Assert.Single(run.FailedLines);
        Assert.Equal(BulkStop.Cancelled, Result("bulk.run/result.cancelled.json", Json.BulkRunResult).Stopped);
        var list = Result("history.list/result.json", Json.HistoryListResult);
        Assert.Equal(
            new HistoryRecord("2026-01-02T03:04:05Z", "Alice Smith", "Ennoblement", "For service", "2026-01-02",
                list.Rows[3].Record.PayloadSha256, list.Rows[3].Record.SignatureB64url),
            list.Rows[3].Record);
        Assert.True(list.Rows[3].Revoked);
        Assert.Equal((false, false, true, false), (list.LoadFailed, list.RevocationsUnavailable, list.RevocationsLoaded, list.RevokeAvailable));
        Assert.Equal(new RegistryEntry("A", "2025-01-01", "2030-12-31", false, "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", ""),
            Result("registry.snapshot/result.json", Json.RegistrySnapshot).Entries[0]);
        var pending = Result("history.revoke/result.pending.json", Json.RevokeResult);
        Assert.Equal((RevokeStatus.Pending, 0, ""), (pending.Status, pending.PrNumber, pending.Url));
        Assert.Equal(RevokeStatus.AlreadyRevoked, Result("history.revoke/result.alreadyRevoked.json", Json.RevokeResult).Status);
        var check = Result("yubikey.check/result.notFound.json", Json.KeyCheck);
        Assert.Equal((KeyCheckOutcome.NotFound, "Key NOT found in registry"), (check.Outcome, check.Status));
        Assert.Equal(KeyCheckOutcome.Failed, Result("yubikey.check/result.failed.json", Json.KeyCheck).Outcome);
        var update = Result("update.current/result.json", Json.UpdateCurrentResult);
        Assert.Equal("9.9.8", update.Updated!.Version);
        Assert.Equal(new SubmitResult(42, "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/pull/42"),
            Result("registry.submit/result.json", Json.SubmitResult));
        var audit = Result("audit.commits/result.json", Json.AuditResult);
        Assert.StartsWith("https://github.com/", audit.Rows[0].Url, StringComparison.Ordinal);
        Assert.Equal(new ReportResult(true, "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues/44"),
            Result("sign.reportError/result.json", Json.ReportResult));
        var load = Result("bulk.load/result.json", Json.BulkLoadResult);
        Assert.Equal(["Carol White"], load.PreviewNames);
        Assert.Single(load.InvalidLines);
        var text = Result("history.recordText/result.json", Json.RecordTextResult);
        Assert.StartsWith("Timestamp:", text.Detail, StringComparison.Ordinal);
        Assert.StartsWith("Revoke", text.RevokeConfirm, StringComparison.Ordinal);
        Assert.NotEmpty(text.DeleteConfirm);
        Assert.False(text.OfferRevoke);
        var deleted = Result("history.deleteEntry/result.json", Json.DeleteEntryResult);
        Assert.Equal(new DeleteEntryResult("/DATA/issuances.json.bak-20260102T030405Z", "Record Deleted", deleted.Message), deleted);
        Assert.NotEmpty(deleted.Message);
    }
}
