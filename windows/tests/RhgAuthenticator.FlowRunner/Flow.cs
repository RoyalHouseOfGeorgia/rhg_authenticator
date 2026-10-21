using System.Diagnostics;
using System.Text;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.FlowRunner;

/// <summary>A scenario; its name is the command-line argument.</summary>
#pragma warning disable CA1707, IDE1006 // The members are the command-line names.
internal enum Scenario
{
    /// <summary>Registry unreachable: signing is refused before any PIN prompt; a panic is an internal error and the process stays alive.</summary>
    offline,

    /// <summary>Registry served: Sign with the PIN submitted, a stale requestId, the other Sign-tab methods, and the NFC round trip of Georgian and accented names.</summary>
    online,

    /// <summary>Registry served: a cancelled PIN prompt cancels the Sign.</summary>
    pinCancel,

    /// <summary>Registry served, 300 ms PIN timeout: an unanswered prompt is dismissed and the Sign fails.</summary>
    pinTimeout,
}
#pragma warning restore CA1707, IDE1006

/// <summary>A failed check.</summary>
internal sealed class CheckFailedException(string check, string detail) : Exception($"{check}: {detail}")
{
    public string Check { get; } = check;

    public string Detail { get; } = detail;
}

/// <summary>test.configure failed with input: most likely not the rhgfake build (exit 3).</summary>
internal sealed class NotRhgFakeException(string coreMessage) : Exception(coreMessage);

/// <summary>How <see cref="Flow.RunAnsweringAsync{T}"/> answers the call's pin.request.</summary>
internal enum PinAnswer
{
    Submit,
    Cancel,
    Ignore,
}

/// <summary>One scenario's checks, in order; the bridge calls run on LiveBridge's threads.</summary>
internal sealed class Flow
{
    /// <summary>The fake card's PIN (service.FakeCardPIN).</summary>
    public const string FakePin = "123456";

    private readonly IBridge _bridge;
    private readonly LiveBridge _live;
    private readonly List<BridgeEvent> _events = [];
    private readonly Lock _eventsLock = new();
    private int _checks;

    public Flow(LiveBridge bridge)
    {
        _live = bridge;
        _bridge = bridge;
    }

    /// <summary>Writes one output line, flushed, so a killed runner leaves every line.</summary>
    public static void Emit(string line)
    {
        Console.Out.WriteLine(line);
        Console.Out.Flush();
    }

    public static int Usage()
    {
        Emit($"usage: RhgAuthenticator.FlowRunner <library> {string.Join(" | ", Enum.GetNames<Scenario>())}");
        return 2;
    }

    /// <summary>
    /// Runs <paramref name="scenario"/> with a fresh data directory,
    /// <c>&lt;tmp&gt;/rhgflow-&lt;guid&gt;/data</c> (files are saved next to it: the
    /// core refuses saves into the data folder), and returns the exit code.
    /// </summary>
    public async Task<int> RunAsync(Scenario scenario)
    {
        var root = Path.Combine(Path.GetTempPath(), $"rhgflow-{Guid.NewGuid():N}");
        var dataDir = Path.Combine(root, "data");
        try
        {
            Directory.CreateDirectory(dataDir);
            await (scenario switch
            {
                Scenario.offline => OfflineAsync(dataDir),
                Scenario.online => OnlineAsync(dataDir),
                Scenario.pinCancel => PinCancelAsync(dataDir),
                Scenario.pinTimeout => PinTimeoutAsync(dataDir),
                _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, null),
            }).ConfigureAwait(false);
        }
        catch (NotRhgFakeException e)
        {
            Emit($"FAIL: test.configure: input ({e.Message}): the library is probably not the rhgfake build: "
                + "point RHGCORE_LIB_DIR at go/release/rhgcore/rhgfake");
            return 3;
        }
        catch (CheckFailedException e)
        {
            Emit($"FAIL: {e.Check}: {e.Detail}");
            return 1;
        }
        catch (Exception e)
        {
            Emit($"FAIL: {scenario}: {e.GetType().Name}: {e.Message}");
            return 1;
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
            }
        }
        Emit($"PASS: {scenario} ({_checks} checks)");
        return 0;
    }

    // Scenarios

    private async Task OfflineAsync(string dataDir)
    {
        var info = await ConfigureAndInitAsync(online: false, pinTimeoutMs: 0, dataDir).ConfigureAwait(false);
        Check(!info.Online, "app.init offline", $"online {info.Online}");

        var start = EventCount;
        var refused = await SignResultAsync(Credential("Jane Doe")).ConfigureAwait(false);
        ExpectError(refused, RpcErrorCode.Failed, "sign.sign offline is refused");
        Check(First<BridgeEvent.PinRequested>(start) is null, "sign.sign offline asks for no PIN", "a pin.request");

        await ExpectErrorAsync(RpcErrorCode.Internal, "test.panic is an internal error",
            () => _live.CallAsync("test.panic", Empty.Value, TestHooksJsonContext.Default.Empty, TestHooksJsonContext.Default.Empty))
            .ConfigureAwait(false);
        await StepAsync("app.canQuit after a panic", () => _bridge.CanQuitAsync()).ConfigureAwait(false);
        await ShutdownAndCheckClosedAsync().ConfigureAwait(false);
    }

    private async Task OnlineAsync(string dataDir)
    {
        var info = await ConfigureAndInitAsync(online: true, pinTimeoutMs: 0, dataDir).ConfigureAwait(false);
        Check(info.Online && info.ActiveKeys == 1, "app.init online with the fake card's key",
            $"online {info.Online}, activeKeys {info.ActiveKeys}");
        await StepAsync("app.start", () => _bridge.StartAppAsync()).ConfigureAwait(false);
        var again = await StepAsync("app.info", () => _bridge.AppInfoAsync()).ConfigureAwait(false);
        Check(Same(again, info), "app.info matches app.init", "differs");
        var honors = await StepAsync("sign.honors", () => _bridge.HonorsAsync()).ConfigureAwait(false);
        Check(honors.Honors.Contains("Ennoblement"), "sign.honors lists Ennoblement", $"{honors.Honors.Count} honors");
        var update = await StepAsync("update.current", () => _bridge.CurrentUpdateAsync()).ConfigureAwait(false);
        Check(update.Status.State == UpdateState.Idle && update.Updated is null, "update.current is idle",
            update.Status.State.ToString());
        await StepAsync("sign.validate", () => _bridge.ValidateAsync(Credential("Jane Doe"))).ConfigureAwait(false);
        await ExpectErrorAsync(RpcErrorCode.Failed, "sign.validate without a recipient fails",
            () => _bridge.ValidateAsync(Credential(""))).ConfigureAwait(false);

        // Sign with the PIN submitted from the event stream.
        var start = EventCount;
        var (signed, request) = await SignAnsweringAsync(Credential("Jane Doe"), PinAnswer.Submit).ConfigureAwait(false);
        var result = Succeeded(signed, "sign.sign with the PIN submitted");
        Check(request is not null, "one pin.request", "none");
        Check(result.Url.StartsWith("https://verify.royalhouseofgeorgia.ge/", StringComparison.Ordinal) && !result.Existing,
            "sign.sign returns a new credential's verification URL", $"existing {result.Existing}");
        Check(result.PngPreview.Length > 0, "sign.sign returns a PNG preview", "empty");
        await WaitForAsync("sign.connecting", () => First<BridgeEvent.SignConnecting>(start) is not null).ConfigureAwait(false);
        if (request is not null)
        {
            await ExpectErrorAsync(RpcErrorCode.Input, "pin.submit with a stale requestId",
                () => _bridge.SubmitPinAsync(request.RequestId, FakePin, remember: false)).ConfigureAwait(false);
        }

        var svg = Path.Combine(Path.GetDirectoryName(dataDir)!, "qr.svg");
        await StepAsync("sign.saveQR", () => _bridge.SaveQrAsync(result.Url, QrFormat.Svg, svg)).ConfigureAwait(false);
        Check(File.Exists(svg), "sign.saveQR wrote the file", "missing");
        await ExpectErrorAsync(RpcErrorCode.NotFound, "sign.reportError of an unknown report",
            () => _bridge.ReportErrorAsync("999")).ConfigureAwait(false);

        await RoundTripNamesAsync().ConfigureAwait(false);

        var quit = await StepAsync("app.canQuit", () => _bridge.CanQuitAsync()).ConfigureAwait(false);
        Check(!quit.Dirty, "app.canQuit is not dirty", "dirty");
        await ShutdownAndCheckClosedAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Signs Georgian and accented names; the signed recipient must be the NFC
    /// form, compared as UTF-8 bytes.
    /// </summary>
    private async Task RoundTripNamesAsync()
    {
        const string georgian = "ნიკოლოზ ბაგრატიონი";
        const string nfc = "José";
        const string nfd = "José";
        Check(!Utf8(nfc).SequenceEqual(Utf8(nfd)), "NFC and NFD inputs differ in bytes", "same bytes");
        Check(georgian.IsNormalized(NormalizationForm.FormC), "the Georgian name is NFC", "not NFC");

        var signedGeorgian = Succeeded((await SignAnsweringAsync(Credential(georgian), PinAnswer.Submit).ConfigureAwait(false)).Result,
            "sign.sign a Georgian name");
        Check(Utf8(signedGeorgian.Recipient).SequenceEqual(Utf8(georgian)),
            "Georgian recipient round-trips byte for byte", "bytes differ");

        var georgianNfd = georgian.Normalize(NormalizationForm.FormD);
        var signedGeorgianNfd = Succeeded((await SignAnsweringAsync(Credential(georgianNfd), PinAnswer.Submit).ConfigureAwait(false)).Result,
            "sign.sign a Georgian name in NFD");
        Check(Utf8(signedGeorgianNfd.Recipient).SequenceEqual(Utf8(georgian)),
            "Georgian NFD recipient is signed as NFC bytes", "bytes differ");

        var signedNfd = Succeeded((await SignAnsweringAsync(Credential(nfd), PinAnswer.Submit).ConfigureAwait(false)).Result,
            "sign.sign an NFD name");
        Check(Utf8(signedNfd.Recipient).SequenceEqual(Utf8(nfc)), "NFD recipient is signed as NFC bytes",
            $"bytes {Convert.ToHexString(Utf8(signedNfd.Recipient))}");
        Check(!signedNfd.Existing, "NFD name is a new credential", "existing");

        var signedNfc = Succeeded((await SignAnsweringAsync(Credential(nfc), PinAnswer.Submit).ConfigureAwait(false)).Result,
            "sign.sign an NFC name");
        Check(Utf8(signedNfc.Recipient).SequenceEqual(Utf8(nfc)), "NFC recipient is signed as NFC bytes",
            $"bytes {Convert.ToHexString(Utf8(signedNfc.Recipient))}");
        Check(signedNfc.Existing && signedNfc.Url == signedNfd.Url, "NFC name is the NFD name's credential",
            $"existing {signedNfc.Existing}");
    }

    private async Task PinCancelAsync(string dataDir)
    {
        await ConfigureAndInitAsync(online: true, pinTimeoutMs: 0, dataDir).ConfigureAwait(false);
        var (signed, request) = await SignAnsweringAsync(Credential("Jane Doe"), PinAnswer.Cancel).ConfigureAwait(false);
        Check(request is not null, "one pin.request", "none");
        ExpectError(signed, RpcErrorCode.Cancelled, "sign.sign with the PIN cancelled");
        await ShutdownAndCheckClosedAsync().ConfigureAwait(false);
    }

    private async Task PinTimeoutAsync(string dataDir)
    {
        await ConfigureAndInitAsync(online: true, pinTimeoutMs: 300, dataDir).ConfigureAwait(false);
        var start = EventCount;
        var (signed, request) = await SignAnsweringAsync(Credential("Jane Doe"), PinAnswer.Ignore).ConfigureAwait(false);
        if (request is null)
        {
            throw new CheckFailedException("one pin.request", "none");
        }
        Pass("one pin.request");
        ExpectError(signed, RpcErrorCode.Failed, "sign.sign fails when the PIN prompt times out");
        await WaitForAsync("pin.dismiss withdraws the timed-out request",
            () => First<BridgeEvent.PinDismissed>(start, d => d.Dismiss.RequestId == request.RequestId) is not null)
            .ConfigureAwait(false);
        await ShutdownAndCheckClosedAsync().ConfigureAwait(false);
    }

    // Steps

    private static CredentialParams Credential(string recipient)
    {
        return new CredentialParams(recipient, "Ennoblement", "For service", "2026-01-02");
    }

    private static byte[] Utf8(string s)
    {
        return Encoding.UTF8.GetBytes(s);
    }

    private static bool Same(AppInfo a, AppInfo b)
    {
        var json = BridgeJsonContext.Default.AppInfo;
        return CanonicalJson.Encode(a, json) == CanonicalJson.Encode(b, json);
    }

    private async Task<AppInfo> ConfigureAndInitAsync(bool online, int pinTimeoutMs, string dataDir)
    {
        try
        {
            await _live.CallAsync("test.configure", new TestConfigureParams(online, pinTimeoutMs),
                TestHooksJsonContext.Default.TestConfigureParams, TestHooksJsonContext.Default.Empty).ConfigureAwait(false);
        }
        catch (RpcException e) when (e.Code == RpcErrorCode.Input)
        {
            // The release build has no test.* methods: unknown method, input.
            throw new NotRhgFakeException(e.Message);
        }
        catch (RpcException e)
        {
            throw new CheckFailedException("test.configure", $"code {e.RawCode}");
        }
        Pass("test.configure");
        return await StepAsync("app.init", () => _bridge.InitAppAsync(dataDir)).ConfigureAwait(false);
    }

    /// <summary>app.shutdown, then any method but app.canQuit/app.shutdown is refused.</summary>
    private async Task ShutdownAndCheckClosedAsync()
    {
        await StepAsync("app.shutdown", () => _bridge.ShutdownAsync(relaunch: false)).ConfigureAwait(false);
        await ExpectErrorAsync(RpcErrorCode.Input, "app.info after app.shutdown", () => _bridge.AppInfoAsync()).ConfigureAwait(false);
    }

    private Task<(Outcome<SignResult> Result, PinRequest? Request)> SignAnsweringAsync(CredentialParams credential, PinAnswer answer)
    {
        return RunAnsweringAsync("sign.sign", answer, () => SignResultAsync(credential));
    }

    /// <summary>
    /// Runs <paramref name="body"/> (a call that may prompt for the PIN) and
    /// answers its first pin.request, if one comes (an already-issued
    /// credential returns without one).
    /// </summary>
    private async Task<(Outcome<T> Result, PinRequest? Request)> RunAnsweringAsync<T>(
        string what, PinAnswer answer, Func<Task<Outcome<T>>> body)
    {
        var start = EventCount;
        var call = body();
        var deadline = Stopwatch.StartNew();
        PinRequest? request = null;
        while (deadline.Elapsed < TimeSpan.FromSeconds(30))
        {
            if (call.IsCompleted)
            {
                return (await call.ConfigureAwait(false), request);
            }
            if (request is null && First<BridgeEvent.PinRequested>(start) is { } requested)
            {
                request = requested.Request;
                var id = request.RequestId;
                switch (answer)
                {
                    case PinAnswer.Submit:
                        await StepAsync("pin.submit", () => _bridge.SubmitPinAsync(id, FakePin, remember: false)).ConfigureAwait(false);
                        break;
                    case PinAnswer.Cancel:
                        await StepAsync("pin.cancel", () => _bridge.CancelPinAsync(id)).ConfigureAwait(false);
                        break;
                    default:
                        break;
                }
            }
            await Task.Delay(10).ConfigureAwait(false);
        }
        throw new CheckFailedException(what, "no result within 30 s");
    }

    private async Task<Outcome<SignResult>> SignResultAsync(CredentialParams credential)
    {
        try
        {
            return new Outcome<SignResult>(await _bridge.SignAsync(credential).ConfigureAwait(false), null);
        }
        catch (RpcException e)
        {
            return new Outcome<SignResult>(default, e);
        }
    }

    private T Succeeded<T>(Outcome<T> outcome, string what)
    {
        if (outcome.Error is { } e)
        {
            throw new CheckFailedException(what, $"code {e.RawCode}");
        }
        Pass(what);
        return outcome.Value!;
    }

    private async Task<T> StepAsync<T>(string what, Func<Task<T>> body)
    {
        try
        {
            var value = await body().ConfigureAwait(false);
            Pass(what);
            return value;
        }
        catch (RpcException e)
        {
            throw new CheckFailedException(what, $"code {e.RawCode}");
        }
    }

    private Task StepAsync(string what, Func<Task> body)
    {
        return StepAsync(what, async () =>
        {
            await body().ConfigureAwait(false);
            return true;
        });
    }

    private async Task ExpectErrorAsync(RpcErrorCode code, string what, Func<Task> body)
    {
        try
        {
            await body().ConfigureAwait(false);
        }
        catch (RpcException e)
        {
            Check(e.Code == code, what, $"code {e.RawCode}");
            return;
        }
        throw new CheckFailedException(what, "succeeded");
    }

    private void ExpectError<T>(Outcome<T> outcome, RpcErrorCode code, string what)
    {
        if (outcome.Error is not { } e)
        {
            throw new CheckFailedException(what, "succeeded");
        }
        Check(e.Code == code, what, $"code {e.RawCode}");
    }

    /// <summary>Polls <paramref name="found"/> for up to 5 s.</summary>
    private async Task WaitForAsync(string what, Func<bool> found)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(5))
        {
            if (found())
            {
                Pass(what);
                return;
            }
            await Task.Delay(10).ConfigureAwait(false);
        }
        throw new CheckFailedException(what, "not seen within 5 s");
    }

    private int EventCount
    {
        get
        {
            lock (_eventsLock)
            {
                Drain();
                return _events.Count;
            }
        }
    }

    /// <summary>
    /// Moves every queued event into the record. Reading synchronously (under
    /// the lock, the single reader) means an event the core emitted before a
    /// call returned is seen by a check right after it.
    /// </summary>
    private void Drain()
    {
        while (_live.Events.TryRead(out var e))
        {
            _events.Add(e);
        }
    }

    /// <summary>The first event of type <typeparamref name="T"/> at or after index <paramref name="start"/> matching <paramref name="match"/>.</summary>
    private T? First<T>(int start, Func<T, bool>? match = null)
        where T : BridgeEvent
    {
        lock (_eventsLock)
        {
            Drain();
            return _events.Skip(start).OfType<T>().FirstOrDefault(e => match is null || match(e));
        }
    }

    private void Check(bool condition, string what, string detail)
    {
        if (!condition)
        {
            throw new CheckFailedException(what, detail);
        }
        Pass(what);
    }

    private void Pass(string what)
    {
        _checks++;
        Emit($"ok: {what}");
    }
}

/// <summary>A call's value or its error.</summary>
internal sealed record Outcome<T>(T? Value, RpcException? Error);
