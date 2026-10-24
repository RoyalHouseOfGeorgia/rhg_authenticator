using System.Diagnostics;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Channels;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

/// <summary>
/// A scriptable <see cref="IBridge"/>: each method answers from its script (a
/// queue of results or <see cref="RpcException"/>s, the last one sticky;
/// unscripted void methods succeed, others fail like an undecodable response),
/// every call is recorded with its canonical params, and tests feed the event
/// channel. A <see cref="Hold"/> keeps a call open until the test releases it.
/// </summary>
internal sealed class FakeBridge : IBridge
{
    private readonly Lock _lock = new();
    private readonly Dictionary<string, List<Func<Task<object>>>> _scripts = [];
    private readonly List<(string Method, string Params)> _calls = [];
    private readonly Channel<BridgeEvent> _events = Channel.CreateUnbounded<BridgeEvent>();

    public ChannelReader<BridgeEvent> Events => _events.Reader;

    /// <summary>Answers the next call of <paramref name="method"/> with <paramref name="result"/>.</summary>
    public void Respond(string method, object result)
    {
        Enqueue(method, () => Task.FromResult(result));
    }

    /// <summary>Fails the next call of <paramref name="method"/> with <paramref name="error"/>.</summary>
    public void Fail(string method, RpcException error)
    {
        Enqueue(method, () => Task.FromResult<object>(error));
    }

    /// <summary>Keeps the next call of <paramref name="method"/> open until the hold is released.</summary>
    public Hold Hold(string method)
    {
        var hold = new Hold();
        Enqueue(method, () => hold.Task);
        return hold;
    }

    /// <summary>Drops the rest of <paramref name="method"/>'s script (its sticky last answer too).</summary>
    public void Reset(string method)
    {
        lock (_lock)
        {
            _scripts.Remove(method);
        }
    }

    public void Emit(BridgeEvent bridgeEvent)
    {
        Assert.True(_events.Writer.TryWrite(bridgeEvent));
    }

    /// <summary>Completes the event channel, as no live bridge does.</summary>
    public void CompleteEvents()
    {
        _events.Writer.Complete();
    }

    public IReadOnlyList<(string Method, string Params)> Calls
    {
        get
        {
            lock (_lock)
            {
                return [.. _calls];
            }
        }
    }

    public IReadOnlyList<string> Methods => [.. Calls.Select(c => c.Method)];

    /// <summary>The canonical params JSON of each call of <paramref name="method"/>.</summary>
    public IReadOnlyList<string> Params(string method)
    {
        return [.. Calls.Where(c => c.Method == method).Select(c => c.Params)];
    }

    public int Count(string method)
    {
        return Params(method).Count;
    }

    public async Task<TResult> CallAsync<TParams, TResult>(
        string method, TParams parameters, JsonTypeInfo<TParams> paramsTypeInfo, JsonTypeInfo<TResult> resultTypeInfo)
    {
        Func<Task<object>>? handler = null;
        lock (_lock)
        {
            _calls.Add((method, CanonicalJson.Encode(parameters, paramsTypeInfo)));
            if (_scripts.TryGetValue(method, out var queue))
            {
                handler = queue[0];
                if (queue.Count > 1)
                {
                    queue.RemoveAt(0);
                }
            }
        }
        if (handler is null)
        {
            return Empty.Value is TResult empty ? empty : throw RpcException.BadResponse();
        }
        return await handler() switch
        {
            RpcException error => throw error,
            TResult result => result,
            var other => throw new InvalidOperationException($"{method} scripted with a {other.GetType().Name}."),
        };
    }

    private void Enqueue(string method, Func<Task<object>> handler)
    {
        lock (_lock)
        {
            if (!_scripts.TryGetValue(method, out var queue))
            {
                _scripts[method] = queue = [];
            }
            queue.Add(handler);
        }
    }
}

/// <summary>A call held open by <see cref="FakeBridge.Hold"/>; release completes it.</summary>
internal sealed class Hold
{
    private readonly TaskCompletionSource<object> _source = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task<object> Task => _source.Task;

    public void Release(object result)
    {
        _source.SetResult(result);
    }

    public void ReleaseFailing(RpcException error)
    {
        _source.SetResult(error);
    }
}

/// <summary>A clock stopped at <paramref name="now"/>, in <paramref name="zone"/> (default UTC, so no test depends on the machine's).</summary>
internal sealed class FixedClock(DateTimeOffset now, TimeZoneInfo? zone = null) : TimeProvider
{
    public override TimeZoneInfo LocalTimeZone => zone ?? TimeZoneInfo.Utc;

    public override DateTimeOffset GetUtcNow()
    {
        return now;
    }
}

/// <summary>A save dialog answering from a queue (null = cancelled); records what it was asked.</summary>
internal sealed class FakeFileSave : IFileSaveService
{
    private readonly Queue<string?> _answers = new();

    public List<(string SuggestedFileName, string Extension)> Requests { get; } = [];

    public void Answer(string? path)
    {
        _answers.Enqueue(path);
    }

    public string? ChooseSavePath(string suggestedFileName, string extension)
    {
        Requests.Add((suggestedFileName, extension));
        return _answers.Count > 0 ? _answers.Dequeue() : null;
    }
}

/// <summary>
/// An open dialog answering from a queue (null = cancelled); records what it
/// was asked, each request's extensions joined with ",".
/// </summary>
internal sealed class FakeFileOpen : IFileOpenService
{
    private readonly Queue<string?> _answers = new();

    public List<string> Requests { get; } = [];

    public void Answer(string? path)
    {
        _answers.Enqueue(path);
    }

    public string? ChooseOpenPath(params string[] extensions)
    {
        Requests.Add(string.Join(",", extensions));
        return _answers.Count > 0 ? _answers.Dequeue() : null;
    }
}

/// <summary>Answers each question with the next scripted choice, Cancel once none is left; records every question.</summary>
internal sealed class FakeConfirm : IConfirmService
{
    private readonly Queue<ConfirmChoice> _answers = new();

    public List<Confirmation> Questions { get; } = [];

    /// <summary>Runs while a question is open, before it is answered (to raise events meanwhile).</summary>
    public Action<Confirmation>? OnAsk { get; set; }

    public void Answer(bool confirmed)
    {
        Answer(confirmed ? ConfirmChoice.Confirm : ConfirmChoice.Cancel);
    }

    public void Answer(ConfirmChoice choice)
    {
        _answers.Enqueue(choice);
    }

    public ConfirmChoice Choose(Confirmation question)
    {
        Questions.Add(question);
        OnAsk?.Invoke(question);
        return _answers.Count > 0 ? _answers.Dequeue() : ConfirmChoice.Cancel;
    }
}

internal sealed class FakeClipboard : IClipboard
{
    public List<string> Texts { get; } = [];

    /// <summary>What SetText returns: null succeeds.</summary>
    public string? Failure { get; set; }

    public string? SetText(string text)
    {
        Texts.Add(text);
        return Failure;
    }
}

internal sealed class FakeUrlOpener : IUrlOpener
{
    private readonly Lock _lock = new();
    private readonly List<Uri> _opened = [];

    public IReadOnlyList<Uri> Opened
    {
        get
        {
            lock (_lock)
            {
                return [.. _opened];
            }
        }
    }

    /// <summary>What Open returns: null succeeds.</summary>
    public string? Failure { get; set; }

    public string? Open(Uri url)
    {
        lock (_lock)
        {
            _opened.Add(url);
        }
        return Failure;
    }
}

internal static class Fixtures
{
    /// <summary>2026-01-01T23:30:00Z.</summary>
    public static readonly DateTimeOffset LateNewYearsDay = new(2026, 1, 1, 23, 30, 0, TimeSpan.Zero);

    /// <summary>
    /// Its status items are not what the numbers would make, so a test that
    /// shows them proves they are the core's, rendered as given.
    /// </summary>
    public static readonly AppInfo OnlineInfo = new(
        3, true, 1, "v1.2.3", ["Core keys: three", "Core expired: one", "Core version 1.2.3"]);

    /// <summary>A plan with <paramref name="toSign"/> rows to sign (at most 2) and one invalid row.</summary>
    public static BulkLoadResult BulkPlan(int toSign = 2, IReadOnlyList<string>? invalid = null)
    {
        invalid ??= ["line 4: honor: not one of the allowed honor titles"];
        return new BulkLoadResult(
            toSign,
            $"3 rows: {toSign} to sign, 0 already issued, {invalid.Count} invalid",
            [.. new[] { "Jane Doe", "Carol White" }.Take(toSign)],
            invalid);
    }

    public static BulkRunResult BulkOutcome(
        BulkStop stopped = BulkStop.Completed, string stopMessage = "", IReadOnlyList<string>? failed = null)
    {
        return new BulkRunResult(
            stopped,
            "Processed 3 rows: 2 successful (2 newly signed, 0 already issued), 1 invalid, 0 failed/not attempted.",
            stopMessage,
            failed ?? [],
            "rhg-bulk-results-2026-01-02-030405.csv");
    }

    public static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47];

    public static SignResult SignResult(bool existing = false, string warning = "")
    {
        return new SignResult(
            "José", "Order of the Eagle", "Knight", "2026-01-01", "https://verify.royalhouseofgeorgia.ge/?p=abc",
            existing, Png, warning, "rhg-0123abcd.svg", "rhg-0123abcd.png");
    }

    /// <summary>Waits (at most 5 s) until <paramref name="condition"/> holds; returns whether it did.</summary>
    public static async Task<bool> Settle(Func<bool> condition)
    {
        var waited = Stopwatch.StartNew();
        while (waited.Elapsed < TimeSpan.FromSeconds(5))
        {
            if (condition())
            {
                return true;
            }
            await Task.Delay(1, TestContext.Current.CancellationToken);
        }
        return condition();
    }

    public static readonly AuthState LoggedOut = new(false, false, "", "Not logged in");
    public static readonly AuthState LoggedIn = new(true, false, "octocat", "Logged in as @octocat");
    public static readonly AuthState LoggedInOffline = new(true, true, "octocat", "Offline");

    public static readonly IReadOnlyList<string> RegistryColumns = ["#", "Authority", "From", "To", "Restrictions", "Note", "Fingerprint"];

    /// <summary>Registry entry <paramref name="n"/> (1 to 9) and its table row (the cell texts are the core's).</summary>
    public static (RegistryEntry Entry, IReadOnlyList<string> Row) RegistryEntry(int n)
    {
        var entry = new RegistryEntry($"Authority {n}", $"2025-01-0{n}", $"2030-12-2{n}", false, $"KEY{n}=", "");
        return (entry, [$"{n}", entry.Authority, $"2025-Jan-0{n}", $"2030-Dec-2{n}", "(none)", "", $"fp{n}"]);
    }

    /// <summary>A new snapshot of entries 1 to <paramref name="count"/> (records compare its lists by reference).</summary>
    public static RegistrySnapshot Snapshot(int count, bool dirty = false, bool loaded = true)
    {
        var made = Enumerable.Range(1, count).Select(RegistryEntry).ToList();
        return new RegistrySnapshot([.. made.Select(m => m.Entry)], [.. made.Select(m => m.Row)], dirty, loaded);
    }

    /// <summary>Scripts startup's auth.state, registry.columns and registry.snapshot.</summary>
    public static void ScriptStartupReads(FakeBridge fake, AuthState? auth = null, RegistrySnapshot? snapshot = null)
    {
        fake.Respond(RpcMethod.AuthState, auth ?? LoggedOut);
        fake.Respond(RpcMethod.RegistryColumns, new ColumnsResult(RegistryColumns));
        fake.Respond(RpcMethod.RegistrySnapshot, snapshot ?? Snapshot(2));
    }

    /// <summary>
    /// An app whose startup succeeded, so its events are being drained. Later
    /// auth.state and registry.snapshot reads answer from each test's own script.
    /// </summary>
    public static async Task<AppViewModel> StartedApp(
        FakeBridge fake,
        TimeProvider? clock = null,
        FakeUrlOpener? urls = null,
        FakeFileSave? fileSave = null,
        FakeFileOpen? fileOpen = null,
        FakeConfirm? confirm = null)
    {
        fake.Respond(RpcMethod.AppInit, OnlineInfo);
        fake.Respond(RpcMethod.SignHonors, new HonorsResult(["Order of Queen Tamar", "Order of the Eagle"]));
        ScriptStartupReads(fake);
        var app = new AppViewModel(
            fake, fileSave ?? new FakeFileSave(), fileOpen ?? new FakeFileOpen(), new FakeClipboard(), urls ?? new FakeUrlOpener(),
            confirm ?? new FakeConfirm(), clock ?? new FixedClock(LateNewYearsDay));
        await app.StartAsync();
        Assert.Equal(AppPhase.Ready, app.Phase);
        fake.Reset(RpcMethod.AuthState);
        fake.Reset(RpcMethod.RegistrySnapshot);
        return app;
    }
}
