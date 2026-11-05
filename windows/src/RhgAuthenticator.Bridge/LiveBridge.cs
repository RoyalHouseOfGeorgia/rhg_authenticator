using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Channels;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// The <see cref="IBridge"/> to the Go core loaded by
/// <see cref="CoreLibrary.Load"/>, through its C ABI. There is one per
/// process: <see cref="Install"/>.
/// </summary>
public sealed class LiveBridge : IBridge
{
    private static readonly Lock s_lock = new();
    private static LiveBridge? s_instance;

    /// <summary>
    /// The process's event queue, unbounded so the callback never blocks a Go
    /// thread. Continuations never run inline on the writer, the Go thread.
    /// </summary>
    private static readonly Channel<BridgeEvent> s_events = Channel.CreateUnbounded<BridgeEvent>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = false, AllowSynchronousContinuations = false });

    private LiveBridge()
    {
    }

    /// <summary>
    /// Registers the event callback (once per process) and returns the bridge.
    /// Call it after <see cref="CoreLibrary.Load"/> and before app.init: from
    /// then on every event is queued in <see cref="Events"/> until read, so none
    /// emitted at start-up is lost.
    /// </summary>
    /// <exception cref="InvalidOperationException">The core library is not loaded.</exception>
    public static LiveBridge Install()
    {
        lock (s_lock)
        {
            if (s_instance is null)
            {
                CoreLibrary.EnsureLoaded();
                unsafe
                {
                    NativeMethods.RHGSetEventCallback(EventCallback);
                }
                s_instance = new LiveBridge();
            }
            return s_instance;
        }
    }

    /// <summary>Every event since <see cref="Install"/>, unbounded. Single consumer.</summary>
    public ChannelReader<BridgeEvent> Events => s_events.Reader;

    /// <summary>The C event callback, valid for the life of the process.</summary>
    internal static unsafe delegate* unmanaged[Cdecl]<byte*, void> EventCallback => &OnEvent;

    /// <summary>
    /// Calls <paramref name="method"/> on a dedicated thread, because RHGCall
    /// blocks (card, network, up to five minutes waiting for a PIN). Calls run
    /// concurrently, so pin.submit and app.canQuit run while sign.sign waits.
    /// Also reaches methods outside the contract (the rhgfake build's test.*).
    /// </summary>
    public async Task<TResult> CallAsync<TParams, TResult>(
        string method, TParams parameters, JsonTypeInfo<TParams> paramsTypeInfo, JsonTypeInfo<TResult> resultTypeInfo)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(paramsTypeInfo);
        ArgumentNullException.ThrowIfNull(resultTypeInfo);
        string paramsJson;
        try
        {
            paramsJson = CanonicalJson.Encode(parameters, paramsTypeInfo);
        }
        catch (Exception e) when (e is JsonException or NotSupportedException or ArgumentException)
        {
            throw RpcException.BadParams();
        }
        var response = await Task.Factory.StartNew(
            () => BlockingCall(method, paramsJson),
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default).ConfigureAwait(false);
        return RpcEnvelope.Decode(response, resultTypeInfo);
    }

    /// <summary>
    /// Runs RHGCall on the current thread and returns a copy of the response
    /// envelope, freed with RHGFree (never NULL per the ABI; an empty response
    /// decodes as a bad response).
    /// </summary>
    private static unsafe byte[] BlockingCall(string method, string paramsJson)
    {
        var response = NativeMethods.RHGCall(method, paramsJson);
        try
        {
            return response == 0 ? [] : MemoryMarshal.CreateReadOnlySpanFromNullTerminated((byte*)response).ToArray();
        }
        finally
        {
            NativeMethods.RHGFree(response);
        }
    }

    /// <summary>
    /// The C event callback. It may run on any Go thread, possibly inside an
    /// RHGCall on another thread, and must not block or throw: it copies the
    /// string (valid only during the call, and never freed here) into an event
    /// and queues it.
    /// </summary>
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe void OnEvent(byte* json)
    {
        try
        {
            if (json != null)
            {
                s_events.Writer.TryWrite(BridgeEvent.Parse(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(json)));
            }
        }
        catch (Exception)
        {
            // An exception must not unwind into Go; Parse never throws, so this
            // is only out-of-memory, and the event is dropped.
        }
    }
}
