using System.Runtime.Versioning;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// One running app per session: a named mutex says whether this process is
/// the first, and a named auto-reset event lets a later launch ask the first
/// to bring its window forward. Keep the instance for the process's lifetime:
/// its handles are the guard, and closing them drops it.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SingleInstance : IDisposable
{
    private readonly EventWaitHandle? _activate;
    private readonly Mutex? _mutex;
    private RegisteredWaitHandle? _wait;

    /// <summary>
    /// Opens (or creates) the activation event first, then the mutex, so
    /// whenever a later process can see the mutex, this one's event handle
    /// already exists and keeps a signal sent to it alive. Either name being
    /// inaccessible (another instance running elevated) or held by another
    /// kind of object counts as another instance running.
    /// </summary>
    /// <param name="mutexName">The mutex's name, e.g. <c>Local\App-{GUID}</c>.</param>
    /// <param name="eventName">The activation event's name.</param>
    public SingleInstance(string mutexName, string eventName)
    {
        ArgumentException.ThrowIfNullOrEmpty(mutexName);
        ArgumentException.ThrowIfNullOrEmpty(eventName);
        try
        {
            // Create-or-open, never OpenExisting: that would fail while the
            // first instance is between starting and creating the event.
            _activate = new EventWaitHandle(false, EventResetMode.AutoReset, eventName);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or WaitHandleCannotBeOpenedException)
        {
            return;
        }
        try
        {
            // Only createdNew decides, so the mutex is never owned: it goes
            // when its last handle closes (a crashed first instance's among
            // them).
            _mutex = new Mutex(false, mutexName, out var createdNew);
            IsFirst = createdNew;
        }
        catch (Exception e) when (e is UnauthorizedAccessException or WaitHandleCannotBeOpenedException)
        {
            // Not first. The event did open, so SignalFirst still reaches
            // the running instance.
        }
    }

    /// <summary>Whether this is the first instance (it created the mutex).</summary>
    public bool IsFirst { get; }

    /// <summary>
    /// Asks the first instance to come forward (from a later one). Does
    /// nothing when the event could not be opened; a failed signal is ignored.
    /// </summary>
    /// <exception cref="InvalidOperationException">This is the first instance.</exception>
    public void SignalFirst()
    {
        if (IsFirst)
        {
            throw new InvalidOperationException("The first instance cannot signal itself.");
        }
        try
        {
            _ = _activate?.Set();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Nothing to do: the later instance exits either way.
        }
    }

    /// <summary>
    /// Runs <paramref name="onActivate"/> on a thread-pool thread for every
    /// later signal. A signal sent before this call is still set and runs it
    /// once straight away. Signals that arrive before the previous one is
    /// picked up count once. Callbacks may run concurrently on different
    /// threads: marshal to one thread before touching state.
    /// </summary>
    /// <exception cref="InvalidOperationException">This is not the first instance, or it is already registered.</exception>
    public void RegisterActivation(Action onActivate)
    {
        ArgumentNullException.ThrowIfNull(onActivate);
        if (!IsFirst)
        {
            throw new InvalidOperationException("Only the first instance receives activations.");
        }
        if (_wait is not null)
        {
            throw new InvalidOperationException("Activation is already registered.");
        }
        _wait = ThreadPool.RegisterWaitForSingleObject(
            _activate!, (_, _) => onActivate(), null, Timeout.Infinite, executeOnlyOnce: false);
    }

    /// <summary>
    /// Stops the activations and closes the handles, releasing the guard. Once
    /// it returns, no activation runs, and none is still running. Never call
    /// it from an activation, which it would wait for.
    /// </summary>
    public void Dispose()
    {
        if (_wait is { } wait)
        {
            // Signalled once a running callback has finished and the wait
            // thread has let go of the event, so the event really closes below.
            using var unregistered = new ManualResetEvent(false);
            if (wait.Unregister(unregistered))
            {
                _ = unregistered.WaitOne();
            }
            _wait = null;
        }
        _activate?.Dispose();
        _mutex?.Dispose();
    }
}
