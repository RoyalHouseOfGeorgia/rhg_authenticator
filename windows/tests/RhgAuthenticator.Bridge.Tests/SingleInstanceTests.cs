using System.Runtime.Versioning;

namespace RhgAuthenticator.Bridge.Tests;

/// <summary>
/// The single-instance guard: named kernel objects, so Windows only (each
/// test skips elsewhere). Each test uses its own names; each instance is one
/// process's view, and a second instance in the same process sees the
/// first's objects as another process would.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SingleInstanceTests
{
    private const string WindowsOnly = "Named kernel objects: Windows only.";

    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(10);

    // Long enough for a stray callback to have run.
    private static readonly TimeSpan s_quiet = TimeSpan.FromMilliseconds(500);

    private readonly string _mutexName = $@"Local\RhgAuthenticator-test-{Guid.NewGuid():N}";

    private string EventName => _mutexName + "-activate";

    [Fact]
    public void TheFirstAcquires()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        using var first = new SingleInstance(_mutexName, EventName);
        Assert.True(first.IsFirst);
    }

    [Fact]
    public void ASecondInstanceDoesNotAcquire()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        using var first = new SingleInstance(_mutexName, EventName);
        using var second = new SingleInstance(_mutexName, EventName);
        Assert.True(first.IsFirst);
        Assert.False(second.IsFirst);
    }

    [Fact]
    public void ClosingTheFirstLetsTheNextLaunchAcquire()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        new SingleInstance(_mutexName, EventName).Dispose();
        using var next = new SingleInstance(_mutexName, EventName);
        Assert.True(next.IsFirst);
    }

    [Fact]
    public void TwoSignalsReachTheFirstAsTwoDeliveriesAndNoMore()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        using var first = new SingleInstance(_mutexName, EventName);
        using var deliveries = new SemaphoreSlim(0);
        first.RegisterActivation(() => deliveries.Release());

        using (var second = new SingleInstance(_mutexName, EventName))
        {
            second.SignalFirst();
        }
        Assert.True(deliveries.Wait(s_timeout, TestContext.Current.CancellationToken));
        // Only after the first is picked up: an auto-reset event counts
        // signals that land together once.
        using (var third = new SingleInstance(_mutexName, EventName))
        {
            third.SignalFirst();
        }
        Assert.True(deliveries.Wait(s_timeout, TestContext.Current.CancellationToken));
        Assert.False(deliveries.Wait(s_quiet, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void ASignalSentBeforeTheWaitIsRegisteredIsDeliveredAfter()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        using var first = new SingleInstance(_mutexName, EventName);
        using (var second = new SingleInstance(_mutexName, EventName))
        {
            second.SignalFirst();
        }
        using var delivered = new ManualResetEventSlim();
        first.RegisterActivation(delivered.Set);
        Assert.True(delivered.Wait(s_timeout, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void AMutexNameHeldByAnotherKindOfObjectCountsAsAnotherInstance()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        using var squatter = new EventWaitHandle(false, EventResetMode.AutoReset, _mutexName);
        using var instance = new SingleInstance(_mutexName, EventName);
        Assert.False(instance.IsFirst);
        // The event opened, so the signal still goes out.
        using var activate = new EventWaitHandle(false, EventResetMode.AutoReset, EventName);
        instance.SignalFirst();
        Assert.True(activate.WaitOne(s_timeout));
    }

    [Fact]
    public void AnEventNameHeldByAnotherKindOfObjectCountsAsAnotherInstanceAndSignalFirstIsANoOp()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        using var squatter = new Mutex(false, EventName);
        using var instance = new SingleInstance(_mutexName, EventName);
        Assert.False(instance.IsFirst);
        // No event to set: not throwing is the assertion.
        instance.SignalFirst();
        // The mutex was never created: the next launch is first.
        using var next = new SingleInstance(_mutexName, _mutexName + "-other");
        Assert.True(next.IsFirst);
    }

    [Fact]
    public void TheFirstCannotSignalItself()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        using var first = new SingleInstance(_mutexName, EventName);
        Assert.Throws<InvalidOperationException>(first.SignalFirst);
    }

    [Fact]
    public void OnlyTheFirstRegistersAndOnlyOnce()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        using var first = new SingleInstance(_mutexName, EventName);
        using var second = new SingleInstance(_mutexName, EventName);
        Assert.Throws<InvalidOperationException>(() => second.RegisterActivation(() => { }));
        first.RegisterActivation(() => { });
        Assert.Throws<InvalidOperationException>(() => first.RegisterActivation(() => { }));
        Assert.Throws<ArgumentNullException>(() => first.RegisterActivation(null!));
    }

    [Fact]
    public void EmptyNamesAreRefused()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        Assert.Throws<ArgumentException>(() => new SingleInstance("", EventName));
        Assert.Throws<ArgumentException>(() => new SingleInstance(_mutexName, ""));
    }

    [Fact]
    public void DisposingStopsTheActivationsAndIsIdempotent()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), WindowsOnly);
        using var called = new ManualResetEventSlim();
        var first = new SingleInstance(_mutexName, EventName);
        first.RegisterActivation(called.Set);
        // Opened before Dispose, so the event outlives it: a wait left
        // registered by Dispose would see the signal below.
        using var activate = new EventWaitHandle(false, EventResetMode.AutoReset, EventName);
        first.Dispose();
        first.Dispose();
        _ = activate.Set();
        Assert.False(called.Wait(s_quiet, TestContext.Current.CancellationToken));
    }
}
