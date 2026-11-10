using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// Undoes, on Linux (where the core library is loaded only by tests), the one
/// change the Go runtime makes to .NET's signal handling that crashes the
/// process. A Go c-shared library adds SA_ONSTACK to every signal handler
/// already installed (pkg.go.dev/os/signal, "Non-Go programs that call Go
/// code"), including .NET's GC-suspension activation handler on SIGRTMIN.
/// That handler then runs on the thread's alternate signal stack, which .NET
/// sizes (16 KiB with its guard page) for its SIGSEGV handler only; decoding GC
/// info there can overflow it, and the kernel kills the process with SIGSEGV
/// (dotnet/runtime#127320, golang/go#78883). .NET sends the activation signal
/// only to threads running managed code, which is never on a goroutine stack,
/// so the handler can run on the thread's own stack as .NET installed it.
/// Windows has no POSIX signals: nothing to undo there.
/// </summary>
[SupportedOSPlatform("linux")]
internal static unsafe partial class LinuxActivationSignal
{
    /// <summary>SA_ONSTACK (Linux, every architecture .NET runs on).</summary>
    internal const int SaOnStack = 0x08000000;

    /// <summary>glibc's struct sigaction (x86-64 and arm64): handler, 1024-bit mask, flags, restorer.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct SigAction
    {
        public nint Handler;
        public fixed ulong Mask[16];
        public int Flags;
        public nint Restorer;
    }

    /// <summary>
    /// Clears SA_ONSTACK on the activation signal's handler. Call it once the
    /// library is loaded: a Go c-shared library's constructor
    /// (runtime.libpreinit → initsig) adds the flag synchronously while it loads.
    /// </summary>
    /// <exception cref="InvalidOperationException">The handler could not be read or written.</exception>
    public static void ClearOnStack()
    {
        var signal = CurrentSigRtMin();
        SigAction action;
        if (Sigaction(signal, null, &action) != 0)
        {
            throw new InvalidOperationException($"sigaction({signal}) failed: errno {Marshal.GetLastPInvokeError()}.");
        }
        if ((action.Flags & SaOnStack) == 0)
        {
            return;
        }
        action.Flags &= ~SaOnStack;
        if (Sigaction(signal, &action, null) != 0)
        {
            throw new InvalidOperationException($"sigaction({signal}) failed: errno {Marshal.GetLastPInvokeError()}.");
        }
    }

    /// <summary>Whether the activation signal's handler has SA_ONSTACK (for tests).</summary>
    /// <exception cref="InvalidOperationException">The handler could not be read.</exception>
    internal static bool IsOnStack()
    {
        var signal = CurrentSigRtMin();
        SigAction action;
        if (Sigaction(signal, null, &action) != 0)
        {
            throw new InvalidOperationException($"sigaction({signal}) failed: errno {Marshal.GetLastPInvokeError()}.");
        }
        return (action.Flags & SaOnStack) != 0;
    }

    [LibraryImport("libc.so.6", EntryPoint = "__libc_current_sigrtmin")]
    private static partial int CurrentSigRtMin();

    [LibraryImport("libc.so.6", EntryPoint = "sigaction", SetLastError = true)]
    private static partial int Sigaction(int signal, SigAction* action, SigAction* oldAction);
}
