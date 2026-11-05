using System.Runtime.InteropServices;

namespace RhgAuthenticator.Bridge;

/// <summary>The core's command-line invocations (<c>--version</c>, <c>--verify-update-zip …</c>).</summary>
public static class MainCli
{
    /// <summary>
    /// Runs the core's command-line handling with this process's
    /// <paramref name="args"/> (as passed to <c>Main</c>, without the program
    /// name, which is prepended). Returns null when they are not a command-line
    /// invocation, and the app should start its UI; otherwise the exit code,
    /// after the core has written its output. Call it after
    /// <see cref="CoreLibrary.Load"/> and before anything starts the UI.
    /// </summary>
    public static int? Run(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var program = Environment.ProcessPath ?? AppContext.BaseDirectory;
        return RunArgv([program, .. args]);
    }

    /// <summary>
    /// <see cref="Run"/> with a full argument vector, program name first (C's
    /// argv). An empty vector is never a command-line invocation.
    /// </summary>
    internal static unsafe int? RunArgv(IReadOnlyList<string> argv)
    {
        ArgumentNullException.ThrowIfNull(argv);
        CoreLibrary.EnsureLoaded();
        var count = argv.Count;
        // argv[argc] is NULL, as in C; the core reads only argc entries.
        var vector = (byte**)NativeMemory.AllocZeroed((nuint)(count + 1), (nuint)sizeof(byte*));
        try
        {
            for (var i = 0; i < count; i++)
            {
                vector[i] = (byte*)Marshal.StringToCoTaskMemUTF8(argv[i]);
            }
            var code = NativeMethods.RHGMainCLI(count, vector);
            return code == -1 ? null : code;
        }
        finally
        {
            for (var i = 0; i < count; i++)
            {
                Marshal.FreeCoTaskMem((nint)vector[i]);
            }
            NativeMemory.Free(vector);
        }
    }
}
