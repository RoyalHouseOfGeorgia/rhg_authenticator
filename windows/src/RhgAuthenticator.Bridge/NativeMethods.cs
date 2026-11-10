using System.Runtime.InteropServices;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// The Go core's C ABI (librhgcore.h). "rhgcore" resolves only to the library
/// <see cref="CoreLibrary.Load"/> opened, never through a search path.
/// </summary>
internal static unsafe partial class NativeMethods
{
    /// <summary>The library name every import uses; <see cref="CoreLibrary"/> resolves it.</summary>
    public const string LibraryName = "rhgcore";

    /// <summary>
    /// Runs <paramref name="method"/> and returns the response envelope, a
    /// NUL-terminated UTF-8 string the caller frees with <see cref="RHGFree"/>
    /// (never with a .NET allocator, so the return is a raw pointer). Blocks for
    /// as long as the method runs; never returns NULL.
    /// </summary>
    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint RHGCall(string method, string paramsJson);

    /// <summary>Frees a string returned by <see cref="RHGCall"/>; NULL is ignored.</summary>
    [LibraryImport(LibraryName)]
    public static partial void RHGFree(nint p);

    /// <summary>
    /// Makes <paramref name="callback"/> receive every later event as UTF-8 JSON,
    /// valid only during the call. It may run on any thread and must not block.
    /// </summary>
    [LibraryImport(LibraryName)]
    public static partial void RHGSetEventCallback(delegate* unmanaged[Cdecl]<byte*, void> callback);

    /// <summary>
    /// Runs the command-line invocations (argv[0] is the program); -1 when argv
    /// is not one, else the exit code.
    /// </summary>
    [LibraryImport(LibraryName)]
    public static partial int RHGMainCLI(int argc, byte** argv);
}
