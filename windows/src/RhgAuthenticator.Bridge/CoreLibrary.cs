using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// Locates and loads the Go core library. The app ships it as an embedded
/// resource: <see cref="Extract(Stream, string, string, string)"/> writes it to
/// <c>&lt;root&gt;/&lt;sha256&gt;/&lt;file name&gt;</c> (the app passes
/// <c>%LOCALAPPDATA%\rhg-authenticator\native</c> and the resource's SHA-256,
/// computed at build time), and <see cref="Load"/> opens it by full path. No
/// search path is ever used, so a library planted next to the executable is
/// never loaded. Both throw <see cref="CoreLibraryException"/> with a
/// user-facing message on failure.
/// </summary>
public static class CoreLibrary
{
    private static readonly Lock s_lock = new();
    private static nint s_handle;

    /// <summary>
    /// The core library's file name on this OS: <c>rhgcore.dll</c> on Windows,
    /// <c>librhgcore.so</c> on Linux (tests only).
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">On any other OS.</exception>
    public static string FileName =>
        OperatingSystem.IsWindows() ? "rhgcore.dll"
        : OperatingSystem.IsLinux() ? "librhgcore.so"
        : throw new PlatformNotSupportedException("The core library is built for Windows and Linux only.");

    /// <summary>Whether <see cref="Load"/> has succeeded in this process.</summary>
    internal static bool IsLoaded
    {
        get
        {
            lock (s_lock)
            {
                return s_handle != 0;
            }
        }
    }

    /// <summary>
    /// Opens the library at <paramref name="fullPath"/> and makes every call into
    /// the core use it. Call it once, before anything else in this assembly;
    /// loading the same file again does nothing.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="fullPath"/> is not a full path.</exception>
    /// <exception cref="CoreLibraryException">The library could not be loaded.</exception>
    /// <exception cref="InvalidOperationException">A different library is already loaded.</exception>
    public static void Load(string fullPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(fullPath);
        if (!Path.IsPathFullyQualified(fullPath))
        {
            throw new ArgumentException("The core library path must be a full path.", nameof(fullPath));
        }
        var handle = Open(fullPath);
        lock (s_lock)
        {
            if (s_handle != 0)
            {
                // Balances this Open: the first Load's reference keeps the library loaded.
                NativeLibrary.Free(handle);
                if (handle == s_handle)
                {
                    return;
                }
                throw new InvalidOperationException("A different core library is already loaded.");
            }
            s_handle = handle;
            NativeLibrary.SetDllImportResolver(typeof(CoreLibrary).Assembly, Resolve);
        }
    }

    /// <summary>Throws unless <see cref="Load"/> has succeeded.</summary>
    internal static void EnsureLoaded()
    {
        if (!IsLoaded)
        {
            throw new InvalidOperationException("Call CoreLibrary.Load before using the core.");
        }
    }

    /// <summary>Opens the library at <paramref name="fullPath"/>, mapping failure to the user-facing error.</summary>
    internal static nint Open(string fullPath)
    {
        try
        {
            return NativeLibrary.Load(fullPath);
        }
        catch (Exception e) when (e is DllNotFoundException or BadImageFormatException)
        {
            throw new CoreLibraryException($"The app's core library could not be loaded.\n\n{e.Message}", e);
        }
    }

    /// <summary>Resolves only the core's own imports, only to the loaded handle.</summary>
    private static nint Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        return libraryName == NativeMethods.LibraryName ? s_handle : 0;
    }

    /// <summary>
    /// Writes <paramref name="library"/> (the embedded resource stream) to
    /// <c>&lt;rootDirectory&gt;/&lt;expectedSha256&gt;/&lt;fileName&gt;</c> and returns
    /// that path, for <see cref="Load"/>. A file already there with the expected
    /// hash is kept as is; one with other content is replaced. The written file
    /// is re-hashed before its path is returned (rewritten once on a mismatch).
    /// </summary>
    /// <param name="library">The library's bytes; read to the end, not disposed.</param>
    /// <param name="expectedSha256">Its SHA-256 as 64 hex digits (any case), computed at build time.</param>
    /// <param name="rootDirectory">A full path; created as needed.</param>
    /// <param name="fileName">A bare file name, normally <see cref="FileName"/>.</param>
    /// <exception cref="ArgumentException">An argument is malformed.</exception>
    /// <exception cref="CoreLibraryException">
    /// The stream does not match the hash, or the file could not be written or verified.
    /// </exception>
    public static string Extract(Stream library, string expectedSha256, string rootDirectory, string fileName)
    {
        return Extract(library, expectedSha256, rootDirectory, fileName, afterWrite: null);
    }

    /// <summary>
    /// The <see cref="AssemblyMetadataAttribute"/> key under which the app
    /// records its embedded library's SHA-256 at build time.
    /// </summary>
    public const string Sha256MetadataKey = "RhgCoreSha256";

    /// <summary>
    /// <see cref="Extract(Stream, string, string, string)"/> for the library
    /// embedded in <paramref name="assembly"/> as <paramref name="resourceName"/>,
    /// against the hash in its <see cref="Sha256MetadataKey"/> metadata, as
    /// <see cref="FileName"/>.
    /// </summary>
    /// <exception cref="CoreLibraryException">
    /// The resource or its hash is missing (a build without the library), or extraction failed.
    /// </exception>
    public static string ExtractEmbedded(Assembly assembly, string resourceName, string rootDirectory)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentException.ThrowIfNullOrEmpty(resourceName);
        var hash = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == Sha256MetadataKey)?.Value;
        using var library = assembly.GetManifestResourceStream(resourceName);
        if (library is null || string.IsNullOrEmpty(hash))
        {
            throw new CoreLibraryException("This copy of the app was built without its core library. Reinstall the app.");
        }
        return Extract(library, hash, rootDirectory, FileName);
    }

    /// <summary>
    /// <see cref="Extract(Stream, string, string, string)"/>, calling
    /// <paramref name="afterWrite"/> with the path after each write (a test seam).
    /// </summary>
    internal static string Extract(
        Stream library, string expectedSha256, string rootDirectory, string fileName, Action<string>? afterWrite)
    {
        ArgumentNullException.ThrowIfNull(library);
        ArgumentException.ThrowIfNullOrEmpty(expectedSha256);
        ArgumentException.ThrowIfNullOrEmpty(rootDirectory);
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        if (expectedSha256.Length != 64 || !expectedSha256.All(char.IsAsciiHexDigit))
        {
            throw new ArgumentException("Expected a SHA-256 as 64 hex digits.", nameof(expectedSha256));
        }
        if (!Path.IsPathFullyQualified(rootDirectory))
        {
            throw new ArgumentException("The root directory must be a full path.", nameof(rootDirectory));
        }
        if (Path.GetFileName(fileName) != fileName || fileName is "." or "..")
        {
            throw new ArgumentException("Expected a bare file name.", nameof(fileName));
        }
        var hash = expectedSha256.ToLowerInvariant();
        var directory = Path.Combine(rootDirectory, hash);
        var path = Path.Combine(directory, fileName);
        try
        {
            if (FileMatches(path, hash))
            {
                return path;
            }
            var bytes = ReadAll(library);
            if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != hash)
            {
                throw new CoreLibraryException("The app's embedded core library is damaged. Reinstall the app.");
            }
            for (var attempt = 0; attempt < 2; attempt++)
            {
                Write(directory, path, bytes);
                afterWrite?.Invoke(path);
                if (FileMatches(path, hash))
                {
                    return path;
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Another instance starting at the same time may have written the
            // file and loaded it (which locks it against our replace).
            if (MatchesQuietly(path, hash))
            {
                return path;
            }
            throw new CoreLibraryException($"The app's core library could not be unpacked.\n\n{e.Message}", e);
        }
        throw new CoreLibraryException($"The app's core library could not be unpacked.\n\n{path} does not match the app's copy.");
    }

    private static byte[] ReadAll(Stream stream)
    {
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static bool MatchesQuietly(string path, string hash)
    {
        try
        {
            return FileMatches(path, hash);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool FileMatches(string path, string hash)
    {
        if (!File.Exists(path))
        {
            return false;
        }
        using var file = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(file)) == hash;
    }

    /// <summary>Writes <paramref name="bytes"/> to a temporary file beside <paramref name="path"/>, then moves it into place.</summary>
    private static void Write(string directory, string path, byte[] bytes)
    {
        Directory.CreateDirectory(directory);
        var temp = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllBytes(temp, bytes);
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            File.Delete(temp);
        }
    }
}
