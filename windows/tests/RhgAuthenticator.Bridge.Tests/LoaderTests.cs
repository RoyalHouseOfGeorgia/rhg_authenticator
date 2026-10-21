using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RhgAuthenticator.Bridge.Tests;

/// <summary>Extraction of the embedded library, and load failures.</summary>
public sealed class LoaderTests : IDisposable
{
    private static readonly byte[] s_library = [.. "pretend library "u8, .. RandomNumberGenerator.GetBytes(64)];
    private static readonly string s_hash = Convert.ToHexStringLower(SHA256.HashData(s_library));
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"rhg-loader-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string Extract(byte[]? content = null, string? hash = null, Action<string>? afterWrite = null)
    {
        using var stream = new MemoryStream(content ?? s_library);
        return CoreLibrary.Extract(stream, hash ?? s_hash, _root, "librhgcore.so", afterWrite);
    }

    private string Expected => Path.Combine(_root, s_hash, "librhgcore.so");

    /// <summary>The stand-in library's LogicalName in the test project file.</summary>
    internal const string EmbeddedResourceName = "embedded-library";

    [Fact]
    public void WritesRootHashFileName()
    {
        using var stream = new MemoryStream(s_library);
        var path = CoreLibrary.Extract(stream, s_hash, _root, "librhgcore.so");
        Assert.Equal(Expected, path);
        Assert.Equal(s_library, File.ReadAllBytes(path));
        Assert.Equal([Path.GetFileName(path)], Directory.GetFiles(Path.GetDirectoryName(path)!).Select(Path.GetFileName));
    }

    [Fact]
    public void AnUppercaseHashNamesTheLowercaseDirectory()
    {
        Assert.Equal(Expected, Extract(hash: s_hash.ToUpperInvariant()));
    }

    [Fact]
    public void KeepsAnExistingFileWithTheExpectedHash()
    {
        var path = Extract();
        var old = new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(path, old);
        var writes = 0;
        Assert.Equal(path, Extract(afterWrite: _ => writes++));
        Assert.Equal(0, writes);
        Assert.Equal(old, File.GetLastWriteTimeUtc(path));
    }

    [Fact]
    public void ReplacesAnExistingFileWithOtherContent()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Expected)!);
        File.WriteAllText(Expected, "tampered");
        Assert.Equal(Expected, Extract());
        Assert.Equal(s_library, File.ReadAllBytes(Expected));
    }

    [Fact]
    public void AStreamNotMatchingTheHashFailsWithoutWriting()
    {
        var e = Assert.Throws<CoreLibraryException>(() => Extract(content: "other"u8.ToArray()));
        Assert.Contains("damaged", e.Message, StringComparison.Ordinal);
        Assert.EndsWith(CoreLibraryException.ReportSuffix, e.UserMessage, StringComparison.Ordinal);
        Assert.False(File.Exists(Expected));
    }

    [Fact]
    public void RewritesOnceWhenTheWrittenFileDoesNotVerify()
    {
        var writes = 0;
        var path = Extract(afterWrite: p =>
        {
            if (writes++ == 0)
            {
                File.WriteAllText(p, "corrupted on disk");
            }
        });
        Assert.Equal(2, writes);
        Assert.Equal(s_library, File.ReadAllBytes(path));
    }

    [Fact]
    public void FailsWhenTheRewriteDoesNotVerifyEither()
    {
        var writes = 0;
        var e = Assert.Throws<CoreLibraryException>(() => Extract(afterWrite: p =>
        {
            writes++;
            File.WriteAllText(p, "corrupted on disk");
        }));
        Assert.Equal(2, writes);
        Assert.Contains("does not match", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnIoFailureWithAMatchingFileInPlaceSucceeds()
    {
        // As when another instance wrote and loaded the file meanwhile.
        var path = Extract(afterWrite: _ => throw new IOException("in use"));
        Assert.Equal(Expected, path);
        Assert.Equal(s_library, File.ReadAllBytes(path));
    }

    [Fact]
    public void AnIoFailureWithoutAMatchingFileFails()
    {
        var e = Assert.Throws<CoreLibraryException>(() => Extract(afterWrite: p =>
        {
            File.WriteAllText(p, "half written");
            throw new IOException("disk full");
        }));
        Assert.Contains("disk full", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnwritableRootFails()
    {
        File.WriteAllText(_root, "a file, not a directory");
        try
        {
            var e = Assert.Throws<CoreLibraryException>(() => Extract());
            Assert.Contains("could not be unpacked", e.Message, StringComparison.Ordinal);
            Assert.NotNull(e.InnerException);
        }
        finally
        {
            File.Delete(_root);
        }
    }

    [Theory]
    [InlineData("abc", "librhgcore.so")]
    [InlineData("zz2f8e2c4b0a1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e", "librhgcore.so")]
    [InlineData(null, "sub/librhgcore.so")]
    [InlineData(null, "..")]
    [InlineData(null, ".")]
    public void MalformedArgumentsThrow(string? hash, string fileName)
    {
        using var stream = new MemoryStream(s_library);
        Assert.ThrowsAny<ArgumentException>(() => CoreLibrary.Extract(stream, hash ?? s_hash, _root, fileName));
    }

    [Fact]
    public void ARelativeRootOrNullArgumentThrows()
    {
        using var stream = new MemoryStream(s_library);
        Assert.Throws<ArgumentException>(() => CoreLibrary.Extract(stream, s_hash, "relative/dir", "librhgcore.so"));
        Assert.Throws<ArgumentNullException>(() => CoreLibrary.Extract(null!, s_hash, _root, "librhgcore.so"));
        Assert.ThrowsAny<ArgumentException>(() => CoreLibrary.Extract(stream, "", _root, "librhgcore.so"));
        Assert.ThrowsAny<ArgumentException>(() => CoreLibrary.Extract(stream, s_hash, "", "librhgcore.so"));
        Assert.ThrowsAny<ArgumentException>(() => CoreLibrary.Extract(stream, s_hash, _root, ""));
    }

    [Fact]
    public void LoadingANonexistentPathFailsWithAUserMessage()
    {
        var missing = Path.Combine(_root, "missing", CoreLibrary.FileName);
        var e = Assert.Throws<CoreLibraryException>(() => CoreLibrary.Load(missing));
        Assert.StartsWith("The app's core library could not be loaded.", e.Message, StringComparison.Ordinal);
        Assert.Equal(e.Message + CoreLibraryException.ReportSuffix, e.UserMessage);
        Assert.Contains("https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues", e.UserMessage, StringComparison.Ordinal);
        Assert.IsAssignableFrom<DllNotFoundException>(e.InnerException);
    }

    [Fact]
    public void LoadingAGarbageFileFails()
    {
        Directory.CreateDirectory(_root);
        var garbage = Path.Combine(_root, CoreLibrary.FileName);
        File.WriteAllText(garbage, "not a library");
        Assert.Throws<CoreLibraryException>(() => CoreLibrary.Load(garbage));
    }

    [Fact]
    public void LoadNeedsAFullPath()
    {
        Assert.Throws<ArgumentException>(() => CoreLibrary.Load(CoreLibrary.FileName));
        Assert.ThrowsAny<ArgumentException>(() => CoreLibrary.Load(""));
    }

    [Fact]
    public void LoadingTheSameLibraryAgainDoesNothing()
    {
        CoreLibrary.Load(Support.LibraryPath);
        Assert.True(CoreLibrary.IsLoaded);
    }

    [Fact]
    public void LoadingADifferentLibraryIsRefused()
    {
        // A harmless native library of the runtime itself, not a second Go runtime.
        var other = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(),
            OperatingSystem.IsWindows() ? "System.IO.Compression.Native.dll" : "libSystem.Native.so");
        Assert.True(File.Exists(other), other);
        Assert.Throws<InvalidOperationException>(() => CoreLibrary.Load(other));
    }

    [Fact]
    public void ExtractEmbeddedUnpacksTheResourceItsBuildHashed()
    {
        // The test assembly embeds a stand-in library and records its hash
        // the way the app's build does (GetFileHash into AssemblyMetadata).
        var path = CoreLibrary.ExtractEmbedded(typeof(LoaderTests).Assembly, EmbeddedResourceName, _root);
        var bytes = File.ReadAllBytes(path);
        Assert.Equal(Path.Combine(_root, Convert.ToHexStringLower(SHA256.HashData(bytes)), CoreLibrary.FileName), path);
        Assert.StartsWith("A stand-in for the embedded core library", Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
    }

    [Fact]
    public void ExtractEmbeddedWithoutTheResourceFails()
    {
        var e = Assert.Throws<CoreLibraryException>(
            () => CoreLibrary.ExtractEmbedded(typeof(LoaderTests).Assembly, "missing.dll", _root));
        Assert.Contains("built without its core library", e.Message, StringComparison.Ordinal);
        Assert.False(Directory.Exists(_root));
    }

    [Fact]
    public void ExtractEmbeddedWithoutTheHashFails()
    {
        // The bridge assembly records no hash.
        var e = Assert.Throws<CoreLibraryException>(
            () => CoreLibrary.ExtractEmbedded(typeof(CoreLibrary).Assembly, EmbeddedResourceName, _root));
        Assert.Contains("built without its core library", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ExtractEmbeddedChecksItsArguments()
    {
        Assert.Throws<ArgumentNullException>(() => CoreLibrary.ExtractEmbedded(null!, EmbeddedResourceName, _root));
        Assert.ThrowsAny<ArgumentException>(
            () => CoreLibrary.ExtractEmbedded(typeof(LoaderTests).Assembly, "", _root));
        Assert.Throws<ArgumentException>(
            () => CoreLibrary.ExtractEmbedded(typeof(LoaderTests).Assembly, EmbeddedResourceName, "relative/dir"));
    }

    [Fact]
    public void FileNameIsPerOs()
    {
        Assert.Equal(OperatingSystem.IsWindows() ? "rhgcore.dll" : "librhgcore.so", CoreLibrary.FileName);
    }
}
