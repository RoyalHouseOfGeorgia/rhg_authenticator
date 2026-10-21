using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Channels;
using RhgAuthenticator.Bridge.Tests;

[assembly: AssemblyFixture(typeof(CoreLibraryFixture))]

namespace RhgAuthenticator.Bridge.Tests;

/// <summary>Paths and helpers shared by the tests.</summary>
internal static class Support
{
    /// <summary>go/service/rpc/testdata/contract (AssemblyMetadata ContractDir).</summary>
    public static string ContractDir { get; } = Metadata("ContractDir");

    /// <summary>The core library under test: RhgCoreLibDir (RHGCORE_LIB_DIR, default the rhgfake build).</summary>
    public static string LibraryPath { get; } = Path.Combine(Metadata("RhgCoreLibDir"), CoreLibrary.FileName);

    public static byte[] ContractFile(string relativePath)
    {
        return File.ReadAllBytes(Path.Combine(ContractDir, relativePath));
    }

    /// <summary>The regular files under <paramref name="dir"/>, as sorted '/'-separated relative paths.</summary>
    public static IReadOnlyList<string> FilesUnder(string dir)
    {
        return [.. Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(dir, f).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)];
    }

    /// <summary><paramref name="value"/> canonically encoded, with the trailing newline every contract file has.</summary>
    public static byte[] Canonical<T>(T value, JsonTypeInfo<T> typeInfo)
    {
        return [.. CanonicalJson.EncodeToUtf8(value, typeInfo), (byte)'\n'];
    }

    /// <summary>A success envelope around the canonical encoding of <paramref name="result"/>.</summary>
    public static byte[] SuccessEnvelope<T>(T result, JsonTypeInfo<T> typeInfo)
    {
        return [.. "{\"ok\":true,\"result\":"u8, .. CanonicalJson.EncodeToUtf8(result, typeInfo), .. "}\n"u8];
    }

    public static byte[] Utf8(string s)
    {
        return Encoding.UTF8.GetBytes(s);
    }

    /// <summary>
    /// Runs RhgAuthenticator.FlowRunner (copied next to this assembly) with the
    /// library under test and <paramref name="args"/>; kills it after
    /// <paramref name="timeout"/>. Returns its exit code and output lines
    /// (stdout then stderr).
    /// </summary>
    public static async Task<(int Status, IReadOnlyList<string> Lines, string Stderr)> RunFlowAsync(
        IEnumerable<string> args, TimeSpan timeout)
    {
        var start = new ProcessStartInfo(DotnetHost())
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "RhgAuthenticator.FlowRunner.dll"));
        start.ArgumentList.Add(LibraryPath);
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }
        using var process = Process.Start(start) ?? throw new InvalidOperationException("FlowRunner did not start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var cancel = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(cancel.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            Assert.Fail($"FlowRunner {string.Join(' ', args)} timed out after {timeout}:\n{await stdout}\n{await stderr}");
        }
        var lines = (await stdout).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.TrimEnd('\r')).ToList();
        return (process.ExitCode, lines, await stderr);
    }

    /// <summary>The dotnet host running this test: &lt;root&gt;/shared/Microsoft.NETCore.App/&lt;version&gt;/../../../dotnet.</summary>
    private static string DotnetHost()
    {
        var root = Path.GetFullPath(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", ".."));
        return Path.Combine(root, OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet");
    }

    private static string Metadata(string key)
    {
        return typeof(Support).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(a => a.Key == key).Value!;
    }
}

/// <summary>
/// Loads the core library under test into this process once, for every test
/// (a process can register its import resolver only once), after planting a
/// garbage library of the same name next to the test assembly, where a search
/// path would find it first. Fails every test with a clear message when the
/// library is missing or is not the rhgfake build.
/// </summary>
public sealed class CoreLibraryFixture : IDisposable
{
    public CoreLibraryFixture()
    {
        if (!File.Exists(Support.LibraryPath))
        {
            throw new InvalidOperationException(
                $"{Support.LibraryPath} not found: run `bash scripts/rhgcore-smoke.sh` from the repo root "
                + "(or set RHGCORE_LIB_DIR to the directory holding the rhgfake build).");
        }
        PlantedPath = Path.Combine(AppContext.BaseDirectory, CoreLibrary.FileName);
        File.WriteAllText(PlantedPath, "not a library");
        CoreLibrary.Load(Support.LibraryPath);

        var (status, lines, stderr) = Support.RunFlowAsync(["--version"], TimeSpan.FromSeconds(60)).GetAwaiter().GetResult();
        if (status != 0 || lines.Count != 1 || !lines[0].EndsWith("(rhgfake)", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{Support.LibraryPath} is not the rhgfake build (--version: {string.Join(" / ", lines)} {stderr}): "
                + "point RHGCORE_LIB_DIR at go/release/rhgcore/rhgfake.");
        }
    }

    /// <summary>The garbage library planted next to the test assembly.</summary>
    public string PlantedPath { get; }

    public void Dispose()
    {
        File.Delete(PlantedPath);
    }
}

/// <summary>
/// An <see cref="IBridge"/> that records each call's method and canonical
/// params and answers from a table of response envelopes.
/// </summary>
internal sealed class RecordingBridge(IReadOnlyDictionary<string, byte[]> responses) : IBridge
{
    private readonly Lock _lock = new();
    private readonly List<(string Method, string Params)> _calls = [];

    public ChannelReader<BridgeEvent> Events { get; } = Channel.CreateUnbounded<BridgeEvent>().Reader;

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

    public Task<TResult> CallAsync<TParams, TResult>(
        string method, TParams parameters, JsonTypeInfo<TParams> paramsTypeInfo, JsonTypeInfo<TResult> resultTypeInfo)
    {
        var encoded = CanonicalJson.Encode(parameters, paramsTypeInfo);
        lock (_lock)
        {
            _calls.Add((method, encoded));
        }
        return Task.FromResult(RpcEnvelope.Decode(responses.GetValueOrDefault(method, []), resultTypeInfo));
    }
}
