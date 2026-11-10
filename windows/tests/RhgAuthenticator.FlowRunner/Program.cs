// Test support, never shipped: runs one LiveBridge scenario against the
// rhgfake build of the core library, one scenario per process (the core can be
// configured and initialized only once per process). RhgAuthenticator.Bridge.Tests
// spawns it.
//
//   RhgAuthenticator.FlowRunner <library> <scenario>   scenario: offline | online | pinCancel | pinTimeout
//   RhgAuthenticator.FlowRunner <library> --version   the core's CLI, handled first as the app does
//
// <library> is the core library's full path, loaded as the app loads it.
// Prints "ok: <check>" per passed check, then "PASS: <scenario>" and exits 0;
// on the first failure prints "FAIL: <check>: <detail>" and exits 1 (2: usage,
// 3: not the rhgfake library, 4: the library did not load). Never prints
// params, envelopes or the PIN.

using RhgAuthenticator.Bridge;
using RhgAuthenticator.FlowRunner;

if (args.Length < 2)
{
    return Flow.Usage();
}
try
{
    CoreLibrary.Load(args[0]);
}
catch (CoreLibraryException e)
{
    Flow.Emit($"FAIL: load: {e.Message}");
    return 4;
}
if (MainCli.Run(args[1..]) is { } code)
{
    return code;
}
if (args.Length != 2 || !Enum.GetNames<Scenario>().Contains(args[1]))
{
    return Flow.Usage();
}
return await new Flow(LiveBridge.Install()).RunAsync(Enum.Parse<Scenario>(args[1])).ConfigureAwait(false);
