using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class YubiKeyViewModelTests
{
    private readonly FakeBridge _fake = new();

    public static TheoryData<KeyCheck> Checks =>
    [
        new KeyCheck(KeyCheckOutcome.Found, "Key found in registry", ["Authority: A", "Fingerprint: ae21"]),
        new KeyCheck(KeyCheckOutcome.NotFound, "Key NOT found in registry", ["Fingerprint: ae21"]),
        new KeyCheck(KeyCheckOutcome.Failed, "Registry unavailable — connect to internet to check key", []),
    ];

    [Fact]
    public void CopyMatchesTheFyneApp()
    {
        Assert.Equal("Check YubiKey", YubiKeyViewModel.CheckTitle);
        Assert.Equal("Checking...", YubiKeyViewModel.CheckingStatus);
    }

    [Fact]
    public void RequiresABridge()
    {
        Assert.Throws<ArgumentNullException>(() => new YubiKeyViewModel(null!));
    }

    [Theory]
    [MemberData(nameof(Checks))]
    public async Task ACheckShowsTheCoresStatusAndDetails(KeyCheck result)
    {
        _fake.Respond(RpcMethod.YubikeyCheck, result);
        var model = new YubiKeyViewModel(_fake);
        Assert.Equal("", model.Status);
        Assert.Empty(model.Details);
        Assert.False(model.IsChecking);
        Assert.True(model.CheckCommand.CanExecute(null));
        await model.CheckCommand.ExecuteAsync(null);
        Assert.Equal(result.Status, model.Status);
        Assert.Equal(result.Details, model.Details);
        Assert.False(model.IsChecking);
        Assert.Equal(["{}"], _fake.Params(RpcMethod.YubikeyCheck));
    }

    [Fact]
    public async Task AnErrorShowsTheCoresMessageWithoutDetails()
    {
        _fake.Respond(RpcMethod.YubikeyCheck, new KeyCheck(KeyCheckOutcome.Found, "Key found in registry", ["Authority: A"]));
        _fake.Fail(RpcMethod.YubikeyCheck, new RpcException(RpcErrorCode.Busy, "Another YubiKey operation is running."));
        var model = new YubiKeyViewModel(_fake);
        await model.CheckCommand.ExecuteAsync(null);
        Assert.Equal(["Authority: A"], model.Details);
        await model.CheckCommand.ExecuteAsync(null);
        Assert.Equal("Another YubiKey operation is running.", model.Status);
        Assert.Empty(model.Details);
        Assert.False(model.IsChecking);
    }

    [Fact]
    public async Task WhileCheckingStatusIsCheckingDetailsAreClearedAndASecondCheckIsIgnored()
    {
        _fake.Respond(RpcMethod.YubikeyCheck, new KeyCheck(KeyCheckOutcome.NotFound, "Key NOT found in registry", ["F"]));
        var held = _fake.Hold(RpcMethod.YubikeyCheck);
        var model = new YubiKeyViewModel(_fake);
        await model.CheckCommand.ExecuteAsync(null);
        Assert.Equal(["F"], model.Details);
        var checking = model.CheckCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.YubikeyCheck) == 2));
        Assert.True(model.IsChecking);
        Assert.False(model.CheckCommand.CanExecute(null));
        Assert.Equal("Checking...", model.Status);
        Assert.Empty(model.Details);
        await model.CheckCommand.ExecuteAsync(null);
        Assert.Equal(2, _fake.Count(RpcMethod.YubikeyCheck));
        held.Release(new KeyCheck(KeyCheckOutcome.Found, "Key found in registry", ["A"]));
        await checking;
        Assert.False(model.IsChecking);
        Assert.True(model.CheckCommand.CanExecute(null));
        Assert.Equal("Key found in registry", model.Status);
        Assert.Equal(["A"], model.Details);
    }
}
