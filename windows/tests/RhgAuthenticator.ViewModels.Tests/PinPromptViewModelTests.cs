using System.Text;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class PinPromptViewModelTests
{
    private static PinPromptViewModel Shown(FakeBridge fake, ulong id = 7, bool rememberDefault = false, int maxBytes = 8)
    {
        var model = new PinPromptViewModel(fake);
        model.Present(new PinRequest(id, rememberDefault, maxBytes));
        return model;
    }

    [Fact]
    public void CopyMatchesTheFyneApp()
    {
        Assert.Equal("YubiKey PIN", PinPromptViewModel.Title);
        Assert.Equal("Enter your YubiKey PIN to sign:", PinPromptViewModel.Prompt);
        Assert.Equal("YubiKey PIN", PinPromptViewModel.Placeholder);
        Assert.Equal("Remember PIN for this session", PinPromptViewModel.RememberLabel);
        Assert.Equal("OK", PinPromptViewModel.OkTitle);
        Assert.Equal("Cancel", PinPromptViewModel.CancelTitle);
    }

    [Fact]
    public void RequiresABridge()
    {
        Assert.Throws<ArgumentNullException>(() => new PinPromptViewModel(null!));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ARequestShowsWithItsRememberDefaultAndHint(bool rememberDefault)
    {
        var model = new PinPromptViewModel(new FakeBridge());
        Assert.Null(model.Request);
        Assert.False(model.IsOpen);
        Assert.Equal("", model.Hint);
        var changed = new List<string?>();
        model.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        model.Present(new PinRequest(1, rememberDefault, 8));
        Assert.Equal(1UL, model.Request?.RequestId);
        Assert.True(model.IsOpen);
        Assert.Equal(rememberDefault, model.Remember);
        Assert.Equal("Up to 8 characters", model.Hint);
        Assert.Equal("", model.Pin);
        Assert.Contains(nameof(PinPromptViewModel.IsOpen), changed);
        Assert.Contains(nameof(PinPromptViewModel.Hint), changed);
    }

    [Fact]
    public void WithoutARequestThePinStaysEmpty()
    {
        var model = new PinPromptViewModel(new FakeBridge());
        model.Pin = "1234";
        Assert.Equal("", model.Pin);
    }

    [Fact]
    public void ANullPinIsEmpty()
    {
        var model = Shown(new FakeBridge());
        model.Pin = "12";
        model.Pin = null!;
        Assert.Equal("", model.Pin);
    }

    [Theory]
    [InlineData("12345678", 8, "12345678")]
    [InlineData("123456789", 8, "12345678")]
    [InlineData("1234567é", 8, "1234567")]
    [InlineData("123456é", 8, "123456é")]
    // Georgian letters are 3 UTF-8 bytes each: 8 bytes keep 2 of them, not 8 UTF-16 units.
    [InlineData("ქართული", 8, "ქა")]
    [InlineData("12ქა", 8, "12ქა")]
    // A combining mark is a scalar of its own and may be cut from its base.
    [InlineData("ééé", 4, "ée")]
    // An emoji is one 4-byte scalar (two UTF-16 units), never split.
    [InlineData("\U0001F600\U0001F600", 6, "\U0001F600")]
    [InlineData("1234567\U0001F600", 8, "1234567")]
    public void ThePinIsCappedToMaxBytesBetweenScalars(string typed, int maxBytes, string kept)
    {
        var model = Shown(new FakeBridge(), maxBytes: maxBytes);
        model.Pin = typed;
        Assert.Equal(Encoding.UTF8.GetBytes(kept), Encoding.UTF8.GetBytes(model.Pin));
        Assert.True(Encoding.UTF8.GetByteCount(model.Pin) <= maxBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SubmitClosesThePromptAndClearsThePinBeforeTheCallReturns(bool remember)
    {
        var fake = new FakeBridge();
        var held = fake.Hold(RpcMethod.PinSubmit);
        var model = Shown(fake);
        model.Pin = "1234";
        model.Remember = remember;
        var submitting = model.SubmitCommand.ExecuteAsync(null);
        Assert.Equal(1, fake.Count(RpcMethod.PinSubmit));
        Assert.Equal("", model.Pin);
        Assert.Null(model.Request);
        Assert.False(model.IsOpen);
        held.Release(Empty.Value);
        await submitting;
        Assert.Equal(
            [$"{{\"pin\":\"1234\",\"remember\":{(remember ? "true" : "false")},\"requestId\":7}}"],
            fake.Params(RpcMethod.PinSubmit));
        Assert.Equal("", model.Pin);
    }

    [Theory]
    [InlineData(RpcMethod.PinSubmit)]
    [InlineData(RpcMethod.PinCancel)]
    public async Task AStaleSubmitOrCancelIsIgnored(string method)
    {
        var fake = new FakeBridge();
        fake.Fail(method, new RpcException(RpcErrorCode.Input, "no such PIN request"));
        var model = Shown(fake);
        model.Pin = "1234";
        var command = method == RpcMethod.PinSubmit ? model.SubmitCommand : model.CancelCommand;
        await command.ExecuteAsync(null);
        Assert.Null(model.Request);
        Assert.Equal("", model.Pin);
        Assert.Equal(1, fake.Count(method));
    }

    [Fact]
    public async Task CancelClosesThePromptClearsThePinAndWithdrawsTheRequest()
    {
        var fake = new FakeBridge();
        var model = Shown(fake, id: 12);
        model.Pin = "1234";
        await model.CancelCommand.ExecuteAsync(null);
        Assert.Null(model.Request);
        Assert.Equal("", model.Pin);
        Assert.Equal([RpcMethod.PinCancel], fake.Methods);
        Assert.Equal(["{\"requestId\":12}"], fake.Params(RpcMethod.PinCancel));
    }

    [Fact]
    public async Task SubmitAndCancelWithoutARequestDoNothing()
    {
        var fake = new FakeBridge();
        var model = new PinPromptViewModel(fake);
        await model.SubmitCommand.ExecuteAsync(null);
        await model.CancelCommand.ExecuteAsync(null);
        Assert.Empty(fake.Calls);
    }

    [Fact]
    public void DismissClosesOnlyTheMatchingRequestWithoutACall()
    {
        var fake = new FakeBridge();
        var model = Shown(fake, id: 5);
        model.Pin = "1234";
        model.Dismiss(4);
        Assert.Equal(5UL, model.Request?.RequestId);
        Assert.Equal("1234", model.Pin);
        model.Dismiss(5);
        Assert.Null(model.Request);
        Assert.Equal("", model.Pin);
        Assert.Empty(fake.Calls);
        model.Dismiss(5);
        Assert.Null(model.Request);
    }

    [Fact]
    public void ANewRequestReplacesTheShownOneAndResetsTheForm()
    {
        var model = Shown(new FakeBridge(), id: 1);
        model.Pin = "1234";
        model.Remember = true;
        model.Present(new PinRequest(2, false, 6));
        Assert.Equal(2UL, model.Request?.RequestId);
        Assert.Equal("", model.Pin);
        Assert.False(model.Remember);
        Assert.Equal("Up to 6 characters", model.Hint);
    }

    [Fact]
    public void ThePinNeverAppearsInToString()
    {
        var model = Shown(new FakeBridge());
        model.Pin = "4321";
        var text = model.ToString();
        Assert.DoesNotContain("4321", text, StringComparison.Ordinal);
        Assert.Contains("<redacted>", text, StringComparison.Ordinal);
    }

    [Fact]
    public void PresentRequiresARequest()
    {
        Assert.Throws<ArgumentNullException>(() => new PinPromptViewModel(new FakeBridge()).Present(null!));
    }
}
