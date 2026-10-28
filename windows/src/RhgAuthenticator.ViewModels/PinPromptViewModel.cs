using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>
/// The YubiKey PIN prompt: shown while <see cref="Request"/> is non-null,
/// answered with <see cref="SubmitCommand"/> or <see cref="CancelCommand"/>.
/// The core owns the timeout, the cache and the byte cap; the PIN is dropped
/// as soon as the prompt is answered or withdrawn, and never appears in
/// <see cref="ToString"/>.
/// </summary>
public sealed partial class PinPromptViewModel : ObservableObject
{
    /// <summary>The prompt's title.</summary>
    public const string Title = "YubiKey PIN";

    /// <summary>The text above the field.</summary>
    public const string Prompt = "Enter your YubiKey PIN to sign:";

    /// <summary>The field's placeholder.</summary>
    public const string Placeholder = "YubiKey PIN";

    /// <summary>The checkbox's label.</summary>
    public const string RememberLabel = "Remember PIN for this session";

    /// <summary>The submit button's title.</summary>
    public const string OkTitle = "OK";

    /// <summary>The cancel button's title.</summary>
    public const string CancelTitle = "Cancel";

    private readonly IBridge _bridge;
    private string _pin = "";

    /// <summary>Creates the prompt, closed.</summary>
    public PinPromptViewModel(IBridge bridge)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        _bridge = bridge;
    }

    /// <summary>The pending pin.request; non-null shows the prompt.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOpen), nameof(Hint))]
    public partial PinRequest? Request { get; private set; }

    /// <summary>
    /// The "Remember PIN for this session" checkbox, reset to the request's
    /// <see cref="PinRequest.RememberDefault"/> on each request.
    /// </summary>
    [ObservableProperty]
    public partial bool Remember { get; set; }

    /// <summary>The prompt is shown.</summary>
    public bool IsOpen => Request is not null;

    /// <summary>
    /// The PIN field, capped to the request's <see cref="PinRequest.MaxBytes"/>
    /// UTF-8 bytes (<see cref="PinTruncation.Truncate"/>); always "" while no
    /// request is pending. A view writing the field reads it back and shows
    /// the capped value.
    /// </summary>
    public string Pin
    {
        get => _pin;
        set => SetProperty(ref _pin, Request is { } request ? PinTruncation.Truncate(value ?? "", request.MaxBytes) : "");
    }

    /// <summary>The hint under the field, e.g. "Up to 8 characters"; "" without a request.</summary>
    public string Hint => Request is { } request ? $"Up to {request.MaxBytes} characters" : "";

    /// <summary>
    /// Shows <paramref name="request"/>, replacing any pending one: the core
    /// keeps a single pending prompt, and the latest id is the live one.
    /// </summary>
    public void Present(PinRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        Request = request;
        Pin = "";
        Remember = request.RememberDefault;
    }

    /// <summary>pin.dismiss: closes the prompt if it shows request <paramref name="requestId"/>.</summary>
    public void Dismiss(ulong requestId)
    {
        if (Request?.RequestId == requestId)
        {
            Clear();
        }
    }

    /// <inheritdoc />
    public override string ToString()
    {
        return "PinPromptViewModel(Pin = <redacted>)";
    }

    /// <summary>
    /// OK: closes the prompt, then sends the PIN. A failure (a request that
    /// was withdrawn meanwhile) needs no handling: the signing call reports
    /// its own outcome.
    /// </summary>
    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task SubmitAsync()
    {
        if (Request is not { } request)
        {
            return;
        }
        var pin = _pin;
        var remember = Remember;
        Clear();
        try
        {
            await _bridge.SubmitPinAsync(request.RequestId, pin, remember);
        }
        catch (RpcException)
        {
        }
    }

    /// <summary>Cancel: closes the prompt, then withdraws the request; the signing call fails <c>cancelled</c>.</summary>
    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task CancelAsync()
    {
        if (Request is not { } request)
        {
            return;
        }
        Clear();
        try
        {
            await _bridge.CancelPinAsync(request.RequestId);
        }
        catch (RpcException)
        {
        }
    }

    private void Clear()
    {
        Request = null;
        Pin = "";
    }
}
