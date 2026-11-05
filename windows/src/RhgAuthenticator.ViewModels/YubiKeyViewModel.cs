using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>
/// The YubiKey tab: looks the inserted key up in the registry. The core reads
/// the card and words the outcome (offline it answers without the card).
/// </summary>
public sealed partial class YubiKeyViewModel : ObservableObject
{
    /// <summary>The check button's title.</summary>
    public const string CheckTitle = "Check YubiKey";

    /// <summary>The status line while a check runs.</summary>
    public const string CheckingStatus = "Checking...";

    private readonly IBridge _bridge;

    /// <summary>Creates the tab's view model over <paramref name="bridge"/>.</summary>
    public YubiKeyViewModel(IBridge bridge)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        _bridge = bridge;
    }

    /// <summary>The status line; "" until the first check.</summary>
    [ObservableProperty]
    public partial string Status { get; private set; } = "";

    /// <summary>The key's details, one line each.</summary>
    [ObservableProperty]
    public partial IReadOnlyList<string> Details { get; private set; } = [];

    /// <summary>A check is running: Check YubiKey is disabled.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckCommand))]
    public partial bool IsChecking { get; private set; }

    private bool CanCheck()
    {
        return !IsChecking;
    }

    /// <summary>Check YubiKey (yubikey.check). Ignored while a check is running.</summary>
    [RelayCommand(CanExecute = nameof(CanCheck))]
    private async Task CheckAsync()
    {
        if (IsChecking)
        {
            return;
        }
        IsChecking = true;
        try
        {
            Status = CheckingStatus;
            Details = [];
            var result = await _bridge.CheckYubiKeyAsync();
            Status = result.Status;
            Details = result.Details;
        }
        catch (RpcException error)
        {
            Status = error.Message;
        }
        finally
        {
            IsChecking = false;
        }
    }
}
