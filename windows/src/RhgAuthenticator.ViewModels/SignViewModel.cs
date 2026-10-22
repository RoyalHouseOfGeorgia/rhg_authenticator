using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>
/// The Sign tab: the credential form, the signing flow and its result. The
/// core validates, normalizes and signs; this view model shows what it returns.
/// </summary>
public sealed partial class SignViewModel : ObservableObject
{
#pragma warning disable CS1591 // UI copy; each constant's name says where it shows.
    public const string RecipientLabel = "Recipient";
    public const string RecipientPlaceholder = "Full name of recipient";
    public const string HonorLabel = "Honor";
    public const string HonorPlaceholder = "Select honor title";
    public const string DetailLabel = "Detail";
    public const string DetailPlaceholder = "Specific distinction or rank";
    public const string DateLabel = "Date";
    public const string SignTitle = "Sign Credential";
    public const string PrintAdvisory = "Print QR at minimum 3×3 cm";
    public const string SaveSvgTitle = "Save SVG";
    public const string SavePngTitle = "Save PNG";
    public const string CopyUrlTitle = "Copy URL";
    public const string PreparingStatus = "Preparing to sign...";
    public const string ConnectingStatus = "Connecting to YubiKey...";
    public const string SignedStatus = "Signed successfully.";
    public const string ExistingStatus = "Credential previously generated.";
    public const string AlreadyIssuedTitle = "Already Issued";
    public const string AlreadyIssuedMessage = "Credential previously generated, no new record created.";
    public const string NotRecordedTitle = "Not Recorded";
#pragma warning restore CS1591

    private readonly IBridge _bridge;
    private readonly IFileSaveService _fileSave;
    private readonly IClipboard _clipboard;
    private readonly IUrlOpener _urlOpener;
    private readonly AlertQueue _alerts;
    private DateTime _date;

    /// <summary>
    /// Creates the tab's view model, posting its alerts to
    /// <paramref name="alerts"/>; <paramref name="clock"/> (default the system
    /// clock) sets the initial <see cref="Date"/>, today in UTC.
    /// <paramref name="bulk"/>'s flow, while active, also disables Sign
    /// Credential; whoever owns both calls
    /// <c>SignCommand.NotifyCanExecuteChanged()</c> when it changes.
    /// </summary>
    public SignViewModel(
        IBridge bridge,
        IFileSaveService fileSave,
        IClipboard clipboard,
        IUrlOpener urlOpener,
        AlertQueue alerts,
        BulkViewModel bulk,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        ArgumentNullException.ThrowIfNull(fileSave);
        ArgumentNullException.ThrowIfNull(clipboard);
        ArgumentNullException.ThrowIfNull(urlOpener);
        ArgumentNullException.ThrowIfNull(alerts);
        ArgumentNullException.ThrowIfNull(bulk);
        _bridge = bridge;
        _fileSave = fileSave;
        _clipboard = clipboard;
        _urlOpener = urlOpener;
        _alerts = alerts;
        Bulk = bulk;
        _date = (clock ?? TimeProvider.System).GetUtcNow().UtcDateTime.Date;
    }

    /// <summary>Bulk Sign from File, whose button sits on this tab.</summary>
    public BulkViewModel Bulk { get; }

    /// <summary>The recipient field.</summary>
    [ObservableProperty]
    public partial string Recipient { get; set; } = "";

    /// <summary>The selected honor title; "" while none is selected.</summary>
    [ObservableProperty]
    public partial string Honor { get; set; } = "";

    /// <summary>The detail field.</summary>
    [ObservableProperty]
    public partial string Detail { get; set; } = "";

    /// <summary>The honor titles to choose from (sign.honors).</summary>
    [ObservableProperty]
    public partial IReadOnlyList<string> Honors { get; private set; } = [];

    /// <summary>
    /// A signing is running: Sign Credential (and Bulk Sign) are disabled.
    /// The core's busy error is the real guard.
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignCommand))]
    public partial bool IsBusy { get; private set; }

    /// <summary>The status line under the buttons.</summary>
    [ObservableProperty]
    public partial string Status { get; private set; } = "";

    /// <summary>The last successful signing; its fields are the ones signed (NFC), not the form's.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasResult), nameof(QrPreviewPng))]
    [NotifyCanExecuteChangedFor(nameof(SaveSvgCommand), nameof(SavePngCommand), nameof(CopyUrlCommand))]
    public partial SignResult? Result { get; private set; }

    /// <summary>The Report Issue button.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ReportIssueCommand))]
    public partial ReportState Report { get; private set; } = new ReportState.Unavailable();

    /// <summary>
    /// The credential date, for a date picker: a calendar date (any time of
    /// day is dropped), signed as is.
    /// </summary>
    public DateTime Date
    {
        get => _date;
        set
        {
            if (SetProperty(ref _date, value.Date))
            {
                OnPropertyChanged(nameof(SelectedDate));
                OnPropertyChanged(nameof(DateString));
                OnPropertyChanged(nameof(DisplayDateText));
            }
        }
    }

    /// <summary>
    /// <see cref="Date"/> for a date picker, whose selection can be cleared:
    /// clearing it keeps <see cref="Date"/> and shows it again.
    /// </summary>
    public DateTime? SelectedDate
    {
        get => _date;
        set
        {
            if (value is { } date)
            {
                Date = date;
            }
            else
            {
                OnPropertyChanged();
            }
        }
    }

    /// <summary><see cref="Date"/> as the signed YYYY-MM-DD, whatever the machine's culture.</summary>
    public string DateString => DisplayDate.Ymd(_date);

    /// <summary><see cref="Date"/> as shown next to the picker, YYYY-Mon-DD.</summary>
    public string DisplayDateText => DisplayDate.Format(DateString);

    /// <summary>A result is shown.</summary>
    public bool HasResult => Result is not null;

    /// <summary>The result's QR code as PNG; null without a result.</summary>
    public byte[]? QrPreviewPng => Result?.PngPreview;

    /// <summary>Loads the honor titles (sign.honors).</summary>
    public async Task LoadHonorsAsync()
    {
        Honors = (await _bridge.HonorsAsync()).Honors;
    }

    /// <summary>The suggested file name for saving the result's QR code as <paramref name="format"/>; "" without a result.</summary>
    public string SuggestedFilename(QrFormat format)
    {
        return format == QrFormat.Svg ? Result?.SvgFilename ?? "" : Result?.PngFilename ?? "";
    }

    /// <summary>sign.connecting: the PIN is resolved and the card is being opened.</summary>
    internal void OnSignConnecting()
    {
        if (IsBusy)
        {
            Status = ConnectingStatus;
        }
    }

    private bool CanSign()
    {
        return !IsBusy && !Bulk.IsActive;
    }

    /// <summary>Sign Credential: validates the form, then signs it. Ignored while busy or during a bulk flow.</summary>
    [RelayCommand(CanExecute = nameof(CanSign))]
    private async Task SignAsync()
    {
        if (!CanSign())
        {
            return;
        }
        IsBusy = true;
        try
        {
            Result = null;
            Report = new ReportState.Unavailable();
            var credential = new CredentialParams(Recipient, Honor, Detail, DateString);
            try
            {
                await _bridge.ValidateAsync(credential);
            }
            catch (RpcException error)
            {
                Status = error.Message;
                return;
            }
            Status = PreparingStatus;
            SignResult signed;
            try
            {
                signed = await _bridge.SignAsync(credential);
            }
            catch (RpcException error)
            {
                // cancelled: the operator cancelled the PIN prompt.
                Status = error.Code == RpcErrorCode.Cancelled ? "" : error.Message;
                if (error.OfferReport && error.ReportId is { } reportId)
                {
                    Report = new ReportState.Available(reportId);
                }
                return;
            }
            if (signed.Existing)
            {
                Status = ExistingStatus;
                _alerts.Show(new AlertState(AlreadyIssuedTitle, AlreadyIssuedMessage));
            }
            else if (signed.Warning.Length > 0)
            {
                Status = signed.Warning;
                _alerts.Show(new AlertState(NotRecordedTitle, signed.Warning));
            }
            else
            {
                Status = SignedStatus;
            }
            Result = signed;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private bool CanReportIssue()
    {
        return Report.IsButtonEnabled;
    }

    /// <summary>
    /// Report Issue: files the failure (sign.reportError), opening the URL the
    /// core returns, if any. A failure shows the core's message and leaves the
    /// button enabled. The core bounds the report's GitHub calls.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanReportIssue))]
    private async Task ReportIssueAsync()
    {
        if (Report is not ReportState.Available { ReportId: var reportId })
        {
            return;
        }
        var reporting = new ReportState.Reporting(reportId);
        Report = reporting;
        var filed = false;
        RpcException? failure = null;
        string? openFailure = null;
        try
        {
            var outcome = await _bridge.ReportErrorAsync(reportId);
            if (Uri.TryCreate(outcome.Url, UriKind.Absolute, out var url) && url.Scheme == Uri.UriSchemeHttps)
            {
                openFailure = _urlOpener.Open(url);
            }
            filed = outcome.Filed;
        }
        catch (RpcException error)
        {
            failure = error;
        }
        // A new signing meanwhile replaced the report state: this outcome is stale.
        if (Report != reporting)
        {
            return;
        }
        Report = filed ? new ReportState.Reported() : new ReportState.Available(reportId);
        if (failure is not null)
        {
            _alerts.Show(AlertState.Error(failure));
        }
        ShowIfFailed(openFailure);
    }

    private bool CanUseResult()
    {
        return HasResult;
    }

    /// <summary>Save SVG: asks where, then writes the result's QR code there (sign.saveQR).</summary>
    [RelayCommand(CanExecute = nameof(CanUseResult))]
    private Task SaveSvgAsync()
    {
        return SaveQrAsync(QrFormat.Svg);
    }

    /// <summary>Save PNG: asks where, then writes the result's QR code there (sign.saveQR).</summary>
    [RelayCommand(CanExecute = nameof(CanUseResult))]
    private Task SavePngAsync()
    {
        return SaveQrAsync(QrFormat.Png);
    }

    /// <summary>Copy URL: puts the result's verification URL on the clipboard.</summary>
    [RelayCommand(CanExecute = nameof(CanUseResult))]
    private void CopyUrl()
    {
        if (Result is { } result)
        {
            ShowIfFailed(_clipboard.SetText(result.Url));
        }
    }

    /// <summary>Shows a host service's failure, if any, as an error alert.</summary>
    private void ShowIfFailed(string? failure)
    {
        if (failure is not null)
        {
            _alerts.Show(new AlertState(AlertState.ErrorTitle, failure));
        }
    }

    private async Task SaveQrAsync(QrFormat format)
    {
        if (Result is not { } result)
        {
            return;
        }
        var extension = format == QrFormat.Svg ? "svg" : "png";
        if (_fileSave.ChooseSavePath(SuggestedFilename(format), extension) is not { } path)
        {
            return;
        }
        try
        {
            await _bridge.SaveQrAsync(result.Url, format, path);
        }
        catch (RpcException error)
        {
            _alerts.Show(AlertState.Error(error));
        }
    }
}
