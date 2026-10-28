using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>Where a bulk flow is.</summary>
public enum BulkPhase
{
    /// <summary>No flow.</summary>
    Idle,

    /// <summary>The file dialog is open.</summary>
    ChoosingFile,

    /// <summary>
    /// bulk.load is reading the chosen file; with nothing to sign, bulk.run
    /// then runs here too (no dialog: no card or PIN prompt is involved).
    /// </summary>
    Loading,

    /// <summary>Show the confirm content for <see cref="BulkViewModel.Plan"/> (it has rows to sign).</summary>
    Confirming,

    /// <summary>
    /// bulk.run is signing <see cref="BulkViewModel.Plan"/>: show the progress
    /// content. The PIN prompt stacks on the dialog.
    /// </summary>
    Running,

    /// <summary>Show the results content: <see cref="BulkViewModel.Plan"/> and <see cref="BulkViewModel.Outcome"/>.</summary>
    Results,
}

/// <summary>
/// Bulk Sign from File: pick a CSV, confirm the plan, sign it with progress,
/// then show the results, all in one dialog over the Sign tab. The core plans,
/// signs and words every line; this view model shows what it returns.
/// </summary>
public sealed partial class BulkViewModel : ObservableObject
{
#pragma warning disable CS1591 // UI copy; each constant's name says where it shows.
    public const string BulkSignTitle = "Bulk Sign from File…";
    public const string Title = "Bulk Sign";
    public const string SignTitle = "Sign";
    public const string CancelTitle = "Cancel";
    public const string PreviewHeading = "First names to be signed:";
    public const string InvalidToSkipHeading = "Invalid rows (will be skipped):";
    public const string ResultsTitle = "Bulk Sign — Results";
    public const string FailedHeading = "Failed rows:";
    public const string InvalidSkippedHeading = "Invalid rows (skipped):";
    public const string ExportTitle = "Export Results CSV…";
    public const string RegenerateNote = "Re-open the same file to regenerate results later.";
    public const string CloseTitle = "Close";
    public const string ConnectingLabel = "Connecting to YubiKey...";
    public const string StoppingLabel = "Stopping after current row…";
#pragma warning restore CS1591

    private readonly IBridge _bridge;
    private readonly IFileOpenService _fileOpen;
    private readonly IFileSaveService _fileSave;
    private readonly AlertQueue _alerts;
    private readonly Func<bool> _isSignBusy;

    /// <summary>
    /// Creates the flow's view model, posting its alerts to
    /// <paramref name="alerts"/>. <paramref name="isSignBusy"/> (Sign
    /// Credential is signing) disables Bulk Sign from File; whoever owns it
    /// calls <c>BulkSignCommand.NotifyCanExecuteChanged()</c> when it changes.
    /// </summary>
    public BulkViewModel(
        IBridge bridge, IFileOpenService fileOpen, IFileSaveService fileSave, AlertQueue alerts, Func<bool> isSignBusy)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        ArgumentNullException.ThrowIfNull(fileOpen);
        ArgumentNullException.ThrowIfNull(fileSave);
        ArgumentNullException.ThrowIfNull(alerts);
        ArgumentNullException.ThrowIfNull(isSignBusy);
        _bridge = bridge;
        _fileOpen = fileOpen;
        _fileSave = fileSave;
        _alerts = alerts;
        _isSignBusy = isSignBusy;
    }

    /// <summary>Where the flow is.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(
        nameof(IsActive), nameof(IsShowingDialog), nameof(IsConfirming), nameof(IsRunning), nameof(IsShowingResults),
        nameof(DialogTitle), nameof(IsCancelEnabled))]
    [NotifyCanExecuteChangedFor(
        nameof(BulkSignCommand), nameof(ConfirmCommand), nameof(CancelConfirmCommand), nameof(CancelRunCommand),
        nameof(CloseResultsCommand), nameof(ExportResultsCommand))]
    public partial BulkPhase Phase { get; private set; } = BulkPhase.Idle;

    /// <summary>The plan being confirmed, signed or shown with its results (bulk.load); null otherwise.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasInvalidLines))]
    public partial BulkLoadResult? Plan { get; private set; }

    /// <summary>The run's outcome (bulk.run), while the results show; null otherwise.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFailedLines), nameof(SuggestedResultsFilename))]
    public partial BulkRunResult? Outcome { get; private set; }

    /// <summary>The latest bulk.progress of the run; null before the first.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProgressLabel), nameof(ProgressFraction))]
    public partial BulkProgress? Progress { get; private set; }

    /// <summary>Cancel was pressed: the run stops after its current row.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProgressLabel), nameof(IsCancelEnabled))]
    [NotifyCanExecuteChangedFor(nameof(CancelRunCommand))]
    public partial bool IsStopping { get; private set; }

    /// <summary>
    /// A flow is under way, from the file dialog opening until the results
    /// are closed or the flow ends: Bulk Sign (and Sign Credential) are disabled.
    /// </summary>
    public bool IsActive => Phase != BulkPhase.Idle;

    /// <summary>
    /// The bulk dialog is up: confirm, progress (from confirm on, so the PIN
    /// prompt stacks on it instead of a closing dialog) or results.
    /// </summary>
    public bool IsShowingDialog => IsConfirming || IsRunning || IsShowingResults;

    /// <summary>The dialog shows the confirm content.</summary>
    public bool IsConfirming => Phase == BulkPhase.Confirming;

    /// <summary>The dialog shows the progress content.</summary>
    public bool IsRunning => Phase == BulkPhase.Running;

    /// <summary>The dialog shows the results content.</summary>
    public bool IsShowingResults => Phase == BulkPhase.Results;

    /// <summary>The dialog's title: <see cref="ResultsTitle"/> on the results, else <see cref="Title"/>.</summary>
    public string DialogTitle => IsShowingResults ? ResultsTitle : Title;

    /// <summary>Show the plan's invalid rows (skipped by the run) with their heading.</summary>
    public bool HasInvalidLines => Plan?.InvalidLines.Count > 0;

    /// <summary>The progress label: stopping, connecting (no progress yet) or the row being signed.</summary>
    public string ProgressLabel
    {
        get
        {
            if (IsStopping)
            {
                return StoppingLabel;
            }
            return Progress is { } progress
                ? $"Signing {progress.Done + 1} of {progress.Total}: {progress.Name} — touch your YubiKey if it is blinking"
                : ConnectingLabel;
        }
    }

    /// <summary>The progress bar, 0 to 1.</summary>
    public double ProgressFraction => Progress is { Total: > 0 } progress ? (double)progress.Done / progress.Total : 0;

    /// <summary>The progress content's Cancel button is enabled.</summary>
    public bool IsCancelEnabled => IsRunning && !IsStopping;

    /// <summary>Show the outcome's failed (or not attempted) rows with their heading.</summary>
    public bool HasFailedLines => Outcome?.FailedLines.Count > 0;

    /// <summary>The suggested results CSV name; "" without results.</summary>
    public string SuggestedResultsFilename => Outcome?.ResultsFilename ?? "";

    /// <summary>bulk.progress: the row about to be signed. Applies only while running.</summary>
    internal void OnBulkProgress(BulkProgress progress)
    {
        if (IsRunning)
        {
            Progress = progress;
        }
    }

    private bool CanBulkSign()
    {
        return Phase == BulkPhase.Idle && !_isSignBusy();
    }

    /// <summary>
    /// Bulk Sign from File…: asks for a CSV, plans it (bulk.load), then asks
    /// to confirm, or, with nothing to sign, runs at once without the dialog.
    /// Ignored while a signing or a flow is under way.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanBulkSign))]
    private async Task BulkSignAsync()
    {
        if (!CanBulkSign())
        {
            return;
        }
        Phase = BulkPhase.ChoosingFile;
        if (_fileOpen.ChooseOpenPath("csv") is not { } path)
        {
            Phase = BulkPhase.Idle;
            return;
        }
        Phase = BulkPhase.Loading;
        BulkLoadResult plan;
        try
        {
            plan = await _bridge.LoadBulkAsync(path);
        }
        catch (RpcException error)
        {
            Phase = BulkPhase.Idle;
            _alerts.Show(AlertState.Error(error));
            return;
        }
        Plan = plan;
        if (plan.ToSign == 0)
        {
            await RunAsync();
        }
        else
        {
            Phase = BulkPhase.Confirming;
        }
    }

    private bool CanConfirm()
    {
        return IsConfirming;
    }

    /// <summary>Sign on the confirm content: runs the plan (bulk.run) with progress.</summary>
    [RelayCommand(CanExecute = nameof(CanConfirm))]
    private async Task ConfirmAsync()
    {
        if (!IsConfirming)
        {
            return;
        }
        Phase = BulkPhase.Running;
        await RunAsync();
    }

    /// <summary>Cancel on the confirm content: ends the flow.</summary>
    [RelayCommand(CanExecute = nameof(CanConfirm))]
    private void CancelConfirm()
    {
        if (IsConfirming)
        {
            End();
        }
    }

    private bool CanCancelRun()
    {
        return IsCancelEnabled;
    }

    /// <summary>
    /// Cancel on the progress content: the run stops after its current row
    /// (bulk.cancel) and bulk.run returns a cancelled outcome.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanCancelRun))]
    private async Task CancelRunAsync()
    {
        if (!IsCancelEnabled)
        {
            return;
        }
        IsStopping = true;
        try
        {
            await _bridge.CancelBulkAsync();
        }
        catch (RpcException)
        {
            // The run reports its own outcome either way.
        }
    }

    private bool CanUseResults()
    {
        return IsShowingResults;
    }

    /// <summary>Close on the results content: ends the flow.</summary>
    [RelayCommand(CanExecute = nameof(CanUseResults))]
    private void CloseResults()
    {
        if (IsShowingResults)
        {
            End();
        }
    }

    /// <summary>Export Results CSV…: asks where, then writes the results there (bulk.exportResults). Success shows nothing.</summary>
    [RelayCommand(CanExecute = nameof(CanUseResults))]
    private async Task ExportResultsAsync()
    {
        if (!IsShowingResults || _fileSave.ChooseSavePath(SuggestedResultsFilename, "csv") is not { } path)
        {
            return;
        }
        try
        {
            await _bridge.ExportBulkResultsAsync(path);
        }
        catch (RpcException error)
        {
            _alerts.Show(AlertState.Error(error));
        }
    }

    /// <summary>
    /// Runs bulk.run on <see cref="Plan"/>, then shows the results. A failure
    /// ends the flow first, so the dialog closes, then shows its alert over
    /// the main window.
    /// </summary>
    private async Task RunAsync()
    {
        BulkRunResult outcome;
        try
        {
            outcome = await _bridge.RunBulkAsync();
        }
        catch (RpcException error)
        {
            End();
            _alerts.Show(AlertState.Error(error));
            return;
        }
        Outcome = outcome;
        Phase = BulkPhase.Results;
    }

    private void End()
    {
        Phase = BulkPhase.Idle;
        Plan = null;
        Outcome = null;
        Progress = null;
        IsStopping = false;
    }
}
