using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>Where startup is.</summary>
public enum AppPhase
{
    /// <summary>app.init is fetching the registry: only the Help tab is enabled, and it shows <see cref="AppViewModel.LoadingText"/>.</summary>
    Starting,

    /// <summary>Every tab is enabled and the status bar shown.</summary>
    Ready,

    /// <summary>
    /// Startup failed: every tab header is disabled (the selected Help
    /// content stays usable until the window closes) and
    /// <see cref="AppViewModel.FatalMessage"/> is posted to the alerts
    /// (offering the error log); exit once they are shown.
    /// </summary>
    Fatal,
}

/// <summary>
/// A tab of the main window; <see cref="AppViewModel"/> enables it by
/// <see cref="AppViewModel.Phase"/>.
/// </summary>
/// <param name="title">The tab's title.</param>
/// <param name="content">The tab's view model; null shows <see cref="PlaceholderText"/>.</param>
public sealed partial class AppTab(string title, ObservableObject? content) : ObservableObject
{
    /// <summary>The text of a tab that is not built yet.</summary>
    public const string PlaceholderText = "Not yet available";

    /// <summary>The tab's title.</summary>
    public string Title { get; } = title;

    /// <summary>The tab's view model; null shows <see cref="PlaceholderText"/>.</summary>
    public ObservableObject? Content { get; } = content;

    /// <summary>
    /// The tab's header is enabled (it can be clicked); at Fatal every header
    /// is disabled while Help's content stays shown.
    /// </summary>
    [ObservableProperty]
    public partial bool IsEnabled { get; internal set; }

    /// <summary>The tab shows <see cref="PlaceholderText"/>.</summary>
    public bool IsPlaceholder => Content is null;
}

/// <summary>
/// The app: startup, the status bar, core events and the quit sequence. It
/// owns the tab and prompt view models and routes the core's events to them.
/// </summary>
public sealed partial class AppViewModel : ObservableObject
{
    /// <summary>The main window's title.</summary>
    public const string WindowTitle = "RHG Authenticator";

    /// <summary>The Help tab's loading text while starting.</summary>
    public const string LoadingText = "Loading key registry…";

    /// <summary>The Help tab's title.</summary>
    public const string HelpTitle = "Help";

    /// <summary>The Help tab's line under its Export Error Log button.</summary>
    public const string HelpText = "Saves the app's diagnostic log to a file you choose, to attach to an issue report.";

    /// <summary>Appended to a startup failure's message.</summary>
    public const string ReportSuffix = CoreLibraryException.ReportSuffix;

    /// <summary>The Export Error Log button's title (the Help tab, and alerts offering it).</summary>
    public const string ExportErrorLogTitle = "Export Error Log…";

    private readonly IBridge _bridge;
    private readonly IFileSaveService _fileSave;
    private readonly TimeProvider _clock;
    private readonly AppTab _help;
    private Task? _eventLoop;
    private Task<bool>? _quit;

    /// <summary>
    /// Creates the app's view models over <paramref name="bridge"/>, with the
    /// host's services; <paramref name="clock"/> (default the system clock)
    /// dates the Sign form and names exported files.
    /// </summary>
    public AppViewModel(
        IBridge bridge,
        IFileSaveService fileSave,
        IFileOpenService fileOpen,
        IClipboard clipboard,
        IUrlOpener urlOpener,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        ArgumentNullException.ThrowIfNull(fileSave);
        _bridge = bridge;
        _fileSave = fileSave;
        _clock = clock ?? TimeProvider.System;
        // Each flow is disabled while the other runs. Sign is assigned next,
        // before anything can query Bulk's command.
        Bulk = new BulkViewModel(bridge, fileOpen, fileSave, Alerts, () => Sign!.IsBusy);
        Sign = new SignViewModel(bridge, fileSave, clipboard, urlOpener, Alerts, Bulk, _clock);
        YubiKey = new YubiKeyViewModel(bridge);
        PinPrompt = new PinPromptViewModel(bridge);
        Sign.PropertyChanged += OnSigningStateChanged;
        Bulk.PropertyChanged += OnSigningStateChanged;
        _help = new AppTab(HelpTitle, this);
        Tabs =
        [
            new AppTab("Sign", Sign),
            new AppTab("History", null),
            new AppTab("Registry", null),
            new AppTab("Audit", null),
            new AppTab("YubiKey", YubiKey),
            _help,
        ];
        // The initial Phase does not raise OnPhaseChanged.
        ApplyPhase();
    }

    /// <summary>Every alert of the app and its tabs, shown one at a time.</summary>
    public AlertQueue Alerts { get; } = new();

    /// <summary>The Sign tab.</summary>
    public SignViewModel Sign { get; }

    /// <summary>Bulk Sign from File; its dialog shows over the Sign tab.</summary>
    public BulkViewModel Bulk { get; }

    /// <summary>The YubiKey tab.</summary>
    public YubiKeyViewModel YubiKey { get; }

    /// <summary>The YubiKey PIN prompt.</summary>
    public PinPromptViewModel PinPrompt { get; }

    /// <summary>The tabs, in order.</summary>
    public IReadOnlyList<AppTab> Tabs { get; }

    /// <summary>Where startup is.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsStarting))]
    public partial AppPhase Phase { get; private set; } = AppPhase.Starting;

    /// <summary>The phase is <see cref="AppPhase.Starting"/>: the Help tab shows <see cref="LoadingText"/>.</summary>
    public bool IsStarting => Phase == AppPhase.Starting;

    /// <summary>
    /// The selected tab: Help while starting, Sign once ready. A null or
    /// disabled tab is replaced with Help while Help is enabled.
    /// </summary>
    [ObservableProperty]
    public partial AppTab? SelectedTab { get; set; }

    /// <summary>The startup failure to show (<see cref="AppPhase.Fatal"/>), with <see cref="ReportSuffix"/>; null otherwise.</summary>
    [ObservableProperty]
    public partial string? FatalMessage { get; private set; }

    /// <summary>The app.init result; null until it succeeds.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusItems))]
    public partial AppInfo? Info { get; private set; }

    /// <summary>The status bar's texts as the core words them (app.init); empty before startup.</summary>
    public IReadOnlyList<string> StatusItems => Info?.StatusItems ?? [];

    /// <summary>
    /// The error log's suggested file name, rhg-error-log-YYYY-MM-DD.log, by
    /// today's date in the machine's time zone.
    /// </summary>
    public string SuggestedErrorLogFilename => $"rhg-error-log-{DisplayDate.Ymd(_clock.GetLocalNow().DateTime)}.log";

    /// <summary>The event drain, once started; it ends when the bridge's event channel completes.</summary>
    internal Task? EventLoop => _eventLoop;

    /// <summary>
    /// Starts the core: drains its events (buffered since the bridge was
    /// installed), then app.init, sign.honors and app.start. Ends in
    /// <see cref="AppPhase.Ready"/> or <see cref="AppPhase.Fatal"/>. Call once,
    /// on the UI thread; later calls return at once.
    /// </summary>
    public async Task StartAsync(string? dataDir = null)
    {
        if (_eventLoop is not null)
        {
            return;
        }
        _eventLoop = DrainEventsAsync();
        try
        {
            Info = await _bridge.InitAppAsync(dataDir);
            await Sign.LoadHonorsAsync();
            await _bridge.StartAppAsync();
        }
        catch (RpcException error)
        {
            FatalMessage = error.Message + ReportSuffix;
            Phase = AppPhase.Fatal;
            // The host exits once it has shown the alerts; the error log may
            // explain the failure, and the core can export it once it knows
            // the data folder.
            Alerts.Show(new AlertState(AlertState.ErrorTitle, FatalMessage, OffersErrorLogExport: true));
            return;
        }
        Phase = AppPhase.Ready;
    }

    /// <summary>
    /// The quit sequence: app.shutdown, without relaunch. Returns whether the
    /// host may exit; core errors never block quitting. Concurrent and later
    /// calls share the first sequence, so shutdown runs once.
    /// </summary>
    public Task<bool> PrepareToQuitAsync()
    {
        return _quit ??= QuitAsync();
    }

    private async Task<bool> QuitAsync()
    {
        try
        {
            await _bridge.ShutdownAsync(relaunch: false);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // Never block quitting: the core's own failure, or a bridge fault.
        }
        return true;
    }

    /// <summary>
    /// Export Error Log…: asks where, then writes the diagnostic log there
    /// (app.exportErrorLog) and shows the core's alert saying where it went or
    /// why it failed. Available in every phase: the core accepts it once it
    /// knows the data folder.
    /// </summary>
    [RelayCommand]
    private async Task ExportErrorLogAsync()
    {
        if (_fileSave.ChooseSavePath(SuggestedErrorLogFilename, "log") is not { } path)
        {
            return;
        }
        try
        {
            var result = await _bridge.ExportErrorLogAsync(path);
            Alerts.Show(new AlertState(result.Title, result.Message));
        }
        catch (RpcException error)
        {
            Alerts.Show(AlertState.Error(error));
        }
    }

    partial void OnPhaseChanged(AppPhase value)
    {
        ApplyPhase();
    }

    partial void OnSelectedTabChanged(AppTab? value)
    {
        // Undoes the view's own selections (such as its first item) of a
        // tab the phase disables; at Fatal, when Help is disabled too, any
        // selection stands.
        if ((value is null || !value.IsEnabled) && _help.IsEnabled)
        {
            SelectedTab = _help;
        }
    }

    /// <summary>Enables the tabs <see cref="Phase"/> allows, then selects its tab (Fatal keeps the selection).</summary>
    private void ApplyPhase()
    {
        foreach (var tab in Tabs)
        {
            tab.IsEnabled = Phase == AppPhase.Ready || (Phase == AppPhase.Starting && tab == _help);
        }
        switch (Phase)
        {
            case AppPhase.Starting:
                SelectedTab = _help;
                break;
            case AppPhase.Ready:
                SelectedTab = Tabs[0];
                break;
            default:
                break;
        }
    }

    private void OnSigningStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(SignViewModel.IsBusy) or nameof(BulkViewModel.IsActive))
        {
            Sign.SignCommand.NotifyCanExecuteChanged();
            Bulk.BulkSignCommand.NotifyCanExecuteChanged();
        }
    }

    private async Task DrainEventsAsync()
    {
        await foreach (var bridgeEvent in _bridge.Events.ReadAllAsync())
        {
            try
            {
                Handle(bridgeEvent);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                // A failing view handler must not stop event delivery: every
                // later pin.request would go unanswered until the core's timeout.
                // A request it failed to present is cancelled now for the same reason.
                if (bridgeEvent is BridgeEvent.PinRequested && PinPrompt.IsOpen)
                {
                    PinPrompt.CancelCommand.Execute(null);
                }
                ShowInternalError();
            }
        }
    }

    private void ShowInternalError()
    {
        Alerts.Show(new AlertState(AlertState.ErrorTitle, RpcException.BadResponseMessage));
    }

    /// <summary>
    /// Handles one event, synchronously, so events apply in order and none
    /// waits behind a core call (pin.request least of all). Events of tabs
    /// not built yet are ignored, as are unknown ones.
    /// </summary>
    private void Handle(BridgeEvent bridgeEvent)
    {
        switch (bridgeEvent)
        {
            case BridgeEvent.PinRequested e:
                PinPrompt.Present(e.Request);
                break;
            case BridgeEvent.PinDismissed e:
                PinPrompt.Dismiss(e.Dismiss.RequestId);
                break;
            case BridgeEvent.SignConnecting:
                Sign.OnSignConnecting();
                break;
            case BridgeEvent.BulkProgressed e:
                Bulk.OnBulkProgress(e.Progress);
                break;
            case BridgeEvent.BulkConnecting:
                // The bulk dialog is up from confirm on, showing "Connecting
                // to YubiKey..." until the first bulk.progress: nothing changes.
                break;
            case BridgeEvent.AppInternalError:
                ShowInternalError();
                break;
            default:
                break;
        }
    }
}
