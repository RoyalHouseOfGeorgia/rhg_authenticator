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
/// <param name="content">The tab's view model.</param>
public sealed partial class AppTab(string title, ObservableObject content) : ObservableObject
{
    /// <summary>The tab's title.</summary>
    public string Title { get; } = title;

    /// <summary>The tab's view model.</summary>
    public ObservableObject Content { get; } = content;

    /// <summary>
    /// The tab's header is enabled (it can be clicked); at Fatal every header
    /// is disabled while Help's content stays shown.
    /// </summary>
    [ObservableProperty]
    public partial bool IsEnabled { get; internal set; }
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

    /// <summary>The quit confirmation with unsubmitted registry edits.</summary>
    public static readonly Confirmation QuitConfirmation = new(
        "Unsubmitted Changes", "The registry has unsubmitted changes. Exit anyway?", "Exit", IsDestructive: true);

    private readonly IBridge _bridge;
    private readonly IFileSaveService _fileSave;
    private readonly IConfirmService _confirm;
    private readonly IUrlOpener _urlOpener;
    private readonly TimeProvider _clock;
    private readonly AppTab _help;
    private Task? _eventLoop;
    private Task<bool>? _quit;

    /// <summary>
    /// Creates the app's view models over <paramref name="bridge"/>, with the
    /// host's services; <paramref name="clock"/> (default the system clock)
    /// dates the Sign and entry forms, times the History search and names
    /// exported files.
    /// </summary>
    public AppViewModel(
        IBridge bridge,
        IFileSaveService fileSave,
        IFileOpenService fileOpen,
        IClipboard clipboard,
        IUrlOpener urlOpener,
        IConfirmService confirm,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        ArgumentNullException.ThrowIfNull(fileSave);
        ArgumentNullException.ThrowIfNull(urlOpener);
        ArgumentNullException.ThrowIfNull(confirm);
        _bridge = bridge;
        _fileSave = fileSave;
        _urlOpener = urlOpener;
        _confirm = confirm;
        _clock = clock ?? TimeProvider.System;
        // Each flow is disabled while the other runs. Sign is assigned next,
        // before anything can query Bulk's command.
        Bulk = new BulkViewModel(bridge, fileOpen, fileSave, Alerts, () => Sign!.IsBusy);
        Sign = new SignViewModel(bridge, fileSave, clipboard, urlOpener, Alerts, Bulk, _clock);
        YubiKey = new YubiKeyViewModel(bridge);
        PinPrompt = new PinPromptViewModel(bridge);
        Login = new LoginViewModel(bridge, confirm, clipboard, urlOpener, Alerts);
        Registry = new RegistryViewModel(bridge, Login, confirm, fileOpen, urlOpener, Alerts, _clock);
        History = new HistoryViewModel(bridge, Login, confirm, fileSave, Alerts, _clock);
        Audit = new AuditViewModel(bridge, urlOpener, Alerts);
        Sign.PropertyChanged += OnSigningStateChanged;
        Bulk.PropertyChanged += OnSigningStateChanged;
        _help = new AppTab(HelpTitle, this);
        Tabs =
        [
            new AppTab("Sign", Sign),
            new AppTab("History", History),
            new AppTab("Registry", Registry),
            new AppTab("Audit", Audit),
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

    /// <summary>The GitHub login (the Registry and History tabs' button and the device-code dialog).</summary>
    public LoginViewModel Login { get; }

    /// <summary>The Registry tab.</summary>
    public RegistryViewModel Registry { get; }

    /// <summary>The History tab.</summary>
    public HistoryViewModel History { get; }

    /// <summary>The Audit tab.</summary>
    public AuditViewModel Audit { get; }

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

    /// <summary>The update banner (update.status); null shows none.</summary>
    [ObservableProperty]
    public partial UpdateBanner? UpdateBanner { get; private set; }

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
    /// installed), then app.init, sign.honors, auth.state, the registry
    /// (registry.columns, registry.snapshot) and app.start, whose
    /// history.changed brings History's first rows. Ends in
    /// <see cref="AppPhase.Ready"/>, then fetches the Audit tab's commits in
    /// the background so a slow GitHub never holds startup, or in
    /// <see cref="AppPhase.Fatal"/>. Call once, on the UI thread; later calls
    /// return at once.
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
            await Login.LoadStateAsync();
            await Registry.LoadAsync();
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
        _ = ObserveAsync(Audit.RefreshAsync());
    }

    /// <summary>
    /// The quit sequence: app.canQuit, asking <see cref="QuitConfirmation"/>
    /// with unsubmitted registry edits, then app.shutdown, without relaunch.
    /// Returns whether the host may exit: false only when the operator keeps
    /// the edits (a later call then asks again). Core errors never block
    /// quitting. Concurrent and later calls share the first sequence, so
    /// shutdown runs once. Call on the UI thread: the question is asked there.
    /// </summary>
    public async Task<bool> PrepareToQuitAsync()
    {
        var quit = _quit ??= QuitAsync();
        var terminate = await quit;
        if (!terminate && _quit == quit)
        {
            _quit = null;
        }
        return terminate;
    }

    private async Task<bool> QuitAsync()
    {
        bool dirty;
        try
        {
            dirty = (await _bridge.CanQuitAsync()).Dirty;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // Never block quitting: the core's own failure, or a bridge fault.
            dirty = false;
        }
        if (dirty && !_confirm.Ask(QuitConfirmation))
        {
            return false;
        }
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

    /// <summary>The update banner's Download link: opens the release page. Nothing without a banner.</summary>
    [RelayCommand]
    private void OpenRelease()
    {
        if (UpdateBanner is { } offer && _urlOpener.Open(offer.ReleaseUrl) is { } failure)
        {
            Alerts.Show(new AlertState(AlertState.ErrorTitle, failure));
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
    /// Runs <paramref name="work"/> (a re-read started by an event) to its
    /// end: a failure shows the restart alert, as a failing handler does.
    /// </summary>
    private async Task ObserveAsync(Task work)
    {
        try
        {
            await work;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            ShowInternalError();
        }
    }

    /// <summary>
    /// Handles one event, synchronously, so events apply in order and none
    /// waits behind a core call (pin.request least of all). auth.changed,
    /// registry.changed and the history events re-read in their own tasks,
    /// each starting (and so ordered) here; each view model applies only its
    /// latest read. update.status sets the update banner; update.updated and
    /// unknown events are ignored.
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
            case BridgeEvent.AuthChanged:
                // Only a signal: the payloads can arrive out of order. Logging
                // in or out changes whether History can revoke.
                _ = ObserveAsync(Login.AuthChangedAsync());
                _ = ObserveAsync(History.RereadAsync());
                break;
            case BridgeEvent.AuthDeviceCode e:
                Login.ShowDeviceCode(e.Code);
                break;
            case BridgeEvent.RegistryChanged:
                _ = ObserveAsync(Registry.RegistryChangedAsync());
                break;
            case BridgeEvent.HistoryChanged:
                _ = ObserveAsync(History.HistoryChangedAsync());
                break;
            case BridgeEvent.HistoryRevocationsChanged:
                _ = ObserveAsync(History.RereadAsync());
                break;
            case BridgeEvent.UpdateStatusChanged e:
                UpdateBanner = UpdateBanner.From(e.Status);
                break;
            case BridgeEvent.UpdateUpdated:
                // Emitted only after an in-app update, which Windows never
                // does: it updates by hand from the Download link.
                break;
            default:
                break;
        }
    }
}
