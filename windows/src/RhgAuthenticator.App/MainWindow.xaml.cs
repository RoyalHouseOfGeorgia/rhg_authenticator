using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The window: the tab row in every phase (the view model enables and
/// selects the tabs: Help with its loading text while the core starts,
/// every tab once it is ready), the update banner under it while there is
/// an update (bound in the XAML), the status bar once ready, and the fatal
/// startup error's alert, after which it closes. Closing it runs the core's
/// quit sequence first.
/// </summary>
public partial class MainWindow : Window
{
    // The window's sizes (only here; the XAML sets none): FitToWorkArea caps each at the work area.

    /// <summary>The preferred startup width.</summary>
    internal const double DefaultWidth = 1100;

    /// <summary>The preferred startup height.</summary>
    internal const double DefaultHeight = 680;

    /// <summary>The preferred minimum width.</summary>
    internal const double MinimumWidth = 800;

    /// <summary>The preferred minimum height.</summary>
    internal const double MinimumHeight = 560;

    private readonly AppViewModel _model;
    private bool _isShowingAlerts;
    private bool _isQuitting;
    private bool _canClose;

    /// <summary>Creates the window over <paramref name="model"/>; it starts the core once loaded.</summary>
    public MainWindow(AppViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);
        _model = model;
        // Before InitializeComponent: the TabControl's bindings then apply as
        // the XAML loads, ItemsSource and then SelectedItem (the view model's
        // Help), before it could select its first, disabled tab itself.
        DataContext = model;
        InitializeComponent();
        FitToWorkArea();
        PinDialog.Attach(model.PinPrompt);
        BulkDialog.Attach(model.Bulk);
        EntryFormDialog.Attach(model.Registry);
        DeviceCodeDialog.Attach(model.Login);
        model.PropertyChanged += OnModelChanged;
        model.Alerts.PropertyChanged += OnAlertsChanged;
        Loaded += OnLoaded;
        Closing += OnClosing;
        ShowPhase();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        await _model.StartAsync();
    }

    /// <summary>Holding F5 refreshes once: its key repeats never reach the F5 binding.</summary>
    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.F5 && e.IsRepeat)
        {
            e.Handled = true;
        }
    }

    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(AppViewModel.Phase):
                ShowPhase();
                break;
            case nameof(AppViewModel.StatusItems):
                ShowStatusItems();
                break;
            default:
                break;
        }
    }

    /// <summary>
    /// The default and minimum sizes, each capped by the primary monitor's
    /// work area, so the window opens wholly on a small or scaled screen.
    /// </summary>
    private void FitToWorkArea()
    {
        var area = SystemParameters.WorkArea;
        Width = Math.Min(DefaultWidth, area.Width);
        Height = Math.Min(DefaultHeight, area.Height);
        MinWidth = Math.Min(MinimumWidth, area.Width);
        MinHeight = Math.Min(MinimumHeight, area.Height);
    }

    /// <summary>
    /// Shows the app's alerts one at a time, over whatever window is active.
    /// They open on a later dispatcher turn, never inside the change, so
    /// whatever posted one (an event or a command's continuation) is not held
    /// up by the modal dialog. BeginInvoke, not InvokeAsync: a failure ends
    /// the app instead of vanishing into a discarded task and leaving later
    /// alerts unshown.
    /// </summary>
    private void OnAlertsChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_isShowingAlerts || _model.Alerts.Current is null)
        {
            return;
        }
        _isShowingAlerts = true;
        _ = Dispatcher.BeginInvoke(new Action(ShowAlerts));
    }

    /// <summary>
    /// Shows alerts until none is left: an alert posted meanwhile (an export's
    /// result among them) is shown by this loop, which re-checks
    /// <see cref="AlertQueue.Current"/> after each. Async void, so a failure
    /// after an await reaches the dispatcher as an unhandled exception and
    /// ends the app, as one before it does. After a fatal startup's alert
    /// (and its export's result) the window closes.
    /// </summary>
    private async void ShowAlerts()
    {
        try
        {
            while (_model.Alerts.Current is { } alert)
            {
                if (!alert.OffersErrorLogExport)
                {
                    DialogOwner.ShowMessage(
                        alert.Title, alert.Message, alert.IsError ? MessageBoxImage.Error : MessageBoxImage.None);
                    Dismiss();
                    continue;
                }
                var export = AlertDialog.Ask(alert);
                Dismiss();
                if (export)
                {
                    // Asks where, writes the log and posts its result alert, shown next.
                    await _model.ExportErrorLogCommand.ExecuteAsync(null);
                }
            }
        }
        finally
        {
            _isShowingAlerts = false;
        }
        if (_model.Phase == AppPhase.Fatal)
        {
            Close();
        }
    }

    /// <summary>
    /// Dismisses the current alert. Its follow-up (a login after Session
    /// Expired, which can run for minutes) runs on its own, so the alerts
    /// after it are not held up; async void, so its failure ends the app,
    /// as the loop's own does.
    /// </summary>
    private async void Dismiss()
    {
        await _model.Alerts.DismissAsync();
    }

    private void ShowPhase()
    {
        StatusBarArea.Visibility = _model.Phase == AppPhase.Ready ? Visibility.Visible : Visibility.Collapsed;
        // Fatal: the view model disables every tab and posts the error as an
        // alert; ShowAlerts closes the window once it (and any export's
        // result) is shown.
    }

    /// <summary>
    /// Lays the status items out: the first at the left, the last at the
    /// right, flexible space between each pair.
    /// </summary>
    private void ShowStatusItems()
    {
        StatusBar.Children.Clear();
        StatusBar.ColumnDefinitions.Clear();
        var items = _model.StatusItems;
        for (var i = 0; i < items.Count; i++)
        {
            if (i > 0)
            {
                StatusBar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            }
            StatusBar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var text = new TextBlock { Text = items[i] };
            text.SetResourceReference(TextBlock.ForegroundProperty, "TextFillColorSecondaryBrush");
            Grid.SetColumn(text, StatusBar.ColumnDefinitions.Count - 1);
            StatusBar.Children.Add(text);
        }
    }

    /// <summary>
    /// Every close (the X, Alt+F4, a fatal error) runs the core's quit
    /// sequence first, then shuts the app down. The core calls run off the
    /// UI thread, so the window stays responsive meanwhile; closing again
    /// while it runs does nothing.
    /// </summary>
    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_canClose)
        {
            return;
        }
        e.Cancel = true;
        if (_isQuitting)
        {
            return;
        }
        _isQuitting = true;
        if (await _model.PrepareToQuitAsync())
        {
            _canClose = true;
            Application.Current.Shutdown();
        }
        else
        {
            _isQuitting = false;
        }
    }
}
