using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The window: a progress view while the core starts, the tabs and status
/// bar once it is ready, or the fatal startup error. Closing it runs the
/// core's quit sequence first.
/// </summary>
public partial class MainWindow : Window
{
    private readonly AppViewModel _model;
    private bool _isShowingAlerts;
    private bool _isQuitting;
    private bool _canClose;

    /// <summary>Creates the window over <paramref name="model"/>; it starts the core once loaded.</summary>
    public MainWindow(AppViewModel model)
    {
        ArgumentNullException.ThrowIfNull(model);
        _model = model;
        InitializeComponent();
        DataContext = model;
        PinDialog.Attach(model.PinPrompt);
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
        _ = Dispatcher.BeginInvoke(new Action(() =>
        {
            try
            {
                while (_model.Alerts.Current is { } alert)
                {
                    DialogOwner.ShowMessage(
                        alert.Title, alert.Message, alert.IsError ? MessageBoxImage.Error : MessageBoxImage.None);
                    _model.Alerts.Dismiss();
                }
            }
            finally
            {
                _isShowingAlerts = false;
            }
        }));
    }

    private void ShowPhase()
    {
        var phase = _model.Phase;
        LoadingView.Visibility = phase == AppPhase.Starting ? Visibility.Visible : Visibility.Collapsed;
        TabsView.Visibility = phase == AppPhase.Ready ? Visibility.Visible : Visibility.Collapsed;
        StatusBarArea.Visibility = TabsView.Visibility;
        if (phase == AppPhase.Fatal)
        {
            // Startup failed: the error, then quit, as the Fyne app did.
            _ = Dispatcher.BeginInvoke(new Action(() =>
            {
                DialogOwner.ShowMessage(AlertState.ErrorTitle, _model.FatalMessage ?? "", MessageBoxImage.Error);
                Close();
            }));
        }
    }

    /// <summary>
    /// Lays the status items out as Fyne's HBox did: the first at the left,
    /// the last at the right, flexible space between each pair.
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
