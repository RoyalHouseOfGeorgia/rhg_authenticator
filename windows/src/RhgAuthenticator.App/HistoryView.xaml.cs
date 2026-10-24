using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The History tab over a <see cref="HistoryViewModel"/> (its DataContext):
/// the command row with the login button, then two panes: the search, the
/// issuance log's records and the status line; and the selected record's
/// detail. The selected row lives in the view model; the list follows it
/// both ways. Its confirmations and alerts are shown by MainWindow's
/// services, since this view is rebuilt on every return to the tab. It
/// starts no reads: the app's events load the log. Del on the list deletes
/// the selected record (bound in the XAML); Ctrl+F, anywhere in the window
/// while the tab is shown, focuses the search.
/// </summary>
public partial class HistoryView : UserControl
{
    /// <summary>The list pane's starting width.</summary>
    internal const double DefaultListPaneWidth = 420;

    /// <summary>The list pane's narrowest, unless the view is too narrow for both panes.</summary>
    internal const double MinListPaneWidth = 340;

    /// <summary>The detail pane's narrowest.</summary>
    internal const double MinDetailPaneWidth = 280;

    private HistoryViewModel? _model;

    /// <summary>The list and the view model's selection are being matched: their changes are not echoed back.</summary>
    private bool _isSyncing;

    /// <summary>
    /// The hosting window while the view is loaded: it holds the Find binding,
    /// and the list's focus is read and put back through it
    /// (Window.GetWindow returns null once the view is unloaded).
    /// </summary>
    private Window? _window;

    /// <summary>Ctrl+F (ApplicationCommands.Find) on the window, while the view is loaded.</summary>
    private CommandBinding? _findBinding;

    /// <summary>The list's focus is to be put back once the window is active again.</summary>
    private bool _isFocusPending;

    /// <summary>Creates the view.</summary>
    public HistoryView()
    {
        InitializeComponent();
        // A pixel column, never a star one: FitPanes clamps it to the view's width.
        ListColumn.Width = new GridLength(DefaultListPaneWidth);
        DetailColumn.MinWidth = MinDetailPaneWidth;
    }

    /// <summary>Shows the view model's rows and selection, and follows them while the view is shown.</summary>
    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        FitPanes();
        if (_model is not null || DataContext is not HistoryViewModel model)
        {
            return;
        }
        _model = model;
        model.PropertyChanged += OnModelChanged;
        _window = Window.GetWindow(this);
        if (_window is not null)
        {
            _findBinding = new CommandBinding(ApplicationCommands.Find, OnFind);
            _window.CommandBindings.Add(_findBinding);
        }
        ShowRows();
    }

    /// <summary>Stops following the view model, which outlives the view.</summary>
    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_model is not null)
        {
            _model.PropertyChanged -= OnModelChanged;
            _model = null;
        }
        if (_window is not null)
        {
            if (_findBinding is not null)
            {
                _window.CommandBindings.Remove(_findBinding);
            }
            if (_isFocusPending)
            {
                _window.Activated -= OnWindowActivated;
                _isFocusPending = false;
            }
        }
        _window = null;
        _findBinding = null;
    }

    /// <summary>Ctrl+F: the search box, its text selected, so typing replaces it.</summary>
    private void OnFind(object sender, ExecutedRoutedEventArgs e)
    {
        _ = SearchBox.Focus();
        SearchBox.SelectAll();
    }

    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(HistoryViewModel.Snapshot):
                ShowRows();
                break;
            case nameof(HistoryViewModel.SelectedIndex) when !_isSyncing:
                ShowSelection();
                break;
            default:
                break;
        }
    }

    /// <summary>
    /// The rows, set here rather than bound, so the selection is shown again
    /// only once the list holds the new rows (a new ItemsSource clears it,
    /// which is not the operator deselecting). When the list had the focus
    /// (a delete by Del among them), it gets it back, on the selected row.
    /// </summary>
    private void ShowRows()
    {
        if (_model is null)
        {
            return;
        }
        // Before the swap, while the focused row is still in the list.
        var hadFocus = IsFocusInList();
        _isSyncing = true;
        try
        {
            Records.ItemsSource = _model.Snapshot.Rows.Select(row => new ListRow(row.Summary)).ToList();
        }
        finally
        {
            _isSyncing = false;
        }
        ShowSelection();
        if (hadFocus)
        {
            _ = Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(RestoreListFocus));
        }
    }

    /// <summary>
    /// Whether the window's logical focus is the list or one of its rows.
    /// Logical, not keyboard, focus: while an alert (a modal window) is open
    /// it holds the keyboard focus, but the window still names its row.
    /// </summary>
    private bool IsFocusInList()
    {
        return _window is not null
            && FocusManager.GetFocusedElement(_window) is DependencyObject focused
            && (focused == Records || (focused is Visual visual && Records.IsAncestorOf(visual)));
    }

    /// <summary>
    /// Once the new rows are laid out (and the view model's selection, which
    /// may follow the rows, is shown): the selected row takes the focus. With
    /// the window inactive (an alert is open — a MessageBox is no WPF window,
    /// so this cannot tell it from another app being in front), that waits
    /// for its activation, then focuses the row selected by then: the list
    /// had the focus either way.
    /// </summary>
    private void RestoreListFocus()
    {
        if (_window is null)
        {
            return;
        }
        if (_window.IsActive)
        {
            FocusSelectedRow();
        }
        else if (!_isFocusPending)
        {
            _isFocusPending = true;
            _window.Activated += OnWindowActivated;
        }
    }

    /// <summary>
    /// Once only. At Input priority, so after WPF's own focus restore, which
    /// follows Activated and aims at the row that was removed.
    /// </summary>
    private void OnWindowActivated(object? sender, EventArgs e)
    {
        if (sender is Window window)
        {
            window.Activated -= OnWindowActivated;
        }
        _isFocusPending = false;
        _ = Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(FocusSelectedRow));
    }

    /// <summary>The selected row, as the list now holds it, or the list itself without one.</summary>
    private void FocusSelectedRow()
    {
        if (_model is null)
        {
            return;
        }
        var index = Records.SelectedIndex;
        UIElement? row = null;
        if (index >= 0)
        {
            row = Records.ItemContainerGenerator.ContainerFromIndex(index) as UIElement;
            if (row is null)
            {
                // Far down a long list the row may not be realized yet.
                Records.ScrollIntoView(Records.Items[index]);
                Records.UpdateLayout();
                row = Records.ItemContainerGenerator.ContainerFromIndex(index) as UIElement;
            }
        }
        _ = (row ?? Records).Focus();
    }

    /// <summary>
    /// Selects the view model's row in the list, by index, or nothing when it
    /// has none (or it is out of range).
    /// </summary>
    private void ShowSelection()
    {
        if (_model is null)
        {
            return;
        }
        _isSyncing = true;
        try
        {
            if (_model.SelectedIndex is { } index && index < Records.Items.Count)
            {
                Records.SelectedIndex = index;
                Records.ScrollIntoView(Records.Items[index]);
            }
            else
            {
                Records.SelectedIndex = -1;
            }
        }
        finally
        {
            _isSyncing = false;
        }
    }

    /// <summary>
    /// The operator selected a row, or deselected it (Ctrl+click): the view
    /// model takes it and reads its detail. Only the call's synchronous part
    /// is guarded, so the model's own changes during the read still show.
    /// Async void, so a failure reaches the dispatcher and ends the app.
    /// </summary>
    private async void OnRecordsSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_isSyncing || _model is null)
        {
            return;
        }
        Task selecting;
        _isSyncing = true;
        try
        {
            selecting = _model.SelectAsync(Records.SelectedIndex < 0 ? null : Records.SelectedIndex);
        }
        finally
        {
            _isSyncing = false;
        }
        await selecting;
    }

    /// <summary>
    /// The view's size, not its grid's: a grid whose pixel columns exceed
    /// its slot is arranged at its full width (and clipped), so its own size
    /// never drops, while the view's is what its parent offers.
    /// </summary>
    private void OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        FitPanes();
    }

    /// <summary>
    /// Keeps the panes at their minimums: the list at least
    /// <see cref="MinListPaneWidth"/> unless the view is too narrow for both
    /// (then the list yields), and never so wide that the detail pane drops
    /// below its own. WPF never shrinks a pixel-width column itself.
    /// </summary>
    private void FitPanes()
    {
        if (!IsLoaded)
        {
            return;
        }
        var cap = Math.Max(0, ActualWidth - Splitter.Width - DetailColumn.MinWidth);
        ListColumn.MinWidth = Math.Min(MinListPaneWidth, cap);
        var current = ListColumn.Width.IsAbsolute ? ListColumn.Width.Value : ListColumn.ActualWidth;
        ListColumn.Width = new GridLength(Math.Clamp(current, ListColumn.MinWidth, cap));
    }
}
