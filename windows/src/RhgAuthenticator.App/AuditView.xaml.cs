using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Media3D;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The Audit tab over an <see cref="AuditViewModel"/> (its DataContext): the
/// command row, the registry's commits and the status line. The selected row
/// lives in the view model; the list follows it both ways. Selecting a
/// commit never opens it: a double-click or Enter runs Open on GitHub. It
/// starts no fetch: the app's startup loads the commits.
/// </summary>
public partial class AuditView : UserControl
{
    private AuditViewModel? _model;

    /// <summary>The list and the view model's selection are being matched: their changes are not echoed back.</summary>
    private bool _isSyncing;

    /// <summary>Creates the view.</summary>
    public AuditView()
    {
        InitializeComponent();
    }

    /// <summary>Shows the view model's rows and selection, and follows them while the view is shown.</summary>
    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_model is not null || DataContext is not AuditViewModel model)
        {
            return;
        }
        _model = model;
        model.PropertyChanged += OnModelChanged;
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
    }

    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(AuditViewModel.Rows):
                ShowRows();
                break;
            case nameof(AuditViewModel.SelectedIndex) when !_isSyncing:
                ShowSelection();
                break;
            default:
                break;
        }
    }

    /// <summary>
    /// The rows, set here rather than bound, so the selection is shown again
    /// only once the list holds the new rows (a new ItemsSource clears it,
    /// which is not the operator deselecting).
    /// </summary>
    private void ShowRows()
    {
        if (_model is null)
        {
            return;
        }
        _isSyncing = true;
        try
        {
            Commits.ItemsSource = _model.Rows.Select(row => new ListRow(row.Summary)).ToList();
        }
        finally
        {
            _isSyncing = false;
        }
        ShowSelection();
    }

    /// <summary>Selects the view model's row in the list, by index, or nothing when it has none (or it is out of range).</summary>
    private void ShowSelection()
    {
        if (_model is null)
        {
            return;
        }
        _isSyncing = true;
        try
        {
            if (_model.SelectedIndex is { } index && index < Commits.Items.Count)
            {
                Commits.SelectedIndex = index;
                Commits.ScrollIntoView(Commits.Items[index]);
            }
            else
            {
                Commits.SelectedIndex = -1;
            }
        }
        finally
        {
            _isSyncing = false;
        }
    }

    /// <summary>The operator selected a row, or deselected it (Ctrl+click): the view model takes it (Open on GitHub enables).</summary>
    private void OnCommitsSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_isSyncing || _model is null)
        {
            return;
        }
        _isSyncing = true;
        try
        {
            _model.Select(Commits.SelectedIndex < 0 ? null : Commits.SelectedIndex);
        }
        finally
        {
            _isSyncing = false;
        }
    }

    /// <summary>A double-click on a row (not the scrollbar or the empty space below the rows) opens its commit.</summary>
    private void OnCommitsDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left && IsInRow(e.OriginalSource as DependencyObject))
        {
            OpenSelectedCommit();
        }
    }

    /// <summary>Enter opens the selected commit.</summary>
    private void OnCommitsPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            OpenSelectedCommit();
        }
    }

    private void OpenSelectedCommit()
    {
        if (_model?.OpenCommand is { } command && command.CanExecute(null))
        {
            command.Execute(null);
        }
    }

    /// <summary>
    /// Whether <paramref name="element"/> lies in one of the list's rows. The
    /// click's source may be a text element (a Run), which has no visual
    /// parent: its logical parent is followed instead.
    /// </summary>
    private bool IsInRow(DependencyObject? element)
    {
        while (element is not null && element != Commits)
        {
            if (element is ListBoxItem)
            {
                return true;
            }
            element = element is Visual or Visual3D
                ? VisualTreeHelper.GetParent(element)
                : LogicalTreeHelper.GetParent(element);
        }
        return false;
    }
}
