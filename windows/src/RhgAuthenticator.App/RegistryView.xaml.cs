using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Media3D;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The Registry tab over a <see cref="RegistryViewModel"/> (its DataContext):
/// the command row with the login button, the registry's table and the
/// status line. The selected cell lives in the view model; the table follows
/// it both ways. The entry and device-code dialogs are MainWindow's, since
/// this view is rebuilt on every return to the tab.
/// </summary>
public partial class RegistryView : UserControl
{
    /// <summary>A column's widest; longer text trims, its tooltip holding it whole.</summary>
    internal const double MaxColumnWidth = 360;

    private RegistryViewModel? _model;

    /// <summary>The table and the view model's selection are being matched: their changes are not echoed back.</summary>
    private bool _isSyncing;

    /// <summary>Creates the view.</summary>
    public RegistryView()
    {
        InitializeComponent();
    }

    /// <summary>Shows the view model's columns, rows and selection, and follows them while the view is shown.</summary>
    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_model is not null || DataContext is not RegistryViewModel model)
        {
            return;
        }
        _model = model;
        model.PropertyChanged += OnModelChanged;
        ShowColumns();
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
            case nameof(RegistryViewModel.Columns):
                ShowColumns();
                ShowSelection();
                break;
            case nameof(RegistryViewModel.Snapshot):
                ShowRows();
                break;
            case nameof(RegistryViewModel.SelectedCell) when !_isSyncing:
                ShowSelection();
                break;
            default:
                break;
        }
    }

    /// <summary>One text column per heading, bound to that index of each row's cells.</summary>
    private void ShowColumns()
    {
        if (_model is null)
        {
            return;
        }
        var cellText = (Style)Resources["TableCellText"];
        // Guarded: clearing the columns empties the grid's selection, which is not the operator deselecting.
        _isSyncing = true;
        try
        {
            Table.Columns.Clear();
            for (var i = 0; i < _model.Columns.Count; i++)
            {
                Table.Columns.Add(new DataGridTextColumn
                {
                    Header = _model.Columns[i],
                    Binding = new Binding($"[{i}]") { Mode = BindingMode.OneWay },
                    MaxWidth = MaxColumnWidth,
                    ElementStyle = cellText,
                });
            }
        }
        finally
        {
            _isSyncing = false;
        }
    }

    /// <summary>
    /// The rows, set here rather than bound, so the selection is shown again
    /// only once the table holds the new rows (a new ItemsSource clears it).
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
            Table.ItemsSource = _model.Snapshot.Rows;
        }
        finally
        {
            _isSyncing = false;
        }
        ShowSelection();
    }

    /// <summary>Selects the view model's cell in the table, or nothing when it has none (or it is out of range).</summary>
    private void ShowSelection()
    {
        if (_model is null)
        {
            return;
        }
        _isSyncing = true;
        try
        {
            if (_model.SelectedCell is { } cell && cell.Row < Table.Items.Count && cell.Column < Table.Columns.Count)
            {
                var info = new DataGridCellInfo(Table.Items[cell.Row], Table.Columns[cell.Column]);
                Table.CurrentCell = info;
                Table.SelectedCells.Clear();
                Table.SelectedCells.Add(info);
                Table.ScrollIntoView(info.Item, info.Column);
            }
            else
            {
                Table.UnselectAllCells();
            }
        }
        finally
        {
            _isSyncing = false;
        }
    }

    /// <summary>The operator selected a cell, or deselected it: the view model takes it (a selected cell's text goes to the status line).</summary>
    private void OnSelectedCellsChanged(object sender, SelectedCellsChangedEventArgs e)
    {
        if (_isSyncing || _model is null)
        {
            return;
        }
        _isSyncing = true;
        try
        {
            switch (Table.SelectedCells)
            {
                case []:
                    // The operator deselected the cell (Ctrl+click): Edit Entry disables.
                    _model.ClearSelection();
                    break;
                case [{ IsValid: true, Column: { } column } cell]:
                    _model.SelectCell(Table.Items.IndexOf(cell.Item), Table.Columns.IndexOf(column));
                    break;
                default:
                    break;
            }
        }
        finally
        {
            _isSyncing = false;
        }
    }

    /// <summary>A double-click on a cell (not a header or scrollbar) edits its entry.</summary>
    private void OnTableDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left && IsInCell(e.OriginalSource as DependencyObject))
        {
            EditSelectedEntry();
        }
    }

    /// <summary>Enter edits the selected entry, instead of the table's default of moving down a row.</summary>
    private void OnTablePreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            EditSelectedEntry();
        }
    }

    private void EditSelectedEntry()
    {
        if (_model?.EditEntryCommand is { } command && command.CanExecute(null))
        {
            command.Execute(null);
        }
    }

    /// <summary>
    /// Whether <paramref name="element"/> lies in one of the table's cells.
    /// The click's source may be a text element (a Run), which has no visual
    /// parent: its logical parent is followed instead.
    /// </summary>
    private bool IsInCell(DependencyObject? element)
    {
        while (element is not null && element != Table)
        {
            if (element is DataGridCell)
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
