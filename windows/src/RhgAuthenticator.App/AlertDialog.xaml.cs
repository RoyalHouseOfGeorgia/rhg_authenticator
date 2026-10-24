using System.Windows;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// An alert that offers <see cref="AlertState.OffersErrorLogExport"/>: its
/// message (selectable, so it can be copied into a report) with the buttons
/// Export Error Log… and OK, which a MessageBox cannot be given. Plain
/// alerts stay MessageBoxes (<see cref="DialogOwner.ShowMessage"/>).
/// </summary>
public partial class AlertDialog : Window
{
    private AlertDialog(AlertState alert)
    {
        InitializeComponent();
        DataContext = alert;
    }

    /// <summary>
    /// Shows <paramref name="alert"/> modally over the active window and
    /// returns whether the operator chose Export Error Log… (OK, Escape and
    /// the close button do not).
    /// </summary>
    public static bool Ask(AlertState alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        return DialogOwner.ShowModal(new AlertDialog(alert)) == true;
    }

    private void OnExportClick(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
    }
}
