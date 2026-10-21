using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The Sign tab over a <see cref="SignViewModel"/> (its DataContext). Its
/// alerts are shown by <see cref="MainWindow"/>, whichever tab is selected.
/// </summary>
public partial class SignView : UserControl
{
    /// <summary>Creates the view.</summary>
    public SignView()
    {
        InitializeComponent();
    }

    /// <summary>The date is picked from the calendar only: its text box takes no typing.</summary>
    private void OnDatePickerLoaded(object sender, RoutedEventArgs e)
    {
        var picker = (DatePicker)sender;
        if (picker.Template?.FindName("PART_TextBox", picker) is DatePickerTextBox text)
        {
            text.IsReadOnly = true;
        }
    }
}
