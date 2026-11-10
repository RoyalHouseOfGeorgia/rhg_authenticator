using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace RhgAuthenticator.App;

/// <summary>The app's date pickers: dates are picked from the calendar, never typed.</summary>
internal static class DatePickers
{
    /// <summary>
    /// Makes <paramref name="picker"/>'s text box read-only. Call from its
    /// Loaded event, once the template has built the text box.
    /// </summary>
    public static void MakePickOnly(DatePicker picker)
    {
        if (picker.Template?.FindName("PART_TextBox", picker) is DatePickerTextBox text)
        {
            text.IsReadOnly = true;
        }
    }
}
