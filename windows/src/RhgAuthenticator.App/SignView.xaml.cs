using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The Sign tab over a <see cref="SignViewModel"/> (its DataContext). Its
/// alerts are shown by <see cref="MainWindow"/>, whichever tab is selected.
/// </summary>
public partial class SignView : UserControl
{
    /// <summary>The form pane's width when the honor titles need no more.</summary>
    internal const double FormPaneWidth = 340;

    /// <summary>The divider's width: its drag handle.</summary>
    internal const double SplitterWidth = 5;

    /// <summary>
    /// The Honor box's width around its text: the Fluent box's padding, its
    /// drop-down button and border, and 2 DIP of slack against rounding.
    /// </summary>
    internal const double ComboChrome = 54;

    /// <summary>The form pane's left and right margins and the labels' right margin, as in the XAML.</summary>
    internal const double FormMargins = 24 + 16 + 12;

    /// <summary>The QR and its side margins in the result pane, as in the XAML.</summary>
    internal const double ResultContentWidth = 256 + 24 + 24;

    /// <summary>Creates the view.</summary>
    public SignView()
    {
        InitializeComponent();
        // Room for the QR beside the result pane's scrollbar, so it never clips.
        ResultColumn.MinWidth = ResultContentWidth + SystemParameters.VerticalScrollBarWidth + 1;
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

    /// <summary>
    /// The divider starts where the longest honor title fits. The tab's
    /// content is rebuilt on every return to it, so a dragged divider resets then.
    /// </summary>
    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        FormColumn.Width = new GridLength(Math.Max(FormPaneWidth, HonorFitWidth()));
        FitPanes();
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
    /// Keeps the panes at their minimums: the form wide enough for the longest
    /// honor title unless the view is too narrow for both (then the form
    /// yields and the Honor box trims, its tooltip holding the title), and
    /// never so wide that the result pane drops below its own. WPF never
    /// shrinks a pixel-width column itself.
    /// </summary>
    private void FitPanes()
    {
        if (!IsLoaded)
        {
            return;
        }
        var cap = Math.Max(0, ActualWidth - SplitterWidth - ResultColumn.MinWidth);
        FormColumn.MinWidth = Math.Min(HonorFitWidth(), cap);
        var current = FormColumn.Width.IsAbsolute ? FormColumn.Width.Value : FormColumn.ActualWidth;
        FormColumn.Width = new GridLength(Math.Clamp(current, FormColumn.MinWidth, cap));
    }

    /// <summary>
    /// The form pane's width at which the Honor box shows the longest title
    /// whole, with room for the pane's scrollbar should it appear; 0 without honors.
    /// </summary>
    private double HonorFitWidth()
    {
        if (DataContext is not SignViewModel { Honors.Count: > 0 } model)
        {
            return 0;
        }
        var typeface = new Typeface(HonorBox.FontFamily, HonorBox.FontStyle, HonorBox.FontWeight, HonorBox.FontStretch);
        var pixelsPerDip = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var widest = model.Honors.Max(honor => new FormattedText(
            honor, CultureInfo.CurrentUICulture, FlowDirection, typeface, HonorBox.FontSize, Brushes.Black, pixelsPerDip)
            .WidthIncludingTrailingWhitespace);
        return Math.Ceiling(widest) + ComboChrome + LabelColumn.ActualWidth + FormMargins
            + SystemParameters.VerticalScrollBarWidth;
    }
}
