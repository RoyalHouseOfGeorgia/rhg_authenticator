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
    /// <summary>The form pane's starting width when the honor titles need no more.</summary>
    internal const double DefaultFormPaneWidth = 340;

    /// <summary>
    /// The Honor box's width around its text: the Fluent template's padding,
    /// border and drop-down button, as one figure because the template's
    /// parts (the button above all) are not exposed.
    /// </summary>
    internal const double ComboChrome = 52;

    /// <summary>Slack added to each measured minimum against layout rounding.</summary>
    internal const double RoundingSlack = 2;

    /// <summary>Creates the view.</summary>
    public SignView()
    {
        InitializeComponent();
        // A pixel column from the start (OnLoaded widens it to fit the honors), never a star one.
        FormColumn.Width = new GridLength(DefaultFormPaneWidth);
        // Room for the QR and its margins beside the result pane's scrollbar, so it never clips.
        ResultColumn.MinWidth = QrImage.Width + ResultPanel.Margin.Left + ResultPanel.Margin.Right
            + SystemParameters.VerticalScrollBarWidth + RoundingSlack;
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
    /// content is rebuilt on every return to it, so a dragged divider resets
    /// then. The honors are loaded before the Sign tab is enabled
    /// (AppViewModel.StartAsync), so they are here already.
    /// </summary>
    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        FormColumn.Width = new GridLength(Math.Max(DefaultFormPaneWidth, HonorFitWidth()));
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
        var cap = Math.Max(0, ActualWidth - Splitter.Width - ResultColumn.MinWidth);
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
        // LabelColumn sizes to the labels' DesiredSize, which includes their margin.
        return Math.Ceiling(widest) + ComboChrome + RoundingSlack + LabelColumn.ActualWidth
            + FormPanel.Margin.Left + FormPanel.Margin.Right + SystemParameters.VerticalScrollBarWidth;
    }
}
