using System.Windows;
using System.Windows.Input;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// A <see cref="Confirmation"/>: its message (selectable) with its confirm
/// and cancel buttons, and its alternate button when it has one, which a
/// MessageBox cannot be given. A destructive question (discarding edits,
/// deleting an issuance record) keeps Enter and the focus on the cancel
/// button, so a stray Enter never discards anything.
/// </summary>
public partial class ConfirmDialog : Window
{
    /// <summary>The button chosen; cancel, Escape and the close button leave it <see cref="ConfirmChoice.Cancel"/>.</summary>
    private ConfirmChoice _choice = ConfirmChoice.Cancel;

    private ConfirmDialog(Confirmation question)
    {
        InitializeComponent();
        DataContext = question;
        if (question.AlternateTitle is { } alternate)
        {
            AlternateButton.Content = alternate;
            AlternateButton.Visibility = Visibility.Visible;
        }
        if (question.IsDestructive)
        {
            ConfirmButton.IsDefault = false;
            ConfirmButton.ClearValue(StyleProperty);
            CancelButton.IsDefault = true;
            FocusManager.SetFocusedElement(this, CancelButton);
        }
    }

    /// <summary>
    /// Shows <paramref name="question"/> modally over the active window and
    /// returns the button chosen (<see cref="ConfirmChoice.Cancel"/> for
    /// cancel, Escape and the close button).
    /// </summary>
    public static ConfirmChoice Choose(Confirmation question)
    {
        ArgumentNullException.ThrowIfNull(question);
        var dialog = new ConfirmDialog(question);
        _ = DialogOwner.ShowModal(dialog);
        return dialog._choice;
    }

    private void OnConfirmClick(object sender, RoutedEventArgs e)
    {
        _choice = ConfirmChoice.Confirm;
        DialogResult = true;
    }

    private void OnAlternateClick(object sender, RoutedEventArgs e)
    {
        _choice = ConfirmChoice.Alternate;
        DialogResult = true;
    }
}
