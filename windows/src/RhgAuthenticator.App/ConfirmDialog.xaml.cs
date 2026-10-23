using System.Windows;
using System.Windows.Input;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// A <see cref="Confirmation"/>: its message (selectable) with its confirm
/// and cancel buttons, which a MessageBox cannot be given. A destructive
/// question (discarding edits) keeps Enter and the focus on the cancel
/// button, so a stray Enter never discards anything.
/// </summary>
public partial class ConfirmDialog : Window
{
    private ConfirmDialog(Confirmation question)
    {
        InitializeComponent();
        DataContext = question;
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
    /// returns whether the operator confirmed (cancel, Escape and the close
    /// button do not).
    /// </summary>
    public static bool Ask(Confirmation question)
    {
        ArgumentNullException.ThrowIfNull(question);
        return DialogOwner.ShowModal(new ConfirmDialog(question)) == true;
    }

    private void OnConfirmClick(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
    }
}
