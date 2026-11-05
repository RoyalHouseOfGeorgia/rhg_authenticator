namespace RhgAuthenticator.ViewModels;

/// <summary>
/// A question to confirm before acting (<see cref="IConfirmService.Choose"/>):
/// title, message and the button titles, all display only.
/// </summary>
/// <param name="Title">The dialog's title.</param>
/// <param name="Message">The question.</param>
/// <param name="ConfirmTitle">The confirm button's title (the default button).</param>
/// <param name="CancelTitle">The cancel button's title.</param>
/// <param name="IsDestructive">The confirm button discards something.</param>
/// <param name="AlternateTitle">
/// A third button's title, offering another action instead
/// (<see cref="ConfirmChoice.Alternate"/>); null shows two buttons.
/// </param>
public sealed record Confirmation(
    string Title,
    string Message,
    string ConfirmTitle,
    string CancelTitle = "Cancel",
    bool IsDestructive = false,
    string? AlternateTitle = null);

/// <summary>The operator's answer to a <see cref="Confirmation"/>.</summary>
public enum ConfirmChoice
{
    /// <summary>Cancelled, or closed the question (Escape, the close button).</summary>
    Cancel,

    /// <summary>The confirm button.</summary>
    Confirm,

    /// <summary>The <see cref="Confirmation.AlternateTitle"/> button.</summary>
    Alternate,
}
