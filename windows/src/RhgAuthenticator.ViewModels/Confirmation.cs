namespace RhgAuthenticator.ViewModels;

/// <summary>
/// A question to confirm before acting (<see cref="IConfirmService.Ask"/>):
/// title, message and the two button titles, all display only.
/// </summary>
/// <param name="Title">The dialog's title.</param>
/// <param name="Message">The question.</param>
/// <param name="ConfirmTitle">The confirm button's title (the default button).</param>
/// <param name="CancelTitle">The cancel button's title.</param>
/// <param name="IsDestructive">The confirm button discards something.</param>
public sealed record Confirmation(
    string Title, string Message, string ConfirmTitle, string CancelTitle = "Cancel", bool IsDestructive = false);
