namespace RhgAuthenticator.Bridge;

/// <summary>
/// The core library could not be unpacked or loaded, so the app cannot start.
/// Show <see cref="UserMessage"/> in an error dialog, then exit.
/// </summary>
public sealed class CoreLibraryException : Exception
{
    /// <summary>Appended to a start-up failure's message: where to report it.</summary>
    public const string ReportSuffix =
        "\n\nPlease report this error at https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues";

    /// <summary>Creates the exception with its user-facing <paramref name="message"/>.</summary>
    public CoreLibraryException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }

    /// <summary>The dialog text: <see cref="Exception.Message"/> and <see cref="ReportSuffix"/>.</summary>
    public string UserMessage => Message + ReportSuffix;
}
