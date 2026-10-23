namespace RhgAuthenticator.ViewModels;

// The host's services, implemented by the WPF app and faked in tests. View
// models call them on the UI thread.

/// <summary>A file save dialog.</summary>
public interface IFileSaveService
{
    /// <summary>
    /// Asks where to save a file, starting with <paramref name="suggestedFileName"/>
    /// and filtering on <paramref name="extension"/> (without the dot, e.g.
    /// "svg"). Returns the chosen full path, or null when cancelled.
    /// </summary>
    string? ChooseSavePath(string suggestedFileName, string extension);
}

/// <summary>A file open dialog.</summary>
public interface IFileOpenService
{
    /// <summary>
    /// Asks for an existing file, filtering on <paramref name="extensions"/>
    /// (without the dot, e.g. "csv"; at least one). Returns the chosen full
    /// path, or null when cancelled.
    /// </summary>
    string? ChooseOpenPath(params string[] extensions);
}

/// <summary>The system clipboard.</summary>
public interface IClipboard
{
    /// <summary>
    /// Replaces the clipboard's content with <paramref name="text"/>. Returns
    /// null, or why it failed (shown as an error alert).
    /// </summary>
    string? SetText(string text);
}

/// <summary>Opens URLs in the default browser.</summary>
public interface IUrlOpener
{
    /// <summary>
    /// Opens <paramref name="url"/>, an absolute https URL. Returns null, or
    /// why it failed (shown as an error alert).
    /// </summary>
    string? Open(Uri url);
}

/// <summary>A modal question with two buttons.</summary>
public interface IConfirmService
{
    /// <summary>
    /// Asks <paramref name="question"/> and waits for the answer. Returns
    /// whether the operator confirmed (cancelling or closing does not).
    /// </summary>
    bool Ask(Confirmation question);
}

/// <summary>URLs from the core that the host may open.</summary>
internal static class HttpsUrl
{
    /// <summary><paramref name="text"/> as an absolute https URI; null for anything else ("" included).</summary>
    public static Uri? Parse(string text)
    {
        return Uri.TryCreate(text, UriKind.Absolute, out var url) && url.Scheme == Uri.UriSchemeHttps ? url : null;
    }
}
