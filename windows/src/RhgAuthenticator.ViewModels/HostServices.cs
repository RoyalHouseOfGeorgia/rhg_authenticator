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
    /// Asks for an existing file, filtering on <paramref name="extension"/>
    /// (without the dot, e.g. "csv"). Returns the chosen full path, or null
    /// when cancelled.
    /// </summary>
    string? ChooseOpenPath(string extension);
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
