namespace RhgAuthenticator.ViewModels;

/// <summary>
/// Where save dialogs open: the folder of the last file saved in this
/// session, while it exists, else the Desktop.
/// </summary>
/// <param name="desktop">
/// The Desktop folder, "" when unknown; by default
/// <see cref="Environment.SpecialFolder.Desktop"/>, which follows redirection
/// (OneDrive's "Back up Desktop"). Tests inject it.
/// </param>
public sealed class SaveLocation(Func<string>? desktop = null)
{
    private readonly Func<string> _desktop = desktop ?? (() => Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
    private string? _lastFolder;

    /// <summary>The folder a save dialog starts in; null leaves it to the dialog.</summary>
    public string? InitialDirectory
    {
        get
        {
            if (_lastFolder is { } last && Directory.Exists(last))
            {
                return last;
            }
            var desktop = _desktop();
            return string.IsNullOrEmpty(desktop) ? null : desktop;
        }
    }

    /// <summary>Records <paramref name="path"/>, the file just chosen, so the next dialog starts in its folder.</summary>
    public void Remember(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        var folder = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(folder))
        {
            _lastFolder = folder;
        }
    }
}
