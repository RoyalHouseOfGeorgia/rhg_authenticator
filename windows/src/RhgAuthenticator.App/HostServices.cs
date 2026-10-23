using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using Microsoft.Win32;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>The window dialogs belong to.</summary>
internal static class DialogOwner
{
    /// <summary>
    /// The app's active window (a dialog while one is up, so a new one stacks
    /// over it), else the main window; null before the app has one.
    /// </summary>
    public static Window? Current =>
        Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive) ?? Application.Current?.MainWindow;

    /// <summary>Whether any of the app's windows is active (the app is in the foreground).</summary>
    public static bool IsAppActive => Application.Current?.Windows.OfType<Window>().Any(w => w.IsActive) ?? false;

    /// <summary>
    /// Shows <paramref name="dialog"/> modally, owned by <see cref="Current"/>
    /// when it is visible, else centred on the screen; returns its result.
    /// </summary>
    public static bool? ShowModal(Window dialog)
    {
        if (Current is { IsVisible: true } owner)
        {
            dialog.Owner = owner;
        }
        else
        {
            dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }
        return dialog.ShowDialog();
    }

    /// <summary>Shows <paramref name="message"/> under <paramref name="title"/> with an OK button, over <see cref="Current"/>.</summary>
    public static void ShowMessage(string title, string message, MessageBoxImage image = MessageBoxImage.None)
    {
        if (Current is { } owner)
        {
            MessageBox.Show(owner, message, title, MessageBoxButton.OK, image);
        }
        else
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, image);
        }
    }
}

/// <summary>
/// The save dialog: starts in <see cref="SaveLocation.InitialDirectory"/>
/// (the last folder saved to this session, else the Desktop) and asks before
/// overwriting.
/// </summary>
internal sealed class FileSaveService : IFileSaveService
{
    private readonly SaveLocation _location = new();

    /// <inheritdoc />
    public string? ChooseSavePath(string suggestedFileName, string extension)
    {
        var dialog = new SaveFileDialog
        {
            FileName = suggestedFileName,
            DefaultExt = extension,
            AddExtension = true,
            Filter = $"{extension.ToUpperInvariant()} files (*.{extension})|*.{extension}",
            OverwritePrompt = true,
            InitialDirectory = _location.InitialDirectory ?? "",
        };
        var chosen = DialogOwner.Current is { } owner ? dialog.ShowDialog(owner) : dialog.ShowDialog();
        if (chosen != true)
        {
            return null;
        }
        _location.Remember(dialog.FileName);
        return dialog.FileName;
    }
}

/// <summary>
/// The open dialog, filtered on the requested extensions. It keeps its own
/// folder history, apart from the save dialog's: it starts in the last
/// folder opened from this session, else the Desktop.
/// </summary>
internal sealed class FileOpenService : IFileOpenService
{
    private readonly SaveLocation _location = new();

    /// <inheritdoc />
    public string? ChooseOpenPath(params string[] extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);
        ArgumentOutOfRangeException.ThrowIfZero(extensions.Length);
        // "CSV files (*.csv)|*.csv"; "CRT/PEM files (*.crt;*.pem)|*.crt;*.pem".
        var names = string.Join("/", extensions.Select(e => e.ToUpperInvariant()));
        var patterns = string.Join(";", extensions.Select(e => $"*.{e}"));
        var dialog = new OpenFileDialog
        {
            DefaultExt = extensions[0],
            Filter = $"{names} files ({patterns})|{patterns}",
            CheckFileExists = true,
            InitialDirectory = _location.InitialDirectory ?? "",
        };
        var chosen = DialogOwner.Current is { } owner ? dialog.ShowDialog(owner) : dialog.ShowDialog();
        if (chosen != true)
        {
            return null;
        }
        _location.Remember(dialog.FileName);
        return dialog.FileName;
    }
}

/// <summary>The system clipboard (WPF retries a clipboard held open by another app).</summary>
internal sealed class ClipboardService : IClipboard
{
    /// <inheritdoc />
    public string? SetText(string text)
    {
        try
        {
            Clipboard.SetText(text);
            return null;
        }
        catch (ExternalException e)
        {
            return $"Could not copy to the clipboard.\n\n{e.Message}";
        }
    }
}

/// <summary>
/// Opens URLs in the default browser; the view models pass only https URLs
/// the core returned. A failure (no browser, blocked by policy) names the
/// URL, so it can still be copied by hand.
/// </summary>
internal sealed class UrlOpener : IUrlOpener
{
    /// <inheritdoc />
    public string? Open(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);
        try
        {
            using var process = Process.Start(new ProcessStartInfo(url.AbsoluteUri) { UseShellExecute = true });
            return null;
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException)
        {
            return $"Could not open {url.AbsoluteUri}\n\n{e.Message}";
        }
    }
}

/// <summary>Asks a <see cref="Confirmation"/> in a <see cref="ConfirmDialog"/> over the active window.</summary>
internal sealed class ConfirmService : IConfirmService
{
    /// <inheritdoc />
    public bool Ask(Confirmation question)
    {
        return ConfirmDialog.Ask(question);
    }
}
