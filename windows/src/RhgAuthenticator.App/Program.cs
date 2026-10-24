using System.Globalization;
using System.IO;
using System.Windows;
using RhgAuthenticator.Bridge;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The entry point. The core library is unpacked and loaded first; the
/// core's command-line invocations (<c>--version</c>,
/// <c>--verify-update-zip</c>, run by CI and the release checks) are handled
/// next, so they never start WPF; anything else starts the app.
/// </summary>
internal static class Program
{
    /// <summary>The embedded core library's LogicalName (the project file).</summary>
    internal const string LibraryResourceName = "rhgcore.dll";

    /// <summary>Exit code when the core library cannot be unpacked or loaded.</summary>
    internal const int CoreLibraryFailure = 1;

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            // Only ever this full path: nothing loads rhgcore.dll from a search path.
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "rhg-authenticator", "native");
            CoreLibrary.Load(CoreLibrary.ExtractEmbedded(typeof(Program).Assembly, LibraryResourceName, root));
        }
        catch (CoreLibraryException e)
        {
            // Also on stderr, for a command-line run (CI's --version check) with no one to close the box.
            Console.Error.WriteLine(e.UserMessage);
            MessageBox.Show(e.UserMessage, AlertState.ErrorTitle, MessageBoxButton.OK, MessageBoxImage.Error);
            return CoreLibraryFailure;
        }

        if (MainCli.Run(args) is { } exitCode)
        {
            return exitCode;
        }

        // The process-wide date format (this thread and every later one), so the
        // date picker, which formats in the current culture, shows YYYY-Mon-DD too.
        var culture = DisplayDate.Culture(CultureInfo.CurrentCulture);
        CultureInfo.DefaultThreadCurrentCulture = culture;
        CultureInfo.CurrentCulture = culture;

        // Buffers the core's events from here on; AppViewModel.StartAsync drains them.
        IBridge bridge = LiveBridge.Install();
        var app = new App();
        var model = new AppViewModel(
            bridge, new FileSaveService(), new FileOpenService(), new ClipboardService(), new UrlOpener(), new ConfirmService());
        return app.Run(new MainWindow(model));
    }
}
