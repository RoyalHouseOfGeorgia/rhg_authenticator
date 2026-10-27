using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Interop;
using RhgAuthenticator.Bridge;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The entry point. The core library is unpacked and loaded first; the
/// core's command-line invocations (<c>--version</c>,
/// <c>--verify-update-zip</c>, run by CI and the release checks) are handled
/// next, so they never start WPF; anything else starts the app, unless it is
/// already running, which is then brought forward instead.
/// </summary>
internal static class Program
{
    /// <summary>The embedded core library's LogicalName (the project file).</summary>
    internal const string LibraryResourceName = "rhgcore.dll";

    /// <summary>Exit code when the core library cannot be unpacked or loaded.</summary>
    internal const int CoreLibraryFailure = 1;

    /// <summary>Exit code of a launch that handed over to the running instance.</summary>
    internal const int AnotherInstanceRunning = 0;

    /// <summary>
    /// The single-instance mutex's name. <c>Local\</c> is per session (a second
    /// user signed in on the same machine runs their own instance).
    /// </summary>
    internal const string InstanceMutexName = @"Local\RhgAuthenticator-9be274aa-7692-4f66-b2d9-bda0a7865b79";

    /// <summary>The event a later launch signals to bring the running instance forward.</summary>
    internal const string InstanceEventName = InstanceMutexName + "-activate";

    // The process's lifetime: its handles are the guard.
    private static SingleInstance? s_instance;

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

        // After the command-line runs (never blocked by a running app), before
        // the core starts: a later launch brings the running app forward and exits.
        s_instance = new SingleInstance(InstanceMutexName, InstanceEventName);
        if (!s_instance.IsFirst)
        {
            NativeMethods.AllowAnyProcessToSetForeground();
            s_instance.SignalFirst();
            return AnotherInstanceRunning;
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
        var window = new MainWindow(model);
        var instance = s_instance;
        // From the window's load on, every later launch's signal brings it
        // forward; one sent during start-up is still set and does so now.
        // Signals arrive on thread-pool threads; the window is the dispatcher's.
        // Loaded can fire again; registering twice throws, so once only.
        void OnLoaded(object sender, RoutedEventArgs e)
        {
            window.Loaded -= OnLoaded;
            instance.RegisterActivation(() => _ = window.Dispatcher.BeginInvoke(() => BringForward(window)));
        }
        window.Loaded += OnLoaded;
        return app.Run(window);
    }

    /// <summary>Brings the main window (or its open dialog) forward, unless it has closed.</summary>
    private static void BringForward(Window window)
    {
        // Zero once the window has closed.
        var handle = new WindowInteropHelper(window).Handle;
        if (handle != 0)
        {
            NativeMethods.Activate(handle);
        }
    }
}
