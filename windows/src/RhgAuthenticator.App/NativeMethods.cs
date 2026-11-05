using System.Runtime.InteropServices;

namespace RhgAuthenticator.App;

/// <summary>The Win32 calls WPF does not wrap.</summary>
internal static partial class NativeMethods
{
    /// <summary>Flash both the caption and the taskbar button.</summary>
    internal const uint FlashAll = 0x3;

    /// <summary>Flash until the window comes to the foreground.</summary>
    internal const uint FlashUntilForeground = 0xC;

    /// <summary>ASFW_ANY: every process may set the foreground window.</summary>
    internal const uint AsfwAny = 0xFFFFFFFF;

    /// <summary>SW_RESTORE: a minimized window back to its previous size and position.</summary>
    internal const int SwRestore = 9;

    /// <summary>Flashes <paramref name="window"/>'s taskbar button until it comes to the foreground.</summary>
    public static void FlashUntilActivated(nint window)
    {
        var info = new FlashWindowInfo
        {
            Size = (uint)Marshal.SizeOf<FlashWindowInfo>(),
            Window = window,
            Flags = FlashAll | FlashUntilForeground,
        };
        // Its result is the window's previous state, not success.
        _ = FlashWindowEx(in info);
    }

    /// <summary>
    /// Lets the running instance take the foreground when this process (a
    /// later launch, which the user just started and so may) signals it.
    /// Failure is ignored: the window then flashes on the taskbar instead.
    /// </summary>
    public static void AllowAnyProcessToSetForeground() => _ = AllowSetForegroundWindow(AsfwAny);

    /// <summary>
    /// Brings <paramref name="window"/> forward: restored only when minimized
    /// (a maximized window comes back maximized, and one merely behind others
    /// keeps its size), then its open modal dialog, if any, else the window
    /// itself, takes the foreground and the keyboard focus.
    /// </summary>
    public static void Activate(nint window)
    {
        if (IsIconic(window))
        {
            _ = ShowWindow(window, SwRestore);
        }
        _ = SetForegroundWindow(GetLastActivePopup(window));
    }

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FlashWindowEx(in FlashWindowInfo info);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AllowSetForegroundWindow(uint processId);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsIconic(nint window);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ShowWindow(nint window, int command);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint GetLastActivePopup(nint window);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetForegroundWindow(nint window);

    /// <summary>FLASHWINFO.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct FlashWindowInfo
    {
        public uint Size;
        public nint Window;
        public uint Flags;
        public uint Count;
        public uint Timeout;
    }
}
