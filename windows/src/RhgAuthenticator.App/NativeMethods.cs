using System.Runtime.InteropServices;

namespace RhgAuthenticator.App;

/// <summary>The Win32 calls WPF does not wrap.</summary>
internal static partial class NativeMethods
{
    /// <summary>Flash both the caption and the taskbar button.</summary>
    internal const uint FlashAll = 0x3;

    /// <summary>Flash until the window comes to the foreground.</summary>
    internal const uint FlashUntilForeground = 0xC;

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

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FlashWindowEx(in FlashWindowInfo info);

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
