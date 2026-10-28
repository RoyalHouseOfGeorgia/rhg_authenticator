using System.Windows;

namespace RhgAuthenticator.App;

/// <summary>
/// The WPF application: the shared resources, and the Fluent theme following
/// the system's light or dark mode. Started by <see cref="Program"/>; it
/// shuts down when <see cref="MainWindow"/>'s quit sequence closes it.
/// </summary>
public partial class App : Application
{
    /// <summary>Creates the application with its resources and theme.</summary>
    public App()
    {
        InitializeComponent();
        // After the resources load, not as a XAML attribute: WPF keeps
        // ThemeMode in sync with the Fluent dictionary in Resources, and XAML
        // sets attributes before Resources replaces the dictionary.
        // WPF0001: ThemeMode (the Fluent theme) is still marked experimental in .NET 10.
#pragma warning disable WPF0001
        ThemeMode = ThemeMode.System;
#pragma warning restore WPF0001
    }
}
