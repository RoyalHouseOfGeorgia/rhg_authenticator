using System.Windows.Controls;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The Help tab over the <see cref="AppViewModel"/> itself (its DataContext):
/// Export Error Log…, and the loading progress while the core starts.
/// </summary>
public partial class HelpView : UserControl
{
    /// <summary>Creates the view.</summary>
    public HelpView()
    {
        InitializeComponent();
    }
}
