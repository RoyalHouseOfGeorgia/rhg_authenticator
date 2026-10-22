using System.Windows.Controls;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The YubiKey tab over a <see cref="YubiKeyViewModel"/> (its DataContext).
/// It stays enabled offline: the core answers without the card then.
/// </summary>
public partial class YubiKeyView : UserControl
{
    /// <summary>Creates the view.</summary>
    public YubiKeyView()
    {
        InitializeComponent();
    }
}
