using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>
/// The Add Entry / Edit Entry dialog: a modal window up while the
/// <see cref="RegistryViewModel"/> shows its <see cref="EntryFormViewModel"/>.
/// Add / Save submits; the view model closes the dialog once the core accepts
/// the entry, and keeps it up with the core's message otherwise. Cancel,
/// Escape and the close button cancel the entry, except while it is being
/// added or saved, when they do nothing.
/// </summary>
public partial class EntryFormDialog : Window
{
    private readonly RegistryViewModel _registry;
    private readonly EntryFormViewModel _form;

    private EntryFormDialog(RegistryViewModel registry, EntryFormViewModel form)
    {
        _registry = registry;
        _form = form;
        InitializeComponent();
        DataContext = form;
        Closing += OnClosing;
    }

    /// <summary>
    /// Shows a new dialog whenever <paramref name="registry"/> opens an entry
    /// form, and closes it when the form closes or is replaced. Call once, on
    /// the UI thread.
    /// </summary>
    public static void Attach(RegistryViewModel registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        // Keyed on the form: a form that replaces it closes this dialog and opens its own.
        _ = new ModalPresenter<EntryFormDialog>(
            registry, nameof(RegistryViewModel.EntryForm), () => registry.EntryForm,
            form => new EntryFormDialog(registry, (EntryFormViewModel)form));
    }

    /// <summary>
    /// Closing while the form is still open (Cancel, Escape, the close
    /// button) cancels it, and the view model's change then closes the
    /// window; while the entry is being added or saved it does nothing, so
    /// the core's answer is never lost behind a closed dialog.
    /// </summary>
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_form.IsSubmitting && _registry.EntryForm == _form)
        {
            e.Cancel = true;
            return;
        }
        _ = ModalPresenter.CloseByHand(this, e, () => _registry.EntryForm == _form, _registry.CancelEntry);
    }

    /// <summary>The date is picked from the calendar only: its text box takes no typing.</summary>
    private void OnDatePickerLoaded(object sender, RoutedEventArgs e)
    {
        DatePickers.MakePickOnly((DatePicker)sender);
    }

    /// <summary>
    /// Add / Save. The view model closes the dialog on success; async void,
    /// so a failure ends the app, as MainWindow's handlers' do.
    /// </summary>
    private async void OnConfirmClick(object sender, RoutedEventArgs e)
    {
        await _registry.SubmitEntryAsync();
    }
}
