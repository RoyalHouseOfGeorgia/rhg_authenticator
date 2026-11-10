using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>What an entry form edits. Match on the nested records.</summary>
public abstract record EntryFormMode
{
    private protected EntryFormMode()
    {
    }

    /// <summary>A new entry; its key is imported on the form.</summary>
    public sealed record Add : EntryFormMode;

    /// <summary>The entry at <paramref name="Index"/> of the snapshot, whose key is <paramref name="PublicKey"/>.</summary>
    /// <param name="Index">The entry's index in <see cref="RegistrySnapshot.Entries"/>.</param>
    /// <param name="PublicKey">The key the entry must still hold.</param>
    public sealed record Edit(int Index, string PublicKey) : EntryFormMode;
}

/// <summary>
/// The Add Entry / Edit Entry dialog. Fields go to the core as typed; it
/// validates them and reads the imported keys.
/// </summary>
public sealed partial class EntryFormViewModel : ObservableObject
{
#pragma warning disable CS1591 // UI copy; each constant's name says where it shows.
    public const string AddTitle = "Add Entry";
    public const string EditTitle = "Edit Entry";
    public const string AddConfirmTitle = "Add";
    public const string EditConfirmTitle = "Save";
    public const string CancelTitle = "Cancel";
    public const string AuthorityLabel = "Authority";
    public const string AuthorityPlaceholder = "Authority name";
    public const string FromLabel = "From date";
    public const string ToLabel = "To date";
    public const string NoExpiryLabel = "No expiry";
    public const string PublicKeyLabel = "Public Key";
    public const string NoteLabel = "Note";
    public const string NotePlaceholder = "Optional note";
    public const string ImportCertificateTitle = "Import Certificate";
    public const string ImportFromYubiKeyTitle = "Import from YubiKey";
    public const string NoKeyText = "No key imported";
    public const string YubiKeyBusyText = "The YubiKey is busy with another operation. Try again when it finishes.";
#pragma warning restore CS1591

    /// <summary>The certificate file types Import Certificate offers.</summary>
    public static readonly IReadOnlyList<string> CertificateExtensions = ["crt", "pem"];

    private readonly IBridge _bridge;
    private readonly IFileOpenService _fileOpen;
    private DateTime _from;
    private DateTime _to;

    /// <summary>
    /// An Add Entry form: from today, no expiry, no key. <paramref name="clock"/>
    /// (default the system clock) sets today, in UTC.
    /// </summary>
    public EntryFormViewModel(IBridge bridge, IFileOpenService fileOpen, TimeProvider? clock = null)
        : this(bridge, fileOpen, new EntryFormMode.Add(), clock)
    {
        NoExpiry = true;
        KeyText = NoKeyText;
    }

    /// <summary>
    /// An Edit Entry form for <paramref name="entry"/>, the entry at
    /// <paramref name="index"/> of the snapshot. A date that does not parse
    /// (or no expiry) starts at today, in UTC by <paramref name="clock"/>.
    /// </summary>
    public EntryFormViewModel(
        IBridge bridge, IFileOpenService fileOpen, int index, RegistryEntry entry, TimeProvider? clock = null)
        : this(
            bridge, fileOpen,
            new EntryFormMode.Edit(index, (entry ?? throw new ArgumentNullException(nameof(entry))).PublicKey), clock)
    {
        Authority = entry.Authority;
        _from = DisplayDate.ParseYmd(entry.From) ?? _from;
        if (!entry.NoExpiry)
        {
            _to = DisplayDate.ParseYmd(entry.To) ?? _to;
        }
        NoExpiry = entry.NoExpiry;
        Note = entry.Note;
        KeyText = entry.PublicKey;
    }

    private EntryFormViewModel(IBridge bridge, IFileOpenService fileOpen, EntryFormMode mode, TimeProvider? clock)
    {
        ArgumentNullException.ThrowIfNull(bridge);
        ArgumentNullException.ThrowIfNull(fileOpen);
        _bridge = bridge;
        _fileOpen = fileOpen;
        Mode = mode;
        var today = (clock ?? TimeProvider.System).GetUtcNow().UtcDateTime.Date;
        _from = today;
        _to = today;
    }

    /// <summary>What the form edits.</summary>
    public EntryFormMode Mode { get; }

    /// <summary>The form adds a new entry (it can import a key).</summary>
    public bool IsAdding => Mode is EntryFormMode.Add;

    /// <summary>The dialog's title.</summary>
    public string Title => IsAdding ? AddTitle : EditTitle;

    /// <summary>The confirm button's title.</summary>
    public string ConfirmTitle => IsAdding ? AddConfirmTitle : EditConfirmTitle;

    /// <summary>The authority field.</summary>
    [ObservableProperty]
    public partial string Authority { get; set; } = "";

    /// <summary>The note field.</summary>
    [ObservableProperty]
    public partial string Note { get; set; } = "";

    /// <summary>The key never expires: <see cref="To"/> is not sent.</summary>
    [ObservableProperty]
    public partial bool NoExpiry { get; set; }

    /// <summary>The imported public key (add only); "" while none is.</summary>
    [ObservableProperty]
    public partial string ImportedKey { get; private set; } = "";

    /// <summary>
    /// The Public Key text: the imported key, <see cref="NoKeyText"/> or an
    /// import error (add); the entry's key, read-only (edit).
    /// </summary>
    [ObservableProperty]
    public partial string KeyText { get; private set; } = "";

    /// <summary>The error line; "" when there is none.</summary>
    [ObservableProperty]
    public partial string ErrorText { get; private set; } = "";

    /// <summary>Import from YubiKey is running: it is disabled.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ImportFromYubiKeyCommand))]
    public partial bool IsImporting { get; private set; }

    /// <summary>The entry is being added or saved.</summary>
    [ObservableProperty]
    public partial bool IsSubmitting { get; private set; }

    /// <summary>The from date, for a date picker: a calendar date (any time of day is dropped).</summary>
    public DateTime From
    {
        get => _from;
        set
        {
            if (SetProperty(ref _from, value.Date))
            {
                OnPropertyChanged(nameof(SelectedFrom));
            }
        }
    }

    /// <summary>
    /// <see cref="From"/> for a date picker, whose selection can be cleared:
    /// clearing it keeps <see cref="From"/> and shows it again.
    /// </summary>
    public DateTime? SelectedFrom
    {
        get => _from;
        set
        {
            if (value is { } date)
            {
                From = date;
            }
            else
            {
                OnPropertyChanged();
            }
        }
    }

    /// <summary>The to date, used only without <see cref="NoExpiry"/>: a calendar date (any time of day is dropped).</summary>
    public DateTime To
    {
        get => _to;
        set
        {
            if (SetProperty(ref _to, value.Date))
            {
                OnPropertyChanged(nameof(SelectedTo));
            }
        }
    }

    /// <summary>
    /// <see cref="To"/> for a date picker, whose selection can be cleared:
    /// clearing it keeps <see cref="To"/> and shows it again.
    /// </summary>
    public DateTime? SelectedTo
    {
        get => _to;
        set
        {
            if (value is { } date)
            {
                To = date;
            }
            else
            {
                OnPropertyChanged();
            }
        }
    }

    /// <summary>The form as sent: text as typed, dates as YYYY-MM-DD, To "" with no expiry.</summary>
    public EntryForm Form =>
        new(Authority, DisplayDate.Ymd(_from), NoExpiry ? "" : DisplayDate.Ymd(_to), Note, NoExpiry);

    /// <summary>
    /// Add / Save (registry.addEntry or registry.updateEntry). Returns whether
    /// the core accepted the entry; on failure the dialog stays open with the
    /// core's message. Ignored (false) while a submit is running.
    /// </summary>
    public async Task<bool> SubmitAsync()
    {
        if (IsSubmitting)
        {
            return false;
        }
        IsSubmitting = true;
        try
        {
            if (Mode is EntryFormMode.Edit edit)
            {
                await _bridge.UpdateEntryAsync(edit.Index, edit.PublicKey, Form);
            }
            else
            {
                await _bridge.AddEntryAsync(Form, ImportedKey);
            }
        }
        catch (RpcException error)
        {
            ErrorText = error.Message;
            return false;
        }
        finally
        {
            IsSubmitting = false;
        }
        ErrorText = "";
        return true;
    }

    private bool CanImportCertificate()
    {
        return IsAdding;
    }

    /// <summary>
    /// Import Certificate: asks for a certificate file, then reads its key
    /// (registry.importCertificate). Add forms only.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanImportCertificate))]
    private async Task ImportCertificateAsync()
    {
        if (!CanImportCertificate() || _fileOpen.ChooseOpenPath([.. CertificateExtensions]) is not { } path)
        {
            return;
        }
        try
        {
            Imported(await _bridge.ImportCertificateAsync(path));
        }
        catch (RpcException error)
        {
            ErrorText = error.Message;
            KeyText = NoKeyText;
            ImportedKey = "";
        }
    }

    private bool CanImportFromYubiKey()
    {
        return IsAdding && !IsImporting;
    }

    /// <summary>
    /// Import from YubiKey (registry.importFromYubiKey). A busy card keeps the
    /// current key; any other failure shows in the key text. Add forms only;
    /// ignored while an import is running.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanImportFromYubiKey))]
    private async Task ImportFromYubiKeyAsync()
    {
        if (!CanImportFromYubiKey())
        {
            return;
        }
        IsImporting = true;
        try
        {
            Imported(await _bridge.ImportFromYubiKeyAsync());
        }
        catch (RpcException error)
        {
            if (error.Code == RpcErrorCode.Busy)
            {
                ErrorText = YubiKeyBusyText;
                return;
            }
            KeyText = error.Message;
            ImportedKey = "";
            ErrorText = "";
        }
        finally
        {
            IsImporting = false;
        }
    }

    private void Imported(string key)
    {
        ImportedKey = key;
        KeyText = key;
        ErrorText = "";
    }
}
