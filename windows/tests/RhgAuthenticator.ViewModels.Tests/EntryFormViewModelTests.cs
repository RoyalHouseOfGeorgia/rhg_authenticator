using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class EntryFormViewModelTests
{
    private const string Key = "JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0=";
    private const string YubiKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

    private readonly FakeBridge _fake = new();
    private readonly FakeFileOpen _fileOpen = new();
    private readonly FixedClock _clock = new(Fixtures.LateNewYearsDay);

    private EntryFormViewModel AddForm()
    {
        return new EntryFormViewModel(_fake, _fileOpen, _clock);
    }

    private EntryFormViewModel EditForm(int index, RegistryEntry entry)
    {
        return new EntryFormViewModel(_fake, _fileOpen, index, entry, _clock);
    }

    [Fact]
    public void Copy()
    {
        Assert.Equal(["Add Entry", "Edit Entry"], [EntryFormViewModel.AddTitle, EntryFormViewModel.EditTitle]);
        Assert.Equal(
            ["Add", "Save", "Cancel"],
            [EntryFormViewModel.AddConfirmTitle, EntryFormViewModel.EditConfirmTitle, EntryFormViewModel.CancelTitle]);
        Assert.Equal(
            ["Authority", "From date", "To date", "No expiry", "Public Key", "Note"],
            [
                EntryFormViewModel.AuthorityLabel, EntryFormViewModel.FromLabel, EntryFormViewModel.ToLabel,
                EntryFormViewModel.NoExpiryLabel, EntryFormViewModel.PublicKeyLabel, EntryFormViewModel.NoteLabel,
            ]);
        Assert.Equal(
            ["Authority name", "Optional note"], [EntryFormViewModel.AuthorityPlaceholder, EntryFormViewModel.NotePlaceholder]);
        Assert.Equal(
            ["Import Certificate", "Import from YubiKey"],
            [EntryFormViewModel.ImportCertificateTitle, EntryFormViewModel.ImportFromYubiKeyTitle]);
        Assert.Equal("No key imported", EntryFormViewModel.NoKeyText);
        Assert.Equal(
            "The YubiKey is busy with another operation. Try again when it finishes.", EntryFormViewModel.YubiKeyBusyText);
        Assert.Equal(["crt", "pem"], EntryFormViewModel.CertificateExtensions);
    }

    [Fact]
    public void RequiresItsServicesAndEntry()
    {
        var entry = Fixtures.RegistryEntry(1).Entry;
        Assert.Throws<ArgumentNullException>(() => new EntryFormViewModel(null!, _fileOpen));
        Assert.Throws<ArgumentNullException>(() => new EntryFormViewModel(_fake, null!));
        Assert.Throws<ArgumentNullException>(() => new EntryFormViewModel(null!, _fileOpen, 0, entry));
        Assert.Throws<ArgumentNullException>(() => new EntryFormViewModel(_fake, null!, 0, entry));
        Assert.Throws<ArgumentNullException>(() => new EntryFormViewModel(_fake, _fileOpen, 0, null!));
    }

    [Fact]
    public void AddDefaultsTodayInUtcNoExpiryNoKey()
    {
        var form = AddForm();
        Assert.IsType<EntryFormMode.Add>(form.Mode);
        Assert.True(form.IsAdding);
        Assert.Equal("Add Entry", form.Title);
        Assert.Equal("Add", form.ConfirmTitle);
        Assert.Equal("", form.Authority);
        Assert.Equal("", form.Note);
        Assert.True(form.NoExpiry);
        Assert.Equal(new DateTime(2026, 1, 1), form.From);
        Assert.Equal(new DateTime(2026, 1, 1), form.To);
        Assert.Equal(new DateTime(2026, 1, 1), form.SelectedFrom);
        Assert.Equal(new DateTime(2026, 1, 1), form.SelectedTo);
        Assert.Equal("No key imported", form.KeyText);
        Assert.Equal("", form.ImportedKey);
        Assert.Equal("", form.ErrorText);
        Assert.False(form.IsImporting);
        Assert.False(form.IsSubmitting);
        Assert.True(form.ImportCertificateCommand.CanExecute(null));
        Assert.True(form.ImportFromYubiKeyCommand.CanExecute(null));
        Assert.Equal(new EntryForm("", "2026-01-01", "", "", true), form.Form);
    }

    [Fact]
    public void TodayIsTheUtcDateWhateverTheMachinesZone()
    {
        var tbilisi = TimeZoneInfo.CreateCustomTimeZone("test", TimeSpan.FromHours(4), "test", "test");
        var form = new EntryFormViewModel(_fake, _fileOpen, new FixedClock(Fixtures.LateNewYearsDay, tbilisi));
        Assert.Equal("2026-01-01", form.Form.From);
    }

    [Fact]
    public void TheDefaultClockIsTheSystemsInUtc()
    {
        var before = DateTime.UtcNow.Date;
        var form = new EntryFormViewModel(_fake, _fileOpen);
        Assert.InRange(form.From, before, DateTime.UtcNow.Date);
        Assert.Equal(TimeSpan.Zero, form.From.TimeOfDay);
    }

    [Fact]
    public void TheFormSendsTextAsTypedYmdDatesAndToOnlyWithAnExpiry()
    {
        var form = AddForm();
        form.Authority = "  New Authority ";
        form.Note = "Line 1\nLine 2";
        form.From = new DateTime(2026, 3, 4, 13, 14, 15);
        form.To = new DateTime(2030, 12, 31);
        Assert.Equal(new DateTime(2026, 3, 4), form.From);
        Assert.Equal("", form.Form.To);
        form.NoExpiry = false;
        Assert.Equal(new EntryForm("  New Authority ", "2026-03-04", "2030-12-31", "Line 1\nLine 2", false), form.Form);
    }

    [Fact]
    public void TheSelectedDatesFollowTheDatesAndAClearedPickerKeepsThem()
    {
        var form = AddForm();
        var changed = new List<string?>();
        form.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        form.SelectedFrom = new DateTime(2026, 5, 6, 7, 8, 9);
        Assert.Equal(new DateTime(2026, 5, 6), form.From);
        Assert.Equal([nameof(EntryFormViewModel.From), nameof(EntryFormViewModel.SelectedFrom)], changed);
        changed.Clear();
        form.SelectedFrom = null;
        Assert.Equal(new DateTime(2026, 5, 6), form.SelectedFrom);
        Assert.Equal([nameof(EntryFormViewModel.SelectedFrom)], changed);
        changed.Clear();
        form.From = new DateTime(2026, 5, 6, 1, 0, 0); // the same date
        Assert.Empty(changed);

        form.SelectedTo = new DateTime(2027, 1, 2);
        Assert.Equal(new DateTime(2027, 1, 2), form.To);
        Assert.Equal([nameof(EntryFormViewModel.To), nameof(EntryFormViewModel.SelectedTo)], changed);
        changed.Clear();
        form.SelectedTo = null;
        Assert.Equal(new DateTime(2027, 1, 2), form.SelectedTo);
        Assert.Equal([nameof(EntryFormViewModel.SelectedTo)], changed);
        changed.Clear();
        form.To = new DateTime(2027, 1, 2, 23, 0, 0);
        Assert.Empty(changed);
    }

    [Fact]
    public void EditTakesItsFieldsFromTheEntryAndTheKeyIsTheEntrys()
    {
        var entry = new RegistryEntry("A", "2025-01-01", "2030-12-31", false, YubiKey, "n");
        var form = EditForm(3, entry);
        Assert.Equal(new EntryFormMode.Edit(3, YubiKey), form.Mode);
        Assert.False(form.IsAdding);
        Assert.Equal("Edit Entry", form.Title);
        Assert.Equal("Save", form.ConfirmTitle);
        Assert.Equal(YubiKey, form.KeyText);
        Assert.Equal("", form.ImportedKey);
        Assert.False(form.NoExpiry);
        Assert.Equal(new DateTime(2025, 1, 1), form.From);
        Assert.Equal(new DateTime(2030, 12, 31), form.To);
        Assert.Equal(new EntryForm("A", "2025-01-01", "2030-12-31", "n", false), form.Form);
        Assert.False(form.ImportCertificateCommand.CanExecute(null));
        Assert.False(form.ImportFromYubiKeyCommand.CanExecute(null));
    }

    [Fact]
    public void EditWithNoExpiryOrAnUnparsableDateStartsAtToday()
    {
        var noExpiry = EditForm(0, new RegistryEntry("A", "2025-01-01", "", true, YubiKey, ""));
        Assert.True(noExpiry.NoExpiry);
        Assert.Equal(new DateTime(2026, 1, 1), noExpiry.To);
        Assert.Equal("", noExpiry.Form.To);
        // A to date while no expiry is set is ignored too.
        var stray = EditForm(0, new RegistryEntry("A", "2025-01-01", "2030-12-31", true, YubiKey, ""));
        Assert.Equal(new DateTime(2026, 1, 1), stray.To);
        var bad = EditForm(0, new RegistryEntry("A", "garbage", "2030-02-30", false, YubiKey, ""));
        Assert.Equal("2026-01-01", bad.Form.From);
        Assert.Equal("2026-01-01", bad.Form.To);
    }

    [Fact]
    public async Task AddSendsTheFormAndTheImportedKey()
    {
        _fake.Respond(RpcMethod.RegistryImportCertificate, new PublicKeyResult(Key));
        var form = AddForm();
        form.Authority = "New Authority";
        form.Note = "Second key";
        _fileOpen.Answer("/OUT/certificate.pem");
        await form.ImportCertificateCommand.ExecuteAsync(null);
        Assert.True(await form.SubmitAsync());
        Assert.Equal("", form.ErrorText);
        Assert.Equal(
            [
                "{\"form\":{\"authority\":\"New Authority\",\"from\":\"2026-01-01\",\"noExpiry\":true,\"note\":\"Second key\",\"to\":\"\"},"
                + "\"publicKey\":\"JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0=\"}",
            ],
            _fake.Params(RpcMethod.RegistryAddEntry));
    }

    [Fact]
    public async Task AddWithoutAKeySendsEmptyAndTheCoresRefusalShows()
    {
        _fake.Fail(RpcMethod.RegistryAddEntry, new RpcException(RpcErrorCode.Failed, "Import a public key first."));
        var form = AddForm();
        Assert.False(await form.SubmitAsync());
        Assert.Equal("Import a public key first.", form.ErrorText);
        Assert.False(form.IsSubmitting);
        Assert.EndsWith("\"publicKey\":\"\"}", _fake.Params(RpcMethod.RegistryAddEntry)[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task EditSendsUpdateEntryWithTheEntrysIndexAndKey()
    {
        _fake.Fail(
            RpcMethod.RegistryUpdateEntry,
            new RpcException(RpcErrorCode.Failed, "The registry changed: this entry's key no longer matches."));
        _fake.Respond(RpcMethod.RegistryUpdateEntry, Empty.Value);
        var form = EditForm(0, new RegistryEntry("A", "2025-01-01", "2030-12-31", false, YubiKey, ""));
        Assert.False(await form.SubmitAsync());
        Assert.Equal("The registry changed: this entry's key no longer matches.", form.ErrorText);
        Assert.Equal(
            [
                "{\"form\":{\"authority\":\"A\",\"from\":\"2025-01-01\",\"noExpiry\":false,\"note\":\"\",\"to\":\"2030-12-31\"},\"index\":0,"
                + "\"publicKey\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\"}",
            ],
            _fake.Params(RpcMethod.RegistryUpdateEntry));
        Assert.True(await form.SubmitAsync());
        Assert.Equal("", form.ErrorText);
        Assert.Equal(0, _fake.Count(RpcMethod.RegistryAddEntry));
    }

    [Fact]
    public async Task ASecondSubmitWhileOneRunsIsIgnored()
    {
        var held = _fake.Hold(RpcMethod.RegistryAddEntry);
        var form = AddForm();
        var first = form.SubmitAsync();
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.RegistryAddEntry) == 1));
        Assert.True(form.IsSubmitting);
        Assert.False(await form.SubmitAsync());
        held.Release(Empty.Value);
        Assert.True(await first);
        Assert.False(form.IsSubmitting);
        Assert.Equal(1, _fake.Count(RpcMethod.RegistryAddEntry));
    }

    [Fact]
    public async Task ImportCertificateAsksForACertificateThenShowsTheKeyOrTheCoresError()
    {
        _fake.Respond(RpcMethod.RegistryImportCertificate, new PublicKeyResult(Key));
        _fake.Fail(RpcMethod.RegistryImportCertificate, new RpcException(RpcErrorCode.Failed, "Not an Ed25519 certificate."));
        var form = AddForm();
        _fileOpen.Answer("/in/a.pem");
        await form.ImportCertificateCommand.ExecuteAsync(null);
        Assert.Equal(Key, form.ImportedKey);
        Assert.Equal(Key, form.KeyText);
        Assert.Equal("", form.ErrorText);
        _fileOpen.Answer("/in/b.crt");
        await form.ImportCertificateCommand.ExecuteAsync(null);
        Assert.Equal("Not an Ed25519 certificate.", form.ErrorText);
        Assert.Equal("No key imported", form.KeyText);
        Assert.Equal("", form.ImportedKey);
        Assert.Equal(["{\"path\":\"/in/a.pem\"}", "{\"path\":\"/in/b.crt\"}"], _fake.Params(RpcMethod.RegistryImportCertificate));
        Assert.Equal(["crt,pem", "crt,pem"], _fileOpen.Requests);
    }

    [Fact]
    public async Task ACancelledCertificateDialogChangesNothing()
    {
        _fake.Respond(RpcMethod.RegistryImportFromYubiKey, new PublicKeyResult(YubiKey));
        var form = AddForm();
        await form.ImportFromYubiKeyCommand.ExecuteAsync(null);
        await form.ImportCertificateCommand.ExecuteAsync(null);
        Assert.Single(_fileOpen.Requests);
        Assert.Equal(0, _fake.Count(RpcMethod.RegistryImportCertificate));
        Assert.Equal(YubiKey, form.ImportedKey);
        Assert.Equal(YubiKey, form.KeyText);
    }

    [Fact]
    public async Task ImportFromYubiKeyShowsTheKeyABusyCardKeepsItAnotherErrorShowsInTheKeyText()
    {
        _fake.Respond(RpcMethod.RegistryImportFromYubiKey, new PublicKeyResult(YubiKey));
        _fake.Fail(RpcMethod.RegistryImportFromYubiKey, new RpcException(RpcErrorCode.Busy, "Another operation is in progress."));
        _fake.Fail(RpcMethod.RegistryImportFromYubiKey, new RpcException(RpcErrorCode.Failed, "No YubiKey detected."));
        var form = AddForm();
        await form.ImportFromYubiKeyCommand.ExecuteAsync(null);
        Assert.Equal(YubiKey, form.ImportedKey);
        Assert.Equal(YubiKey, form.KeyText);
        Assert.Equal("", form.ErrorText);
        await form.ImportFromYubiKeyCommand.ExecuteAsync(null);
        Assert.Equal("The YubiKey is busy with another operation. Try again when it finishes.", form.ErrorText);
        Assert.Equal(YubiKey, form.ImportedKey);
        Assert.Equal(YubiKey, form.KeyText);
        Assert.False(form.IsImporting);
        await form.ImportFromYubiKeyCommand.ExecuteAsync(null);
        Assert.Equal("No YubiKey detected.", form.KeyText);
        Assert.Equal("", form.ImportedKey);
        Assert.Equal("", form.ErrorText);
        Assert.Equal(["{}", "{}", "{}"], _fake.Params(RpcMethod.RegistryImportFromYubiKey));
    }

    [Fact]
    public async Task ASecondYubiKeyImportWhileOneRunsIsIgnoredAndTheCommandIsDisabled()
    {
        var held = _fake.Hold(RpcMethod.RegistryImportFromYubiKey);
        var form = AddForm();
        var changes = 0;
        form.ImportFromYubiKeyCommand.CanExecuteChanged += (_, _) => changes++;
        var first = form.ImportFromYubiKeyCommand.ExecuteAsync(null);
        Assert.True(await Fixtures.Settle(() => _fake.Count(RpcMethod.RegistryImportFromYubiKey) == 1));
        Assert.True(form.IsImporting);
        Assert.False(form.ImportFromYubiKeyCommand.CanExecute(null));
        Assert.True(changes > 0);
        await form.ImportFromYubiKeyCommand.ExecuteAsync(null);
        held.Release(new PublicKeyResult(YubiKey));
        await first;
        Assert.False(form.IsImporting);
        Assert.True(form.ImportFromYubiKeyCommand.CanExecute(null));
        Assert.Equal(YubiKey, form.ImportedKey);
        Assert.Equal(1, _fake.Count(RpcMethod.RegistryImportFromYubiKey));
    }

    [Fact]
    public async Task EditFormsImportNothing()
    {
        var form = EditForm(0, new RegistryEntry("A", "2025-01-01", "", true, YubiKey, ""));
        _fileOpen.Answer("/in/a.pem");
        await form.ImportCertificateCommand.ExecuteAsync(null);
        await form.ImportFromYubiKeyCommand.ExecuteAsync(null);
        Assert.Empty(_fake.Calls);
        Assert.Empty(_fileOpen.Requests);
        Assert.Equal(YubiKey, form.KeyText);
    }
}
