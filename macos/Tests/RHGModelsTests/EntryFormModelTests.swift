import Foundation
import RHGBridge
import Testing

@testable import RHGModels

@Suite("EntryFormModel")
@MainActor
struct EntryFormModelTests {
    let key = "JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0="
    let yubiKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

    func addForm(_ fake: FakeBridge) -> EntryFormModel {
        EntryFormModel(bridge: fake, clock: { lateNewYearsDay })
    }

    @Test("UI copy matches the Fyne app")
    func copy() {
        #expect([EntryFormModel.addTitle, EntryFormModel.editTitle] == ["Add Entry", "Edit Entry"])
        #expect([EntryFormModel.addConfirmTitle, EntryFormModel.editConfirmTitle, EntryFormModel.cancelTitle] == ["Add", "Save", "Cancel"])
        #expect(
            [
                EntryFormModel.authorityLabel, EntryFormModel.fromLabel, EntryFormModel.toLabel, EntryFormModel.noExpiryLabel,
                EntryFormModel.publicKeyLabel, EntryFormModel.noteLabel,
            ] == ["Authority", "From date", "To date", "No expiry", "Public Key", "Note"])
        #expect([EntryFormModel.authorityPlaceholder, EntryFormModel.notePlaceholder] == ["Authority name", "Optional note"])
        #expect(
            [EntryFormModel.importCertificateTitle, EntryFormModel.importFromYubiKeyTitle]
                == ["Import Certificate", "Import from YubiKey"])
        #expect(EntryFormModel.noKeyText == "No key imported")
        #expect(EntryFormModel.yubiKeyBusyText == "The YubiKey is busy with another operation. Try again when it finishes.")
        #expect(EntryFormModel.certificateExtensions == ["crt", "pem"])
    }

    @Test("add defaults: today in UTC, no expiry, no key")
    func addDefaults() {
        let form = addForm(FakeBridge())
        #expect(form.mode == .add && form.isAdding)
        #expect(form.title == "Add Entry" && form.confirmTitle == "Add")
        #expect(form.authority == "" && form.note == "")
        #expect(form.noExpiry)
        #expect(DisplayDate.ymd(form.from) == "2026-01-01")
        #expect(DisplayDate.ymd(form.to) == "2026-01-01")
        #expect(form.keyText == "No key imported" && form.importedKey == "" && form.errorText == "")
        #expect(form.form == EntryForm(authority: "", from: "2026-01-01", to: "", note: "", noExpiry: true))
    }

    @Test("the form sends text as typed, UTC dates, and to only with an expiry")
    func formValues() throws {
        let form = addForm(FakeBridge())
        form.authority = "  New Authority "
        form.note = "Line 1\nLine 2"
        form.from = try #require(DisplayDate.date(fromYMD: "2026-03-04"))
        form.to = try #require(DisplayDate.date(fromYMD: "2030-12-31"))
        #expect(form.form.to == "")
        #expect(form.displayFrom == "2026-Mar-04" && form.displayTo == "")
        form.noExpiry = false
        #expect(form.displayTo == "2030-Dec-31")
        #expect(
            form.form
                == EntryForm(authority: "  New Authority ", from: "2026-03-04", to: "2030-12-31", note: "Line 1\nLine 2", noExpiry: false))
    }

    @Test("edit: fields from the entry; the key is the entry's")
    func editFields() throws {
        let entry = RegistryEntry(authority: "A", from: "2025-01-01", to: "2030-12-31", noExpiry: false, publicKey: yubiKey, note: "n")
        let form = EntryFormModel(bridge: FakeBridge(), index: 3, entry: entry, clock: { lateNewYearsDay })
        #expect(form.mode == .edit(index: 3, publicKey: yubiKey) && !form.isAdding)
        #expect(form.title == "Edit Entry" && form.confirmTitle == "Save")
        #expect(form.keyText == yubiKey && form.importedKey == "")
        #expect(form.form == EntryForm(authority: "A", from: "2025-01-01", to: "2030-12-31", note: "n", noExpiry: false))
    }

    @Test("edit: no expiry or an unparseable date starts at today")
    func editFallbackDates() {
        let noExpiry = RegistryEntry(authority: "A", from: "2025-01-01", to: "", noExpiry: true, publicKey: yubiKey, note: "")
        let form = EntryFormModel(bridge: FakeBridge(), index: 0, entry: noExpiry, clock: { lateNewYearsDay })
        #expect(form.noExpiry)
        #expect(DisplayDate.ymd(form.to) == "2026-01-01")
        #expect(form.form.to == "")
        let bad = RegistryEntry(authority: "A", from: "garbage", to: "2030-02-30", noExpiry: false, publicKey: yubiKey, note: "")
        let badForm = EntryFormModel(bridge: FakeBridge(), index: 0, entry: bad, clock: { lateNewYearsDay })
        #expect(badForm.form.from == "2026-01-01" && badForm.form.to == "2026-01-01")
    }

    @Test("add: the form and the imported key go to registry.addEntry")
    func addSubmit() async {
        let fake = FakeBridge()
        fake.respond(.registryImportCertificate, PublicKeyResult(publicKey: key))
        let form = addForm(fake)
        form.authority = "New Authority"
        form.note = "Second key"
        await form.importCertificate(path: "/OUT/certificate.pem")
        #expect(await form.submit())
        #expect(form.errorText == "")
        #expect(
            fake.params(.registryAddEntry) == [
                #"{"form":{"authority":"New Authority","from":"2026-01-01","noExpiry":true,"note":"Second key","to":""},"#
                    + #""publicKey":"JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0="}"#
            ])
    }

    @Test("add without a key sends \"\"; the core's refusal shows and the sheet stays")
    func addRefused() async {
        let fake = FakeBridge()
        fake.fail(.registryAddEntry, RPCError(code: .failed, message: "Import a public key first."))
        let form = addForm(fake)
        #expect(await form.submit() == false)
        #expect(form.errorText == "Import a public key first.")
        #expect(fake.params(.registryAddEntry).first?.hasSuffix(#""publicKey":""}"#) == true)
    }

    @Test("edit: registry.updateEntry with the entry's index and key; a key mismatch shows and the sheet stays")
    func editSubmit() async {
        let fake = FakeBridge()
        fake.fail(.registryUpdateEntry, RPCError(code: .failed, message: "The registry changed: this entry's key no longer matches."))
        fake.respond(.registryUpdateEntry, Empty())
        let entry = RegistryEntry(authority: "A", from: "2025-01-01", to: "2030-12-31", noExpiry: false, publicKey: yubiKey, note: "")
        let form = EntryFormModel(bridge: fake, index: 0, entry: entry, clock: { lateNewYearsDay })
        #expect(await form.submit() == false)
        #expect(form.errorText == "The registry changed: this entry's key no longer matches.")
        #expect(
            fake.params(.registryUpdateEntry) == [
                #"{"form":{"authority":"A","from":"2025-01-01","noExpiry":false,"note":"","to":"2030-12-31"},"index":0,"#
                    + #""publicKey":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}"#
            ])
        #expect(await form.submit())
        #expect(form.errorText == "")
    }

    @Test("a second submit while one runs is ignored")
    func submitOnce() async {
        let fake = FakeBridge()
        let held = fake.hold(.registryAddEntry)
        let form = addForm(fake)
        let first = Task { await form.submit() }
        #expect(await settle { fake.count(.registryAddEntry) == 1 })
        #expect(form.isSubmitting)
        #expect(await form.submit() == false)
        held.release(Empty())
        #expect(await first.value)
        #expect(!form.isSubmitting)
        #expect(fake.count(.registryAddEntry) == 1)
    }

    @Test("Import Certificate: the key, or the core's error with the key cleared")
    func importCertificate() async {
        let fake = FakeBridge()
        fake.respond(.registryImportCertificate, PublicKeyResult(publicKey: key))
        fake.fail(.registryImportCertificate, RPCError(code: .failed, message: "Not an Ed25519 certificate."))
        let form = addForm(fake)
        await form.importCertificate(path: "/in/a.pem")
        #expect(form.importedKey == key && form.keyText == key && form.errorText == "")
        await form.importCertificate(path: "/in/b.crt")
        #expect(form.errorText == "Not an Ed25519 certificate.")
        #expect(form.keyText == "No key imported" && form.importedKey == "")
        #expect(fake.params(.registryImportCertificate) == [#"{"path":"/in/a.pem"}"#, #"{"path":"/in/b.crt"}"#])
    }

    @Test("Import from YubiKey: the key; a busy card keeps it; another error shows in the key label")
    func importFromYubiKey() async {
        let fake = FakeBridge()
        fake.respond(.registryImportFromYubiKey, PublicKeyResult(publicKey: yubiKey))
        fake.fail(.registryImportFromYubiKey, RPCError(code: .busy, message: "Another operation is in progress."))
        fake.fail(.registryImportFromYubiKey, RPCError(code: .failed, message: "No YubiKey detected."))
        let form = addForm(fake)
        await form.importFromYubiKey()
        #expect(form.importedKey == yubiKey && form.keyText == yubiKey && form.errorText == "")
        await form.importFromYubiKey()
        #expect(form.errorText == "The YubiKey is busy with another operation. Try again when it finishes.")
        #expect(form.importedKey == yubiKey && form.keyText == yubiKey)
        await form.importFromYubiKey()
        #expect(form.keyText == "No YubiKey detected.")
        #expect(form.importedKey == "" && form.errorText == "")
        #expect(fake.params(.registryImportFromYubiKey) == ["{}", "{}", "{}"])
    }

    @Test("a second YubiKey import while one runs is ignored")
    func importOnce() async {
        let fake = FakeBridge()
        let held = fake.hold(.registryImportFromYubiKey)
        let form = addForm(fake)
        let first = Task { await form.importFromYubiKey() }
        #expect(await settle { fake.count(.registryImportFromYubiKey) == 1 })
        #expect(form.isImporting)
        await form.importFromYubiKey()
        held.release(PublicKeyResult(publicKey: yubiKey))
        await first.value
        #expect(!form.isImporting)
        #expect(form.importedKey == yubiKey)
        #expect(fake.count(.registryImportFromYubiKey) == 1)
    }

    @Test("edit forms import nothing")
    func editImportsNothing() async {
        let fake = FakeBridge()
        let entry = RegistryEntry(authority: "A", from: "2025-01-01", to: "", noExpiry: true, publicKey: yubiKey, note: "")
        let form = EntryFormModel(bridge: fake, index: 0, entry: entry)
        await form.importCertificate(path: "/in/a.pem")
        await form.importFromYubiKey()
        #expect(fake.calls.isEmpty)
        #expect(form.keyText == yubiKey)
    }

    @Test(
        "YYYY-MM-DD parses to midnight UTC; anything else is nil",
        arguments: [
            ("2026-01-02", "2026-01-02" as String?), ("2024-02-29", "2024-02-29"), ("2026-02-29", nil), ("2026-13-01", nil),
            ("2026-1-02", nil), ("26-01-02", nil), ("2026-01-02T00:00", nil), ("", nil), ("２０２６-01-02", nil), ("2026/01/02", nil),
        ])
    func parseYMD(_ text: String, _ expected: String?) {
        let date = DisplayDate.date(fromYMD: text)
        #expect(date.map { DisplayDate.ymd($0) } == expected)
        if let date {
            #expect(date.timeIntervalSince1970.truncatingRemainder(dividingBy: 86400) == 0)
        }
    }
}
