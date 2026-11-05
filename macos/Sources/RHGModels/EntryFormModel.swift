import Foundation
import Observation
import RHGBridge

/// The Add Entry / Edit Entry sheet. Fields go to the core as typed; it
/// validates them and reads the imported keys.
@MainActor
@Observable
public final class EntryFormModel {
    nonisolated public static let addTitle = "Add Entry"
    nonisolated public static let editTitle = "Edit Entry"
    nonisolated public static let addConfirmTitle = "Add"
    nonisolated public static let editConfirmTitle = "Save"
    nonisolated public static let cancelTitle = "Cancel"
    nonisolated public static let authorityLabel = "Authority"
    nonisolated public static let authorityPlaceholder = "Authority name"
    nonisolated public static let fromLabel = "From Date"
    nonisolated public static let toLabel = "To Date"
    nonisolated public static let noExpiryLabel = "No expiry"
    nonisolated public static let publicKeyLabel = "Public Key"
    nonisolated public static let noteLabel = "Note"
    nonisolated public static let notePlaceholder = "Optional note"
    nonisolated public static let importCertificateTitle = "Import Certificate\u{2026}"
    nonisolated public static let importFromYubiKeyTitle = "Import from YubiKey"
    nonisolated public static let noKeyText = "No key imported"
    /// Import from YubiKey found the card busy with a signing or check.
    nonisolated public static let yubiKeyBusyText =
        "The YubiKey is busy with another operation. Try again when it finishes."
    /// The certificate file types Import Certificate offers.
    nonisolated public static let certificateExtensions = ["crt", "pem"]

    public enum Mode: Sendable, Equatable {
        /// A new entry; its key is imported on the sheet.
        case add
        /// The entry at `index` of the snapshot, whose key is `publicKey`.
        case edit(index: Int, publicKey: String)
    }

    public let mode: Mode
    public var authority: String
    /// The date pickers show and edit dates in UTC.
    public var from: Date
    /// Used only without `noExpiry`.
    public var to: Date
    public var noExpiry: Bool
    public var note: String
    /// The imported public key (add only); "" while none is.
    public private(set) var importedKey = ""
    /// The Public Key label: the imported key, "No key imported" or an
    /// import error (add); the entry's key, read-only (edit).
    public private(set) var keyText: String
    /// The error line; "" when there is none.
    public private(set) var errorText = ""
    /// Import from YubiKey is running.
    public private(set) var isImporting = false
    /// The entry is being added or saved.
    public private(set) var isSubmitting = false

    @ObservationIgnored private let bridge: any Bridge

    /// An Add Entry form: from today (UTC), no expiry, no key.
    public init(bridge: any Bridge, clock: () -> Date = Date.init) {
        self.bridge = bridge
        let today = clock()
        mode = .add
        authority = ""
        from = today
        to = today
        noExpiry = true
        note = ""
        keyText = Self.noKeyText
    }

    /// An Edit Entry form for `entry`, the entry at `index` of the snapshot.
    /// A date that does not parse (or no expiry) starts at today (UTC).
    public init(bridge: any Bridge, index: Int, entry: RegistryEntry, clock: () -> Date = Date.init) {
        self.bridge = bridge
        let today = clock()
        mode = .edit(index: index, publicKey: entry.publicKey)
        authority = entry.authority
        from = DisplayDate.date(fromYMD: entry.from) ?? today
        to = entry.noExpiry ? today : DisplayDate.date(fromYMD: entry.to) ?? today
        noExpiry = entry.noExpiry
        note = entry.note
        keyText = entry.publicKey
    }

    public var isAdding: Bool { mode == .add }

    /// The sheet's title.
    public var title: String { isAdding ? Self.addTitle : Self.editTitle }

    /// The confirm button's title.
    public var confirmTitle: String { isAdding ? Self.addConfirmTitle : Self.editConfirmTitle }

    /// `from` as YYYY-Mon-DD, shown beside its picker.
    public var displayFrom: String { DisplayDate.format(DisplayDate.ymd(from)) }

    /// `to` as YYYY-Mon-DD, shown beside its picker; "" with no expiry.
    public var displayTo: String { noExpiry ? "" : DisplayDate.format(DisplayDate.ymd(to)) }

    /// The form as sent: text as typed, dates as UTC YYYY-MM-DD, `to` ""
    /// with no expiry.
    public var form: EntryForm {
        EntryForm(
            authority: authority, from: DisplayDate.ymd(from), to: noExpiry ? "" : DisplayDate.ymd(to), note: note,
            noExpiry: noExpiry)
    }

    /// Import Certificate: reads the key of the certificate at `path`, the
    /// file the operator chose (registry.importCertificate).
    public func importCertificate(path: String) async {
        guard isAdding else { return }
        do {
            imported(try await bridge.importCertificate(path: path))
        } catch {
            errorText = error.message
            keyText = Self.noKeyText
            importedKey = ""
        }
    }

    /// Import from YubiKey (registry.importFromYubiKey). A busy card keeps
    /// the current key; any other failure shows in the key label. Ignored
    /// while an import is running.
    public func importFromYubiKey() async {
        guard isAdding, !isImporting else { return }
        isImporting = true
        defer { isImporting = false }
        do {
            imported(try await bridge.importFromYubiKey())
        } catch {
            if error.code == .busy {
                errorText = Self.yubiKeyBusyText
                return
            }
            keyText = error.message
            importedKey = ""
            errorText = ""
        }
    }

    private func imported(_ key: String) {
        importedKey = key
        keyText = key
        errorText = ""
    }

    /// Add / Save (registry.addEntry or registry.updateEntry). Returns
    /// whether the core accepted the entry; on failure the sheet stays open
    /// with the core's message. Ignored (false) while a submit is running.
    public func submit() async -> Bool {
        guard !isSubmitting else { return false }
        isSubmitting = true
        defer { isSubmitting = false }
        do {
            switch mode {
            case .add:
                try await bridge.addEntry(form: form, publicKey: importedKey)
            case .edit(let index, let publicKey):
                try await bridge.updateEntry(index: index, publicKey: publicKey, form: form)
            }
        } catch {
            errorText = error.message
            return false
        }
        errorText = ""
        return true
    }
}
