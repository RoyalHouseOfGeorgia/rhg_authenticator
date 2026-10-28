import AppKit
import RHGModels
import SwiftUI

/// The Add Entry / Edit Entry sheet: a form with labels beside their fields,
/// as Mac forms have them (authority, the from and to dates, No expiry, the
/// public key, imported from a certificate or the YubiKey when adding, the
/// error line and the note), then Cancel and Add / Save. The core validates
/// on Add / Save; the sheet stays up with its message until it accepts the
/// entry.
@MainActor
struct EntryFormSheet: View {
    @Bindable var form: EntryFormModel
    let registry: RegistryModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // A sheet shows no title bar, so the title heads the content.
            Text(form.title)
                .font(.headline)

            Form {
                TextField(text: $form.authority, prompt: Text(EntryFormModel.authorityPlaceholder)) {
                    Text(EntryFormModel.authorityLabel)
                }
                .textFieldStyle(.roundedBorder)

                // The entry's dates are UTC calendar dates; each shows once,
                // as YYYY-Mon-DD, and its button opens the picker.
                LabeledContent(EntryFormModel.fromLabel) {
                    DatePopoverField(title: EntryFormModel.fromLabel, date: $form.from, text: form.displayFrom)
                }
                // Blank and disabled while No expiry is checked.
                LabeledContent(EntryFormModel.toLabel) {
                    DatePopoverField(title: EntryFormModel.toLabel, date: $form.to, text: form.displayTo)
                        .disabled(form.noExpiry)
                }
                Toggle(EntryFormModel.noExpiryLabel, isOn: $form.noExpiry)
                    .toggleStyle(.checkbox)

                LabeledContent(EntryFormModel.publicKeyLabel) {
                    VStack(alignment: .leading, spacing: 6) {
                        if form.isAdding {
                            HStack {
                                Button(EntryFormModel.importCertificateTitle) {
                                    FilePanel.open(extensions: EntryFormModel.certificateExtensions) {
                                        [form] path in
                                        await form.importCertificate(path: path)
                                    }
                                }
                                Button(EntryFormModel.importFromYubiKeyTitle) {
                                    Task { [form] in await form.importFromYubiKey() }
                                }
                                .disabled(form.isImporting)
                            }
                        }
                        Text(form.keyText)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if !form.errorText.isEmpty {
                    Text(form.errorText)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }

                TextField(text: $form.note, prompt: Text(EntryFormModel.notePlaceholder), axis: .vertical) {
                    Text(EntryFormModel.noteLabel)
                }
                .textFieldStyle(.roundedBorder)
                .lineLimit(3...6)
            }
            .formStyle(.columns)

            HStack {
                Spacer()
                Button(EntryFormModel.cancelTitle, role: .cancel) {
                    registry.cancelEntryForm()
                }
                .keyboardShortcut(.cancelAction)
                Button(form.confirmTitle) {
                    Task { [registry] in await registry.submitEntryForm() }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(form.isSubmitting)
            }
            .padding(.top, 8)
        }
        .padding(20)
        .frame(width: 520, alignment: .topLeading)
    }
}
