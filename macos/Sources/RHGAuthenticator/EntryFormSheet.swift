import AppKit
import RHGModels
import SwiftUI

/// The Add Entry / Edit Entry sheet, laid out as the Fyne app's dialog:
/// authority, the from and to dates, No expiry, the public key (imported
/// from a certificate or the YubiKey when adding), the error line and the
/// note, then Cancel and Add / Save. The core validates on Add / Save; the
/// sheet stays up with its message until it accepts the entry.
@MainActor
struct EntryFormSheet: View {
    @Bindable var form: EntryFormModel
    let registry: RegistryModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // A sheet shows no title bar, so the title heads the content.
            Text(form.title)
                .font(.headline)

            Text(EntryFormModel.authorityLabel)
            TextField(text: $form.authority, prompt: Text(EntryFormModel.authorityPlaceholder)) {
                Text(EntryFormModel.authorityLabel)
            }
            .labelsHidden()
            .textFieldStyle(.roundedBorder)

            // The entry's dates are UTC calendar dates, so the pickers show
            // and edit dates in UTC too.
            Text(EntryFormModel.fromLabel)
            HStack {
                DatePicker(EntryFormModel.fromLabel, selection: $form.from, displayedComponents: .date)
                    .labelsHidden()
                    .utcCalendar()
                Text(form.displayFrom)
                    .monospacedDigit()
            }
            Text(EntryFormModel.toLabel)
            HStack {
                DatePicker(EntryFormModel.toLabel, selection: $form.to, displayedComponents: .date)
                    .labelsHidden()
                    .utcCalendar()
                    .disabled(form.noExpiry)
                Text(form.displayTo)
                    .monospacedDigit()
            }
            Toggle(EntryFormModel.noExpiryLabel, isOn: $form.noExpiry)
                .toggleStyle(.checkbox)

            Text(EntryFormModel.publicKeyLabel)
            if form.isAdding {
                HStack {
                    Button(EntryFormModel.importCertificateTitle) {
                        FilePanel.open(extensions: EntryFormModel.certificateExtensions) { [form] path in
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
            if !form.errorText.isEmpty {
                Text(form.errorText)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text(EntryFormModel.noteLabel)
            TextField(text: $form.note, prompt: Text(EntryFormModel.notePlaceholder), axis: .vertical) {
                Text(EntryFormModel.noteLabel)
            }
            .labelsHidden()
            .textFieldStyle(.roundedBorder)
            .lineLimit(3...6)

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
                .disabled(form.isSubmitting)
            }
            .padding(.top, 8)
        }
        .padding(20)
        .frame(width: 460, alignment: .topLeading)
    }
}
