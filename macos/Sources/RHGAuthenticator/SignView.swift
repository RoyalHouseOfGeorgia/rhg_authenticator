import AppKit
import RHGBridge
import RHGModels
import SwiftUI
import UniformTypeIdentifiers

/// The Sign tab, laid out as the Fyne app's: the credential form, Sign
/// Credential, Bulk Sign from File…, the status line and the signed
/// credential's QR code. The bulk flow's sheets and alert hang off it too.
@MainActor
struct SignView: View {
    @Bindable var sign: SignModel
    let bulk: BulkModel
    /// A signing or a bulk flow is under way (`AppModel.isSigningBusy`).
    let isSigningBusy: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                form
                Button(SignModel.signTitle) {
                    Task { [sign] in await sign.sign() }
                }
                .disabled(isSigningBusy)
                .padding(.top, 8)
                Button(BulkModel.bulkSignTitle) {
                    BulkPanels.chooseFile(for: bulk)
                }
                .disabled(isSigningBusy)
                Text(sign.status)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                if let reportTitle = sign.report.buttonTitle {
                    Button(reportTitle) {
                        Task { [sign] in await sign.reportIssue() }
                    }
                    .disabled(!sign.report.isButtonEnabled)
                }
                if let result = sign.result {
                    ResultView(sign: sign, result: result)
                        .frame(maxWidth: .infinity)
                }
            }
            .padding()
            // On the VStack, not the ScrollView, so it does not share a view
            // with the signing alert. Shown only while no bulk sheet is up;
            // BulkSheet shows the same alert over itself otherwise.
            .alert(bulk.alert, when: bulk.isShowingTabAlert) { bulk.dismissAlert() }
            // Only the model closes the sheet, so the binding ignores writes.
            .sheet(isPresented: .constant(bulk.isShowingSheet)) {
                BulkSheet(bulk: bulk)
            }
        }
        .alert(sign.alert) { sign.alert = nil }
    }

    @ViewBuilder
    private var form: some View {
        Text(SignModel.recipientLabel)
        TextField(text: $sign.recipient, prompt: Text(SignModel.recipientPlaceholder)) {
            Text(SignModel.recipientLabel)
        }
        .labelsHidden()
        .textFieldStyle(.roundedBorder)

        Text(SignModel.honorLabel)
        Picker(SignModel.honorLabel, selection: $sign.honor) {
            Text(SignModel.honorPlaceholder).tag("")
            ForEach(sign.honors, id: \.self) { honor in
                Text(honor).tag(honor)
            }
        }
        .labelsHidden()

        Text(SignModel.detailLabel)
        TextField(text: $sign.detail, prompt: Text(SignModel.detailPlaceholder), axis: .vertical) {
            Text(SignModel.detailLabel)
        }
        .labelsHidden()
        .textFieldStyle(.roundedBorder)
        .lineLimit(3...6)

        // The signed date is the UTC calendar date (SignModel.dateString), so
        // the picker shows and edits dates in UTC too.
        Text(SignModel.dateLabel)
        HStack {
            DatePicker(SignModel.dateLabel, selection: $sign.date, displayedComponents: .date)
                .labelsHidden()
                .utcCalendar()
            Text(sign.displayDate)
                .monospacedDigit()
        }
    }
}

/// The signed credential: the fields as signed (not the form, which may have
/// changed meanwhile), its QR code, the print advisory and the save and copy
/// buttons.
@MainActor
struct ResultView: View {
    let sign: SignModel
    let result: SignResult

    var body: some View {
        VStack(spacing: 8) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
                field(SignModel.recipientLabel, result.recipient)
                field(SignModel.honorLabel, result.honor)
                field(SignModel.detailLabel, result.detail)
                field(SignModel.dateLabel, DisplayDate.format(result.date))
            }
            .textSelection(.enabled)
            if let image = NSImage(data: result.pngPreview) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 256, height: 256)
            }
            Text(SignModel.printAdvisory)
            HStack {
                Button(SignModel.saveSVGTitle) { QRSavePanel.present(for: sign, format: .svg) }
                Button(SignModel.savePNGTitle) { QRSavePanel.present(for: sign, format: .png) }
                Button(SignModel.copyURLTitle) {
                    let pasteboard = NSPasteboard.general
                    _ = pasteboard.clearContents()
                    _ = pasteboard.setString(result.url, forType: .string)
                }
            }
        }
    }

    private func field(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            Text(value)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Save SVG / Save PNG: asks where to save, then writes the file through
/// the core.
@MainActor
enum QRSavePanel {
    static func present(for sign: SignModel, format: QRFormat) {
        let type = format == .svg ? UTType.svg : UTType.png
        FilePanel.save(name: sign.suggestedFilename(for: format), type: type) { path in
            await sign.saveQR(format: format, path: path)
        }
    }
}

extension View {
    /// Shows and edits dates in the UTC calendar: the core signs and stores
    /// UTC calendar dates, so every date picker goes through this.
    func utcCalendar() -> some View {
        environment(\.timeZone, DisplayDate.utcCalendar.timeZone)
            .environment(\.calendar, DisplayDate.utcCalendar)
    }
}
