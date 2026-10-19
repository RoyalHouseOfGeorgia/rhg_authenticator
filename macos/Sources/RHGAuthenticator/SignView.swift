import AppKit
import RHGBridge
import RHGModels
import SwiftUI
import UniformTypeIdentifiers

/// The Sign tab, laid out as the Fyne app's: the credential form, Sign
/// Credential, the status line and the signed credential's QR code.
@MainActor
struct SignView: View {
    @Bindable var sign: SignModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                form
                Button(SignModel.signTitle) {
                    Task { [sign] in await sign.sign() }
                }
                .disabled(sign.isBusy)
                .padding(.top, 8)
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
        }
        .alert(sign.alert?.title ?? "", isPresented: $sign.isShowingAlert) {
            Button("OK") {}
        } message: {
            Text(sign.alert?.message ?? "")
        }
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
                .environment(\.timeZone, DisplayDate.utcCalendar.timeZone)
                .environment(\.calendar, DisplayDate.utcCalendar)
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
        let panel = NSSavePanel()
        panel.nameFieldStringValue = sign.suggestedFilename(for: format)
        panel.allowedContentTypes = [format == .svg ? UTType.svg : UTType.png]
        panel.canCreateDirectories = true
        let window = NSApp.keyWindow ?? NSApp.mainWindow
        Task {
            let response: NSApplication.ModalResponse
            if let window {
                response = await panel.beginSheetModal(for: window)
            } else {
                response = await panel.begin()
            }
            guard response == .OK, let url = panel.url else { return }
            await sign.saveQR(format: format, path: url.path)
        }
    }
}

extension SignModel {
    /// The alert's presentation; dismissing it clears the alert.
    var isShowingAlert: Bool {
        get { alert != nil }
        set {
            if !newValue {
                alert = nil
            }
        }
    }
}
