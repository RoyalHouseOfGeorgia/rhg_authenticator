import AppKit
import RHGBridge
import RHGModels
import SwiftUI
import UniformTypeIdentifiers

/// The Sign tab: Sign Credential and Bulk Sign from File… over two panes,
/// the credential form with the status line on the left and the signed
/// credential on the right. The bulk flow's sheet and every alert show
/// from ReadyView.
@MainActor
struct SignView: View {
    @Bindable var sign: SignModel
    let bulk: BulkModel
    /// A signing or a bulk flow is under way (`AppModel.isSigningBusy`).
    let isSigningBusy: Bool
    /// Save SVG / Save PNG are enabled (`AppModel.canSaveQR`).
    let canSaveQR: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Button {
                    Task { [sign] in await sign.sign() }
                } label: {
                    Label(SignModel.signTitle, systemImage: "signature")
                }
                .buttonStyle(.borderedProminent)
                .disabled(isSigningBusy)
                Button {
                    BulkPanels.chooseFile(for: bulk)
                } label: {
                    Label(BulkModel.bulkSignTitle, systemImage: "doc.text")
                }
                .disabled(isSigningBusy)
                Spacer(minLength: 0)
            }
            HSplitView {
                inputPane
                    .frame(minWidth: 340, maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                resultPane
                    .frame(minWidth: 300, maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    /// The form, then the status line (a spinner before it while signing)
    /// and Report Issue under it.
    private var inputPane: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                form
                HStack(alignment: .top, spacing: 6) {
                    if sign.isBusy {
                        ProgressView()
                            .controlSize(.small)
                    }
                    Text(sign.status)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let reportTitle = sign.report.buttonTitle {
                    Button {
                        Task { [sign] in await sign.reportIssue() }
                    } label: {
                        Label(reportTitle, systemImage: "exclamationmark.bubble")
                    }
                    .disabled(!sign.report.isButtonEnabled)
                }
            }
            .padding(.trailing, 12)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
    }

    /// Labels beside their fields, right-aligned, as Mac forms have them.
    private var form: some View {
        Form {
            TextField(text: $sign.recipient, prompt: Text(SignModel.recipientPlaceholder)) {
                Text(SignModel.recipientLabel)
            }
            .textFieldStyle(.roundedBorder)

            // A menu picker, at its natural width: its widest title's.
            Picker(SignModel.honorLabel, selection: $sign.honor) {
                Text(SignModel.honorPlaceholder).tag("")
                ForEach(sign.honors, id: \.self) { honor in
                    Text(honor).tag(honor)
                }
            }

            TextField(text: $sign.detail, prompt: Text(SignModel.detailPlaceholder), axis: .vertical) {
                Text(SignModel.detailLabel)
            }
            .textFieldStyle(.roundedBorder)
            .lineLimit(3...6)

            // The signed date is the UTC calendar date (SignModel.dateString).
            LabeledContent(SignModel.dateLabel) {
                DatePopoverField(title: SignModel.dateLabel, date: $sign.date, text: sign.displayDate)
            }
        }
        .formStyle(.columns)
    }

    /// The signed credential, or the empty state until there is one.
    @ViewBuilder
    private var resultPane: some View {
        if let result = sign.result {
            ScrollView {
                ResultView(sign: sign, result: result, canSaveQR: canSaveQR)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 16)
                    .frame(maxWidth: .infinity)
            }
        } else {
            ContentUnavailableView(SignModel.noResultText, systemImage: "checkmark.seal")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// The signed credential: the fields as signed (not the form, which may have
/// changed meanwhile), its QR code, the print advisory and the save and copy
/// buttons. The save buttons are enabled as File's Save QR Code items are
/// (`AppModel.canSaveQR`).
@MainActor
struct ResultView: View {
    let sign: SignModel
    let result: SignResult
    let canSaveQR: Bool

    var body: some View {
        VStack(spacing: 12) {
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
            HStack(spacing: 8) {
                Button {
                    QRSavePanel.present(for: sign, format: .svg)
                } label: {
                    Label(SignModel.saveSVGTitle, systemImage: "square.and.arrow.down")
                }
                .disabled(!canSaveQR)
                Button {
                    QRSavePanel.present(for: sign, format: .png)
                } label: {
                    Label(SignModel.savePNGTitle, systemImage: "square.and.arrow.down")
                }
                .disabled(!canSaveQR)
                Button {
                    Pasteboard.copy(result.url)
                } label: {
                    Label(SignModel.copyURLTitle, systemImage: "doc.on.doc")
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

/// Save SVG / Save PNG and File's Save QR Code items: asks where to save,
/// then writes the file through the core.
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
