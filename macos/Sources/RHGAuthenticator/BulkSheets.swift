import AppKit
import RHGBridge
import RHGModels
import SwiftUI
import UniformTypeIdentifiers

/// The bulk flow's one sheet: the confirm, progress or results content for
/// the model's phase. Only the model closes it (Escape and clicks outside
/// never do). Errors from a failed run or Export Results CSV… arrive while it
/// is up, so the bulk alert is shown here then (an alert on the covered tab
/// would not show).
@MainActor
struct BulkSheet: View {
    let bulk: BulkModel

    var body: some View {
        content
            .padding(20)
            .frame(minWidth: 520, alignment: .topLeading)
            .interactiveDismissDisabled()
            .alert(bulk.alert, when: bulk.isShowingSheetAlert) { bulk.dismissAlert() }
    }

    @ViewBuilder
    private var content: some View {
        switch bulk.phase {
        case .confirming(let plan):
            BulkConfirmView(bulk: bulk, plan: plan)
        case .running(let run):
            BulkProgressView(bulk: bulk, run: run)
        case .results(let plan, let outcome):
            BulkResultsView(bulk: bulk, plan: plan, outcome: outcome)
        default:
            EmptyView()
        }
    }
}

/// The confirm sheet: the plan's counts, the first names to be signed and
/// the invalid rows that will be skipped; Cancel or Sign.
@MainActor
struct BulkConfirmView: View {
    let bulk: BulkModel
    let plan: BulkLoadResult

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(BulkModel.title)
                .font(.headline)
            Text(plan.countsLine)
                .fixedSize(horizontal: false, vertical: true)
            Text(BulkModel.previewHeading)
            ForEach(plan.previewNames.indices, id: \.self) { index in
                Text(plan.previewNames[index])
                    .padding(.leading, 16)
            }
            if !plan.invalidLines.isEmpty {
                BulkRowsView(heading: BulkModel.invalidToSkipHeading, lines: plan.invalidLines)
            }
            HStack {
                Spacer()
                Button(BulkModel.cancelTitle, role: .cancel) {
                    bulk.cancelConfirm()
                }
                .keyboardShortcut(.cancelAction)
                Button(BulkModel.signTitle) {
                    Task { [bulk] in await bulk.confirm() }
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 8)
        }
    }
}

/// The progress sheet: the bar, the row being signed and Cancel, which stops
/// the run after its current row.
@MainActor
struct BulkProgressView: View {
    let bulk: BulkModel
    let run: BulkModel.Run

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(BulkModel.title)
                .font(.headline)
            ProgressView(value: run.fraction)
            Text(run.label)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button(BulkModel.cancelTitle) {
                    Task { [bulk] in await bulk.cancelRun() }
                }
                .keyboardShortcut(.cancelAction)
                .disabled(!run.isCancelEnabled)
            }
        }
    }
}

/// The results sheet: the summary, why the run stopped, the failed and
/// skipped rows, Export Results CSV… and Close.
@MainActor
struct BulkResultsView: View {
    let bulk: BulkModel
    let plan: BulkLoadResult
    let outcome: BulkRunResult

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(BulkModel.resultsTitle)
                .font(.headline)
            Text(outcome.summaryLine)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            if !outcome.stopMessage.isEmpty {
                Text(outcome.stopMessage)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !outcome.failedLines.isEmpty {
                BulkRowsView(heading: BulkModel.failedHeading, lines: outcome.failedLines)
            }
            if !plan.invalidLines.isEmpty {
                BulkRowsView(heading: BulkModel.invalidSkippedHeading, lines: plan.invalidLines)
            }
            Button(BulkModel.exportTitle) {
                BulkPanels.exportResults(for: bulk)
            }
            Text(BulkModel.regenerateNote)
            HStack {
                Spacer()
                Button(BulkModel.closeTitle) {
                    bulk.closeResults()
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 8)
        }
    }
}

/// A heading over "line N: reason" rows in a fixed-height scroll area. One
/// Text keeps a 500-row file cheap to lay out, as in the Fyne app.
@MainActor
struct BulkRowsView: View {
    let heading: String
    let lines: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(heading)
            ScrollView {
                Text(lines.joined(separator: "\n"))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(4)
            }
            .frame(minWidth: 480, minHeight: 150, maxHeight: 150)
            .background(Color(nsColor: .textBackgroundColor))
            .border(Color(nsColor: .separatorColor))
        }
    }
}

/// Bulk Sign from File…'s file picker and Export Results CSV…'s save panel.
@MainActor
enum BulkPanels {
    /// Starts the bulk flow and asks for the CSV to sign. Does nothing while
    /// a flow is already under way.
    static func chooseFile(for bulk: BulkModel) {
        guard bulk.begin() else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [UTType.commaSeparatedText]
        Task {
            if let url = await FilePanel.run(panel) {
                await bulk.fileChosen(path: url.path)
            } else {
                bulk.pickerCancelled()
            }
        }
    }

    /// Asks where to save the results CSV, then writes it through the core.
    /// The key window is the results sheet, so the panel stacks over it.
    static func exportResults(for bulk: BulkModel) {
        FilePanel.save(name: bulk.suggestedResultsFilename, type: .commaSeparatedText) { path in
            await bulk.exportResults(path: path)
        }
    }
}
