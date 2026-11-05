import RHGModels
import SwiftUI
import UniformTypeIdentifiers

/// The History tab: Refresh, Revoke, Delete Entry…, Export Issuance Log…,
/// Remove Duplicates… and the login button over two panes, the search field,
/// the issuance list and the status lines on the left and the selected
/// record's detail on the right. Its alerts and questions show from
/// ReadyView, over any tab.
@MainActor
struct HistoryView: View {
    let history: HistoryModel
    let login: LoginModel
    /// `AppModel.findRequests`: Find… focuses the search field.
    let findRequests: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            commandRow
            HSplitView {
                listPane
                    .padding(.trailing, 12)
                    .frame(minWidth: 340, maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                detailPane
                    .frame(minWidth: 300, maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var commandRow: some View {
        HStack(spacing: 8) {
            Button {
                Task { [history] in await history.refreshTapped() }
            } label: {
                Label(HistoryModel.refreshTitle, systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent)
            .help(HistoryModel.refreshTooltip)
            Button {
                Task { [history] in await history.revokeTapped() }
            } label: {
                Label(HistoryModel.revokeTitle, systemImage: "xmark.seal")
            }
            .disabled(!history.canRevoke)
            Button {
                Task { [history] in await history.deleteTapped() }
            } label: {
                Label(HistoryModel.deleteTitle, systemImage: "trash")
            }
            .disabled(!history.canDelete)
            .help(history.deleteTooltip)
            Button {
                HistoryExportPanel.present(for: history)
            } label: {
                Label(HistoryModel.exportTitle, systemImage: "square.and.arrow.up")
            }
            Button {
                Task { [history] in await history.removeDuplicatesTapped() }
            } label: {
                Label(HistoryModel.removeDuplicatesTitle, systemImage: "eraser")
            }
            Spacer(minLength: 0)
            LoginButton(login: login)
        }
    }

    /// The search field, the list, then the revocation status and the status
    /// line under it.
    private var listPane: some View {
        VStack(alignment: .leading, spacing: 8) {
            SearchField(history: history, findRequests: findRequests)
                .frame(maxWidth: .infinity)
            HistoryList(history: history)
            if !history.revocationStatus.isEmpty {
                Text(history.revocationStatus)
                    .foregroundStyle(.orange)
                    .lineLimit(1)
            }
            if !history.status.isEmpty {
                Text(history.status)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// The selected record's detail (or why it can't be shown), or the empty
    /// state.
    @ViewBuilder
    private var detailPane: some View {
        if let detail = history.selectedDetail {
            ScrollView {
                Text(detail)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                    .padding(.horizontal, 16)
            }
        } else {
            ContentUnavailableView(HistoryModel.emptyDetailText, systemImage: "doc.text.magnifyingglass")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// Export Issuance Log… (the button and the File menu item): asks where to
/// save, then writes the issuance log there through the core.
@MainActor
enum HistoryExportPanel {
    static func present(for history: HistoryModel) {
        FilePanel.save(name: history.suggestedExportFilename, type: .json) { path in
            await history.exportIssuanceLog(path: path)
        }
    }
}

/// The issuance list, newest first, one summary per row. Every selection
/// change (mouse or arrow keys, a cleared one included) goes to the model,
/// which shows the record's detail; Delete asks to delete the selected
/// record (also Edit → Delete).
@MainActor
struct HistoryList: View {
    let history: HistoryModel

    var body: some View {
        let rows = history.snapshot.rows
        List(selection: Binding(get: { history.selection }, set: { history.select(row: $0) })) {
            ForEach(rows.indices, id: \.self) { index in
                Text(rows[index].summary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(rows[index].summary)
                    .tag(index)
            }
        }
        .onDeleteCommand {
            Task { [history] in await history.deleteTapped() }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
