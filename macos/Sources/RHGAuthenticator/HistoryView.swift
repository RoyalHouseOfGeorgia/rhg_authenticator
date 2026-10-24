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
    @FocusState private var isSearchFocused: Bool

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
            .keyboardShortcut("r")
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
            .help(HistoryModel.deleteTooltip)
            Button {
                FilePanel.save(name: history.suggestedExportFilename, type: .json) { [history] path in
                    await history.exportIssuanceLog(path: path)
                }
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
            TextField(
                HistoryModel.searchPlaceholder,
                text: Binding(get: { history.query }, set: { history.setQuery($0) })
            )
            .textFieldStyle(.roundedBorder)
            .focused($isSearchFocused)
            .help(HistoryModel.searchTooltip)
            .background {
                // Gives ⌘F, which puts the focus in the search field. Present
                // but invisible: hidden() would drop the keyboard shortcut,
                // and as a background it takes no room.
                Button(HistoryModel.searchTooltip) {
                    isSearchFocused = true
                }
                .keyboardShortcut("f")
                .frame(width: 0, height: 0)
                .opacity(0)
                .focusable(false)
                .accessibilityHidden(true)
            }
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

    /// The selected record's detail, or the muted empty state.
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
            Text(HistoryModel.emptyDetailText)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(16)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
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
