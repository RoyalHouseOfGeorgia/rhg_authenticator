import RHGModels
import SwiftUI
import UniformTypeIdentifiers

/// The History tab, laid out as the Fyne app's: the search field, then
/// Refresh, Connect to GitHub (without a usable session), Revoke, Export
/// Issuance Log…, Remove Duplicates… and the revocation status, over the
/// issuance list. Selecting a row shows its record. Its alerts and questions
/// show from ReadyView, over any tab.
@MainActor
struct HistoryView: View {
    let history: HistoryModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                TextField(
                    HistoryModel.searchPlaceholder,
                    text: Binding(get: { history.query }, set: { history.setQuery($0) })
                )
                .textFieldStyle(.roundedBorder)
                Button(HistoryModel.refreshTitle) {
                    Task { [history] in await history.refreshTapped() }
                }
                if history.showsConnectButton {
                    Button(HistoryModel.connectTitle) {
                        Task { [history] in await history.connectTapped() }
                    }
                }
                Button(HistoryModel.revokeTitle) {
                    Task { [history] in await history.revokeTapped() }
                }
                .disabled(!history.canRevoke)
                Button(HistoryModel.exportTitle) {
                    FilePanel.save(name: history.suggestedExportFilename, type: .json) { [history] path in
                        await history.exportIssuanceLog(path: path)
                    }
                }
                Button(HistoryModel.removeDuplicatesTitle) {
                    Task { [history] in await history.removeDuplicatesTapped() }
                }
                if !history.revocationStatus.isEmpty {
                    Text(history.revocationStatus)
                        .foregroundStyle(.orange)
                        .lineLimit(1)
                }
            }
            HistoryList(history: history)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

/// The issuance list, newest first, one summary per row. Selecting a row
/// hands it to the model, which shows its record.
@MainActor
struct HistoryList: View {
    let history: HistoryModel

    var body: some View {
        let rows = history.snapshot.rows
        List(
            selection: Binding(
                get: { history.selection },
                set: { row in
                    guard let row else { return }
                    Task { [history] in await history.select(row: row) }
                })
        ) {
            ForEach(rows.indices, id: \.self) { index in
                Text(rows[index].summary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(rows[index].summary)
                    .tag(index)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
