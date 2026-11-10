import AppKit
import RHGModels
import SwiftUI

/// The Registry tab: Fetch from Server, Add Entry, Edit Entry, Submit for
/// Review and the login button, the status line under them, then the
/// registry's table. The entry sheet hangs off it; its alerts and questions
/// show from ReadyView, over any tab.
@MainActor
struct RegistryView: View {
    let registry: RegistryModel
    let login: LoginModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Button {
                    Task { [registry] in await registry.fetchTapped() }
                } label: {
                    Label(RegistryModel.fetchTitle, systemImage: "arrow.down")
                }
                .disabled(!registry.canFetch)
                .help(RegistryModel.fetchTooltip)
                Button {
                    registry.addEntryTapped()
                } label: {
                    Label(RegistryModel.addEntryTitle, systemImage: "plus")
                }
                .disabled(!registry.canAddEntry)
                Button {
                    registry.editEntryTapped()
                } label: {
                    Label(RegistryModel.editEntryTitle, systemImage: "pencil")
                }
                .disabled(!registry.canEditEntry)
                .help(RegistryModel.editEntryTooltip)
                Button {
                    Task { [registry] in await registry.submitForReview() }
                } label: {
                    Label(RegistryModel.submitTitle, systemImage: "paperplane")
                }
                .buttonStyle(.borderedProminent)
                .disabled(registry.isBusy)
                Spacer(minLength: 0)
                LoginButton(login: login)
            }
            // The fetch and submit status: one line, truncated when it is
            // longer than the window is wide, after a spinner while either
            // runs.
            HStack(spacing: 6) {
                if registry.isBusy {
                    ProgressView()
                        .controlSize(.small)
                }
                Text(registry.status)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(registry.status)
            }
            RegistryTable(registry: registry)
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        // Only the model closes the sheet (its Cancel and Add / Save), so
        // the binding ignores writes.
        .sheet(isPresented: .constant(registry.entryForm != nil)) {
            if let form = registry.entryForm {
                EntryFormSheet(form: form, registry: registry)
                    .interactiveDismissDisabled()
            }
        }
    }
}

/// The registry's table, one row per entry, in resizable columns, so a long
/// cell truncates rather than reflowing the table; hovering shows its full
/// text. Double-click or Return edits the selected entry, and ⌘C or the
/// context menu's Copy copies a row as tab-separated cells.
@MainActor
struct RegistryTable: View {
    let registry: RegistryModel

    /// The columns' minimum and ideal widths, in `registry.columns` order,
    /// one per column (`RegistryModel.columnCount`).
    private static let widths: [(min: CGFloat, ideal: CGFloat)] = [
        (40, 40), (100, 200), (80, 100), (80, 100), (80, 150), (100, 200), (150, 450),
    ]

    var body: some View {
        let rows = registry.snapshot.rows.indices.map(RegistryRow.init)
        Table(rows, selection: Binding(get: { registry.selection }, set: { registry.select(row: $0) })) {
            // One column(n) per column: TableColumnForEach needs macOS 14.4.
            column(0)
            column(1)
            column(2)
            column(3)
            column(4)
            column(5)
            column(6)
        }
        .alternatingRowBackgrounds()
        .contextMenu(forSelectionType: Int.self) { ids in
            Button(RegistryModel.editEntryTitle) {
                if let row = ids.first {
                    registry.editEntry(row: row)
                }
            }
            .disabled(!canEditEntry(ids.first))
            Button("Copy") {
                if let row = ids.first {
                    Pasteboard.copy(registry.copyText(row: row))
                }
            }
            .disabled(ids.isEmpty)
        } primaryAction: { ids in
            if let row = ids.first {
                registry.editEntry(row: row)
            }
        }
        .onCopyCommand {
            guard let row = registry.selection else { return [] }
            return [NSItemProvider(object: registry.copyText(row: row) as NSString)]
        }
    }

    /// The `index`th column (of `RegistryModel.columnCount`): its header is
    /// "" until the registry has loaded.
    private func column(_ index: Int) -> TableColumn<RegistryRow, Never, RegistryCell, Text> {
        assert(Self.widths.count == RegistryModel.columnCount)
        let columns = registry.columns
        let title = columns.indices.contains(index) ? columns[index] : ""
        return TableColumn(title) { row in
            RegistryCell(text: registry.cell(row: row.id, column: index))
        }
        .width(min: Self.widths[index].min, ideal: Self.widths[index].ideal)
    }

    private func canEditEntry(_ row: Int?) -> Bool {
        guard let row else { return false }
        return registry.canEditEntry(row: row)
    }
}

/// A registry table row: the index of a row in the registry's snapshot.
struct RegistryRow: Identifiable {
    let id: Int
}

/// A registry table cell: one line, truncated, with its full text on hover.
@MainActor
struct RegistryCell: View {
    let text: String

    var body: some View {
        Text(text)
            .lineLimit(1)
            .truncationMode(.tail)
            .help(text)
    }
}
