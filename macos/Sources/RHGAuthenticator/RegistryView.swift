import AppKit
import RHGModels
import SwiftUI

/// The Registry tab, laid out as the Fyne app's: Fetch from Server, Submit
/// for Review, the login button and the status line over the registry's
/// table, then Add Entry and Edit Entry. The entry sheet hangs off it; its
/// alerts and questions show from ReadyView, over any tab.
@MainActor
struct RegistryView: View {
    let registry: RegistryModel
    let login: LoginModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Button(RegistryModel.fetchTitle) {
                    Task { [registry] in await registry.fetchTapped() }
                }
                Button(RegistryModel.submitTitle) {
                    Task { [registry] in await registry.submitForReview() }
                }
                Spacer()
                Button(login.buttonTitle) {
                    Task { [login] in await login.buttonTapped() }
                }
                .disabled(login.isLoggingIn)
                // A selected cell's full text lands here: one line, truncated
                // when it would crowd the buttons.
                Text(registry.status)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(registry.status)
            }
            RegistryTable(registry: registry)
            HStack {
                Button(RegistryModel.addEntryTitle) {
                    registry.addEntryTapped()
                }
                Button(RegistryModel.editEntryTitle) {
                    registry.editEntryTapped()
                }
            }
        }
        .padding()
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

/// The registry's table: a bold header row that stays put while the rows
/// scroll under it, then one row per entry, in fixed-width columns as in the
/// Fyne app. Clicking a cell selects it (its text goes to the status line);
/// hovering shows its full text.
@MainActor
struct RegistryTable: View {
    let registry: RegistryModel

    /// The Fyne app's column widths, in `registry.columns` order.
    private static let columnWidths: [CGFloat] = [40, 200, 100, 100, 150, 200, 450]
    /// The width of any column past those.
    private static let defaultColumnWidth: CGFloat = 150

    var body: some View {
        let columns = registry.columns
        let rows = registry.snapshot.rows
        ScrollView([.horizontal, .vertical]) {
            LazyVStack(alignment: .leading, spacing: 0, pinnedViews: [.sectionHeaders]) {
                Section {
                    ForEach(rows.indices, id: \.self) { row in
                        rowView(row, cells: rows[row], columnCount: columns.count)
                    }
                } header: {
                    HStack(spacing: 0) {
                        ForEach(columns.indices, id: \.self) { column in
                            cell(columns[column], column: column).bold()
                        }
                    }
                    .background(Color(nsColor: .windowBackgroundColor))
                    .overlay(alignment: .bottom) { Divider() }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .textBackgroundColor))
        .border(Color(nsColor: .separatorColor))
    }

    /// One entry's row, padded with empty cells to the header's columns.
    private func rowView(_ row: Int, cells: [String], columnCount: Int) -> some View {
        let selection = registry.selection
        return HStack(spacing: 0) {
            ForEach(0..<columnCount, id: \.self) { column in
                let text = cells.indices.contains(column) ? cells[column] : ""
                let isSelected = selection == RegistryModel.Cell(row: row, column: column)
                cell(text, column: column)
                    .background(isSelected ? Color.accentColor.opacity(0.3) : Color.clear)
                    .contentShape(Rectangle())
                    .onTapGesture { registry.select(row: row, column: column) }
                    .help(text)
            }
        }
        .background(selection?.row == row ? Color.accentColor.opacity(0.15) : Color.clear)
    }

    private func cell(_ text: String, column: Int) -> some View {
        let widths = Self.columnWidths
        let width = widths.indices.contains(column) ? widths[column] : Self.defaultColumnWidth
        return Text(text)
            .lineLimit(1)
            .truncationMode(.tail)
            .padding(.horizontal, 4)
            .padding(.vertical, 3)
            .frame(width: width, alignment: .leading)
    }
}
