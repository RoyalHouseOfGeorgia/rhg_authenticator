import RHGModels
import SwiftUI

/// The Audit tab, laid out as the Fyne app's: the status line with Refresh
/// beside it, over the registry's commit list. Selecting a commit opens its
/// page on GitHub and clears the selection.
@MainActor
struct AuditView: View {
    let audit: AuditModel

    var body: some View {
        let rows = audit.rows
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(audit.status)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(audit.status)
                Spacer()
                Button(AuditModel.refreshTitle) {
                    Task { [audit] in await audit.refresh() }
                }
                .disabled(audit.isRefreshing)
            }
            // The selection always reads nil, so a row never stays selected.
            List(
                selection: Binding<Int?>(
                    get: { nil },
                    set: { row in
                        if let row {
                            audit.open(row: row)
                        }
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
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
