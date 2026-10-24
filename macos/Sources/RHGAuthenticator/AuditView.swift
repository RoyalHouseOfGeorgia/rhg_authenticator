import RHGModels
import SwiftUI

/// The Audit tab: Refresh and Open on GitHub, the status line, then the
/// registry's commit list. Open on GitHub, a double-click or Return opens
/// the selected commit's page on GitHub.
@MainActor
struct AuditView: View {
    let audit: AuditModel

    var body: some View {
        let rows = audit.rows
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Button {
                    Task { [audit] in await audit.refresh() }
                } label: {
                    Label(AuditModel.refreshTitle, systemImage: "arrow.clockwise")
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut("r")
                .disabled(audit.isRefreshing)
                .help(AuditModel.refreshTooltip)
                Button {
                    audit.openSelected()
                } label: {
                    Label(AuditModel.openTitle, systemImage: "safari")
                }
                .disabled(!audit.canOpen)
                .help(AuditModel.openTooltip)
                Spacer(minLength: 0)
            }
            Text(audit.status)
                .lineLimit(1)
                .truncationMode(.tail)
                .help(audit.status)
            List(selection: Binding(get: { audit.selection }, set: { audit.select(row: $0) })) {
                ForEach(rows.indices, id: \.self) { index in
                    Text(rows[index].summary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .help(rows[index].summary)
                        .tag(index)
                }
            }
            // No menu; the primary action is the double-click and Return.
            .contextMenu(
                forSelectionType: Int.self, menu: { _ in EmptyView() },
                primaryAction: { _ in audit.openSelected() })
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
