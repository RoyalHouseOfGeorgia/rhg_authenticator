import RHGModels
import SwiftUI

/// The YubiKey tab: Check YubiKey, the status line, then the key's details,
/// one line each, in a card. It stays enabled offline; the core answers
/// without the card then.
@MainActor
struct YubiKeyView: View {
    let model: YubiKeyModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Button {
                    Task { [model] in await model.check() }
                } label: {
                    Label(YubiKeyModel.checkTitle, systemImage: "key")
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isChecking)
                Spacer(minLength: 0)
            }
            if !model.status.isEmpty {
                Text(model.status)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !model.details.isEmpty {
                GroupBox {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(model.details.indices, id: \.self) { index in
                            Text(model.details[index])
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
