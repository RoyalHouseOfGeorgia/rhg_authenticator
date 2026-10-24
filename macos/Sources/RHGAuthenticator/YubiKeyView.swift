import RHGModels
import SwiftUI

/// The YubiKey tab, laid out as the Fyne app's: Check YubiKey with the
/// status beside it, then the key's details, one line each. It stays enabled
/// offline; the core answers without the card then.
@MainActor
struct YubiKeyView: View {
    let model: YubiKeyModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Button(YubiKeyModel.checkTitle) {
                    Task { [model] in await model.check() }
                }
                .disabled(model.isChecking)
                Text(model.status)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            ForEach(model.details.indices, id: \.self) { index in
                Text(model.details[index])
                    .textSelection(.enabled)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
