import AppKit
import RHGModels
import SwiftUI

/// The update banner between the toolbar and the tabs: the "Updated to"
/// notice, then the update offer. Each part shows only when the model has
/// one, so an empty banner takes no space.
@MainActor
struct UpdateBannerView: View {
    let model: AppModel

    var body: some View {
        if let updated = model.updatedBanner {
            HStack(alignment: .firstTextBaseline) {
                Text(updated.text)
                    .bold()
                if let url = updated.whatsNewURL {
                    Link(UpdatedBanner.whatsNewTitle, destination: url)
                }
                Spacer()
                Button {
                    model.dismissUpdatedNotice()
                } label: {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(UpdatedBanner.closeLabel)
                .help(UpdatedBanner.closeLabel)
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
        }
        if let banner = model.updateBanner {
            Group {
                switch banner {
                case .ready(let title):
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(title)
                                .bold()
                            Text(UpdateBanner.readyDetail)
                        }
                        Spacer()
                        // The usual quit (unsubmitted-edits confirm included),
                        // relaunching once the update installs. Bordered, so
                        // the tab's own action stays the one prominent button.
                        Button(UpdateBanner.restartNowTitle) {
                            model.requestRestart()
                            NSApp.terminate(nil)
                        }
                        .buttonStyle(.bordered)
                    }
                case .manualOnly(let text, let releaseURL, let hint):
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(alignment: .firstTextBaseline) {
                            Text(text)
                            Link(UpdateBanner.downloadTitle, destination: releaseURL)
                        }
                        if let hint {
                            Text(hint)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
        }
    }
}
