import Foundation
import RHGBridge

/// The update banner's status slot, as the Fyne app showed it: an update
/// ready to install (with Restart now), or one to download by hand. Versions
/// are canonical "X.Y.Z" (no "v" prefix). The core blanks any release URL
/// that is not an https://github.com one; an empty URL means no link.
public enum UpdateBanner: Sendable, Equatable {
    /// Downloaded: `title`, then `readyDetail` and Restart now.
    case ready(title: String)
    /// `text` then a Download link to `releaseURL`; `moveToApplicationsHint`
    /// is the line under it, or nil.
    case manualOnly(text: String, releaseURL: URL, moveToApplicationsHint: String?)

    public static let restartNowTitle = "Restart Now"
    public static let downloadTitle = "Download"
    public static let readyDetail = "It will also install the next time you close the app."
    public static let moveToApplicationsHint =
        "To get updates automatically, move RHG Authenticator into your Applications folder."

    /// The banner for `status`; nil (nothing shown) when idle, for an unknown
    /// state, or when a manual-only offer has no release link.
    public init?(_ status: UpdateStatus) {
        switch status.state {
        case .ready:
            self = .ready(title: "Version \(status.version) is ready to install.")
        case .manualOnly:
            guard !status.releaseUrl.isEmpty, let url = URL(string: status.releaseUrl) else { return nil }
            self = .manualOnly(
                text: "Version \(status.version) is available \u{2014}", releaseURL: url,
                moveToApplicationsHint: status.moveToApplications ? Self.moveToApplicationsHint : nil)
        case .idle, .unknown:
            return nil
        }
    }
}

/// The one-time "Updated to" notice, shown above the status slot until the
/// operator closes it. `whatsNewURL` is the What's new link, or nil.
public struct UpdatedBanner: Sendable, Equatable {
    public static let whatsNewTitle = "What's New"
    public static let closeLabel = "Close"

    public let text: String
    public let whatsNewURL: URL?

    init(text: String, whatsNewURL: URL?) {
        self.text = text
        self.whatsNewURL = whatsNewURL
    }

    public init(_ notice: UpdatedNotice) {
        self.init(
            text: "Updated to version \(notice.version).",
            whatsNewURL: notice.releaseUrl.isEmpty ? nil : URL(string: notice.releaseUrl))
    }
}
