import Foundation
import RHGBridge
import Testing

@testable import RHGModels

private let release = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/tag/v1.3.0"

private func status(
    _ state: UpdateState, releaseUrl: String = release, moveToApplications: Bool = false
) -> UpdateStatus {
    UpdateStatus(state: state, version: "1.3.0", releaseUrl: releaseUrl, moveToApplications: moveToApplications)
}

@Suite("UpdateBanner")
struct UpdateBannerTests {
    @Test("ready: the title, whatever the link")
    func ready() {
        let expected = UpdateBanner.ready(title: "Version 1.3.0 is ready to install.")
        #expect(UpdateBanner(status(.ready)) == expected)
        #expect(UpdateBanner(status(.ready, releaseUrl: "", moveToApplications: true)) == expected)
    }

    @Test(
        "manualOnly: the text and the Download link; the Applications folder hint only with moveToApplications",
        arguments: [
            (false, nil),
            (true, "To get updates automatically, move RHG Authenticator into your Applications folder."),
        ] as [(Bool, String?)])
    func manualOnly(moveToApplications: Bool, hint: String?) throws {
        #expect(
            UpdateBanner(status(.manualOnly, moveToApplications: moveToApplications))
                == .manualOnly(
                    text: "Version 1.3.0 is available —", releaseURL: try #require(URL(string: release)),
                    moveToApplicationsHint: hint))
    }

    @Test("manualOnly without a release link shows nothing")
    func manualOnlyNoLink() {
        #expect(UpdateBanner(status(.manualOnly, releaseUrl: "", moveToApplications: false)) == nil)
    }

    @Test("the banners' button titles")
    func buttonTitles() {
        #expect(UpdateBanner.restartNowTitle == "Restart Now")
        #expect(UpdateBanner.downloadTitle == "Download")
        #expect(UpdatedBanner.whatsNewTitle == "What's New")
        #expect(UpdatedBanner.closeLabel == "Close")
    }

    @Test("idle and an unknown state show nothing", arguments: [UpdateState.idle, .unknown("downloading")])
    func nothing(_ state: UpdateState) {
        #expect(UpdateBanner(status(state, moveToApplications: true)) == nil)
    }

    @Test(
        "updated: the text, and the What's new link only with a release link",
        arguments: [(release, release), ("", nil)] as [(String, String?)])
    func updated(releaseUrl: String, whatsNew: String?) throws {
        let url = try whatsNew.map { try #require(URL(string: $0)) }
        #expect(
            UpdatedBanner(UpdatedNotice(version: "1.2.3", releaseUrl: releaseUrl))
                == UpdatedBanner(text: "Updated to version 1.2.3.", whatsNewURL: url))
    }
}
