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

    @Test("manualOnly: the text and the Download link; no hint unless moveToApplications")
    func manualOnly() throws {
        #expect(
            UpdateBanner(status(.manualOnly))
                == .manualOnly(
                    text: "Version 1.3.0 is available —", releaseURL: try #require(URL(string: release)),
                    moveToApplicationsHint: nil))
    }

    @Test("manualOnly with moveToApplications: the Applications folder hint")
    func manualOnlyMoveHint() throws {
        #expect(
            UpdateBanner(status(.manualOnly, moveToApplications: true))
                == .manualOnly(
                    text: "Version 1.3.0 is available —", releaseURL: try #require(URL(string: release)),
                    moveToApplicationsHint:
                        "To get updates automatically, move RHG Authenticator into your Applications folder."))
    }

    @Test("manualOnly without a release link shows nothing", arguments: [false, true])
    func manualOnlyNoLink(moveToApplications: Bool) {
        #expect(UpdateBanner(status(.manualOnly, releaseUrl: "", moveToApplications: moveToApplications)) == nil)
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

    @Test("updated: the text and the What's new link")
    func updated() throws {
        let url = try #require(URL(string: release))
        #expect(
            UpdatedBanner(UpdatedNotice(version: "1.2.3", releaseUrl: release))
                == UpdatedBanner(text: "Updated to version 1.2.3.", whatsNewURL: url))
    }

    @Test("updated without a release link: no What's new")
    func updatedNoLink() {
        #expect(
            UpdatedBanner(UpdatedNotice(version: "1.2.3", releaseUrl: ""))
                == UpdatedBanner(text: "Updated to version 1.2.3.", whatsNewURL: nil))
    }
}
