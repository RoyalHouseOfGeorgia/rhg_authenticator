import AppKit
import RHGBridge
import RHGModels
import SwiftUI
import UniformTypeIdentifiers

/// The process's one AppModel, over the Go core linked into it. Created on
/// first use (by the delegate at launch or the window, whichever comes
/// first); `LiveBridge.install()` buffers the core's events from then on.
@MainActor
enum Shared {
    static let model = AppModel(
        bridge: LiveBridge.install(),
        openURL: { url in _ = NSWorkspace.shared.open(url) })

    /// Opens the main window (SwiftUI's openWindow, set by RootView on
    /// appear); nil until the window first shows.
    static var openMainWindow: (@MainActor () -> Void)?
}

/// The app: one window, as the Fyne app had. Started from main.swift.
@MainActor
struct RHGApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        Window("RHG Authenticator", id: "main") {
            RootView(model: Shared.model)
                .frame(minWidth: 600, minHeight: 450)
        }
        .defaultSize(width: 800, height: 600)
        .commands {
            // The Help menu holds only Export Error Log…, as in the Fyne app.
            // Always enabled (menu items need not track the phase): its
            // result is an AppKit alert, shown over any window or sheet.
            CommandGroup(replacing: .help) {
                Button(AppModel.exportErrorLogTitle) {
                    ErrorLogPanel.present(for: Shared.model)
                }
            }
        }
    }
}

/// Help → Export Error Log…: asks where to save, writes the core's
/// diagnostic log there, then says where it went (or why it failed) in an
/// AppKit alert on the topmost window, so it shows over a bulk sheet too.
@MainActor
enum ErrorLogPanel {
    static func present(for model: AppModel) {
        let type = UTType(filenameExtension: "log") ?? UTType.plainText
        FilePanel.save(name: model.suggestedErrorLogFilename, type: type) { path in
            _ = await FilePanel.alert(await model.exportErrorLog(path: path))
        }
    }
}

/// Quit handling and the AppKit PIN sheet.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var pinSheet: PINSheetController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        pinSheet = PINSheetController(prompt: Shared.model.pinPrompt)
        // An AppKit alert: standalone when the quit came from closing the
        // window, which is gone by then.
        Shared.model.confirmDiscard = { await FilePanel.confirm(AppModel.quitConfirmation) }
    }

    /// Closing the window quits, as in the Fyne app.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// Every quit (menu, Cmd-Q, last window closed, a fatal error) runs the
    /// core's quit sequence first. The bridge calls run off the main thread
    /// (LiveBridge's queue), so the app stays responsive meanwhile.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let model = Shared.model
        Task { @MainActor in
            // A plain quit never relaunches; only the update banner's
            // "Restart now" will quit with relaunch: true.
            let terminate = await model.prepareToQuit(relaunch: false)
            if !terminate {
                Self.showMainWindow()
            }
            NSApp.reply(toApplicationShouldTerminate: terminate)
        }
        return .terminateLater
    }

    /// Brings the main window back after a called-off quit, which may have
    /// come from closing it. Opening a single-window scene that is still open
    /// brings that window forward instead.
    private static func showMainWindow() {
        Shared.openMainWindow?()
        NSApp.activate()
    }
}
