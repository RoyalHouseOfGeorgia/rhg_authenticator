import AppKit
import RHGModels
import UniformTypeIdentifiers

/// Runs the app's open and save panels (NSOpenPanel is an NSSavePanel) and
/// its AppKit alerts.
@MainActor
enum FilePanel {
    /// The window panels and alerts attach to: the key window (a bulk sheet's
    /// own window while one is up, so they stack over it), else the main one.
    static var parentWindow: NSWindow? { NSApp.keyWindow ?? NSApp.mainWindow }

    /// Shows `panel` as a sheet on `parentWindow` and returns the chosen file,
    /// or nil when cancelled. Without a window the panel shows standalone.
    static func run(_ panel: NSSavePanel) async -> URL? {
        let response: NSApplication.ModalResponse
        if let window = parentWindow {
            response = await panel.beginSheetModal(for: window)
        } else {
            response = await panel.begin()
        }
        guard response == .OK else { return nil }
        return panel.url
    }

    /// Asks where to save a `type` file named `name` by default, then hands
    /// the chosen path to `write`. Nothing happens when cancelled.
    static func save(name: String, type: UTType, then write: @escaping @MainActor (String) async -> Void) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.allowedContentTypes = [type]
        panel.canCreateDirectories = true
        Task {
            guard let url = await run(panel) else { return }
            await write(url.path)
        }
    }

    /// Shows `state` as an AppKit alert with an OK button, as a sheet on
    /// `parentWindow` (standalone without one), and returns once it is
    /// closed. Unlike a SwiftUI alert on a view, it shows over any sheet.
    static func alert(_ state: AlertState) async {
        let alert = NSAlert()
        alert.messageText = state.title
        alert.informativeText = state.message
        alert.addButton(withTitle: "OK")
        if let window = parentWindow {
            _ = await alert.beginSheetModal(for: window)
        } else {
            _ = alert.runModal()
        }
    }
}
