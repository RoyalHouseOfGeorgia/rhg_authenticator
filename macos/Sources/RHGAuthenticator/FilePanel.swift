import AppKit
import RHGModels
import UniformTypeIdentifiers

/// Runs the app's open and save panels (NSOpenPanel is an NSSavePanel) and
/// its AppKit alerts.
@MainActor
enum FilePanel {
    /// The window panels and alerts attach to: the main window's deepest
    /// sheet (a bulk sheet while one is up, so they stack over it), else the
    /// main window. A sheet SwiftUI is closing is no longer attached, so it
    /// is never chosen, though it may still be the key window. While the app
    /// is inactive there is no main or key window, so the first open window
    /// that could be main stands in; none is open only after the last closed.
    static var parentWindow: NSWindow? {
        var parent =
            NSApp.mainWindow ?? NSApp.keyWindow
            ?? NSApp.windows.first { $0.isVisible && $0.sheetParent == nil && $0.canBecomeMain }
        while let sheet = parent?.attachedSheet {
            parent = sheet
        }
        return parent
    }

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

    /// Asks for one file of the given extensions (any file when none maps to
    /// a known type) and hands its path to `read`. Nothing happens when
    /// cancelled.
    static func open(extensions: [String], then read: @escaping @MainActor (String) async -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = extensions.compactMap { UTType(filenameExtension: $0) }
        Task {
            guard let url = await run(panel) else { return }
            await read(url.path)
        }
    }

    /// Shows `state` as an AppKit alert with an OK button, as a sheet on
    /// `parentWindow` (standalone without one), and returns once it is
    /// closed. Unlike a SwiftUI alert on a view, it shows over any sheet.
    /// An alert that offers it also has Export Error Log…; returns whether
    /// the operator chose that.
    static func alert(_ state: AlertState) async -> Bool {
        let alert = NSAlert()
        alert.messageText = state.title
        alert.informativeText = state.message
        alert.addButton(withTitle: "OK")
        if state.offersErrorLogExport {
            alert.addButton(withTitle: AppModel.exportErrorLogTitle)
        }
        let response = await present(alert)
        return state.offersErrorLogExport && response == .alertSecondButtonReturn
    }

    /// Asks `question` in an AppKit alert, shown as `alert` is: the confirm
    /// button first (the default, Return), then the cancel button (Escape).
    /// Returns whether the operator confirmed.
    static func confirm(_ question: Confirmation) async -> Bool {
        let alert = NSAlert()
        alert.messageText = question.title
        alert.informativeText = question.message
        let confirmButton = alert.addButton(withTitle: question.confirmTitle)
        confirmButton.hasDestructiveAction = question.isDestructive
        // NSAlert gives Escape only to a button titled "Cancel".
        let cancelButton = alert.addButton(withTitle: question.cancelTitle)
        cancelButton.keyEquivalent = "\u{1b}"
        return await present(alert) == .alertFirstButtonReturn
    }

    /// Shows `alert` as a sheet on `parentWindow` and returns the button
    /// chosen. Without a window (the last one closed on the way to quitting)
    /// it brings the app forward and runs standalone.
    private static func present(_ alert: NSAlert) async -> NSApplication.ModalResponse {
        if let window = parentWindow {
            return await alert.beginSheetModal(for: window)
        }
        NSApp.activate()
        return alert.runModal()
    }
}
