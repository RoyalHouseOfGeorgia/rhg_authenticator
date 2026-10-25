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

    /// Asks `question` in an AppKit alert, shown as `alert` is (see
    /// `choose`). Returns whether the operator confirmed.
    static func confirm(_ question: Confirmation) async -> Bool {
        await choose(question) == .confirm
    }

    /// Asks `question` in an AppKit alert, shown as `alert` is, and returns
    /// the button the operator picked. The buttons are added in the
    /// question's `buttonRoles` order, confirm first. NSAlert puts the first
    /// button rightmost and each later one to its left, so the window sheet
    /// reads, left to right, [alternate] [Cancel] [confirm] (Delete Entry…:
    /// [Revoke Instead] [Cancel] [Delete]). In a destructive question no
    /// button has Return, the confirm button is marked destructive and Cancel
    /// has Escape; otherwise confirm keeps Return and Cancel has Escape.
    static func choose(_ question: Confirmation) async -> ConfirmChoice {
        let alert = NSAlert()
        alert.messageText = question.title
        alert.informativeText = question.message
        for role in question.buttonRoles {
            let title =
                switch role {
                case .confirm: question.confirmTitle
                case .alternate: question.alternateTitle ?? ""
                case .cancel: question.cancelTitle
                }
            let button = alert.addButton(withTitle: title)
            if let key = question.keyEquivalent(for: role) {
                button.keyEquivalent = key
            }
            button.hasDestructiveAction = question.hasDestructiveAction(for: role)
        }
        // The buttons answer by position, in the order they were added.
        let index = await present(alert).rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
        return question.choice(forButtonAt: index)
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

/// The general pasteboard.
@MainActor
enum Pasteboard {
    /// Replaces the pasteboard's contents with `text`.
    static func copy(_ text: String) {
        let pasteboard = NSPasteboard.general
        _ = pasteboard.clearContents()
        _ = pasteboard.setString(text, forType: .string)
    }
}
