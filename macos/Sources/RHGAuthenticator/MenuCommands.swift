import AppKit
import RHGModels
import SwiftUI

/// The menu bar's commands: File's Bulk Sign, Save QR Code and Export
/// Issuance Log items (in place of New, which the app doesn't have), Edit's
/// Find… (in place of the text-editing items), View's tabs on ⌘1–⌘5 and
/// Refresh, and Help. Each item is enabled exactly when the matching button
/// is, and everything but Help is disabled until the core is ready.
/// Unavailable items are disabled, never hidden.
@MainActor
struct MenuCommands: Commands {
    let model: AppModel

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            FileMenuItems(model: model)
        }
        // The app's Find… is its only ⌘F, so the default Find, Spelling and
        // Substitutions items go.
        CommandGroup(replacing: .textEditing) {
            FindMenuItem(model: model)
        }
        CommandGroup(before: .toolbar) {
            ViewMenuItems(model: model)
        }
        // Always enabled: neither depends on the phase, and Export Error
        // Log…'s result is an AppKit alert, shown over any window or sheet.
        CommandGroup(replacing: .help) {
            Button("RHG Authenticator Help") {
                _ = NSWorkspace.shared.open(AppModel.helpURL)
            }
            Divider()
            Button(AppModel.exportErrorLogTitle) {
                ErrorLogPanel.present(for: model)
            }
        }
    }

    /// Runs a menu item's action unless the main window has a sheet up (a
    /// SwiftUI sheet, an AppKit alert or question, the PIN prompt or a save
    /// or open panel), which the item's action would land behind.
    static func perform(_ action: @MainActor () -> Void) {
        guard NSApp.mainWindow?.attachedSheet == nil else { return }
        action()
    }
}

/// File's items. Views rather than inline buttons, so their enabled state
/// tracks the models they read.
@MainActor
private struct FileMenuItems: View {
    let model: AppModel

    var body: some View {
        let isReady = model.phase == .ready
        Button(BulkModel.bulkSignTitle) {
            MenuCommands.perform { BulkPanels.chooseFile(for: model.bulk) }
        }
        .disabled(!isReady || model.isSigningBusy)
        Divider()
        Button("Save QR Code as SVG\u{2026}") {
            MenuCommands.perform { QRSavePanel.present(for: model.sign, format: .svg) }
        }
        .disabled(!isReady || !model.canSaveQR)
        Button("Save QR Code as PNG\u{2026}") {
            MenuCommands.perform { QRSavePanel.present(for: model.sign, format: .png) }
        }
        .disabled(!isReady || !model.canSaveQR)
        Divider()
        Button(HistoryModel.exportTitle) {
            MenuCommands.perform { HistoryExportPanel.present(for: model.history) }
        }
        .disabled(!isReady)
    }
}

/// Edit → Find… (⌘F): shows the History tab and focuses its search field.
@MainActor
private struct FindMenuItem: View {
    let model: AppModel

    var body: some View {
        Button("Find\u{2026}") {
            MenuCommands.perform { model.requestFind() }
        }
        .keyboardShortcut("f", modifiers: .command)
        .disabled(model.phase != .ready)
    }
}

/// View's tab items (⌘1–⌘5, in the picker's order) and Refresh (⌘R), which
/// runs the visible tab's refresh (`AppModel.refresh`); Sign and YubiKey
/// have none, so it is disabled there.
@MainActor
private struct ViewMenuItems: View {
    let model: AppModel

    var body: some View {
        let isReady = model.phase == .ready
        let tabs = AppTab.allCases
        ForEach(tabs.indices, id: \.self) { index in
            let tab = tabs[index]
            Button(tab.title) {
                MenuCommands.perform { model.selectedTab = tab }
            }
            .keyboardShortcut(KeyEquivalent(Character(String(index + 1))))
            .disabled(!isReady)
        }
        Divider()
        Button(model.refreshTitle) {
            MenuCommands.perform {
                Task { [model] in await model.refresh() }
            }
        }
        .keyboardShortcut("r", modifiers: .command)
        .disabled(!isReady || !model.canRefresh)
        Divider()
    }
}
