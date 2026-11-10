import AppKit
import RHGModels
import SwiftUI

/// History's search field, an AppKit search field: every edit, its clear
/// button, Escape (which clears it) and Return go to the model's query.
/// Find… (⌘F) puts the focus in it: each new `findRequests` count
/// (`AppModel.requestFind`) focuses it once the History tab shows.
@MainActor
struct SearchField: NSViewRepresentable {
    let history: HistoryModel
    /// `AppModel.findRequests`, so a Find… re-runs `updateNSView`.
    let findRequests: Int

    func makeCoordinator() -> Coordinator {
        Coordinator(history: history, findRequests: findRequests)
    }

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.placeholderString = HistoryModel.searchPlaceholder
        field.toolTip = HistoryModel.searchTooltip
        field.sendsSearchStringImmediately = true
        field.stringValue = history.query
        field.delegate = context.coordinator
        field.target = context.coordinator
        field.action = #selector(Coordinator.searchAction(_:))
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        // A hidden tab is disabled, so its field can't take the focus. A
        // disabled field keeps an edit already under way, so the focus is
        // given up first: typing must not go on filtering the hidden list.
        let isEnabled = context.environment.isEnabled
        if !isEnabled, field.currentEditor() != nil {
            field.window?.makeFirstResponder(nil)
        }
        field.isEnabled = isEnabled
        // Never mid-composition: replacing the text would drop an input
        // method's marked text.
        let isComposing = (field.currentEditor() as? NSTextView)?.hasMarkedText() == true
        if field.stringValue != history.query, !isComposing {
            field.stringValue = history.query
        }
        let coordinator = context.coordinator
        if findRequests != coordinator.findRequests {
            coordinator.findRequests = findRequests
            // After this update, once the History tab shows and is enabled.
            Task { @MainActor in field.window?.makeFirstResponder(field) }
        }
    }

    /// The field's delegate and target: passes its text to the model.
    @MainActor
    final class Coordinator: NSObject, NSSearchFieldDelegate {
        let history: HistoryModel
        /// The last `findRequests` count acted on.
        var findRequests: Int

        init(history: HistoryModel, findRequests: Int) {
            self.history = history
            self.findRequests = findRequests
        }

        /// Each edit.
        func controlTextDidChange(_ obj: Notification) {
            guard let field = obj.object as? NSSearchField else { return }
            history.setQuery(field.stringValue)
        }

        /// The clear button, Escape and Return.
        @objc func searchAction(_ sender: NSSearchField) {
            history.setQuery(sender.stringValue)
        }
    }
}
