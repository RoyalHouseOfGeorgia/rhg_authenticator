import RHGModels
import SwiftUI

/// Shows a model's pending alert or question as an AppKit dialog (FilePanel),
/// so it appears over any sheet and a view can host any number of them. One
/// dialog per model property at a time: a value set while one is up waits
/// for it to close.
@MainActor
struct AppKitDialog<Value: Equatable & Sendable>: ViewModifier {
    /// The value as the view's body read it, so changes re-run `onChange`.
    let value: Value?
    /// The model's value now; the observed one is stale once a dialog is up.
    let current: @MainActor () -> Value?
    /// Shows the dialog and returns the operator's answer.
    let present: @MainActor (Value) async -> Bool
    /// Hands the answer to the model, which clears the value.
    let respond: @MainActor (Bool) async -> Void
    @State private var isPresenting = false

    func body(content: Content) -> some View {
        content.onChange(of: value, initial: true) { _, _ in
            presentLatest()
        }
    }

    private func presentLatest() {
        guard !isPresenting, let first = current() else { return }
        isPresenting = true
        Task {
            var shown = first
            var answer = await present(shown)
            // The model replaced the value while it was on screen: the
            // answer belongs to the newer one, so show that instead.
            while let latest = current(), latest != shown {
                shown = latest
                answer = await present(latest)
            }
            // Cleared before the model runs its follow-up (which may take a
            // while, e.g. a fetch), so a value it sets meanwhile still shows.
            isPresenting = false
            guard current() != nil else { return }
            await respond(answer)
        }
    }
}

extension View {
    /// Shows `value` while non-nil as `FilePanel.confirm`, then hands the
    /// answer to `respond`. `current` reads the same model property.
    func appKitConfirmation(
        _ value: Confirmation?, current: @escaping @MainActor () -> Confirmation?,
        respond: @escaping @MainActor (Bool) async -> Void
    ) -> some View {
        modifier(
            AppKitDialog(
                value: value, current: current, present: { await FilePanel.confirm($0) }, respond: respond))
    }

    /// Shows `value` while non-nil as `FilePanel.alert`, then calls
    /// `dismissed`, which clears it, and opens the error log's save panel
    /// when the operator chose Export Error Log…. `current` reads the same
    /// model property.
    func appKitAlert(
        _ value: AlertState?, current: @escaping @MainActor () -> AlertState?,
        dismissed: @escaping @MainActor () async -> Void
    ) -> some View {
        modifier(
            AppKitDialog(
                value: value, current: current, present: { await FilePanel.alert($0) },
                respond: { exportErrorLog in
                    await dismissed()
                    if exportErrorLog {
                        ErrorLogPanel.present(for: Shared.model)
                    }
                }))
    }
}
