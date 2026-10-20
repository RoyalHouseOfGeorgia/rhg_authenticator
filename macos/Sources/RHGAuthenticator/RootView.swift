import AppKit
import RHGModels
import SwiftUI

/// The window: a progress view while the core starts, the tabs and status
/// bar once it is ready, or the fatal startup error.
@MainActor
struct RootView: View {
    let model: AppModel

    var body: some View {
        content
            .task { await model.start() }
    }

    @ViewBuilder
    private var content: some View {
        switch model.phase {
        case .starting:
            ProgressView("Loading key registry\u{2026}")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .fatal(let message):
            FatalErrorView(message: message)
        case .ready:
            ReadyView(model: model)
        }
    }
}

/// Startup failed: the error, then quit (the Fyne app exited the same way).
@MainActor
struct FatalErrorView: View {
    let message: String
    @State private var isPresented = true

    var body: some View {
        Color.clear
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .alert("Error", isPresented: $isPresented) {
                Button("OK") { NSApp.terminate(nil) }
            } message: {
                Text(message)
            }
    }
}

/// The tabs, in the Fyne app's order, over the status bar.
@MainActor
struct ReadyView: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            TabView {
                SignView(sign: model.sign, bulk: model.bulk, isSigningBusy: model.isSigningBusy)
                    .tabItem { Text("Sign") }
                PlaceholderView()
                    .tabItem { Text("History") }
                PlaceholderView()
                    .tabItem { Text("Registry") }
                PlaceholderView()
                    .tabItem { Text("Audit") }
                YubiKeyView(model: model.yubiKey)
                    .tabItem { Text("YubiKey") }
            }
            .padding([.top, .horizontal])
            Divider()
            StatusBar(items: model.statusItems)
        }
        // An AppKit alert, so an internal error shows over a bulk sheet too.
        .onChange(of: model.internalErrorMessage, initial: true) { _, message in
            guard let message else { return }
            Task {
                await FilePanel.alert(AlertState(title: "Error", message: message))
                model.internalErrorMessage = nil
            }
        }
    }
}

/// A tab not yet ported from the Fyne app.
@MainActor
struct PlaceholderView: View {
    var body: some View {
        Text("Not yet available")
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// The status bar: the items spread across the window with flexible space
/// between them, as in the Fyne app.
@MainActor
struct StatusBar: View {
    let items: [String]

    var body: some View {
        HStack {
            ForEach(items.indices, id: \.self) { index in
                if index > 0 {
                    Spacer()
                }
                Text(items[index])
            }
        }
        .font(.callout)
        .foregroundStyle(.secondary)
        .padding(.horizontal)
        .padding(.vertical, 6)
    }
}

extension View {
    /// Shows `state` as an alert with an OK button while it is non-nil and
    /// `visible`; closing it calls `onDismiss`, which clears the state. One
    /// alert per view: put a second one on a different view.
    func alert(
        _ state: AlertState?, when visible: Bool = true, onDismiss: @escaping @MainActor () -> Void
    ) -> some View {
        alert(
            state?.title ?? "",
            isPresented: Binding(
                get: { state != nil && visible },
                set: { presented in
                    if !presented {
                        MainActor.assumeIsolated { onDismiss() }
                    }
                })
        ) {
            Button("OK") {}
        } message: {
            Text(state?.message ?? "")
        }
    }
}
