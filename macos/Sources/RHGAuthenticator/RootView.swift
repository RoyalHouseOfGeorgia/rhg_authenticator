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
    @Bindable var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            TabView {
                SignView(sign: model.sign)
                    .tabItem { Text("Sign") }
                PlaceholderView()
                    .tabItem { Text("History") }
                PlaceholderView()
                    .tabItem { Text("Registry") }
                PlaceholderView()
                    .tabItem { Text("Audit") }
                PlaceholderView()
                    .tabItem { Text("YubiKey") }
            }
            .padding([.top, .horizontal])
            Divider()
            StatusBar(items: model.statusItems)
        }
        .alert("Error", isPresented: $model.isShowingInternalError) {
            Button("OK") {}
        } message: {
            Text(model.internalErrorMessage ?? "")
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

extension AppModel {
    /// The internal-error alert's presentation; dismissing it clears the message.
    var isShowingInternalError: Bool {
        get { internalErrorMessage != nil }
        set {
            if !newValue {
                internalErrorMessage = nil
            }
        }
    }
}
