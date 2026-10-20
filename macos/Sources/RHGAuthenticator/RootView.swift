import AppKit
import RHGModels
import SwiftUI

/// The window: a progress view while the core starts, the tabs and status
/// bar once it is ready, or the fatal startup error.
@MainActor
struct RootView: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        content
            // Runs again when the window is reopened; start() then returns
            // at once.
            .task { await model.start() }
            // The delegate reopens the window when a quit from closing it is
            // called off.
            .onAppear {
                Shared.openMainWindow = { [openWindow] in openWindow(id: "main") }
            }
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
                HistoryView(history: model.history)
                    .tabItem { Text("History") }
                RegistryView(registry: model.registry, login: model.login)
                    .tabItem { Text("Registry") }
                AuditView(audit: model.audit)
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
                _ = await FilePanel.alert(AlertState(title: "Error", message: message))
                model.internalErrorMessage = nil
            }
        }
        // The registry's, the history's and the login's alerts and questions,
        // here so they show whichever tab started them, over any sheet.
        .appKitConfirmation(registry.pendingConfirmation, current: { registry.pendingConfirmation }) {
            [registry] confirmed in
            if confirmed {
                await registry.confirm()
            } else {
                registry.dismissConfirmation()
            }
        }
        .appKitAlert(registry.alert, current: { registry.alert }) { [registry] in
            await registry.alertDismissed()
        }
        .appKitConfirmation(history.pendingConfirmation, current: { history.pendingConfirmation }) {
            [history] confirmed in
            if confirmed {
                await history.confirm()
            } else {
                history.dismissConfirmation()
            }
        }
        .appKitAlert(history.alert, current: { history.alert }) { [history] in
            await history.alertDismissed()
        }
        .appKitConfirmation(login.pendingConfirmation, current: { login.pendingConfirmation }) {
            [login] confirmed in
            if confirmed {
                await login.confirmLogout()
            } else {
                login.dismissConfirmation()
            }
        }
        .appKitAlert(login.alert, current: { login.alert }) { [login] in
            login.alertDismissed()
        }
        // Here rather than on the Registry tab, so switching tabs mid-login
        // keeps it up. Only the model closes it (its Cancel button calls
        // cancelLogin), so a login that just ended can't cancel the next.
        .sheet(isPresented: .constant(login.deviceCode != nil)) {
            if let prompt = login.deviceCode {
                DeviceCodeSheet(login: login, prompt: prompt)
                    .interactiveDismissDisabled()
            }
        }
    }

    private var registry: RegistryModel { model.registry }
    private var history: HistoryModel { model.history }
    private var login: LoginModel { model.login }
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
