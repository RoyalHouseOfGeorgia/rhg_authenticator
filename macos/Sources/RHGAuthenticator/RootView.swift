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

/// Startup failed: the error, then quit; the app can't work without its core.
@MainActor
struct FatalErrorView: View {
    let message: String
    @State private var isPresented = true

    var body: some View {
        Color.clear
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .alert(AppModel.fatalErrorTitle, isPresented: $isPresented) {
                Button("OK") { NSApp.terminate(nil) }
            } message: {
                Text(message)
            }
    }
}

/// The update banner, then the tab picked in the toolbar (or the View menu),
/// over the status bar; the window's title is the tab's. Every tab's alerts
/// and questions show from here, as AppKit alerts, whichever tab started them
/// and over any sheet.
@MainActor
struct ReadyView: View {
    @Bindable var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            UpdateBannerView(model: model)
            // Every tab stays mounted, so lists keep their scroll position and
            // split views their divider; only the picked one shows and takes
            // input (so only its keyboard shortcuts fire).
            ZStack {
                SignView(sign: sign, bulk: bulk, isSigningBusy: model.isSigningBusy, canSaveQR: model.canSaveQR)
                    .tabVisible(tab == .sign)
                HistoryView(history: history, login: login, findRequests: model.findRequests)
                    .tabVisible(tab == .history)
                RegistryView(registry: registry, login: login)
                    .tabVisible(tab == .registry)
                AuditView(audit: audit)
                    .tabVisible(tab == .audit)
                YubiKeyView(model: yubiKey)
                    .tabVisible(tab == .yubiKey)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            // Here rather than on the Sign tab: the tab picker still works
            // while the core loads the chosen file, so the sheet may come up
            // with another tab picked, and a hidden tab is disabled. Only the
            // model closes it, so the binding ignores writes.
            .sheet(isPresented: .constant(bulk.isShowingSheet)) {
                BulkSheet(bulk: bulk)
            }
            Divider()
            StatusBar(items: model.statusItems)
        }
        .navigationTitle(tab.title)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("Tab", selection: $model.selectedTab) {
                    ForEach(AppTab.allCases, id: \.self) { item in
                        Text(item.title)
                            .help(item.title)
                            .tag(item)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }
        }
        // An AppKit alert, so an internal error shows over a bulk sheet too.
        .onChange(of: model.internalErrorMessage, initial: true) { _, message in
            guard let message else { return }
            Task {
                _ = await FilePanel.alert(AlertState(title: AppModel.internalErrorTitle, message: message))
                model.internalErrorMessage = nil
            }
        }
        .appKitAlert(sign.alert, current: { sign.alert }) { [sign] in
            sign.alert = nil
        }
        // While a bulk sheet is up, BulkSheet shows the bulk alert over it.
        .appKitAlert(bulkTabAlert, current: { bulkTabAlert }) { [bulk] in
            bulk.dismissAlert()
        }
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
        // Delete Entry…'s question may offer Revoke Instead.
        .appKitChoice(history.pendingConfirmation, current: { history.pendingConfirmation }) {
            [history] choice in
            await history.answer(choice)
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
        // Here rather than on a tab, so switching tabs mid-login keeps it
        // up. Only the model closes it (its Cancel button calls
        // cancelLogin), so a login that just ended can't cancel the next.
        .sheet(isPresented: .constant(login.deviceCode != nil)) {
            if let prompt = login.deviceCode {
                DeviceCodeSheet(login: login, prompt: prompt)
                    .interactiveDismissDisabled()
            }
        }
    }

    private var tab: AppTab { model.selectedTab }
    private var sign: SignModel { model.sign }
    private var bulk: BulkModel { model.bulk }
    private var registry: RegistryModel { model.registry }
    private var history: HistoryModel { model.history }
    private var login: LoginModel { model.login }
    private var audit: AuditModel { model.audit }
    private var yubiKey: YubiKeyModel { model.yubiKey }

    /// The bulk alert to show over the tabs: none while a bulk sheet is up.
    private var bulkTabAlert: AlertState? { bulk.isShowingTabAlert ? bulk.alert : nil }
}

extension View {
    /// Shows a tab's view while it is the picked tab; otherwise hides it and
    /// keeps it from taking clicks, keyboard focus, keyboard shortcuts or
    /// VoiceOver's attention, while it stays mounted.
    func tabVisible(_ visible: Bool) -> some View {
        opacity(visible ? 1 : 0)
            .disabled(!visible)
            .allowsHitTesting(visible)
            .accessibilityHidden(!visible)
    }
}

/// The status bar: the items spread across the window with flexible space
/// between them.
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
    /// Shows `state` as a SwiftUI alert with an OK button while it is non-nil
    /// and `visible`; closing it calls `onDismiss`, which clears the state.
    /// One alert per view: put a second one on a different view. For a
    /// sheet's own alert (BulkSheet); the tabs' alerts are AppKit alerts
    /// shown from ReadyView.
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
