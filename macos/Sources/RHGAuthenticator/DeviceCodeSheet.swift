import AppKit
import RHGModels
import SwiftUI

/// The GitHub login's device-code sheet: the code to enter at GitHub, Copy
/// Code, Open GitHub and Cancel. The model closes it when the login ends;
/// Cancel stops the login.
@MainActor
struct DeviceCodeSheet: View {
    let login: LoginModel
    let prompt: LoginModel.DeviceCodePrompt

    var body: some View {
        VStack(spacing: 12) {
            Text(LoginModel.deviceCodeTitle)
                .font(.headline)
            Text(LoginModel.deviceCodePrompt)
            Text(prompt.userCode)
                .font(.system(.title, design: .monospaced).bold())
                .textSelection(.enabled)
                .multilineTextAlignment(.center)
            HStack {
                Button(LoginModel.copyCodeTitle) {
                    Pasteboard.copy(prompt.userCode)
                }
                // The core validated the URL; without one the code can still
                // be entered by hand.
                Button(LoginModel.openGitHubTitle) {
                    if let url = prompt.verificationURL {
                        _ = NSWorkspace.shared.open(url)
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(prompt.verificationURL == nil)
            }
            HStack {
                Spacer()
                Button(LoginModel.cancelTitle, role: .cancel) {
                    Task { [login] in await login.cancelLogin() }
                }
                .keyboardShortcut(.cancelAction)
            }
            .padding(.top, 8)
        }
        .padding(20)
        .frame(minWidth: 320)
    }
}
