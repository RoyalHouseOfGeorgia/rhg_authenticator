import RHGModels
import SwiftUI

/// The login button at the right end of the Registry and History command
/// rows (`LoginModel`): logged in and online, a menu titled "@user" whose
/// Log Out… asks to log out; otherwise a button that logs in or reconnects.
@MainActor
struct LoginButton: View {
    let login: LoginModel

    var body: some View {
        Group {
            if login.hasUsableSession {
                Menu {
                    Button(LoginModel.logOutTitle) {
                        login.logOutTapped()
                    }
                } label: {
                    Label(login.buttonTitle, systemImage: "person.crop.circle")
                }
                .menuStyle(.button)
                .fixedSize()
            } else {
                Button {
                    Task { [login] in await login.buttonTapped() }
                } label: {
                    Label(login.buttonTitle, systemImage: "person.crop.circle")
                }
                .disabled(login.isLoggingIn)
            }
        }
        .accessibilityLabel("GitHub account")
        .accessibilityValue(login.buttonTitle)
    }
}
