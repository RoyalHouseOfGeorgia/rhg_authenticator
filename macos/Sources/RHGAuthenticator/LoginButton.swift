import RHGModels
import SwiftUI

/// The login button at the right end of the Registry and History command
/// rows: logs in, reconnects, or offers to log out (`LoginModel`).
@MainActor
struct LoginButton: View {
    let login: LoginModel

    var body: some View {
        Button {
            Task { [login] in await login.buttonTapped() }
        } label: {
            Label(login.buttonTitle, systemImage: "person.crop.circle")
        }
        .disabled(login.isLoggingIn)
    }
}
