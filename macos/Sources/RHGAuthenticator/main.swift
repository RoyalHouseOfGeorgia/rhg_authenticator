// The app's entry point. The core's command-line invocations (--version,
// --verify-update-zip, run by CI and the release checks) are handled first,
// so they never start AppKit; anything else starts the SwiftUI app.

import Foundation
import RHGBridge

if let code = runMainCLI(CommandLine.arguments) {
    exit(code)
}

MainActor.assumeIsolated {
    RHGApp.main()
}
