internal import CRHGCore
import Foundation

/// Runs the core's command-line invocations (`--version`,
/// `--verify-update-zip …`) with this process's `arguments` (program name
/// first, as `CommandLine.arguments`). Returns nil when `arguments` is not
/// one, and the app should start its UI; otherwise the exit code, after the
/// core has written its output. Call it before anything starts the UI.
public func runMainCLI(_ arguments: [String]) -> Int32? {
    var argv: [UnsafeMutablePointer<CChar>?] = arguments.map { strdup($0) }
    defer { argv.forEach { free($0) } }
    argv.append(nil)  // C's argv[argc]; Go reads only argc entries
    let code = argv.withUnsafeMutableBufferPointer { RHGMainCLI(Int32(arguments.count), $0.baseAddress) }
    return code == -1 ? nil : code
}
