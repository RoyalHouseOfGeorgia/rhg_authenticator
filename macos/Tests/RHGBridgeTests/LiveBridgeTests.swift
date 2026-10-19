import Foundation
import RHGBridge
import Testing

/// Anchors `Bundle(for:)` to this test bundle.
private final class BundleAnchor {}

/// The RHGFlowRunner executable next to the test bundle: on Linux the bundle
/// URL is the products directory, on macOS it is the .xctest bundle inside it.
private func flowRunnerURL() throws -> URL {
    let bundleURL = Bundle(for: BundleAnchor.self).bundleURL
    for dir in [bundleURL, bundleURL.deletingLastPathComponent()] {
        let candidate = dir.appendingPathComponent("RHGFlowRunner")
        if FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
    }
    throw RunnerNotFound(bundle: bundleURL.path)
}

private struct RunnerNotFound: Error, CustomStringConvertible {
    let bundle: String
    var description: String { "RHGFlowRunner not found next to \(bundle)" }
}

/// Runs RHGFlowRunner with `args` and returns its exit status and output
/// lines, killing it after `timeout` seconds. Under code coverage the runner
/// writes its own profile next to the test's, so its LiveBridge lines count.
private func runFlow(_ args: [String], timeout: Double = 90) async throws -> (status: Int32, lines: [String]) {
    let process = Process()
    process.executableURL = try flowRunnerURL()
    process.arguments = args
    var env = ProcessInfo.processInfo.environment
    if let profile = env["LLVM_PROFILE_FILE"] {
        let dir = URL(fileURLWithPath: profile).deletingLastPathComponent()
        env["LLVM_PROFILE_FILE"] = dir.appendingPathComponent("rhgflow-%p.profraw").path
    }
    process.environment = env
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    try process.run()
    return await withCheckedContinuation { continuation in
        DispatchQueue.global().async {
            let killer = DispatchWorkItem { if process.isRunning { process.terminate() } }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
            let output = (try? pipe.fileHandleForReading.readToEnd()) ?? Data()
            process.waitUntilExit()
            killer.cancel()
            let lines = String(decoding: output, as: UTF8.self).split(separator: "\n").map(String.init)
            continuation.resume(returning: (process.terminationStatus, lines))
        }
    }
}

@Suite("LiveBridge in this process (no app.init)")
struct LiveBridgeInProcessTests {
    @Test("install returns the one bridge")
    func installOnce() {
        #expect(LiveBridge.install() === LiveBridge.install())
    }

    @Test("an unknown method is an input error")
    func unknownMethod() async {
        do {
            let _: Empty = try await LiveBridge.install().call("no.such.method", Empty())
            Issue.record("an unknown method succeeded")
        } catch {
            #expect(error.code == .input && !error.offerReport && error.reportId == nil)
        }
    }

    @Test("a method before app.init is an input error")
    func beforeInit() async {
        do {
            _ = try await LiveBridge.install().appInfo()
            Issue.record("app.info succeeded before app.init")
        } catch {
            #expect(error.code == .input)
        }
    }

    @Test("params that cannot be encoded are badParams, not sent")
    func badParams() async {
        struct NotJSON: Encodable, Sendable { var value = Double.nan }
        do {
            let _: Empty = try await LiveBridge.install().call("app.info", NotJSON())
            Issue.record("call succeeded")
        } catch {
            #expect(error == .badParams)
        }
    }

    @Test("a method name with non-ASCII and quotes reaches the core intact")
    func oddMethodName() async {
        do {
            let _: Empty = try await LiveBridge.install().call("ნ\"\\.x", Empty())
            Issue.record("call succeeded")
        } catch {
            #expect(error.code == .input)
        }
    }
}

@Suite("runMainCLI")
struct MainCLITests {
    @Test(
        "arguments that are not a CLI invocation start the UI",
        arguments: [[], ["rhg-authenticator"], ["rhg-authenticator", "--other"], ["rhg-authenticator", "-psn_0_12345"]])
    func notCLI(_ arguments: [String]) {
        #expect(runMainCLI(arguments) == nil)
    }

    // The CLI writes to stdout/stderr, so these run in RHGFlowRunner, which
    // calls runMainCLI first as the app does.
    @Test("--version prints the core's version and exits 0", .timeLimit(.minutes(1)))
    func version() async throws {
        let (status, lines) = try await runFlow(["--version"])
        #expect(status == 0)
        #expect(lines.count == 1)
        #expect(lines.first?.hasSuffix("(rhgfake)") == true, "\(lines)")
    }

    @Test("--verify-update-zip without a zip is a usage error", .timeLimit(.minutes(1)))
    func verifyUsage() async throws {
        let (status, lines) = try await runFlow(["--verify-update-zip"])
        #expect(status > 0)
        #expect(!lines.isEmpty)
        #expect(!lines.contains { $0.hasPrefix("usage: RHGFlowRunner") })
    }
}

@Suite("LiveBridge flows (RHGFlowRunner, one process each)")
struct LiveBridgeFlowTests {
    @Test(
        "each scenario passes against the rhgfake library",
        .timeLimit(.minutes(2)),
        arguments: [
            ("offline", ["no pin.request when offline", "test.panic is an internal error", "app.canQuit after a panic"]),
            ("online", [
                "sign.sign with the PIN submitted", "sign.connecting", "pin.submit with a stale requestId",
                "Georgian recipient round-trips byte for byte", "NFD recipient is signed as NFC bytes",
                "NFC name is the NFD name's credential",
            ]),
            ("pinCancel", ["pin.cancel", "sign.sign with the PIN cancelled"]),
            ("pinTimeout", [
                "sign.sign fails when the PIN prompt times out", "pin.dismiss withdraws the timed-out request",
            ]),
        ])
    func scenario(_ name: String, _ expected: [String]) async throws {
        let (status, lines) = try await runFlow([name])
        #expect(status == 0, "\(lines.joined(separator: "\n"))")
        #expect(lines.last?.hasPrefix("PASS: \(name)") == true)
        #expect(!lines.contains { $0.hasPrefix("FAIL:") })
        for check in expected {
            #expect(lines.contains("ok: \(check)"), "missing check: \(check)")
        }
        #expect(!lines.contains { $0.contains("123456") }, "the PIN appears in the output")
    }

    @Test("an unknown scenario prints usage and exits 2", .timeLimit(.minutes(1)))
    func usage() async throws {
        let (status, lines) = try await runFlow(["nope"])
        #expect(status == 2)
        #expect(lines.first?.hasPrefix("usage:") == true)
    }
}
