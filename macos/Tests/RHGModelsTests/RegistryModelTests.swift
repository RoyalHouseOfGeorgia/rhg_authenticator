import Foundation
import RHGBridge
import Testing

@testable import RHGModels

@Suite("RegistryModel")
@MainActor
struct RegistryModelTests {
    let prURL = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/pull/42"

    /// A loaded model over `snapshot`.
    func loaded(
        _ fake: FakeBridge, snapshot: RegistrySnapshot = registrySnapshot(count: 2),
        openURL: @escaping @MainActor (URL) -> Void = { _ in }
    ) async throws -> RegistryModel {
        fake.respond(.registryColumns, ColumnsResult(columns: registryColumns))
        fake.respond(.registrySnapshot, snapshot)
        let login = LoginModel(bridge: fake)
        let registry = RegistryModel(bridge: fake, login: login, clock: { lateNewYearsDay }, openURL: openURL)
        try await registry.load()
        // Later reads answer from each test's own script.
        fake.reset(.registrySnapshot)
        return registry
    }

    @Test("UI copy matches the Fyne app")
    func copy() {
        #expect(RegistryModel.fetchTitle == "Fetch from Server")
        #expect(RegistryModel.submitTitle == "Submit for Review")
        #expect([RegistryModel.addEntryTitle, RegistryModel.editEntryTitle] == ["Add Entry", "Edit Entry"])
        #expect(
            [RegistryModel.loadedStatus, RegistryModel.fetchingStatus, RegistryModel.loadFailedStatus]
                == ["Loaded from registry server", "Fetching...", "Failed to load registry"])
        #expect(RegistryModel.discardConfirmation.title == "Discard Local Edits?")
        #expect(
            RegistryModel.discardConfirmation.message
                == "This will re-fetch the live registry from the server, discarding your local edits. Continue?")
        #expect(RegistryModel.discardConfirmation.isDestructive)
    }

    @Test("load: columns, snapshot, and the loaded status")
    func load() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        #expect(registry.columns == registryColumns)
        #expect(registry.snapshot == registrySnapshot(count: 2))
        #expect(registry.status == "Loaded from registry server")
        #expect(registry.selection == nil && registry.entryForm == nil && registry.alert == nil)
        #expect(fake.methods == ["registry.columns", "registry.snapshot"])
    }

    @Test("load before the registry arrived: Fetching...")
    func loadNotLoaded() async throws {
        let registry = try await loaded(FakeBridge(), snapshot: registrySnapshot(count: 0, loaded: false))
        #expect(registry.status == "Fetching...")
    }

    @Test("load failures throw the core's error", arguments: [RPCMethod.registryColumns, .registrySnapshot])
    func loadFailure(_ failing: RPCMethod) async {
        let fake = FakeBridge()
        fake.respond(.registryColumns, ColumnsResult(columns: registryColumns))
        fake.respond(.registrySnapshot, registrySnapshot(count: 1))
        fake.reset(failing)
        fake.fail(failing, RPCError(code: .internal, message: "broke"))
        let registry = RegistryModel(bridge: fake, login: LoginModel(bridge: fake))
        await #expect(throws: RPCError(code: .internal, message: "broke")) { try await registry.load() }
    }

    // MARK: Selection

    @Test("selecting a cell shows its text; an empty cell leaves the status; out of range is ignored")
    func select() async throws {
        let registry = try await loaded(FakeBridge())
        registry.select(row: 1, column: 1)
        #expect(registry.selection == RegistryModel.Cell(row: 1, column: 1))
        #expect(registry.status == "Authority 2")
        registry.select(row: 0, column: 5)  // the note column is empty
        #expect(registry.selection == RegistryModel.Cell(row: 0, column: 5))
        #expect(registry.status == "Authority 2")
        registry.select(row: 2, column: 0)
        registry.select(row: 0, column: 7)
        registry.select(row: -1, column: 0)
        #expect(registry.selection == RegistryModel.Cell(row: 0, column: 5))
    }

    @Test("registry.changed clears the selection and re-reads the registry")
    func registryChanged() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        registry.select(row: 0, column: 0)
        fake.respond(.registrySnapshot, registrySnapshot(count: 3))
        await registry.registryChanged()
        #expect(registry.selection == nil)
        #expect(registry.snapshot == registrySnapshot(count: 3))
        #expect(registry.status == "Loaded from registry server")
    }

    @Test("registry.changed without a loaded registry: Failed to load registry")
    func registryChangedFailed() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake, snapshot: registrySnapshot(count: 0, loaded: false))
        fake.respond(.registrySnapshot, registrySnapshot(count: 0, loaded: false))
        await registry.registryChanged()
        #expect(registry.status == "Failed to load registry")
        #expect(fake.count(.registrySnapshot) == 2)
    }

    @Test("a failed snapshot read keeps the table")
    func snapshotReadFailure() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        fake.fail(.registrySnapshot, RPCError(code: .internal, message: "x"))
        await registry.registryChanged()
        #expect(registry.snapshot == registrySnapshot(count: 2))
        #expect(registry.status == "Loaded from registry server")
    }

    @Test("an older snapshot read finishing last is dropped, status included")
    func staleSnapshot() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        let first = fake.hold(.registrySnapshot)
        fake.respond(.registrySnapshot, registrySnapshot(count: 4))
        let older = Task { await registry.registryChanged() }
        #expect(await settle { fake.count(.registrySnapshot) == 2 })
        await registry.registryChanged()
        #expect(registry.snapshot == registrySnapshot(count: 4))
        // A status set after the newer read stays when the older one lands.
        registry.select(row: 3, column: 1)
        #expect(registry.status == "Authority 4")
        first.release(registrySnapshot(count: 1))
        await older.value
        #expect(registry.snapshot == registrySnapshot(count: 4))
        #expect(registry.status == "Authority 4")
    }

    // MARK: Fetch

    @Test("Fetch with no edits fetches at once; success arrives as registry.changed")
    func fetchClean() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        await registry.fetchTapped()
        #expect(registry.pendingConfirmation == nil)
        #expect(fake.params(.registryFetch) == ["{}"])
        #expect(registry.status == "Fetching...")
    }

    @Test("Fetch with edits asks first; confirming fetches")
    func fetchDirtyConfirmed() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake, snapshot: registrySnapshot(count: 2, dirty: true))
        await registry.fetchTapped()
        #expect(registry.pendingConfirmation == RegistryModel.discardConfirmation)
        #expect(fake.count(.registryFetch) == 0)
        await registry.confirm()
        #expect(registry.pendingConfirmation == nil)
        #expect(fake.count(.registryFetch) == 1)
        // A second confirm has nothing to run.
        await registry.confirm()
        #expect(fake.count(.registryFetch) == 1)
    }

    @Test("Fetch with edits, declined: nothing is fetched")
    func fetchDirtyDeclined() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake, snapshot: registrySnapshot(count: 2, dirty: true))
        await registry.fetchTapped()
        registry.dismissConfirmation()
        #expect(registry.pendingConfirmation == nil)
        await registry.confirm()
        #expect(fake.count(.registryFetch) == 0)
        #expect(registry.status == "Loaded from registry server")
    }

    @Test("a failed fetch: Failed to load registry")
    func fetchFailure() async throws {
        let fake = FakeBridge()
        fake.fail(.registryFetch, RPCError(code: .failed, message: "offline"))
        let registry = try await loaded(fake)
        await registry.fetchTapped()
        #expect(registry.status == "Failed to load registry")
    }

    // MARK: Add and Edit

    @Test("Add Entry opens an add form; Cancel closes it")
    func addEntry() async throws {
        let registry = try await loaded(FakeBridge())
        registry.addEntryTapped()
        let form = registry.entryForm
        #expect(form?.mode == .add)
        #expect(form.map { DisplayDate.ymd($0.from) } == "2026-01-01")
        registry.cancelEntryForm()
        #expect(registry.entryForm == nil)
    }

    @Test("Edit Entry with no selection: No entry selected")
    func editNoSelection() async throws {
        let registry = try await loaded(FakeBridge())
        registry.editEntryTapped()
        #expect(registry.entryForm == nil)
        #expect(registry.alert == AlertState(title: "Edit Entry", message: "No entry selected"))
        await registry.alertDismissed()
        #expect(registry.alert == nil)
    }

    @Test("Edit Entry after the selected row went away: No entry selected")
    func editStaleSelection() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        registry.select(row: 1, column: 0)
        fake.respond(.registrySnapshot, registrySnapshot(count: 1))
        registry.addEntryTapped()
        fake.respond(.registryAddEntry, Empty())
        await registry.submitEntryForm()
        #expect(registry.selection == nil)
        registry.editEntryTapped()
        #expect(registry.alert == AlertState(title: "Edit Entry", message: "No entry selected"))
    }

    @Test("Edit Entry opens the selected entry's form")
    func editEntry() async throws {
        let registry = try await loaded(FakeBridge())
        registry.select(row: 1, column: 3)
        registry.editEntryTapped()
        let form = registry.entryForm
        #expect(form?.mode == .edit(index: 1, publicKey: "KEY2="))
        #expect(form?.form == EntryForm(authority: "Authority 2", from: "2025-01-02", to: "2030-12-22", note: "", noExpiry: false))
    }

    @Test("an accepted add closes the sheet and re-reads the registry, keeping the selection")
    func addAccepted() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        registry.select(row: 1, column: 1)
        registry.addEntryTapped()
        fake.respond(.registrySnapshot, registrySnapshot(count: 3, dirty: true))
        await registry.submitEntryForm()
        #expect(registry.entryForm == nil)
        #expect(registry.snapshot == registrySnapshot(count: 3, dirty: true))
        #expect(registry.selection == RegistryModel.Cell(row: 1, column: 1))
        #expect(fake.count(.registryAddEntry) == 1)
    }

    @Test("an edit the core refuses (key mismatch) keeps the sheet open with its message")
    func editRefused() async throws {
        let fake = FakeBridge()
        fake.fail(.registryUpdateEntry, RPCError(code: .failed, message: "The entry's key no longer matches; fetch again."))
        let registry = try await loaded(fake)
        registry.select(row: 0, column: 0)
        registry.editEntryTapped()
        let form = registry.entryForm
        await registry.submitEntryForm()
        #expect(registry.entryForm != nil && registry.entryForm === form)
        #expect(form?.errorText == "The entry's key no longer matches; fetch again.")
        #expect(fake.count(.registrySnapshot) == 1)
        #expect(fake.params(.registryUpdateEntry).first?.contains(#""index":0,"publicKey":"KEY1=""#) == true)
    }

    @Test("an accepted edit closes the sheet and keeps the selection")
    func editAccepted() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake, snapshot: registrySnapshot(count: 2))
        registry.select(row: 0, column: 1)
        registry.editEntryTapped()
        registry.entryForm?.authority = "Renamed"
        fake.respond(.registrySnapshot, registrySnapshot(count: 2, dirty: true))
        await registry.submitEntryForm()
        #expect(registry.entryForm == nil)
        #expect(registry.snapshot.dirty)
        #expect(registry.selection == RegistryModel.Cell(row: 0, column: 1))
        #expect(fake.params(.registryUpdateEntry).first?.contains(#""authority":"Renamed""#) == true)
    }

    @Test("submitting with no sheet up does nothing")
    func submitNoForm() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        await registry.submitEntryForm()
        #expect(fake.count(.registryAddEntry) == 0 && fake.count(.registryUpdateEntry) == 0)
    }

    @Test("a sheet cancelled while its add runs is not closed again on success")
    func cancelledDuringSubmit() async throws {
        let fake = FakeBridge()
        let held = fake.hold(.registryAddEntry)
        let registry = try await loaded(fake)
        registry.addEntryTapped()
        let submit = Task { await registry.submitEntryForm() }
        #expect(await settle { fake.count(.registryAddEntry) == 1 })
        registry.cancelEntryForm()
        registry.addEntryTapped()
        let second = registry.entryForm
        fake.respond(.registrySnapshot, registrySnapshot(count: 3, dirty: true))
        held.release(Empty())
        await submit.value
        #expect(registry.entryForm === second && second != nil)
        #expect(registry.snapshot == registrySnapshot(count: 3, dirty: true))
    }

    // MARK: Submit for Review

    @Test("Submit with no entries calls nothing")
    func submitEmpty() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake, snapshot: registrySnapshot(count: 0))
        await registry.submitForReview()
        #expect(fake.count(.registrySubmit) == 0)
        #expect(registry.status == "Loaded from registry server")
    }

    @Test("Submit success with a URL: PR status, then Open in browser? opens only that URL")
    func submitWithURL() async throws {
        let fake = FakeBridge()
        let held = fake.hold(.registrySubmit)
        let urls = URLRecorder()
        let registry = try await loaded(fake, openURL: urls.open)
        let submit = Task { await registry.submitForReview() }
        #expect(await settle { fake.count(.registrySubmit) == 1 })
        #expect(registry.status == "Creating pull request...")
        held.release(SubmitResult(prNumber: 42, url: prURL))
        await submit.value
        #expect(registry.status == "PR #42 created")
        #expect(
            registry.pendingConfirmation
                == Confirmation(
                    title: "Pull Request Created", message: "PR #42 has been created.\n\nOpen in browser?",
                    confirmTitle: "Open in Browser", cancelTitle: "Close"))
        #expect(registry.alert == nil)
        #expect(urls.opened.isEmpty)
        await registry.confirm()
        #expect(urls.opened == [try #require(URL(string: prURL))])
        #expect(registry.pendingConfirmation == nil)
    }

    @Test("a successful submit re-reads the registry, so a later Fetch does not ask")
    func submitCleansDirty() async throws {
        let fake = FakeBridge()
        fake.respond(.registrySubmit, SubmitResult(prNumber: 5, url: ""))
        let registry = try await loaded(fake, snapshot: registrySnapshot(count: 2, dirty: true))
        fake.respond(.registrySnapshot, registrySnapshot(count: 2))
        await registry.submitForReview()
        #expect(registry.snapshot == registrySnapshot(count: 2))
        await registry.alertDismissed()
        await registry.fetchTapped()
        #expect(registry.pendingConfirmation == nil)
        #expect(fake.count(.registryFetch) == 1)
    }

    @Test("Submit success, browser declined: nothing opens")
    func submitDeclined() async throws {
        let fake = FakeBridge()
        fake.respond(.registrySubmit, SubmitResult(prNumber: 7, url: prURL))
        let urls = URLRecorder()
        let registry = try await loaded(fake, openURL: urls.open)
        await registry.submitForReview()
        registry.dismissConfirmation()
        await registry.confirm()
        #expect(urls.opened.isEmpty)
    }

    @Test("Submit success without a URL: an information alert, nothing to open")
    func submitWithoutURL() async throws {
        let fake = FakeBridge()
        fake.respond(.registrySubmit, SubmitResult(prNumber: 9, url: ""))
        let urls = URLRecorder()
        let registry = try await loaded(fake, openURL: urls.open)
        await registry.submitForReview()
        #expect(registry.status == "PR #9 created")
        #expect(registry.pendingConfirmation == nil)
        #expect(registry.alert == AlertState(title: "Pull Request Created", message: "PR #9 has been created."))
        await registry.alertDismissed()
        #expect(urls.opened.isEmpty)
        #expect(fake.count(.authLogin) == 0)
    }

    @Test("not logged in: Submit starts the login, whose status texts show")
    func submitNotLoggedIn() async throws {
        let fake = FakeBridge()
        fake.fail(.registrySubmit, RPCError(code: .notLoggedIn, message: "Not logged in to GitHub."))
        fake.respond(.authLogin, loggedIn)
        let registry = try await loaded(fake)
        await registry.submitForReview()
        #expect(fake.methods.suffix(2) == ["registry.submit", "auth.login"])
        #expect(registry.status == "Logged in as @octocat")
        #expect(registry.alert == nil)
    }

    @Test("busy: Submit already in progress")
    func submitBusy() async throws {
        let fake = FakeBridge()
        fake.fail(.registrySubmit, RPCError(code: .busy, message: "Another operation is in progress."))
        let registry = try await loaded(fake)
        await registry.submitForReview()
        #expect(registry.status == "Submit already in progress")
        #expect(registry.alert == nil)
    }

    @Test("session expired: the alert, then the login only once it is dismissed")
    func submitSessionExpired() async throws {
        let fake = FakeBridge()
        let message = "Your GitHub session expired. Please log in again."
        fake.fail(.registrySubmit, RPCError(code: .sessionExpired, message: message))
        fake.respond(.authLogin, loggedIn)
        let registry = try await loaded(fake)
        await registry.submitForReview()
        #expect(registry.alert == AlertState(title: "Session Expired", message: message))
        #expect(registry.status == "")
        #expect(fake.count(.authLogin) == 0)
        await registry.alertDismissed()
        #expect(registry.alert == nil)
        #expect(fake.count(.authLogin) == 1)
        #expect(registry.status == "Logged in as @octocat")
        // The follow-up runs once.
        await registry.alertDismissed()
        #expect(fake.count(.authLogin) == 1)
    }

    @Test("registry changed upstream: Registry Changed with the core's message")
    func submitRegistryChanged() async throws {
        let fake = FakeBridge()
        let message = "The registry on GitHub doesn't match the copy you loaded (it changed since)."
        fake.fail(.registrySubmit, RPCError(code: .registryChanged, message: message))
        let registry = try await loaded(fake)
        await registry.submitForReview()
        #expect(registry.alert == AlertState(title: "Registry Changed", message: message))
        #expect(registry.status == "")
    }

    @Test(
        "any other failure: Submission Failed offering the error log",
        arguments: [RPCErrorCode.failed, .internal, .unknown("future")])
    func submitFailed(_ code: RPCErrorCode) async throws {
        let fake = FakeBridge()
        fake.fail(.registrySubmit, RPCError(code: code, message: "GitHub returned an error."))
        let registry = try await loaded(fake)
        await registry.submitForReview()
        #expect(
            registry.alert
                == AlertState(title: "Submission Failed", message: "GitHub returned an error.", offersErrorLogExport: true))
        #expect(registry.status == "")
        await registry.alertDismissed()
        #expect(registry.alert == nil)
        #expect(fake.count(.authLogin) == 0)
    }
}
