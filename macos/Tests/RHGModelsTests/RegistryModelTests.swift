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

    @Test("UI copy")
    func copy() {
        #expect(RegistryModel.fetchTitle == "Fetch from Server")
        #expect(RegistryModel.submitTitle == "Submit for Review")
        #expect([RegistryModel.addEntryTitle, RegistryModel.editEntryTitle] == ["Add Entry\u{2026}", "Edit Entry\u{2026}"])
        #expect(RegistryModel.fetchingStatus == "Fetching registry\u{2026}")
        #expect(
            [RegistryModel.submittingStatus, RegistryModel.submitBusyStatus]
                == ["Creating pull request\u{2026}", "Submit already in progress"])
        #expect(RegistryModel.discardConfirmation.title == "Discard Local Edits?")
        #expect(
            RegistryModel.discardConfirmation.message
                == "This will re-fetch the live registry from the server, discarding your local edits. Continue?")
        #expect(RegistryModel.discardConfirmation.isDestructive)
    }

    @Test("tooltips")
    func tooltips() {
        #expect(RegistryModel.editEntryTooltip == "Select an entry to edit it.")
        #expect(RegistryModel.fetchTooltip == "Download the latest registry (\u{2318}R)")
    }

    // MARK: Selection

    @Test("selecting a row selects it and leaves the status")
    func select() async throws {
        let registry = try await loaded(FakeBridge())
        registry.select(row: 1)
        #expect(registry.selection == 1)
        #expect(registry.status == "Loaded from registry server")
        registry.select(row: 0)
        #expect(registry.selection == 0)
    }

    @Test("selecting nil or a row out of range clears the selection", arguments: [nil, 2, -1] as [Int?])
    func selectClears(_ row: Int?) async throws {
        let registry = try await loaded(FakeBridge())
        registry.select(row: 1)
        registry.select(row: row)
        #expect(registry.selection == nil)
        #expect(!registry.canEditEntry)
    }

    @Test("cells: the core's text; \"\" past a short row's end or for a row or column out of range")
    func cells() async throws {
        let fake = FakeBridge()
        let (entry, row) = registryEntry(1)
        let short = Array(row.prefix(3))
        let snapshot = RegistrySnapshot(entries: [entry], rows: [row, short], dirty: false, loaded: true)
        let registry = try await loaded(fake, snapshot: snapshot)
        #expect(registry.cell(row: 0, column: 1) == "Authority 1")
        #expect(registry.cell(row: 0, column: 6) == "fp1")
        #expect(registry.cell(row: 1, column: 2) == "2025-Jan-01")
        #expect(registry.cell(row: 1, column: 3) == "")
        #expect(registry.cell(row: 0, column: 7) == "")
        #expect(registry.cell(row: 0, column: -1) == "")
        #expect(registry.cell(row: 2, column: 0) == "")
        #expect(registry.cell(row: -1, column: 0) == "")
    }

    @Test("Copy: a row's seven cells joined by tabs, a short row padded; \"\" out of range")
    func copyText() async throws {
        let fake = FakeBridge()
        let (entry, row) = registryEntry(1)
        let snapshot = RegistrySnapshot(
            entries: [entry], rows: [row, Array(row.prefix(2))], dirty: false, loaded: true)
        let registry = try await loaded(fake, snapshot: snapshot)
        #expect(RegistryModel.columnCount == registryColumns.count)
        #expect(registry.copyText(row: 0) == "1\tAuthority 1\t2025-Jan-01\t2030-Dec-21\t(none)\t\tfp1")
        #expect(registry.copyText(row: 1) == "1\tAuthority 1\t\t\t\t\t")
        #expect(registry.copyText(row: 2) == "")
        #expect(registry.copyText(row: -1) == "")
    }

    @Test("registry.changed clears the selection and re-reads the registry")
    func registryChanged() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        registry.select(row: 0)
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
        fake.fail(.registrySubmit, RPCError(code: .busy, message: "Another operation is in progress."))
        await registry.submitForReview()
        #expect(registry.status == RegistryModel.submitBusyStatus)
        first.release(registrySnapshot(count: 1))
        await older.value
        #expect(registry.snapshot == registrySnapshot(count: 4))
        #expect(registry.status == RegistryModel.submitBusyStatus)
    }

    @Test("registry.changed during load's snapshot read: the late read is dropped and fetching ends")
    func registryChangedDuringLoad() async throws {
        let fake = FakeBridge()
        fake.respond(.registryColumns, ColumnsResult(columns: registryColumns))
        let first = fake.hold(.registrySnapshot)
        fake.respond(.registrySnapshot, registrySnapshot(count: 3))
        let registry = RegistryModel(bridge: fake, login: LoginModel(bridge: fake))
        let load = Task { try await registry.load() }
        #expect(await settle { fake.count(.registrySnapshot) == 1 })
        await registry.registryChanged()
        #expect(registry.snapshot == registrySnapshot(count: 3))
        #expect(registry.status == "Loaded from registry server")
        #expect(!registry.isFetching)
        first.release(registrySnapshot(count: 0, loaded: false))
        try await load.value
        #expect(registry.columns == registryColumns)
        #expect(registry.snapshot == registrySnapshot(count: 3))
        #expect(registry.status == "Loaded from registry server")
        #expect(!registry.isFetching)
    }

    // MARK: Busy

    @Test("fetching during the startup load until registry.changed")
    func fetchingDuringStartupLoad() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake, snapshot: registrySnapshot(count: 0, loaded: false))
        #expect(registry.isFetching && registry.isBusy)
        fake.respond(.registrySnapshot, registrySnapshot(count: 2))
        await registry.registryChanged()
        #expect(!registry.isFetching && !registry.isBusy)
    }

    @Test("fetching while Fetch runs and until its registry.changed")
    func fetchingDuringFetch() async throws {
        let fake = FakeBridge()
        let held = fake.hold(.registryFetch)
        let registry = try await loaded(fake)
        let fetch = Task { await registry.fetchTapped() }
        #expect(await settle { fake.count(.registryFetch) == 1 })
        #expect(registry.isFetching && registry.isBusy)
        held.release(Empty())
        await fetch.value
        // Success arrives as registry.changed.
        #expect(registry.isFetching)
        fake.respond(.registrySnapshot, registrySnapshot(count: 3))
        await registry.registryChanged()
        #expect(!registry.isFetching)
    }

    @Test("a failed fetch stops fetching")
    func fetchingEndsOnFailure() async throws {
        let fake = FakeBridge()
        let held = fake.hold(.registryFetch)
        let registry = try await loaded(fake)
        let fetch = Task { await registry.fetchTapped() }
        #expect(await settle { fake.count(.registryFetch) == 1 })
        #expect(registry.isFetching)
        held.release(failing: RPCError(code: .failed, message: "offline"))
        await fetch.value
        #expect(!registry.isFetching && !registry.isBusy)
        #expect(registry.status == "Failed to load registry")
    }

    @Test("registry.changed whose re-read loses to a newer one still stops fetching")
    func fetchingEndsOnStaleRegistryChanged() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        await registry.fetchTapped()
        #expect(registry.isFetching)
        let first = fake.hold(.registrySnapshot)
        fake.respond(.registrySnapshot, registrySnapshot(count: 4))
        let changed = Task { await registry.registryChanged() }
        #expect(await settle { fake.count(.registrySnapshot) == 2 })
        #expect(!registry.isFetching)
        // A newer read (an accepted add's) overtakes registry.changed's.
        registry.addEntryTapped()
        await registry.submitEntryForm()
        first.release(registrySnapshot(count: 1))
        await changed.value
        #expect(!registry.isFetching)
        #expect(registry.snapshot == registrySnapshot(count: 4))
    }

    @Test("submitting while registry.submit runs, and no longer once it returns")
    func submittingDuringSubmit() async throws {
        let fake = FakeBridge()
        let held = fake.hold(.registrySubmit)
        let registry = try await loaded(fake)
        let submit = Task { await registry.submitForReview() }
        #expect(await settle { fake.count(.registrySubmit) == 1 })
        #expect(registry.isSubmitting && registry.isBusy)
        held.release(SubmitResult(prNumber: 3, url: ""))
        await submit.value
        #expect(!registry.isSubmitting && !registry.isBusy)
    }

    @Test("not logged in: submitting has ended before the login starts")
    func submittingEndsBeforeLogin() async throws {
        let fake = FakeBridge()
        fake.fail(.registrySubmit, RPCError(code: .notLoggedIn, message: "Not logged in to GitHub."))
        let login = fake.hold(.authLogin)
        let registry = try await loaded(fake)
        let submit = Task { await registry.submitForReview() }
        #expect(await settle { fake.count(.authLogin) == 1 })
        #expect(!registry.isSubmitting && !registry.isBusy)
        login.release(loggedIn)
        await submit.value
        #expect(!registry.isSubmitting)
    }

    @Test("a failed submit stops submitting before its alert")
    func submittingEndsOnFailure() async throws {
        let fake = FakeBridge()
        fake.fail(.registrySubmit, RPCError(code: .failed, message: "GitHub returned an error."))
        let registry = try await loaded(fake)
        await registry.submitForReview()
        #expect(registry.alert != nil)
        #expect(!registry.isSubmitting)
    }

    @Test("while a fetch runs, Fetch and Submit do nothing")
    func busyDuringFetch() async throws {
        let fake = FakeBridge()
        let held = fake.hold(.registryFetch)
        let registry = try await loaded(fake, snapshot: registrySnapshot(count: 2, dirty: true))
        await registry.fetchTapped()
        let fetch = Task { await registry.confirm() }
        #expect(await settle { fake.count(.registryFetch) == 1 })
        await registry.submitForReview()
        #expect(fake.count(.registrySubmit) == 0)
        await registry.fetchTapped()
        #expect(registry.pendingConfirmation == nil)
        #expect(fake.count(.registryFetch) == 1)
        held.release(Empty())
        await fetch.value
    }

    @Test("while a fetch runs, Add Entry and Edit Entry do nothing: the fetch replaces the core's edits")
    func noEntryFormDuringFetch() async throws {
        let fake = FakeBridge()
        let held = fake.hold(.registryFetch)
        let registry = try await loaded(fake)
        registry.select(row: 0)
        #expect(registry.canAddEntry && registry.canEditEntry)
        let fetch = Task { await registry.fetchTapped() }
        #expect(await settle { fake.count(.registryFetch) == 1 })
        #expect(!registry.canAddEntry && !registry.canEditEntry && !registry.canEditEntry(row: 1))
        registry.addEntryTapped()
        registry.editEntryTapped()
        registry.editEntry(row: 1)
        #expect(registry.entryForm == nil)
        held.release(Empty())
        await fetch.value
        await registry.registryChanged()
        #expect(registry.canAddEntry && registry.canEditEntry(row: 1))
    }

    // MARK: Fetch

    @Test("Fetch with no edits fetches at once; success arrives as registry.changed")
    func fetchClean() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        await registry.fetchTapped()
        #expect(registry.pendingConfirmation == nil)
        #expect(fake.params(.registryFetch) == ["{}"])
        #expect(registry.status == RegistryModel.fetchingStatus)
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

    @Test("Edit Entry with no selection does nothing")
    func editNoSelection() async throws {
        let registry = try await loaded(FakeBridge())
        #expect(!registry.canEditEntry)
        registry.editEntryTapped()
        #expect(registry.entryForm == nil)
        #expect(registry.alert == nil)
    }

    @Test("Edit Entry is enabled for a selected entry, and disabled once a re-read leaves the selected row out")
    func editStaleSelection() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        registry.select(row: 1)
        #expect(registry.canEditEntry)
        fake.respond(.registrySnapshot, registrySnapshot(count: 1))
        registry.addEntryTapped()
        fake.respond(.registryAddEntry, Empty())
        await registry.submitEntryForm()
        #expect(registry.selection == nil)
        #expect(!registry.canEditEntry)
        registry.editEntryTapped()
        #expect(registry.entryForm == nil)
        #expect(registry.alert == nil)
    }

    @Test("Edit Entry opens the selected entry's form")
    func editEntry() async throws {
        let registry = try await loaded(FakeBridge())
        registry.select(row: 1)
        registry.editEntryTapped()
        let form = registry.entryForm
        #expect(form?.mode == .edit(index: 1, publicKey: "KEY2="))
        #expect(form?.form == EntryForm(authority: "Authority 2", from: "2025-01-02", to: "2030-12-22", note: "", noExpiry: false))
    }

    @Test("editing a given row opens that row's form, whatever is selected")
    func editEntryRow() async throws {
        let registry = try await loaded(FakeBridge())
        registry.select(row: 1)
        #expect(registry.canEditEntry(row: 0))
        registry.editEntry(row: 0)
        #expect(registry.entryForm?.mode == .edit(index: 0, publicKey: "KEY1="))
        #expect(registry.selection == 1)
    }

    @Test("editing a row that is not an entry does nothing", arguments: [1, 2, -1])
    func editEntryRowNotEntry(_ row: Int) async throws {
        let fake = FakeBridge()
        let two = registrySnapshot(count: 2)
        let snapshot = RegistrySnapshot(entries: [two.entries[0]], rows: two.rows, dirty: false, loaded: true)
        let registry = try await loaded(fake, snapshot: snapshot)
        #expect(!registry.canEditEntry(row: row))
        registry.editEntry(row: row)
        #expect(registry.entryForm == nil)
    }

    @Test("a successful submit's re-read keeps the selection")
    func submitKeepsSelection() async throws {
        let fake = FakeBridge()
        fake.respond(.registrySubmit, SubmitResult(prNumber: 5, url: ""))
        let registry = try await loaded(fake, snapshot: registrySnapshot(count: 2, dirty: true))
        registry.select(row: 1)
        fake.respond(.registrySnapshot, registrySnapshot(count: 2))
        await registry.submitForReview()
        #expect(registry.snapshot == registrySnapshot(count: 2))
        #expect(registry.selection == 1)
    }

    @Test("an accepted add closes the sheet and re-reads the registry, keeping the selection")
    func addAccepted() async throws {
        let fake = FakeBridge()
        let registry = try await loaded(fake)
        registry.select(row: 1)
        registry.addEntryTapped()
        fake.respond(.registrySnapshot, registrySnapshot(count: 3, dirty: true))
        await registry.submitEntryForm()
        #expect(registry.entryForm == nil)
        #expect(registry.snapshot == registrySnapshot(count: 3, dirty: true))
        #expect(registry.selection == 1)
        #expect(fake.count(.registryAddEntry) == 1)
    }

    @Test("an edit the core refuses (key mismatch) keeps the sheet open with its message")
    func editRefused() async throws {
        let fake = FakeBridge()
        fake.fail(.registryUpdateEntry, RPCError(code: .failed, message: "The entry's key no longer matches; fetch again."))
        let registry = try await loaded(fake)
        registry.select(row: 0)
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
        registry.select(row: 0)
        registry.editEntryTapped()
        registry.entryForm?.authority = "Renamed"
        fake.respond(.registrySnapshot, registrySnapshot(count: 2, dirty: true))
        await registry.submitEntryForm()
        #expect(registry.entryForm == nil)
        #expect(registry.snapshot.dirty)
        #expect(registry.selection == 0)
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
        #expect(registry.status == RegistryModel.submittingStatus)
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
        #expect(registry.status == RegistryModel.submitBusyStatus)
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
        arguments: [RPCErrorCode.failed, .unknown("future")])
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
