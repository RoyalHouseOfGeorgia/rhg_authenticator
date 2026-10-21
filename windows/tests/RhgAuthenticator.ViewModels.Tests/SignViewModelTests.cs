using System.Text;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class SignViewModelTests
{
    private static readonly string s_credentialJson =
        "{\"date\":\"2026-01-01\",\"detail\":\"Knight\",\"honor\":\"Order of the Eagle\",\"recipient\":\"Jose\u0301\"}";

    private readonly FakeBridge _fake = new();
    private readonly FakeFileSave _fileSave = new();
    private readonly FakeClipboard _clipboard = new();
    private readonly FakeUrlOpener _urls = new();
    private readonly AlertQueue _alerts = new();

    /// <summary>A view model whose form is filled in, with the clock at <see cref="Fixtures.LateNewYearsDay"/>.</summary>
    private SignViewModel FilledModel()
    {
        var model = new SignViewModel(_fake, _fileSave, _clipboard, _urls, _alerts, new FixedClock(Fixtures.LateNewYearsDay))
        {
            Recipient = "Jose\u0301", // NFD; the core signs NFC
            Honor = "Order of the Eagle",
            Detail = "Knight",
        };
        return model;
    }

    [Fact]
    public void CopyMatchesTheFyneApp()
    {
        Assert.Equal("Recipient", SignViewModel.RecipientLabel);
        Assert.Equal("Honor", SignViewModel.HonorLabel);
        Assert.Equal("Detail", SignViewModel.DetailLabel);
        Assert.Equal("Date", SignViewModel.DateLabel);
        Assert.Equal("Select honor title", SignViewModel.HonorPlaceholder);
        Assert.Equal("Full name of recipient", SignViewModel.RecipientPlaceholder);
        Assert.Equal("Specific distinction or rank", SignViewModel.DetailPlaceholder);
        Assert.Equal("Sign Credential", SignViewModel.SignTitle);
        Assert.Equal(
            [.. "Print QR at minimum 3"u8, 0xC3, 0x97, .. "3 cm"u8], // U+00D7
            Encoding.UTF8.GetBytes(SignViewModel.PrintAdvisory));
        Assert.Equal(
            ["Save SVG", "Save PNG", "Copy URL"],
            [SignViewModel.SaveSvgTitle, SignViewModel.SavePngTitle, SignViewModel.CopyUrlTitle]);
        Assert.Equal([.. "Reporting"u8, 0xE2, 0x80, 0xA6], Encoding.UTF8.GetBytes(ReportState.ReportingTitle)); // U+2026
        Assert.Equal("Preparing to sign...", SignViewModel.PreparingStatus);
        Assert.Equal("Connecting to YubiKey...", SignViewModel.ConnectingStatus);
    }

    [Fact]
    public void RequiresItsServices()
    {
        Assert.Throws<ArgumentNullException>(() => new SignViewModel(null!, _fileSave, _clipboard, _urls, _alerts));
        Assert.Throws<ArgumentNullException>(() => new SignViewModel(_fake, null!, _clipboard, _urls, _alerts));
        Assert.Throws<ArgumentNullException>(() => new SignViewModel(_fake, _fileSave, null!, _urls, _alerts));
        Assert.Throws<ArgumentNullException>(() => new SignViewModel(_fake, _fileSave, _clipboard, null!, _alerts));
        Assert.Throws<ArgumentNullException>(() => new SignViewModel(_fake, _fileSave, _clipboard, _urls, null!));
    }

    [Fact]
    public async Task AValidationErrorShowsTheCoresMessageAndNeverSigns()
    {
        _fake.Fail(RpcMethod.SignValidate, new RpcException(RpcErrorCode.Failed, "Recipient name is required."));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        Assert.Equal("Recipient name is required.", model.Status);
        Assert.False(model.IsBusy);
        Assert.Null(model.Result);
        Assert.Equal([RpcMethod.SignValidate], _fake.Methods);
        Assert.Equal([s_credentialJson], _fake.Params(RpcMethod.SignValidate));
    }

    [Fact]
    public async Task SuccessHoldsTheSignedFieldsNotTheFormText()
    {
        var signed = Fixtures.SignResult();
        _fake.Respond(RpcMethod.SignSign, signed);
        var model = FilledModel();
        Assert.False(model.HasResult);
        Assert.Null(model.QrPreviewPng);
        Assert.False(model.SaveSvgCommand.CanExecute(null));
        Assert.False(model.CopyUrlCommand.CanExecute(null));
        await model.SignCommand.ExecuteAsync(null);
        Assert.Equal("Signed successfully.", model.Status);
        Assert.Null(_alerts.Current);
        Assert.False(model.IsBusy);
        Assert.Same(signed, model.Result);
        Assert.True(model.HasResult);
        Assert.Same(Fixtures.Png, model.QrPreviewPng);
        Assert.Equal("Jos\u00E9", model.Result!.Recipient);
        Assert.NotEqual(model.Recipient, model.Result.Recipient);
        Assert.Equal([RpcMethod.SignValidate, RpcMethod.SignSign], _fake.Methods);
        Assert.Equal([s_credentialJson], _fake.Params(RpcMethod.SignSign));
        Assert.IsType<ReportState.Unavailable>(model.Report);
        Assert.True(model.SaveSvgCommand.CanExecute(null));
        Assert.True(model.SavePngCommand.CanExecute(null));
        Assert.True(model.CopyUrlCommand.CanExecute(null));
    }

    [Fact]
    public async Task AnExistingCredentialShowsAlreadyIssued()
    {
        _fake.Respond(RpcMethod.SignSign, Fixtures.SignResult(existing: true, warning: "ignored"));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        Assert.Equal("Credential previously generated.", model.Status);
        Assert.Equal(
            new AlertState("Already Issued", "Credential previously generated, no new record created."), _alerts.Current);
        Assert.True(model.Result?.Existing);
    }

    [Fact]
    public async Task AWarningShowsNotRecorded()
    {
        _fake.Respond(RpcMethod.SignSign, Fixtures.SignResult(warning: "Core: signed, but the issuance log could not be written."));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        Assert.Equal("Core: signed, but the issuance log could not be written.", model.Status);
        Assert.Equal(
            new AlertState("Not Recorded", "Core: signed, but the issuance log could not be written."), _alerts.Current);
        Assert.NotNull(model.Result);
        _alerts.Dismiss();
        Assert.Null(_alerts.Current);
    }

    [Theory]
    [InlineData(RpcErrorCode.Failed, "No YubiKey detected.")]
    [InlineData(RpcErrorCode.Busy, "Core: another signing is in progress.")]
    [InlineData(RpcErrorCode.Internal, "An internal error occurred — please restart")]
    public async Task AnErrorWithoutOfferReportShowsItsMessageVerbatim(RpcErrorCode code, string message)
    {
        _fake.Fail(RpcMethod.SignSign, new RpcException(code, message));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        Assert.Equal(message, model.Status);
        Assert.IsType<ReportState.Unavailable>(model.Report);
        Assert.False(model.ReportIssueCommand.CanExecute(null));
        Assert.Null(model.Result);
        Assert.False(model.IsBusy);
    }

    [Fact]
    public async Task OfferReportWithoutAReportIdOffersNoButton()
    {
        _fake.Fail(RpcMethod.SignSign, new RpcException(RpcErrorCode.Failed, "m", offerReport: true));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        Assert.IsType<ReportState.Unavailable>(model.Report);
    }

    [Fact]
    public async Task ACancelledPinPromptClearsTheStatus()
    {
        _fake.Fail(RpcMethod.SignSign, new RpcException(RpcErrorCode.Cancelled, "cancelled"));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        Assert.Equal("", model.Status);
        Assert.False(model.IsBusy);
    }

    [Fact]
    public async Task ReportIssueReportingThenFiled()
    {
        _fake.Fail(
            RpcMethod.SignSign, new RpcException(RpcErrorCode.Failed, "Signing failed.", offerReport: true, reportId: "r1"));
        var held = _fake.Hold(RpcMethod.SignReportError);
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        Assert.Equal("Signing failed.", model.Status);
        Assert.Equal(new ReportState.Available("r1"), model.Report);
        Assert.True(model.ReportIssueCommand.CanExecute(null));

        var reporting = model.ReportIssueCommand.ExecuteAsync(null);
        Assert.Equal(1, _fake.Count(RpcMethod.SignReportError));
        Assert.Equal(new ReportState.Reporting("r1"), model.Report);
        Assert.Equal("Reporting\u2026", model.Report.ButtonTitle);
        Assert.False(model.ReportIssueCommand.CanExecute(null));
        await model.ReportIssueCommand.ExecuteAsync(null); // ignored while reporting
        held.Release(new ReportResult(true, ""));
        await reporting;

        Assert.IsType<ReportState.Reported>(model.Report);
        Assert.Equal("Issue Reported", model.Report.ButtonTitle);
        Assert.False(model.ReportIssueCommand.CanExecute(null));
        Assert.Empty(_urls.Opened);
        await model.ReportIssueCommand.ExecuteAsync(null);
        Assert.Equal(["{\"reportId\":\"r1\"}"], _fake.Params(RpcMethod.SignReportError));
    }

    [Fact]
    public async Task ReportIssueFiledOpensTheIssueTheCoreReturns()
    {
        const string issue = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues/42";
        _fake.Fail(RpcMethod.SignSign, new RpcException(RpcErrorCode.Failed, "m", offerReport: true, reportId: "r6"));
        _fake.Respond(RpcMethod.SignReportError, new ReportResult(true, issue));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        await model.ReportIssueCommand.ExecuteAsync(null);
        Assert.Equal([new Uri(issue)], _urls.Opened);
        Assert.IsType<ReportState.Reported>(model.Report);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task ABrowserThatWillNotOpenShowsWhyAndTheReportStillCounts()
    {
        const string issue = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues/43";
        _fake.Fail(RpcMethod.SignSign, new RpcException(RpcErrorCode.Failed, "m", offerReport: true, reportId: "r7"));
        _fake.Respond(RpcMethod.SignReportError, new ReportResult(true, issue));
        _urls.Failure = "Host: no browser.";
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        await model.ReportIssueCommand.ExecuteAsync(null);
        Assert.IsType<ReportState.Reported>(model.Report);
        Assert.Equal(new AlertState("Error", "Host: no browser."), _alerts.Current);
    }

    [Fact]
    public async Task ReportIssueNotFiledOpensTheCoresFormAndReEnables()
    {
        const string form = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues/new?title=Sign%20failure";
        _fake.Fail(RpcMethod.SignSign, new RpcException(RpcErrorCode.Failed, "m", offerReport: true, reportId: "r2"));
        _fake.Respond(RpcMethod.SignReportError, new ReportResult(false, form));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        await model.ReportIssueCommand.ExecuteAsync(null);
        Assert.Equal([new Uri(form)], _urls.Opened);
        Assert.Equal(new ReportState.Available("r2"), model.Report);
        Assert.Equal("Report Issue", model.Report.ButtonTitle);
        Assert.True(model.ReportIssueCommand.CanExecute(null));
        Assert.Null(_alerts.Current);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a url")]
    [InlineData("/relative/path")]
    [InlineData("http://github.com/o/r/issues/new")]
    [InlineData("file:///C:/Windows/System32/calc.exe")]
    public async Task OnlyAnAbsoluteHttpsUrlIsOpened(string url)
    {
        _fake.Fail(RpcMethod.SignSign, new RpcException(RpcErrorCode.Failed, "m", offerReport: true, reportId: "r5"));
        _fake.Respond(RpcMethod.SignReportError, new ReportResult(false, url));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        await model.ReportIssueCommand.ExecuteAsync(null);
        Assert.Empty(_urls.Opened);
        Assert.Equal(new ReportState.Available("r5"), model.Report);
    }

    [Theory]
    [InlineData("Could not reach GitHub.")]
    // The core gives up on GitHub after its report timeout and says so.
    [InlineData("Core: GitHub did not answer in time.")]
    public async Task ReportIssueFailureShowsTheCoresMessageAndReEnablesWithoutOpeningAnything(string message)
    {
        _fake.Fail(RpcMethod.SignSign, new RpcException(RpcErrorCode.Failed, "m", offerReport: true, reportId: "r3"));
        _fake.Fail(RpcMethod.SignReportError, new RpcException(RpcErrorCode.Failed, message));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        await model.ReportIssueCommand.ExecuteAsync(null);
        Assert.Empty(_urls.Opened);
        Assert.Equal(new ReportState.Available("r3"), model.Report);
        Assert.Equal(new AlertState("Error", message), _alerts.Current);
    }

    [Fact]
    public async Task ANewSigningDuringAReportKeepsItsOwnReportState()
    {
        _fake.Fail(RpcMethod.SignSign, new RpcException(RpcErrorCode.Failed, "m", offerReport: true, reportId: "r4"));
        _fake.Respond(RpcMethod.SignSign, Fixtures.SignResult(existing: true)); // the second signing
        var held = _fake.Hold(RpcMethod.SignReportError);
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        var reporting = model.ReportIssueCommand.ExecuteAsync(null);
        Assert.Equal(1, _fake.Count(RpcMethod.SignReportError));
        await model.SignCommand.ExecuteAsync(null);
        Assert.IsType<ReportState.Unavailable>(model.Report);
        var alreadyIssued = _alerts.Current;
        Assert.Equal("Already Issued", alreadyIssued?.Title);
        held.ReleaseFailing(new RpcException(RpcErrorCode.Failed, "offline"));
        await reporting;
        Assert.IsType<ReportState.Unavailable>(model.Report);
        Assert.Same(alreadyIssued, _alerts.Current);
        _alerts.Dismiss();
        Assert.Null(_alerts.Current); // the stale report failure posted nothing
    }

    [Fact]
    public async Task BusyDisablesSignAndIgnoresASecondSign()
    {
        var held = _fake.Hold(RpcMethod.SignSign);
        var model = FilledModel();
        Assert.True(model.SignCommand.CanExecute(null));
        var canExecuteChanges = 0;
        model.SignCommand.CanExecuteChanged += (_, _) => canExecuteChanges++;
        var signing = model.SignCommand.ExecuteAsync(null);
        Assert.Equal(1, _fake.Count(RpcMethod.SignSign));
        Assert.True(model.IsBusy);
        Assert.False(model.SignCommand.CanExecute(null));
        Assert.Equal("Preparing to sign...", model.Status);
        await model.SignCommand.ExecuteAsync(null);
        Assert.Equal(1, _fake.Count(RpcMethod.SignValidate));

        held.Release(Fixtures.SignResult());
        await signing;
        Assert.False(model.IsBusy);
        Assert.True(model.SignCommand.CanExecute(null));
        Assert.True(canExecuteChanges >= 2);
        Assert.Equal(1, _fake.Count(RpcMethod.SignSign));
    }

    [Fact]
    public async Task StatusSequencePreparingConnectingResult()
    {
        var held = _fake.Hold(RpcMethod.SignSign);
        var app = await Fixtures.StartedApp(_fake);
        var model = app.Sign;
        model.Honor = "Order of the Eagle";
        var statuses = new List<string>();
        model.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(SignViewModel.Status))
            {
                lock (statuses)
                {
                    statuses.Add(model.Status);
                }
            }
        };
        var signing = model.SignCommand.ExecuteAsync(null);
        Assert.Equal("Preparing to sign...", model.Status);
        _fake.Emit(new BridgeEvent.SignConnecting());
        Assert.True(await Fixtures.Settle(() => model.Status == "Connecting to YubiKey..."));
        held.Release(Fixtures.SignResult());
        await signing;
        Assert.False(model.IsBusy);
        Assert.Equal(["Preparing to sign...", "Connecting to YubiKey...", "Signed successfully."], statuses);

        // A late connecting event is ignored (events are handled in order).
        _fake.Emit(new BridgeEvent.SignConnecting());
        _fake.Emit(new BridgeEvent.AppInternalError());
        Assert.True(await Fixtures.Settle(() => app.Alerts.Current is not null));
        Assert.Equal("Signed successfully.", model.Status);
    }

    [Fact]
    public async Task ANewSigningClearsThePreviousResult()
    {
        _fake.Respond(RpcMethod.SignSign, Fixtures.SignResult());
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        Assert.NotNull(model.Result);
        _fake.Fail(RpcMethod.SignValidate, new RpcException(RpcErrorCode.Failed, "invalid"));
        await model.SignCommand.ExecuteAsync(null);
        Assert.Null(model.Result);
        Assert.False(model.SaveSvgCommand.CanExecute(null));
    }

    [Fact]
    public void TheDateDefaultsToTheClocksUtcDateAroundMidnight()
    {
        var late = new SignViewModel(_fake, _fileSave, _clipboard, _urls, _alerts, new FixedClock(Fixtures.LateNewYearsDay));
        Assert.Equal(new DateTime(2026, 1, 1), late.Date);
        Assert.Equal("2026-01-01", late.DateString);
        Assert.Equal("2026-Jan-01", late.DisplayDateText);

        // 2026-01-02T01:30 in Tbilisi (+04:00) is still 2026-01-01 in UTC.
        var tbilisi = new DateTimeOffset(2026, 1, 2, 1, 30, 0, TimeSpan.FromHours(4));
        Assert.Equal("2026-01-01", new SignViewModel(_fake, _fileSave, _clipboard, _urls, _alerts, new FixedClock(tbilisi)).DateString);

        var lastTick = new DateTimeOffset(2026, 1, 1, 23, 59, 59, TimeSpan.Zero).AddTicks(TimeSpan.TicksPerSecond - 1);
        Assert.Equal("2026-01-01", new SignViewModel(_fake, _fileSave, _clipboard, _urls, _alerts, new FixedClock(lastTick)).DateString);
        var midnight = new DateTimeOffset(2026, 1, 2, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal("2026-01-02", new SignViewModel(_fake, _fileSave, _clipboard, _urls, _alerts, new FixedClock(midnight)).DateString);

        // 2026-01-01T20:00 in Los Angeles (-08:00) is already 2026-01-02 in UTC.
        var losAngeles = new DateTimeOffset(2026, 1, 1, 20, 0, 0, TimeSpan.FromHours(-8));
        Assert.Equal("2026-01-02", new SignViewModel(_fake, _fileSave, _clipboard, _urls, _alerts, new FixedClock(losAngeles)).DateString);
    }

    [Fact]
    public async Task ThePickedDateIsSignedAsACalendarDate()
    {
        var model = FilledModel();
        var changed = new List<string?>();
        model.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        model.Date = new DateTime(2026, 3, 15, 13, 45, 0);
        Assert.Equal(new DateTime(2026, 3, 15), model.Date);
        Assert.Equal("2026-03-15", model.DateString);
        Assert.Equal("2026-Mar-15", model.DisplayDateText);
        Assert.Equal(
            [
                nameof(SignViewModel.Date), nameof(SignViewModel.SelectedDate), nameof(SignViewModel.DateString),
                nameof(SignViewModel.DisplayDateText),
            ],
            changed);
        model.Date = new DateTime(2026, 3, 15, 1, 0, 0);
        Assert.Equal(4, changed.Count);

        _fake.Fail(RpcMethod.SignValidate, new RpcException(RpcErrorCode.Failed, "x"));
        await model.SignCommand.ExecuteAsync(null);
        Assert.Contains("\"date\":\"2026-03-15\"", _fake.Params(RpcMethod.SignValidate)[0], StringComparison.Ordinal);
    }

    [Fact]
    public void ClearingThePickersSelectionKeepsTheDate()
    {
        var model = FilledModel();
        var changed = new List<string?>();
        model.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        model.SelectedDate = new DateTime(2026, 3, 15, 13, 0, 0);
        Assert.Equal(new DateTime(2026, 3, 15), model.Date);
        Assert.Equal(new DateTime(2026, 3, 15), model.SelectedDate);
        Assert.Contains(nameof(SignViewModel.SelectedDate), changed);
        changed.Clear();
        model.SelectedDate = null;
        Assert.Equal(new DateTime(2026, 3, 15), model.SelectedDate); // the picker shows the kept date again
        Assert.Equal("2026-03-15", model.DateString);
        Assert.Equal([nameof(SignViewModel.SelectedDate)], changed);
    }

    [Fact]
    public void TheDefaultClockIsNow()
    {
        var model = new SignViewModel(_fake, _fileSave, _clipboard, _urls, _alerts);
        var before = DateTimeOffset.UtcNow.UtcDateTime.Date;
        Assert.InRange(model.Date, before.AddDays(-1), before.AddDays(1));
    }

    [Theory]
    [InlineData(QrFormat.Svg, "svg", "rhg-0123abcd.svg")]
    [InlineData(QrFormat.Png, "png", "rhg-0123abcd.png")]
    public async Task SaveAsksWhereThenSendsTheResultsUrlAndTheChosenPath(QrFormat format, string extension, string name)
    {
        _fake.Respond(RpcMethod.SignSign, Fixtures.SignResult());
        var model = FilledModel();
        Assert.Equal("", model.SuggestedFilename(format));
        await model.SignCommand.ExecuteAsync(null);
        Assert.Equal(name, model.SuggestedFilename(format));
        _fileSave.Answer($"/out/chosen.{extension}");
        var command = format == QrFormat.Svg ? model.SaveSvgCommand : model.SavePngCommand;
        await command.ExecuteAsync(null);
        Assert.Equal([(name, extension)], _fileSave.Requests);
        Assert.Null(_alerts.Current);
        Assert.Equal(
            [$"{{\"format\":\"{extension}\",\"path\":\"/out/chosen.{extension}\",\"url\":\"https://verify.royalhouseofgeorgia.ge/?p=abc\"}}"],
            _fake.Params(RpcMethod.SignSaveQr));
    }

    [Fact]
    public async Task CancellingTheSaveDialogSavesNothing()
    {
        _fake.Respond(RpcMethod.SignSign, Fixtures.SignResult());
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        _fileSave.Answer(null);
        await model.SavePngCommand.ExecuteAsync(null);
        Assert.Single(_fileSave.Requests);
        Assert.Equal(0, _fake.Count(RpcMethod.SignSaveQr));
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task SaveWithoutAResultDoesNothing()
    {
        var model = FilledModel();
        await model.SaveSvgCommand.ExecuteAsync(null);
        model.CopyUrlCommand.Execute(null);
        Assert.Empty(_fileSave.Requests);
        Assert.Empty(_clipboard.Texts);
        Assert.Empty(_fake.Calls);
    }

    [Theory]
    [InlineData(QrFormat.Svg)]
    [InlineData(QrFormat.Png)]
    public async Task SaveFailureShowsTheCoresMessage(QrFormat format)
    {
        _fake.Respond(RpcMethod.SignSign, Fixtures.SignResult());
        _fake.Fail(RpcMethod.SignSaveQr, new RpcException(RpcErrorCode.Failed, "Choose a folder outside the app's data folder."));
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        _fileSave.Answer("/data/a");
        await (format == QrFormat.Svg ? model.SaveSvgCommand : model.SavePngCommand).ExecuteAsync(null);
        Assert.Equal(new AlertState("Error", "Choose a folder outside the app's data folder."), _alerts.Current);
    }

    [Fact]
    public async Task CopyUrlPutsTheResultsUrlOnTheClipboard()
    {
        _fake.Respond(RpcMethod.SignSign, Fixtures.SignResult());
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        model.CopyUrlCommand.Execute(null);
        Assert.Equal(["https://verify.royalhouseofgeorgia.ge/?p=abc"], _clipboard.Texts);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task ABrowserFailureOfAStaleReportShowsNothing()
    {
        const string issue = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues/44";
        _fake.Fail(RpcMethod.SignSign, new RpcException(RpcErrorCode.Failed, "m", offerReport: true, reportId: "r8"));
        _fake.Respond(RpcMethod.SignSign, Fixtures.SignResult()); // the second signing
        var held = _fake.Hold(RpcMethod.SignReportError);
        _urls.Failure = "Host: no browser.";
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        var reporting = model.ReportIssueCommand.ExecuteAsync(null);
        await model.SignCommand.ExecuteAsync(null);
        held.Release(new ReportResult(true, issue));
        await reporting;
        Assert.Equal([new Uri(issue)], _urls.Opened);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task ACopyFailureShowsWhy()
    {
        _fake.Respond(RpcMethod.SignSign, Fixtures.SignResult());
        _clipboard.Failure = "Host: clipboard busy.";
        var model = FilledModel();
        await model.SignCommand.ExecuteAsync(null);
        model.CopyUrlCommand.Execute(null);
        Assert.Equal(new AlertState("Error", "Host: clipboard busy."), _alerts.Current);
    }

    [Fact]
    public async Task LoadHonorsFillsThePicker()
    {
        _fake.Respond(RpcMethod.SignHonors, new HonorsResult(["X", "Y"]));
        var model = FilledModel();
        Assert.Empty(model.Honors);
        await model.LoadHonorsAsync();
        Assert.Equal(["X", "Y"], model.Honors);
    }
}
