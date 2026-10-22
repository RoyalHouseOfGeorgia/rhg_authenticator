using System.Globalization;
using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class DisplayDateTests
{
    [Theory]
    [InlineData("2026-01-02", "2026-Jan-02")]
    [InlineData("2026-02-28", "2026-Feb-28")]
    [InlineData("2026-03-15", "2026-Mar-15")]
    [InlineData("2026-04-01", "2026-Apr-01")]
    [InlineData("2026-05-01", "2026-May-01")]
    [InlineData("2026-06-01", "2026-Jun-01")]
    [InlineData("2026-07-01", "2026-Jul-01")]
    [InlineData("2026-08-01", "2026-Aug-01")]
    [InlineData("2026-09-01", "2026-Sep-01")]
    [InlineData("2026-10-19", "2026-Oct-19")]
    [InlineData("2026-11-01", "2026-Nov-01")]
    [InlineData("2026-12-31", "2026-Dec-31")]
    public void FormatsYmdAsYyyyMonDd(string ymd, string shown)
    {
        Assert.Equal(shown, DisplayDate.Format(ymd));
    }

    [Theory]
    [InlineData("")]
    [InlineData("2026-01")]
    [InlineData("2026-13-01")]
    [InlineData("2026-00-01")]
    [InlineData("2026-1-02")]
    [InlineData("26-01-02")]
    [InlineData("2026-+1-02")]
    [InlineData("abcd-01-02")]
    [InlineData("2026-01-02-03")]
    [InlineData("2026/01/02")]
    [InlineData("2026-01/02")]
    [InlineData("２０２６-01-02")]
    [InlineData("٢٠٢٦-01-02")]
    public void LeavesOtherTextUnchanged(string text)
    {
        Assert.Equal(text, DisplayDate.Format(text));
    }

    [Fact]
    public void YmdOfACalendarDateIgnoresItsTimeOfDay()
    {
        Assert.Equal("2026-03-05", DisplayDate.Ymd(new DateTime(2026, 3, 5, 23, 59, 59)));
        Assert.Equal("0999-01-01", DisplayDate.Ymd(new DateTime(999, 1, 1)));
    }

    [Fact]
    public void NullTextThrows()
    {
        Assert.Throws<ArgumentNullException>(() => DisplayDate.Format(null!));
        Assert.Throws<ArgumentNullException>(() => DisplayDate.Culture(null!));
    }

    [Fact]
    public void TheCultureShowsShortDatesAsYyyyMonDdOverAReadOnlyCulture()
    {
        var culture = DisplayDate.Culture(CultureInfo.InvariantCulture);
        Assert.Equal("2026-Mar-05", new DateTime(2026, 3, 5).ToString("d", culture));
        Assert.Equal("MM/dd/yyyy", CultureInfo.InvariantCulture.DateTimeFormat.ShortDatePattern);
        Assert.True(CultureInfo.InvariantCulture.IsReadOnly);
    }

    [Fact]
    public void TheCultureHasEnglishMonthNamesAndKeepsTheBaseCulturesNumbers()
    {
        // As a localized culture would: the test project has no culture data.
        var local = (CultureInfo)CultureInfo.InvariantCulture.Clone();
        local.DateTimeFormat.ShortDatePattern = "dd.MM.yyyy";
        string[] months = ["i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x", "xi", "xii", ""];
        local.DateTimeFormat.MonthNames = months;
        local.DateTimeFormat.AbbreviatedMonthNames = months;
        local.NumberFormat.NumberDecimalSeparator = ",";

        var culture = DisplayDate.Culture(local);

        Assert.Equal("2026-Mar-05", new DateTime(2026, 3, 5).ToString("d", culture));
        Assert.Equal("October", culture.DateTimeFormat.MonthNames[9]);
        Assert.Equal("Oct", culture.DateTimeFormat.AbbreviatedMonthNames[9]);
        Assert.Equal(",", culture.NumberFormat.NumberDecimalSeparator);
        Assert.Equal("dd.MM.yyyy", local.DateTimeFormat.ShortDatePattern);
        Assert.Equal("x", local.DateTimeFormat.MonthNames[9]);
        Assert.Equal("x", local.DateTimeFormat.AbbreviatedMonthNames[9]);
        Assert.False(local.IsReadOnly);
    }
}

public sealed class SaveLocationTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("rhg-vm-tests-").FullName;

    public void Dispose()
    {
        Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public void StartsOnTheDesktop()
    {
        Assert.Equal("/home/op/Desktop", new SaveLocation(() => "/home/op/Desktop").InitialDirectory);
    }

    [Fact]
    public void AnUnknownDesktopLeavesItToTheDialog()
    {
        Assert.Null(new SaveLocation(() => "").InitialDirectory);
    }

    [Fact]
    public void TheDefaultDesktopIsTheShellFolder()
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        Assert.Equal(desktop.Length == 0 ? null : desktop, new SaveLocation().InitialDirectory);
    }

    [Fact]
    public void ThenTheFolderOfTheLastFileChosen()
    {
        var location = new SaveLocation(() => "/desktop");
        var first = Directory.CreateDirectory(Path.Combine(_root, "first")).FullName;
        var second = Directory.CreateDirectory(Path.Combine(_root, "second")).FullName;
        location.Remember(Path.Combine(first, "a.svg"));
        Assert.Equal(first, location.InitialDirectory);
        location.Remember(Path.Combine(second, "b.png"));
        Assert.Equal(second, location.InitialDirectory);
    }

    [Fact]
    public void AFolderThatNoLongerExistsFallsBackToTheDesktop()
    {
        var location = new SaveLocation(() => "/desktop");
        var gone = Directory.CreateDirectory(Path.Combine(_root, "gone")).FullName;
        location.Remember(Path.Combine(gone, "a.svg"));
        Directory.Delete(gone);
        Assert.Equal("/desktop", location.InitialDirectory);
    }

    [Fact]
    public void APathWithoutAFolderIsIgnored()
    {
        var location = new SaveLocation(() => "/desktop");
        location.Remember("a.svg");
        Assert.Equal("/desktop", location.InitialDirectory);
        Assert.Throws<ArgumentNullException>(() => location.Remember(null!));
    }
}

public sealed class AlertStateTests
{
    [Fact]
    public void ACoreErrorIsShownAsIsUnderError()
    {
        var alert = AlertState.Error(new RpcException(RpcErrorCode.Failed, "Core says no.", offerReport: true, reportId: "r"));
        Assert.Equal(new AlertState("Error", "Core says no."), alert);
        Assert.True(alert.IsError);
        Assert.False(new AlertState("Already Issued", "m").IsError);
        Assert.Throws<ArgumentNullException>(() => AlertState.Error(null!));
    }

    [Fact]
    public void OnlyAnAlertThatSaysSoOffersTheErrorLogExport()
    {
        Assert.False(new AlertState("Error", "m").OffersErrorLogExport);
        Assert.False(AlertState.Error(new RpcException(RpcErrorCode.Failed, "m")).OffersErrorLogExport);
        var offering = new AlertState("Error", "m", OffersErrorLogExport: true);
        Assert.True(offering.OffersErrorLogExport);
        Assert.True(offering.IsError);
        Assert.NotEqual(new AlertState("Error", "m"), offering);
        Assert.False(new AlertState("Update Failed", "m", OffersErrorLogExport: true).IsError);
    }

    [Fact]
    public void AlertsShowOneAtATimeInOrder()
    {
        var alerts = new AlertQueue();
        var changes = 0;
        alerts.PropertyChanged += (_, _) => changes++;
        Assert.Null(alerts.Current);
        alerts.Dismiss();
        Assert.Null(alerts.Current);

        var first = new AlertState("A", "1");
        var second = new AlertState("B", "2");
        var third = new AlertState("A", "1");
        alerts.Show(first);
        alerts.Show(second);
        alerts.Show(third);
        Assert.Same(first, alerts.Current);
        alerts.Dismiss();
        Assert.Same(second, alerts.Current);
        alerts.Dismiss();
        Assert.Same(third, alerts.Current); // an equal alert posted again still shows
        alerts.Dismiss();
        Assert.Null(alerts.Current);
        Assert.Equal(4, changes);
        Assert.Throws<ArgumentNullException>(() => alerts.Show(null!));
    }

    [Fact]
    public void ReportStateButtons()
    {
        ReportState unavailable = new ReportState.Unavailable();
        Assert.Null(unavailable.ButtonTitle);
        Assert.False(unavailable.IsButtonEnabled);

        ReportState available = new ReportState.Available("r1");
        Assert.Equal("Report Issue", available.ButtonTitle);
        Assert.True(available.IsButtonEnabled);

        ReportState reporting = new ReportState.Reporting("r1");
        Assert.Equal("Reporting…", reporting.ButtonTitle);
        Assert.False(reporting.IsButtonEnabled);

        ReportState reported = new ReportState.Reported();
        Assert.Equal("Issue Reported", reported.ButtonTitle);
        Assert.False(reported.IsButtonEnabled);

        Assert.Equal(new ReportState.Reporting("r1"), reporting);
        Assert.NotEqual(new ReportState.Reporting("r2"), reporting);
        Assert.Equal<ReportState>(new ReportState.Reported(), reported);
    }
}
