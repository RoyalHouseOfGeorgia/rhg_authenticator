using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels.Tests;

public sealed class AuditViewModelTests
{
    private const string CommitUrl = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/commit/abc123";

    private readonly FakeBridge _fake = new();
    private readonly FakeUrlOpener _urls = new();
    private readonly AlertQueue _alerts = new();

    private AuditViewModel NewModel()
    {
        return new AuditViewModel(_fake, _urls, _alerts);
    }

    private static AuditResult Commits(params string[] urls)
    {
        return new AuditResult([.. urls.Select((url, i) => new AuditRow($"Commit {i + 1}", url))], $"{urls.Length} commits");
    }

    /// <summary>A model whose fetch returned rows with <paramref name="urls"/>; later fetches answer from each test's own script.</summary>
    private async Task<AuditViewModel> Loaded(params string[] urls)
    {
        _fake.Respond(RpcMethod.AuditCommits, Commits(urls));
        var audit = NewModel();
        await audit.RefreshAsync();
        _fake.Reset(RpcMethod.AuditCommits);
        return audit;
    }

    [Fact]
    public void Copy()
    {
        Assert.Equal("Refresh", AuditViewModel.RefreshTitle);
        Assert.Equal("Refresh (F5)", AuditViewModel.RefreshTooltip);
        Assert.Equal("Open on GitHub", AuditViewModel.OpenTitle);
        Assert.Equal("Select a commit to open it.", AuditViewModel.OpenTooltip);
        Assert.Equal("Fetching...", AuditViewModel.FetchingStatus);
    }

    [Fact]
    public void RequiresItsServices()
    {
        Assert.Throws<ArgumentNullException>(() => new AuditViewModel(null!, _urls, _alerts));
        Assert.Throws<ArgumentNullException>(() => new AuditViewModel(_fake, null!, _alerts));
        Assert.Throws<ArgumentNullException>(() => new AuditViewModel(_fake, _urls, null!));
    }

    [Fact]
    public void ANewModelIsEmpty()
    {
        var audit = NewModel();
        Assert.Empty(audit.Rows);
        Assert.Equal("", audit.Status);
        Assert.False(audit.IsRefreshing);
        Assert.Null(audit.SelectedIndex);
        Assert.True(audit.RefreshCommand.CanExecute(null));
        Assert.False(audit.OpenCommand.CanExecute(null));
    }

    [Fact]
    public async Task RefreshSaysFetchingThenShowsTheCoresRowsAndStatus()
    {
        var held = _fake.Hold(RpcMethod.AuditCommits);
        var audit = NewModel();
        var changes = 0;
        audit.RefreshCommand.CanExecuteChanged += (_, _) => changes++;
        var refresh = audit.RefreshCommand.ExecuteAsync(null);
        Assert.Equal("Fetching...", audit.Status);
        Assert.True(audit.IsRefreshing);
        Assert.False(audit.RefreshCommand.CanExecute(null));
        Assert.True(changes > 0);
        var result = Commits(CommitUrl, "");
        held.Release(result);
        await refresh;
        Assert.Same(result.Rows, audit.Rows);
        Assert.Equal("2 commits", audit.Status);
        Assert.False(audit.IsRefreshing);
        Assert.True(audit.RefreshCommand.CanExecute(null));
        Assert.Equal(["{}"], _fake.Params(RpcMethod.AuditCommits));
    }

    [Fact]
    public async Task ARefreshWhileOneRunsIsIgnored()
    {
        var held = _fake.Hold(RpcMethod.AuditCommits);
        var audit = NewModel();
        var first = audit.RefreshAsync();
        await audit.RefreshAsync();
        Assert.Equal(1, _fake.Count(RpcMethod.AuditCommits));
        Assert.True(audit.IsRefreshing);
        held.Release(Commits(CommitUrl));
        await first;
        Assert.Single(audit.Rows);
    }

    [Fact]
    public async Task ABusyCoreKeepsThePreviousStatusRowsAndSelection()
    {
        var audit = await Loaded(CommitUrl);
        audit.Select(0);
        var rows = audit.Rows;
        _fake.Fail(RpcMethod.AuditCommits, new RpcException(RpcErrorCode.Busy, "busy"));
        await audit.RefreshAsync();
        Assert.Equal("1 commits", audit.Status);
        Assert.Same(rows, audit.Rows);
        Assert.Equal(0, audit.SelectedIndex);
        Assert.False(audit.IsRefreshing);
    }

    [Fact]
    public async Task AnyOtherFailureShowsTheCoresMessageOnTheStatusLineAndKeepsTheRows()
    {
        var audit = await Loaded(CommitUrl);
        var rows = audit.Rows;
        _fake.Fail(RpcMethod.AuditCommits, new RpcException(RpcErrorCode.Failed, "GitHub is unreachable."));
        await audit.RefreshAsync();
        Assert.Equal("GitHub is unreachable.", audit.Status);
        Assert.Same(rows, audit.Rows);
        Assert.Null(_alerts.Current);
        Assert.False(audit.IsRefreshing);
    }

    [Fact]
    public async Task NewRowsClearTheSelection()
    {
        var audit = await Loaded(CommitUrl, CommitUrl);
        audit.Select(1);
        _fake.Respond(RpcMethod.AuditCommits, Commits(CommitUrl, CommitUrl));
        await audit.RefreshAsync();
        Assert.Null(audit.SelectedIndex);
        Assert.False(audit.OpenCommand.CanExecute(null));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(-1)]
    [InlineData(2)]
    public async Task NoRowOrOneOutOfRangeClearsTheSelection(int? row)
    {
        var audit = await Loaded(CommitUrl, CommitUrl);
        audit.Select(1);
        Assert.Equal(1, audit.SelectedIndex);
        audit.Select(row);
        Assert.Null(audit.SelectedIndex);
    }

    [Fact]
    public async Task SelectingNeverOpensTheBrowser()
    {
        var audit = await Loaded(CommitUrl);
        audit.Select(0);
        Assert.Empty(_urls.Opened);
    }

    [Theory]
    [InlineData("")]
    [InlineData("http://github.com/RoyalHouseOfGeorgia/rhg_authenticator/commit/abc123")]
    [InlineData("commit/abc123")]
    public async Task OpenIsDisabledForACommitWithoutAnHttpsUrl(string url)
    {
        var audit = await Loaded(url);
        audit.Select(0);
        Assert.False(audit.OpenCommand.CanExecute(null));
        audit.OpenCommand.Execute(null);
        Assert.Empty(_urls.Opened);
    }

    [Fact]
    public async Task OpenIsEnabledOnceACommitIsSelectedAndOpensItsPage()
    {
        var audit = await Loaded(CommitUrl);
        var changes = 0;
        audit.OpenCommand.CanExecuteChanged += (_, _) => changes++;
        Assert.False(audit.OpenCommand.CanExecute(null));
        audit.OpenCommand.Execute(null); // ignored
        Assert.Empty(_urls.Opened);
        audit.Select(0);
        Assert.True(changes > 0);
        Assert.True(audit.OpenCommand.CanExecute(null));
        audit.OpenCommand.Execute(null);
        Assert.Equal([new Uri(CommitUrl)], _urls.Opened);
        Assert.Null(_alerts.Current);
    }

    [Fact]
    public async Task NewRowsReCheckOpen()
    {
        var audit = await Loaded(CommitUrl);
        var changes = 0;
        audit.OpenCommand.CanExecuteChanged += (_, _) => changes++;
        _fake.Respond(RpcMethod.AuditCommits, Commits());
        await audit.RefreshAsync();
        Assert.True(changes > 0);
    }

    [Fact]
    public async Task ABrowserThatFailsToOpenShowsAnErrorAlert()
    {
        var audit = await Loaded(CommitUrl);
        _urls.Failure = "Could not open " + CommitUrl;
        audit.Select(0);
        audit.OpenCommand.Execute(null);
        Assert.Equal(new AlertState("Error", "Could not open " + CommitUrl), _alerts.Current);
    }
}
