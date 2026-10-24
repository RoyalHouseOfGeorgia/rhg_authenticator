namespace RhgAuthenticator.ViewModels;

/// <summary>The "Report Issue" button of a failed signing. Match on the nested records.</summary>
public abstract record ReportState
{
    /// <summary>The button's title while it offers a report.</summary>
    public const string ReportIssueTitle = "Report Issue";

    /// <summary>The button's title while the report is filed.</summary>
    public const string ReportingTitle = "Reporting…";

    /// <summary>The button's title once the issue is filed.</summary>
    public const string IssueReportedTitle = "Issue Reported";

    private protected ReportState()
    {
    }

    /// <summary>The button's title; null when there is no button.</summary>
    public abstract string? ButtonTitle { get; }

    /// <summary>The button is enabled.</summary>
    public virtual bool IsButtonEnabled => false;

    /// <summary>No button: the last failure offered no report.</summary>
    public sealed record Unavailable : ReportState
    {
        /// <inheritdoc />
        public override string? ButtonTitle => null;
    }

    /// <summary>"Report Issue", enabled.</summary>
    /// <param name="ReportId">The failure's <see cref="Bridge.RpcException.ReportId"/>.</param>
    public sealed record Available(string ReportId) : ReportState
    {
        /// <inheritdoc />
        public override string? ButtonTitle => ReportIssueTitle;

        /// <inheritdoc />
        public override bool IsButtonEnabled => true;
    }

    /// <summary>"Reporting…", disabled.</summary>
    /// <param name="ReportId">The failure being reported.</param>
    public sealed record Reporting(string ReportId) : ReportState
    {
        /// <inheritdoc />
        public override string? ButtonTitle => ReportingTitle;
    }

    /// <summary>"Issue Reported", disabled for good.</summary>
    public sealed record Reported : ReportState
    {
        /// <inheritdoc />
        public override string? ButtonTitle => IssueReportedTitle;
    }
}
