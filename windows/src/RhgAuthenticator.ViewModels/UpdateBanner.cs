using RhgAuthenticator.Bridge;

namespace RhgAuthenticator.ViewModels;

/// <summary>
/// The update banner: <paramref name="Text"/>, then a Download link to
/// <paramref name="ReleaseUrl"/>. Windows only ever offers an update to
/// download by hand; the core never reports one ready to install here.
/// </summary>
/// <param name="Text">"Version X.Y.Z is available —".</param>
/// <param name="ReleaseUrl">The release page, an https URL.</param>
public sealed record UpdateBanner(string Text, Uri ReleaseUrl)
{
    /// <summary>The link's title.</summary>
    public const string DownloadTitle = "Download";

    /// <summary>
    /// The banner for <paramref name="status"/>: an update to download by hand
    /// with an https release page; null (no banner) for anything else.
    /// </summary>
    public static UpdateBanner? From(UpdateStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);
        return status.State == UpdateState.ManualOnly && HttpsUrl.Parse(status.ReleaseUrl) is { } url
            ? new UpdateBanner($"Version {status.Version} is available —", url)
            : null;
    }
}
