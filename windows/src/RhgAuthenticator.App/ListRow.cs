namespace RhgAuthenticator.App;

/// <summary>
/// One list row's text, as its own object. WPF's selectors find an item's
/// index with Equals, so two equal rows (duplicate History records, which
/// are equal records) would both map to the first; a class compares by
/// reference, so each row keeps its own index.
/// </summary>
/// <param name="summary">The row's text.</param>
public sealed class ListRow(string summary)
{
    /// <summary>The row's text (shown, and its tooltip).</summary>
    public string Summary { get; } = summary;
}
