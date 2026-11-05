using System.Text;

namespace RhgAuthenticator.Bridge;

/// <summary>The PIN length cap of a pin.request.</summary>
public static class PinTruncation
{
    /// <summary>
    /// Caps <paramref name="pin"/> to at most <paramref name="maxBytes"/> bytes of
    /// its UTF-8 encoding (pin.request <c>maxBytes</c>), cutting only between
    /// Unicode scalars: never inside a scalar's encoding, and without regard to
    /// UTF-16 units or grapheme clusters, so a combining mark or part of an emoji
    /// sequence may be dropped. Matches the core's TruncatePINToBytes (contract
    /// pin-truncation.json). A lone surrogate counts as U+FFFD, the 3 bytes it is
    /// sent as.
    /// </summary>
    public static string Truncate(string pin, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(pin);
        var rest = pin.AsSpan();
        var bytes = 0;
        var end = 0;
        while (end < pin.Length)
        {
            // Invalid UTF-16 decodes as U+FFFD, consuming one unit.
            Rune.DecodeFromUtf16(rest[end..], out var rune, out var consumed);
            bytes += rune.Utf8SequenceLength;
            if (bytes > maxBytes)
            {
                break;
            }
            end += consumed;
        }
        return pin[..end];
    }
}
