/// Caps `pin` to at most `maxBytes` bytes of its UTF-8 encoding (pin.request
/// `maxBytes`), cutting only between Unicode scalars: never inside a scalar's
/// encoding, and without regard to UTF-16 units or grapheme clusters, so a
/// combining mark or part of an emoji sequence may be dropped. Matches the
/// core's TruncatePINToBytes (contract pin-truncation.json).
public func truncatePIN(_ pin: String, maxBytes: Int) -> String {
    var kept = String.UnicodeScalarView()
    var bytes = 0
    for scalar in pin.unicodeScalars {
        bytes += UTF8.width(scalar)
        if bytes > maxBytes {
            break
        }
        kept.append(scalar)
    }
    return String(kept)
}
