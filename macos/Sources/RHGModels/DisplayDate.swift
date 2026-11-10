import Foundation

/// Dates as the GUI shows them, YYYY-Mon-DD (e.g. "2026-Jan-02"), with English
/// month abbreviations whatever the machine's locale. Calendar dates are in
/// UTC, the zone of the signed `date` field.
public enum DisplayDate {
    static let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    /// The Gregorian calendar in UTC; the date picker shows and edits dates in it.
    public static let utcCalendar: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar
    }()

    /// `ymd` ("YYYY-MM-DD") as YYYY-Mon-DD; any other text is returned unchanged.
    public static func format(_ ymd: String) -> String {
        let parts = ymd.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
            parts.allSatisfy({ $0.allSatisfy { ("0"..."9").contains($0) } }),
            let month = Int(parts[1]), (1...12).contains(month)
        else { return ymd }
        return "\(parts[0])-\(months[month - 1])-\(parts[2])"
    }

    /// `ymd` ("YYYY-MM-DD", a real calendar date) as midnight UTC; nil for
    /// any other text.
    public static func date(fromYMD ymd: String) -> Date? {
        let parts = ymd.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
            parts.allSatisfy({ $0.allSatisfy { ("0"..."9").contains($0) } }),
            let date = utcCalendar.date(
                from: DateComponents(year: Int(parts[0]), month: Int(parts[1]), day: Int(parts[2]))),
            self.ymd(date) == ymd
        else { return nil }
        return date
    }

    /// The calendar date of `date` in `timeZone` (UTC by default) as YYYY-MM-DD.
    public static func ymd(_ date: Date, in timeZone: TimeZone = utcCalendar.timeZone) -> String {
        var calendar = utcCalendar
        calendar.timeZone = timeZone
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year!, c.month!, c.day!)
    }
}
