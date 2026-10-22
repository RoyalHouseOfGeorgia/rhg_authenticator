using System.Globalization;

namespace RhgAuthenticator.ViewModels;

/// <summary>
/// Dates as the GUI shows them, YYYY-Mon-DD (e.g. "2026-Jan-02"), with English
/// month abbreviations whatever the machine's culture. Calendar dates are in
/// UTC, the zone of the signed <c>date</c> field.
/// </summary>
public static class DisplayDate
{
    private static readonly string[] s_months =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    /// <summary><paramref name="ymd"/> ("YYYY-MM-DD") as YYYY-Mon-DD; any other text is returned unchanged.</summary>
    public static string Format(string ymd)
    {
        ArgumentNullException.ThrowIfNull(ymd);
        if (!IsYmdShaped(ymd))
        {
            return ymd;
        }
        var month = int.Parse(ymd.AsSpan(5, 2), CultureInfo.InvariantCulture);
        return month is >= 1 and <= 12 ? $"{ymd[..4]}-{s_months[month - 1]}-{ymd[8..]}" : ymd;
    }

    /// <summary>
    /// <paramref name="baseCulture"/> with its dates as the GUI shows them, for
    /// controls that format dates themselves (the date picker): a copy whose
    /// date format is the invariant culture's (Gregorian, English names) with
    /// the short date YYYY-Mon-DD. Numbers and everything else stay the base
    /// culture's. A base culture whose own default calendar is not Gregorian
    /// still makes WPF's DatePicker fall back to its own short date.
    /// </summary>
    public static CultureInfo Culture(CultureInfo baseCulture)
    {
        ArgumentNullException.ThrowIfNull(baseCulture);
        var dates = (DateTimeFormatInfo)CultureInfo.InvariantCulture.DateTimeFormat.Clone();
        dates.ShortDatePattern = "yyyy-MMM-dd";
        var culture = (CultureInfo)baseCulture.Clone();
        culture.DateTimeFormat = dates;
        return culture;
    }

    /// <summary>The calendar date of <paramref name="date"/> as YYYY-MM-DD; its time of day is ignored.</summary>
    public static string Ymd(DateTime date)
    {
        return date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
    }

    /// <summary>Four ASCII digits, '-', two, '-', two.</summary>
    private static bool IsYmdShaped(string text)
    {
        if (text.Length != 10 || text[4] != '-' || text[7] != '-')
        {
            return false;
        }
        for (var i = 0; i < text.Length; i++)
        {
            if (i is not 4 and not 7 && !char.IsAsciiDigit(text[i]))
            {
                return false;
            }
        }
        return true;
    }
}
