using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media.Imaging;
using RhgAuthenticator.ViewModels;

namespace RhgAuthenticator.App;

/// <summary>Visible for a non-null value, collapsed for null.</summary>
[ValueConversion(typeof(object), typeof(Visibility))]
internal sealed class NullToVisibilityConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is null ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>Visible for null or "", collapsed otherwise: a placeholder over an empty field.</summary>
[ValueConversion(typeof(string), typeof(Visibility))]
internal sealed class EmptyToVisibilityConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return string.IsNullOrEmpty(value as string) ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>Collapsed for null or "", visible otherwise: text shown only when there is some.</summary>
[ValueConversion(typeof(string), typeof(Visibility))]
internal sealed class NonEmptyToVisibilityConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return string.IsNullOrEmpty(value as string) ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>The negation of a bool: a control disabled while a flag is set.</summary>
[ValueConversion(typeof(bool), typeof(bool))]
internal sealed class NotConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is not true;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>A YYYY-MM-DD date as the GUI shows dates, YYYY-Mon-DD (<see cref="DisplayDate.Format"/>).</summary>
[ValueConversion(typeof(string), typeof(string))]
internal sealed class DisplayDateConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is string ymd ? DisplayDate.Format(ymd) : value;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// The Honor combo box's selection: "" (none selected) shows no selection,
/// and no selection is written back as "", never null.
/// </summary>
[ValueConversion(typeof(string), typeof(string))]
internal sealed class HonorConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is string { Length: > 0 } honor ? honor : null;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value as string ?? "";
    }
}

/// <summary>Lines as one text, one per line; "" for null.</summary>
[ValueConversion(typeof(IReadOnlyList<string>), typeof(string))]
internal sealed class JoinLinesConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is IEnumerable<string> lines ? string.Join("\n", lines) : "";
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>PNG bytes as a frozen bitmap; null for null.</summary>
[ValueConversion(typeof(byte[]), typeof(BitmapImage))]
internal sealed class PngImageConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not byte[] png)
        {
            return null;
        }
        using var stream = new MemoryStream(png, writable: false);
        var image = new BitmapImage();
        image.BeginInit();
        // Decoded now, so the stream can be closed.
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();
        return image;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
