using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RhgAuthenticator.Bridge;

/// <summary>
/// The wire names of the contract's enums: each member's camelCase name, or
/// its <see cref="JsonStringEnumMemberNameAttribute"/>. Every such enum has an
/// <c>Unknown</c> member, value 0, for a value this build does not know.
/// </summary>
public static class WireEnum
{
    /// <summary>The wire name of <paramref name="value"/> (<c>"unknown"</c> for Unknown).</summary>
    public static string NameOf<TEnum>(TEnum value)
        where TEnum : struct, Enum
    {
        return Names<TEnum>.ByValue.TryGetValue(value, out var name)
            ? name
            : throw new ArgumentOutOfRangeException(nameof(value), value, "Not a member of the enum.");
    }

    /// <summary>The member named <paramref name="name"/> on the wire, or Unknown.</summary>
    public static TEnum Parse<TEnum>(string name)
        where TEnum : struct, Enum
    {
        ArgumentNullException.ThrowIfNull(name);
        return Names<TEnum>.ByName.TryGetValue(name, out var value) ? value : default;
    }

    /// <summary>Every member but Unknown: the values the contract defines.</summary>
    internal static IReadOnlyList<TEnum> Known<TEnum>()
        where TEnum : struct, Enum
    {
        return Names<TEnum>.Known;
    }

    private static class Names<TEnum>
        where TEnum : struct, Enum
    {
        public static readonly Dictionary<TEnum, string> ByValue = typeof(TEnum)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .ToDictionary(
                f => (TEnum)f.GetValue(null)!,
                f => f.GetCustomAttribute<JsonStringEnumMemberNameAttribute>()?.Name
                    ?? JsonNamingPolicy.CamelCase.ConvertName(f.Name));

        public static readonly Dictionary<string, TEnum> ByName =
            ByValue.ToDictionary(p => p.Value, p => p.Key, StringComparer.Ordinal);

        public static readonly TEnum[] Known = [.. ByValue.Keys.Where(v => !EqualityComparer<TEnum>.Default.Equals(v, default))];
    }
}

/// <summary>
/// Reads a contract enum from its wire name, mapping a name this build does
/// not know to Unknown (the contract is additive), and writes the wire name.
/// </summary>
public sealed class WireEnumConverter<TEnum> : JsonConverter<TEnum>
    where TEnum : struct, Enum
{
    /// <inheritdoc />
    public override TEnum Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"Expected a string for {typeof(TEnum).Name}.");
        }
        return WireEnum.Parse<TEnum>(reader.GetString()!);
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, TEnum value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(WireEnum.NameOf(value));
    }
}
