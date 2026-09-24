using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PkiProxy.Domain;

// Offline operator helper. Never writes the mounted authority or grants AD access.
internal static class DeviceFactsEditor
{
    private static readonly JsonSerializerOptions OutputOptions = new() { WriteIndented = true };
    internal static byte[] PrepareDocument(ReadOnlyMemory<byte> current, string expectedSha256,
        ReadOnlyMemory<byte> proposed)
    {
        if (expectedSha256.Length != 64 || !expectedSha256.All(char.IsAsciiHexDigit) ||
            !Convert.ToHexString(SHA256.HashData(current.Span)).Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Source changed. Reload and review the current facts before editing.");
        _ = JsonFileDeviceFactsSource.Parse(current, null);
        _ = JsonFileDeviceFactsSource.Parse(proposed, null);
        static JsonObject Document(ReadOnlyMemory<byte> bytes)
        {
            var span = bytes.Span;
            if (span.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) span = span[3..];
            return JsonNode.Parse(span)!.AsObject();
        }
        var original = Document(current);
        var candidate = Document(proposed);
        if (!JsonNode.DeepEquals(original["useCases"], candidate["useCases"]) ||
            !JsonNode.DeepEquals(original["revision"], candidate["revision"]))
            throw new InvalidDataException("The workbench cannot change the approved use-case catalogue or source revision.");
        if (JsonNode.DeepEquals(original, candidate)) throw new InvalidDataException("No device changes to export.");
        candidate["revision"] = checked(original["revision"]!.GetValue<long>() + 1);
        var output = JsonSerializer.SerializeToUtf8Bytes(candidate, OutputOptions);
        _ = JsonFileDeviceFactsSource.Parse(output, null);
        return output;
    }
    internal static byte[] PrepareUseCase(ReadOnlyMemory<byte> current, string expectedSha256,
        string hostname, string useCase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostname);
        ArgumentException.ThrowIfNullOrWhiteSpace(useCase);
        if (expectedSha256.Length != 64 || !expectedSha256.All(char.IsAsciiHexDigit) ||
            !Convert.ToHexString(SHA256.HashData(current.Span)).Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Source hash differs; review the current facts before preparing an edit.");
        var selected = JsonFileDeviceFactsSource.Parse(current, hostname)
            ?? throw new InvalidDataException("Unknown device FQDN; this command cannot create enrollment identities.");
        if (selected.UseCase == useCase) throw new InvalidDataException("Use-case is unchanged.");
        var json = current.Span;
        if (json.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) json = json[3..];
        var document = JsonNode.Parse(json)!.AsObject();
        if (!document["useCases"]!.AsArray().Any(item => item!["id"]!.GetValue<string>() == useCase))
            throw new InvalidDataException("Use-case is not in the approved catalogue.");
        var device = document["devices"]!.AsArray().Single(item =>
            item!["hostname"]!.GetValue<string>().Equals(hostname, StringComparison.OrdinalIgnoreCase))!;
        device["useCase"] = useCase;
        document["revision"] = checked(selected.SourceVersion + 1);
        var output = JsonSerializer.SerializeToUtf8Bytes(document, OutputOptions);
        _ = JsonFileDeviceFactsSource.Parse(output, hostname); // Identical validator to live enrollment.
        return output;
    }
}
