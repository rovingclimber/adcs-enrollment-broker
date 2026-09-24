using System.Globalization;

namespace PkiProxy.Protocol;

// One immutable limit set is shared by Kestrel, SOAP intake and the decoded
// WSTEP token gate. Secure defaults keep older deployments bounded while an
// explicit section lets operators make the effective policy reviewable.
internal sealed record InboundRequestLimits(
    int MaximumBodyBytes,
    int MaximumXmlDepth,
    int MaximumXmlNodes,
    int MaximumXmlElements,
    int MaximumXmlAttributes,
    int MaximumTextCharacters,
    int MaximumTextNodeCharacters,
    int MaximumDecodedBinaryBytes,
    TimeSpan BodyReadTimeout)
{
    internal const int DefaultMaximumDecodedBinaryBytes = 262_144;

    internal static InboundRequestLimits Default { get; } = new(
        MaximumBodyBytes: 1_048_576,
        MaximumXmlDepth: 32,
        MaximumXmlNodes: 4096,
        MaximumXmlElements: 1024,
        MaximumXmlAttributes: 2048,
        MaximumTextCharacters: 900_000,
        MaximumTextNodeCharacters: 400_000,
        MaximumDecodedBinaryBytes: DefaultMaximumDecodedBinaryBytes,
        BodyReadTimeout: TimeSpan.FromSeconds(10));

    internal static InboundRequestLimits Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("Broker:InboundLimits");
        if (!section.GetChildren().Any()) return Default;
        string[] allowed = ["MaximumBodyBytes", "MaximumXmlDepth", "MaximumXmlNodes",
            "MaximumXmlElements", "MaximumXmlAttributes", "MaximumTextCharacters",
            "MaximumTextNodeCharacters", "MaximumDecodedBinaryBytes", "BodyReadTimeoutMilliseconds"];
        if (section.GetChildren().Any(child => !allowed.Contains(child.Key, StringComparer.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Unsupported inbound request limit setting.");

        int Required(string key, int minimum, int maximum)
        {
            if (!int.TryParse(section[key], NumberStyles.None, CultureInfo.InvariantCulture, out var value) ||
                value < minimum || value > maximum)
                throw new InvalidOperationException($"Explicit valid inbound request limit {key} required.");
            return value;
        }

        var limits = new InboundRequestLimits(
            Required("MaximumBodyBytes", 16_384, 2_097_152),
            Required("MaximumXmlDepth", 8, 64),
            Required("MaximumXmlNodes", 64, 16_384),
            Required("MaximumXmlElements", 16, 4096),
            Required("MaximumXmlAttributes", 16, 8192),
            Required("MaximumTextCharacters", 4096, 1_500_000),
            Required("MaximumTextNodeCharacters", 1024, 1_000_000),
            Required("MaximumDecodedBinaryBytes", 65_536, 1_048_576),
            TimeSpan.FromMilliseconds(Required("BodyReadTimeoutMilliseconds", 1000, 60_000)));
        if (limits.MaximumXmlElements > limits.MaximumXmlNodes ||
            limits.MaximumTextNodeCharacters > limits.MaximumTextCharacters ||
            ((long)limits.MaximumDecodedBinaryBytes + 2) / 3 * 4 > limits.MaximumTextNodeCharacters ||
            limits.MaximumTextCharacters > limits.MaximumBodyBytes)
            throw new InvalidOperationException("Inbound request limits are internally inconsistent.");
        return limits;
    }
}
