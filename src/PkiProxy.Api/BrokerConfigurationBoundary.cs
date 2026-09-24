using System.Net;
using PkiProxy.Signing;

namespace PkiProxy;

internal static class BrokerConfigurationBoundary
{
    private static readonly HashSet<string> AllowedSections = new(StringComparer.OrdinalIgnoreCase)
    {
        "Bootstrap", "BootstrapConfigurationFile", "Certificate", "DeviceFactsFile", "Directory",
        "FactsManagement", "FactsManagementConfigurationFile", "InboundLimits", "Issuance",
        "IssuingCaFile", "Kerberos", "Signer", "XcepPolicyFile"
    };

    internal static void Validate(IConfiguration configuration)
    {
        var broker = configuration.GetSection("Broker");
        if (broker.GetChildren().Any(child => !AllowedSections.Contains(child.Key)))
            throw new InvalidOperationException("Unsupported Broker configuration section.");

        IsolatedSignerConfiguration.Validate(broker.GetSection("Signer"));

        foreach (var setting in broker.AsEnumerable(makePathsRelative: true))
        {
            if (string.IsNullOrWhiteSpace(setting.Value)) continue;
            var value = setting.Value.Trim();
            if (value.Contains("CHANGE_ME", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("REPLACE_ME", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("example.test", StringComparison.OrdinalIgnoreCase) ||
                IsDocumentationAddress(value))
                throw new InvalidOperationException("Documentation placeholder present in Broker configuration.");
        }
    }

    private static bool IsDocumentationAddress(string value)
    {
        foreach (var candidate in value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (!IPAddress.TryParse(candidate, out var address) || address.AddressFamily !=
                System.Net.Sockets.AddressFamily.InterNetwork) continue;
            var bytes = address.GetAddressBytes();
            if (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2 ||
                bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100 ||
                bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)
                return true;
        }
        return false;
    }
}
