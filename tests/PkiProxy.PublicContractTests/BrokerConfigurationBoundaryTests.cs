using Microsoft.Extensions.Configuration;
using PkiProxy;

internal static class BrokerConfigurationBoundaryTests
{
    internal static void Run()
    {
        BrokerConfigurationBoundary.Validate(Configuration([]));
        BrokerConfigurationBoundary.Validate(Configuration([
            new("Broker:Kerberos:Enabled", "false"),
            new("Broker:Directory:Enabled", "false"),
            new("Broker:Issuance:Enabled", "false")
        ]));

        Reject([new("Broker:Unrecognised", "true")], "unknown Broker sections");
        Reject([new("Broker:Kerberos:ServicePrincipal", "HTTP/broker.example.test@EXAMPLE.TEST")],
            "reserved example DNS names");
        Reject([new("Broker:Kerberos:AllowedClientAddresses", "192.0.2.20")],
            "TEST-NET documentation addresses");
        Reject([new("Broker:XcepPolicyFile", "/run/config/CHANGE_ME.json")],
            "explicit replacement markers");
    }

    private static IConfiguration Configuration(IEnumerable<KeyValuePair<string, string?>> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private static void Reject(IEnumerable<KeyValuePair<string, string?>> values, string description)
    {
        try
        {
            BrokerConfigurationBoundary.Validate(Configuration(values));
            throw new InvalidOperationException($"Configuration boundary accepted {description}.");
        }
        catch (InvalidOperationException error) when (!error.Message.StartsWith("Configuration boundary accepted", StringComparison.Ordinal))
        {
        }
    }
}
