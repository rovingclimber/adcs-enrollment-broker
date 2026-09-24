using Microsoft.Extensions.Configuration;
using PkiProxy.Authentication;

internal static class CertificateConfigurationTests
{
    internal static void Run()
    {
        IConfiguration Config(Dictionary<string,string?> values) => new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        if (CertificateListenerConfiguration.Load(Config([]), null, false) is not null ||
            CertificateListenerConfiguration.Load(Config(new() { ["Broker:Certificate:Enabled"] = "false" }), null, false) is not null)
            throw new InvalidOperationException("Absent/disabled certificate listener opened");
        var count = 2;
        foreach (var values in new Dictionary<string,string?>[] {
            new() { ["Broker:Certificate:Enabled"] = "yes" },
            new() { ["Broker:Certificate:Enabled"] = "false", ["Broker:Certificate:AllowAny"] = "true" },
            new() { ["Broker:Certificate:Host"] = "broker.example.test" },
            new() { ["Broker:Certificate:Enabled"] = "true" }
        }) {
            var rejected = false;
            try { using var ignored = CertificateListenerConfiguration.Load(Config(values), null, false); }
            catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("Invalid certificate listener configuration accepted");
            count++;
        }
        Console.WriteLine($"Certificate listener opt-in checks passed: {count}.");
    }
}
