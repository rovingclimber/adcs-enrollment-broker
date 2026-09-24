using Microsoft.Extensions.Configuration;
using PkiProxy.Domain;

internal static class NativeEnrollmentConfigurationTests
{
    internal static void Run()
    {
        var empty = new ConfigurationBuilder().Build();
        if (NativeEnrollmentService.Load(empty, null, null, false) is not null) throw new InvalidOperationException("Default issuance must be closed.");
        var disabled = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Broker:Issuance:Enabled"] = "false" }).Build();
        if (NativeEnrollmentService.Load(disabled, null, null, false) is not null) throw new InvalidOperationException("Disabled issuance must be closed.");
        var checks = 2;
        foreach (var settings in new[] {
            new Dictionary<string, string?> { ["Broker:Issuance:Enabled"] = "true" },
            new Dictionary<string, string?> { ["Broker:Issuance:Enabled"] = "yes" },
            new Dictionary<string, string?> { ["Broker:Issuance:Enable"] = "true" },
            new Dictionary<string, string?> { ["Broker:Issuance:Enabled"] = "false", ["Broker:Issuance:IgnoreRevocation"] = "true" },
            new Dictionary<string, string?> { ["Broker:Issuance:Enabled"] = "false", ["Broker:Issuance:RenewalEnabled"] = "true" },
            new Dictionary<string, string?> { ["Broker:Issuance:Enabled"] = "false", ["Broker:Issuance:RenewalEnabled"] = "yes" },
            new Dictionary<string, string?> { ["Broker:Issuance:Enabled"] = "true", ["Broker:Issuance:RenewalEnabled"] = "true" }
        })
        {
            try { NativeEnrollmentService.Load(new ConfigurationBuilder().AddInMemoryCollection(settings).Build(), null, null, false); }
            catch (InvalidOperationException) { checks++; continue; }
            throw new InvalidOperationException("Unsafe issuance configuration accepted.");
        }
        Console.WriteLine($"Native issuance opt-in checks passed: {checks}.");
    }
}
