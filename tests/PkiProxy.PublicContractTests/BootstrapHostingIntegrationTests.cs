using PkiProxy.Domain;
using System.Text;
using System.Text.Json;

internal static class BootstrapHostingIntegrationTests
{
    internal static void Run()
    {
        var checks = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException("Bootstrap hosting integration: " + label);
            checks++;
        }
        void Reject(BootstrapDeployment.Configuration value, string label)
        {
            try
            {
                BootstrapDeployment.ValidateConfiguration(value);
                throw new InvalidOperationException("Bootstrap hosting integration accepted " + label);
            }
            catch (InvalidDataException) { checks++; }
        }

        var root = OperatingSystem.IsWindows() ? @"C:\bootstrap" : "/bootstrap";
        var valid = new BootstrapDeployment.Configuration(5, "broker.example.test", 443, 8443,
            ["192.0.2.52"], 60, 10, 2, 4,
            Path.Combine(root, "policy.json"), Path.Combine(root, "root.pem"),
            Path.Combine(root, "facts.json"), Path.Combine(root, "intake"), Path.Combine(root, "attestations"),
            Path.Combine(root, "pairings"), Path.Combine(root, "transactions"),
            10, 3, 64, 80L * 1024 * 1024, 4096, 5L * 1024 * 1024 * 1024,
            "dc01.example.test", "DC=example,DC=test",
            "S-1-5-21-1-2-3-1234", "S-1-5-21-1-2-3-1235",
            "S-1-5-21-1-2-3-1236", 5);
        BootstrapDeployment.ValidateConfiguration(valid);
        checks++;

        Reject(valid with { AllowedPeers = [] }, "an empty source allowlist");
        Reject(valid with { AllowedPeers = ["192.0.2.52", "192.0.2.52"] }, "duplicate source peers");
        Reject(valid with { AllowedPeers = ["192.0.2.0/24"] }, "a subnet in place of exact peers");
        Reject(valid with { BrokerHost = "BROKER.example.test" }, "a noncanonical authority");
        Reject(valid with { PolicyFile = "policy.json" }, "a relative policy path");
        Reject(valid with { TechnicianDirectoryServer = "" }, "a missing technician directory server");
        Reject(valid with { TechnicianDirectoryBaseDn = "" }, "a missing technician directory base DN");
        Reject(valid with { BootstrapApprovalRequiredGroupSid = "S-1-5-32-544" }, "a non-domain approval group SID");
        Reject(valid with { FactsReadRequiredGroupSid = "" }, "a missing facts-read group SID");
        Reject(valid with { FactsWriteRequiredGroupSid = "S-1-5-32-544" }, "a non-domain facts-write group SID");
        Reject(valid with { FactsReadRequiredGroupSid = valid.BootstrapApprovalRequiredGroupSid },
            "overlapping approval and facts-read groups");
        Reject(valid with { FactsWriteRequiredGroupSid = valid.FactsReadRequiredGroupSid },
            "overlapping facts-read and facts-write groups");
        Reject(valid with { FactsWriteRequiredGroupSid = "S-1-5-21-01-2-3-1234" },
            "semantically overlapping group SID with alternate numeric spelling");
        Reject(valid with { Version = 4 }, "the legacy shared-technician configuration version");
        Reject(valid with { ExternalAuthorityPort = 0 }, "a missing external authority port");
        Reject(valid with { InternalListenerPort = 0 }, "a missing internal listener port");
        Reject(valid with { LifetimeMinutes = 31 }, "an excessive transaction lifetime");
        Reject(valid with { GlobalConcurrency = 1 }, "a global cap below the peer cap");
        Reject(valid with { MaximumActiveBytes = 1 }, "an undersized active byte quota");
        Reject(valid with { MaximumHistoryRecords = 63 }, "history count below active capacity");
        Reject(valid with { MaximumHistoryBytes = valid.MaximumActiveBytes - 1 }, "history bytes below active capacity");
        BootstrapDeployment.ValidateConfiguration(valid with { InternalListenerPort = 443 });
        checks++;
        BootstrapDeployment.ValidateListenerBinding(valid, 443, 8443);
        checks++;
        foreach (var mismatch in new[] { (External: 9443, Internal: 8443), (External: 443, Internal: 443) })
        {
            try
            {
                BootstrapDeployment.ValidateListenerBinding(valid, mismatch.External, mismatch.Internal);
                throw new InvalidOperationException("Bootstrap hosting integration accepted a listener-port mismatch");
            }
            catch (InvalidDataException) { checks++; }
        }

        var serialized = JsonSerializer.Serialize(valid);
        RejectJson(serialized.Replace(",\"ExternalAuthorityPort\":443", "", StringComparison.Ordinal),
            "a missing external authority port");
        RejectJson(serialized.Replace(",\"InternalListenerPort\":8443", "", StringComparison.Ordinal),
            "a missing internal listener port");
        RejectJson(serialized.Replace("\"ExternalAuthorityPort\":443,\"InternalListenerPort\":8443",
                "\"HttpsPort\":443", StringComparison.Ordinal),
            "a legacy v2 single-port field");
        foreach (var field in new[]
                 {
                     "BootstrapApprovalRequiredGroupSid",
                     "FactsReadRequiredGroupSid",
                     "FactsWriteRequiredGroupSid"
                 })
        {
            var property = JsonDocument.Parse(serialized).RootElement.GetProperty(field).GetString()!;
            RejectJson(serialized.Replace($",\"{field}\":\"{property}\"", "",
                    StringComparison.Ordinal),
                "missing " + field);
        }
        RejectJson(serialized[..^1] + ",\"UnknownPort\":443}",
            "an unknown port field");

        var program = File.ReadAllText(Path.GetFullPath("src/PkiProxy.Api/Program.cs"));
        Check(Count(program, "await BootstrapEnrollmentWorkflowTests.RunAsync()") == 0,
            "production host does not invoke test code");
        Check(Count(program, "Configured bootstrap technician authentication scheme is not registered.") == 1 &&
              Count(program, "AddScheme<AuthenticationSchemeOptions, BootstrapKerberosAuthenticationHandler>") == 1,
            "startup registers and verifies exactly one dedicated technician scheme");
        Check(Count(program, "PkiProxy-Pairing-Code") == 1 && Count(program, "[\"Cache-Control\"] = \"no-store\"") >= 1,
            "pending code has one response location and cache suppression");
        Check(program.IndexOf("Admission.TryAcquire", StringComparison.Ordinal) <
              program.IndexOf("SoapEnvelopeReader.ReadAsync", StringComparison.Ordinal),
            "bootstrap admission is registered before SOAP parsing");
        var approvalReader = File.ReadAllText(Path.GetFullPath(
            "src/PkiProxy.Api/Authentication/BootstrapApprovalRequestReader.cs"));
        Check(approvalReader.IndexOf("AuthenticateAsync(scheme)", StringComparison.Ordinal) <
              approvalReader.IndexOf("request.Body.ReadExactlyAsync", StringComparison.Ordinal),
            "technician authentication completes before approval body parsing");
        Check(program.Contains("WstepRequestKind.QueryTokenStatus", StringComparison.Ordinal) &&
              program.Contains("BootstrapIssuanceResult.Uncertain or BootstrapIssuanceResult.Rejected", StringComparison.Ordinal),
            "unknown and uncertain status requests share the fail-closed SOAP processing boundary");
        var workflow = File.ReadAllText(Path.GetFullPath("src/PkiProxy.Api/Domain/BootstrapEnrollmentWorkflow.cs"));
        Check(!workflow.Contains("TryClaimSubmission", StringComparison.Ordinal) &&
              !workflow.Contains("NativeCesEnrollmentIssuer", StringComparison.Ordinal),
            "bootstrap integration exposes no CA submission capability");
        var runner = File.ReadAllText(Path.GetFullPath("tests/PkiProxy.PublicContractTests/Program.cs"));
        Check(Count(runner, "BootstrapEnrollmentWorkflowTests.RunAsync()") == 1 &&
              Count(runner, "BootstrapHostingIntegrationTests.Run()") == 1 &&
              Count(runner, "BootstrapKerberosAuthenticationTests.RunAsync()") == 1 &&
              Count(runner, "BootstrapIssuanceWorkflowTests.RunAsync()") == 1 &&
              Count(runner, "NativeDomainRenewalTests.RunAsync()") == 1 &&
              Count(runner, "NativeDomainEnrollmentTests.RunAsync(nativePublicFixture)") == 1,
            "new focused contract groups are registered exactly once");

        Console.WriteLine($"Bootstrap hosting integration checks passed ({checks}).");

        void RejectJson(string json, string label)
        {
            try
            {
                using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
                _ = BootstrapDeployment.DeserializeConfigurationAsync(stream).GetAwaiter().GetResult();
                throw new InvalidOperationException("Bootstrap hosting integration accepted " + label);
            }
            catch (InvalidDataException) { checks++; }
        }
    }

    private static int Count(string value, string token) =>
        value.Split(token, StringSplitOptions.None).Length - 1;
}
