using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using PkiProxy.Protocol.Xcep;

internal static class BrokerPolicyConfigurationTests
{
    internal static void Run()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Policy test CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var otherCa = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddDays(2));
        var policy = new BrokerEnrollmentPolicy("test-policy", "Test", "TestMachine", "1.2.3.4", ca.RawData,
            new Uri("https://broker.invalid/ces/kerberos/service.svc/CES"), 2, 2048, 0x88000000, 0, 0, 64,
            31536000, 3628800, 101, 0, 1, DateTimeOffset.UtcNow);
        var checks = 0;
        void Check(byte[] bytes, bool allowed, X509Certificate2? trust = null)
        {
            var accepted = false;
            try { BrokerPolicyConfiguration.Parse(bytes, trust ?? ca, "broker.invalid"); accepted = true; }
            catch (Exception e) when (e is InvalidDataException or InvalidOperationException or JsonException or ArgumentException or CryptographicException) { }
            if (accepted != allowed) throw new InvalidOperationException("Unexpected policy configuration admission.");
            checks++;
        }
        Check(JsonSerializer.SerializeToUtf8Bytes(policy), true);
        var legacyPolicy = System.Text.Json.Nodes.JsonNode.Parse(JsonSerializer.Serialize(policy))!.AsObject();
        legacyPolicy.Remove("RenewalOnly");
        Check(Encoding.UTF8.GetBytes(legacyPolicy.ToJsonString()), true);
        Check(JsonSerializer.SerializeToUtf8Bytes(policy with { RenewalOnly = true }), false);
        // Reserved-bit compatibility experiment did not enable native auto-enrollment.
        Check(JsonSerializer.SerializeToUtf8Bytes(policy with { GeneralFlags = 96 }), false);
        Check(JsonSerializer.SerializeToUtf8Bytes(policy with { GeneralFlags = 128 }), false);
        Check(JsonSerializer.SerializeToUtf8Bytes(policy with { EnrollmentFlags = 0x20 }), false);
        Check(JsonSerializer.SerializeToUtf8Bytes(policy with { EnrollmentFlags = 0x21 }), false);
        Check(JsonSerializer.SerializeToUtf8Bytes(policy with { EnrollmentFlags = 0x100 }), false);
        var autoPolicy = policy;
        var response = BrokerEnrollmentPolicyResponseWriter.Create(autoPolicy, new HashSet<string>());
        System.Xml.Linq.XNamespace xcep = XcepNamespaces.EnrollmentPolicy;
        if (response.Descendants(xcep + "enrollmentFlags").Single().Value != "0" ||
            response.Descendants(xcep + "autoEnroll").Single().Value != "true")
            throw new InvalidOperationException("Auto-enrollment flags and permission must reach the native client.");
        checks++;
        Check(JsonSerializer.SerializeToUtf8Bytes(policy), false, otherCa);
        foreach (var changed in new[] {
            policy with { EnrollmentUri = new Uri("https://other.invalid/ces/kerberos/service.svc/CES") },
            policy with { EnrollmentUri = new Uri("http://broker.invalid/ces/kerberos/service.svc/CES") },
            policy with { EnrollmentUri = new Uri("https://broker.invalid:8443/ces/kerberos/service.svc/CES") },
            policy with { EnrollmentUri = new Uri("https://broker.invalid/ces/kerberos/service.svc/CES?x=1") },
            policy with { ClientAuthentication = 1 }, policy with { MinimumKeyLength = 1024 },
            policy with { SubjectNameFlags = 1 }, policy with { PrivateKeyFlags = 16 },
            policy with { GeneralFlags = 0 }, policy with { EnrollmentFlags = 1 },
            policy with { RenewalPeriodSeconds = policy.ValidityPeriodSeconds } })
            Check(JsonSerializer.SerializeToUtf8Bytes(changed), false);
        Check(Encoding.UTF8.GetBytes("{}"), false);
        var json = JsonSerializer.Serialize(policy);
        Check(Encoding.UTF8.GetBytes(json[..^1] + ",\"ClientAuthentication\":2}"), false);
        Check(Encoding.UTF8.GetBytes(json[..^1] + ",\"Unknown\":true}"), false);
        Check(new byte[1_048_577], false);
        Console.WriteLine($"Broker policy configuration checks passed: {checks}.");
    }
}
