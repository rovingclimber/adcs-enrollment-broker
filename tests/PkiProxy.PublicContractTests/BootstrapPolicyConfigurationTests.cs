using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using PkiProxy.Protocol.Xcep;

internal static class BootstrapPolicyConfigurationTests
{
    internal static void Run()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Bootstrap policy test CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var otherCa = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddDays(2));
        using var expiredCa = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(-1));
        using var futureCa = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(1), DateTimeOffset.UtcNow.AddDays(2));
        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=Not a CA", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using var leaf = leafRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));

        var bootstrap = Policy(
            "bootstrap-policy",
            "1.2.3.4.1",
            ca.RawData,
            "https://broker.invalid/ces/bootstrap/service.svc/CES",
            1);
        var kerberos = Policy(
            "kerberos-policy",
            "1.2.3.4.2",
            ca.RawData,
            "https://broker.invalid/ces/kerberos/service.svc/CES",
            2);

        var checks = 0;
        void ParseCheck(BrokerEnrollmentPolicy policy, bool allowed, X509Certificate2? trust = null)
        {
            var accepted = false;
            try
            {
                BootstrapPolicyConfiguration.Parse(JsonSerializer.SerializeToUtf8Bytes(policy), trust ?? ca, "broker.invalid");
                accepted = true;
            }
            catch (Exception exception) when (exception is InvalidDataException or InvalidOperationException or
                                             JsonException or ArgumentException or CryptographicException) { }
            if (accepted != allowed)
                throw new InvalidOperationException("Unexpected bootstrap policy configuration admission.");
            checks++;
        }

        ParseCheck(bootstrap, true);
        ParseCheck(bootstrap, false, otherCa);
        ParseCheck(bootstrap with { IssuingCaCertificateDer = expiredCa.RawData }, false, expiredCa);
        ParseCheck(bootstrap with { IssuingCaCertificateDer = futureCa.RawData }, false, futureCa);
        ParseCheck(bootstrap with { IssuingCaCertificateDer = leaf.RawData }, false, leaf);
        foreach (var changed in new[]
        {
            bootstrap with { ClientAuthentication = 0 },
            bootstrap with { ClientAuthentication = 2 },
            bootstrap with { RenewalOnly = true },
            bootstrap with { EnrollmentUri = new Uri("https://other.invalid/ces/bootstrap/service.svc/CES") },
            bootstrap with { EnrollmentUri = new Uri("http://broker.invalid/ces/bootstrap/service.svc/CES") },
            bootstrap with { EnrollmentUri = new Uri("https://broker.invalid:8443/ces/bootstrap/service.svc/CES") },
            bootstrap with { EnrollmentUri = new Uri("https://user@broker.invalid/ces/bootstrap/service.svc/CES") },
            bootstrap with { EnrollmentUri = new Uri("https://broker.invalid/ces/bootstrap/service.svc/CES?x=1") },
            bootstrap with { EnrollmentUri = new Uri("https://broker.invalid/ces/bootstrap/service.svc/CES#x") },
            bootstrap with { EnrollmentUri = new Uri("https://broker.invalid/ces/kerberos/service.svc/CES") },
            bootstrap with { MinimumKeyLength = 1024 },
            bootstrap with { SubjectNameFlags = 1 },
            bootstrap with { PrivateKeyFlags = 16 },
            bootstrap with { GeneralFlags = 0 },
            bootstrap with { EnrollmentFlags = 1 },
            bootstrap with { RenewalPeriodSeconds = bootstrap.ValidityPeriodSeconds }
        })
            ParseCheck(changed, false);

        ParseBytesCheck(Encoding.UTF8.GetBytes("{}"), false);
        var json = JsonSerializer.Serialize(bootstrap);
        ParseBytesCheck(Encoding.UTF8.GetBytes(json[..^1] + ",\"ClientAuthentication\":1}"), false);
        ParseBytesCheck(Encoding.UTF8.GetBytes(json[..^1] + ",\"Unknown\":true}"), false);
        ParseBytesCheck(new byte[1_048_577], false);

        CompositionCheck(bootstrap, kerberos, true);
        CompositionCheck(bootstrap with { PolicyServerId = kerberos.PolicyServerId }, kerberos, false);
        CompositionCheck(bootstrap with { TemplateOid = kerberos.TemplateOid }, kerberos, false);
        CompositionCheck(kerberos, bootstrap, false);
        CompositionCheck(bootstrap with { ClientAuthentication = 2 }, kerberos, false);
        CompositionCheck(bootstrap, kerberos with { EnrollmentUri = bootstrap.EnrollmentUri }, false);

        var temporaryDirectory = Path.Combine(Path.GetTempPath(), $"pki-bootstrap-policy-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);
        try
        {
            var policyPath = Path.Combine(temporaryDirectory, "bootstrap-policy.json");
            var trustPath = Path.Combine(temporaryDirectory, "trusted-ca.pem");
            File.WriteAllBytes(policyPath, JsonSerializer.SerializeToUtf8Bytes(bootstrap));
            File.WriteAllText(trustPath, PemEncoding.WriteString("CERTIFICATE", ca.RawData));
            _ = BootstrapPolicyConfiguration.Load(policyPath, trustPath, "broker.invalid");
            checks++;
            LoadCheck("relative-policy.json", trustPath, false);
            LoadCheck(policyPath, "relative-trust.pem", false);
        }
        finally
        {
            Directory.Delete(temporaryDirectory, true);
        }

        Console.WriteLine($"Bootstrap policy configuration checks passed: {checks}.");

        void ParseBytesCheck(byte[] bytes, bool allowed)
        {
            var accepted = false;
            try { BootstrapPolicyConfiguration.Parse(bytes, ca, "broker.invalid"); accepted = true; }
            catch (Exception exception) when (exception is InvalidDataException or InvalidOperationException or
                                             JsonException or ArgumentException or CryptographicException) { }
            if (accepted != allowed)
                throw new InvalidOperationException("Unexpected bootstrap JSON admission.");
            checks++;
        }

        void CompositionCheck(BrokerEnrollmentPolicy candidate, BrokerEnrollmentPolicy domain, bool allowed)
        {
            var accepted = false;
            try { BootstrapPolicyConfiguration.ValidateComposition(candidate, domain, "broker.invalid"); accepted = true; }
            catch (Exception exception) when (exception is InvalidDataException or InvalidOperationException or ArgumentException) { }
            if (accepted != allowed)
                throw new InvalidOperationException("Unexpected bootstrap policy composition admission.");
            checks++;
        }

        void LoadCheck(string policyPath, string trustPath, bool allowed)
        {
            var accepted = false;
            try { BootstrapPolicyConfiguration.Load(policyPath, trustPath, "broker.invalid"); accepted = true; }
            catch (Exception exception) when (exception is InvalidDataException or IOException or CryptographicException) { }
            if (accepted != allowed)
                throw new InvalidOperationException("Unexpected bootstrap file-path admission.");
            checks++;
        }
    }

    private static BrokerEnrollmentPolicy Policy(
        string policyServerId,
        string templateOid,
        byte[] ca,
        string enrollmentUri,
        uint clientAuthentication) =>
        new(
            policyServerId,
            "Bootstrap test",
            "BootstrapTestMachine",
            templateOid,
            ca,
            new Uri(enrollmentUri),
            clientAuthentication,
            2048,
            0x88000000,
            0,
            0,
            64,
            31_536_000,
            2_592_000,
            1,
            null,
            24,
            DateTimeOffset.UtcNow);
}
