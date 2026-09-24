using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using PkiProxy.Domain;

internal static class SignerRotationPolicyTests
{
    internal static void Run()
    {
        var now = DateTimeOffset.UtcNow;
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=rotation-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(now.AddMinutes(-1), now.AddHours(3));
        var hash = SHA256.HashData(certificate.RawData);
        var valid = Load(Convert.ToHexString(hash), "60");
        valid.Validate(certificate, now);
        var checks = 1;

        Reject(() => Load(null, "60"), "missing pin");
        Reject(() => Load("00", "60"), "short pin");
        Reject(() => Load(new string('Z', 64), "60"), "non-hex pin");
        Reject(() => Load(Convert.ToHexString(hash), "59"), "short safety window");
        Reject(() => Load(Convert.ToHexString(hash), "10081"), "long safety window");
        Reject(() => Load(Convert.ToHexString(hash), "1.5"), "non-integer safety window");
        Reject(() => new SignerRotationPolicy(new byte[32], TimeSpan.FromMinutes(60)).Validate(certificate, now), "wrong generation");
        Reject(() => new SignerRotationPolicy(hash, TimeSpan.FromHours(4)).Validate(certificate, now), "inside safety window");

        Console.WriteLine($"Signer rotation policy checks passed: {checks} positive and 8 fail-closed.");

        static SignerRotationPolicy Load(string? pin, string? minutes)
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Broker:Issuance:SignerCertificateSha256"] = pin,
                ["Broker:Issuance:SignerMinimumRemainingValidityMinutes"] = minutes
            }).Build();
            return SignerRotationPolicy.Load(configuration.GetSection("Broker:Issuance"));
        }

        static void Reject(Action action, string label)
        {
            try { action(); }
            catch (Exception exception) when (exception is InvalidOperationException or CryptographicException) { return; }
            throw new InvalidOperationException("Unsafe signer rotation policy accepted: " + label);
        }
    }
}
