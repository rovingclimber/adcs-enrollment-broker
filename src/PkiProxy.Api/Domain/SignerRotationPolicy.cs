using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Domain;

// Pins one reviewed signer generation and defines when it must fail closed.
// Rotation is an explicit configuration-and-restart operation; the application
// never follows a mutable "current" link or selects a certificate implicitly.
internal sealed record SignerRotationPolicy(byte[] CertificateSha256, TimeSpan MinimumRemainingValidity)
{
    internal static SignerRotationPolicy Load(IConfigurationSection section)
    {
        var encodedHash = section["SignerCertificateSha256"];
        if (encodedHash is null || encodedHash.Length != 64 || !encodedHash.All(Uri.IsHexDigit))
            throw new InvalidOperationException("Exact signer certificate SHA256 pin required.");

        if (!int.TryParse(section["SignerMinimumRemainingValidityMinutes"], NumberStyles.None,
                CultureInfo.InvariantCulture, out var minutes) || minutes is < 60 or > 10_080)
            throw new InvalidOperationException("Signer minimum remaining validity must be 60-10080 minutes.");

        return new(Convert.FromHexString(encodedHash), TimeSpan.FromMinutes(minutes));
    }

    internal void Validate(X509Certificate2 certificate, DateTimeOffset now)
    {
        var actualHash = SHA256.HashData(certificate.RawDataMemory.Span);
        if (!CryptographicOperations.FixedTimeEquals(actualHash, CertificateSha256))
            throw new CryptographicException("Signer certificate does not match the configured generation.");
        if (certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime.Add(MinimumRemainingValidity))
            throw new CryptographicException("Signer certificate is inside the configured rotation safety window.");
    }
}
