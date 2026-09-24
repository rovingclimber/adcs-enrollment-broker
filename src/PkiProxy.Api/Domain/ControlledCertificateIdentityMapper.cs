using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Domain;

internal sealed record CertificateClaimPolicy(string BrokerProfileUrn, string FactUrnPrefix)
{
    public void Validate()
    {
        if (!IsUrn(BrokerProfileUrn) || !FactUrnPrefix.EndsWith(':') || !IsUrn(FactUrnPrefix + "placeholder"))
        {
            throw new InvalidOperationException("Certificate claim policy must contain RFC-compliant URNs.");
        }
    }

    private static bool IsUrn(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        string.Equals(uri.Scheme, "urn", StringComparison.OrdinalIgnoreCase);
}

internal static class ControlledCertificateIdentityMapper
{
    public static ControlledCertificateIdentity Create(
        AuthoritativeDeviceFacts facts,
        CertificateClaimPolicy claimPolicy)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(claimPolicy);
        claimPolicy.Validate();
        ValidateDistinguishedName(facts.DirectoryDistinguishedName);

        var claims = new[]
        {
            claimPolicy.BrokerProfileUrn,
            Claim(claimPolicy.FactUrnPrefix, "asset", facts.AssetId),
            Claim(claimPolicy.FactUrnPrefix, "class", facts.DeviceClass),
            Claim(claimPolicy.FactUrnPrefix, "use-case", facts.UseCase),
            Claim(claimPolicy.FactUrnPrefix, "location", facts.Location),
            Claim(claimPolicy.FactUrnPrefix, "management-domain", facts.ManagementDomain)
        };

        return new ControlledCertificateIdentity(
            facts.DirectoryDistinguishedName,
            claims.Select(value => new Uri(value, UriKind.Absolute)).ToArray());
    }

    private static string Claim(string prefix, string name, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return $"{prefix}{name}:{Uri.EscapeDataString(value)}";
    }

    private static void ValidateDistinguishedName(string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        try
        {
            _ = new X500DistinguishedName(distinguishedName);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidOperationException("The authoritative directory distinguished name is invalid.", exception);
        }
    }
}
