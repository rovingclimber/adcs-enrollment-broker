using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Domain;

internal enum CertificateRenewalResult
{
    Valid,
    NotBrokerIssued,
    CertificateNotCurrent,
    MissingClientAuthenticationEku
}

internal sealed record BrokerCertificateBinding(
    string CertificateThumbprint,
    string AuthoritativeAssetId,
    DateTimeOffset RegisteredAt);

internal sealed record CertificateRenewalValidation(
    CertificateRenewalResult Result,
    string? AuthoritativeAssetId);

internal interface IBrokerCertificateBindingStore
{
    void Register(BrokerCertificateBinding binding);

    CertificateRenewalValidation ValidateForRenewal(X509Certificate2 certificate, DateTimeOffset now);
}

// HTTP mTLS/chain validation is a separate transport concern. This store adds
// the broker's application-level invariant: the presented certificate must be
// one that this broker recorded against an authoritative asset at issuance.
internal sealed class InMemoryBrokerCertificateBindingStore : IBrokerCertificateBindingStore
{
    private const string ClientAuthenticationEku = "1.3.6.1.5.5.7.3.2";
    private readonly ConcurrentDictionary<string, BrokerCertificateBinding> _bindings = new(StringComparer.OrdinalIgnoreCase);

    public void Register(BrokerCertificateBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentException.ThrowIfNullOrWhiteSpace(binding.CertificateThumbprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(binding.AuthoritativeAssetId);
        if (!_bindings.TryAdd(binding.CertificateThumbprint, binding))
        {
            throw new InvalidOperationException("A broker certificate binding already exists for this thumbprint.");
        }
    }

    public CertificateRenewalValidation ValidateForRenewal(X509Certificate2 certificate, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (!_bindings.TryGetValue(certificate.Thumbprint, out var binding))
        {
            return new CertificateRenewalValidation(CertificateRenewalResult.NotBrokerIssued, null);
        }

        var utcNow = now.UtcDateTime;
        if (utcNow < certificate.NotBefore.ToUniversalTime() || utcNow >= certificate.NotAfter.ToUniversalTime())
        {
            return new CertificateRenewalValidation(CertificateRenewalResult.CertificateNotCurrent, null);
        }

        if (!HasClientAuthenticationEku(certificate))
        {
            return new CertificateRenewalValidation(CertificateRenewalResult.MissingClientAuthenticationEku, null);
        }

        return new CertificateRenewalValidation(CertificateRenewalResult.Valid, binding.AuthoritativeAssetId);
    }

    private static bool HasClientAuthenticationEku(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(extension => extension.EnhancedKeyUsages.Cast<Oid>())
            .Any(oid => string.Equals(oid.Value, ClientAuthenticationEku, StringComparison.Ordinal));
}
