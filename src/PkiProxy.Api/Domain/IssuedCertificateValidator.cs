using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Protocol.Cmc;

namespace PkiProxy.Domain;

internal enum IssuedCertificateValidationResult
{
    Valid,
    ChainInvalid,
    PublicKeyMismatch,
    SubjectMismatch,
    MissingClientAuthenticationEku,
    KeyUsageMismatch,
    SubjectAlternativeNameMismatch,
    CertificateNotCurrent,
    InvalidCertificateEncoding
}

internal sealed record IssuedCertificateValidation(IssuedCertificateValidationResult Result);

internal sealed record IssuedCertificateValidationPolicy(
    X509Certificate2 TrustedRoot,
    X509KeyUsageFlags ExpectedKeyUsage = X509KeyUsageFlags.DigitalSignature);

internal static class IssuedCertificateValidator
{
    internal static bool MatchesTemplate(X509Certificate2 certificate, CmcTemplate template)
    {
        var extensions = certificate.Extensions.Cast<X509Extension>().ToArray();
        if (extensions.GroupBy(e => e.Oid?.Value, StringComparer.Ordinal).Any(g => g.Count() != 1)) return false;
        var information = extensions.SingleOrDefault(e => e.Oid?.Value == "1.3.6.1.4.1.311.21.7");
        if (information is null) return false;
        var reader = new AsnReader(information.RawData, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        if (sequence.ReadObjectIdentifier() != template.Oid || sequence.ReadInteger() != template.MajorVersion ||
            sequence.ReadInteger() != template.MinorVersion) return false;
        sequence.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
        return true;
    }

    private const string SubjectAlternativeNameOid = "2.5.29.17";
    private const string ClientAuthenticationEku = "1.3.6.1.5.5.7.3.2";
    private static readonly Asn1Tag UriGeneralNameTag = new(TagClass.ContextSpecific, 6);
    private static readonly Asn1Tag DnsGeneralNameTag = new(TagClass.ContextSpecific, 2);

    public static IssuedCertificateValidation Validate(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> certificationRequestDer,
        ControlledCertificateIdentity expectedIdentity,
        IssuedCertificateValidationPolicy policy,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        ArgumentNullException.ThrowIfNull(policy);

        try
        {
            var utcNow = now.UtcDateTime;
            if (utcNow < certificate.NotBefore.ToUniversalTime() || utcNow >= certificate.NotAfter.ToUniversalTime())
            {
                return new IssuedCertificateValidation(IssuedCertificateValidationResult.CertificateNotCurrent);
            }

            var expectedSpki = CsrBinding.ExtractSubjectPublicKeyInfoDer(certificationRequestDer);
            if (!CryptographicOperations.FixedTimeEquals(expectedSpki, certificate.PublicKey.ExportSubjectPublicKeyInfo()))
            {
                return new IssuedCertificateValidation(IssuedCertificateValidationResult.PublicKeyMismatch);
            }

            var expectedSubject = CertificateSubjectEncoder.Encode(expectedIdentity.SubjectDistinguishedName);
            if (!expectedSubject.AsSpan().SequenceEqual(certificate.SubjectName.RawData))
            {
                return new IssuedCertificateValidation(IssuedCertificateValidationResult.SubjectMismatch);
            }

            if (!HasClientAuthenticationEku(certificate))
            {
                return new IssuedCertificateValidation(IssuedCertificateValidationResult.MissingClientAuthenticationEku);
            }

            if (!MatchesSubjectAlternativeNames(certificate, expectedIdentity))
            {
                return new IssuedCertificateValidation(IssuedCertificateValidationResult.SubjectAlternativeNameMismatch);
            }

            var keyUsages = certificate.Extensions.OfType<X509KeyUsageExtension>().ToArray();
            if (keyUsages.Length != 1 || keyUsages[0].KeyUsages != policy.ExpectedKeyUsage ||
                !policy.ExpectedKeyUsage.HasFlag(X509KeyUsageFlags.DigitalSignature) ||
                (policy.ExpectedKeyUsage & ~(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment)) != 0)
            {
                return new IssuedCertificateValidation(IssuedCertificateValidationResult.KeyUsageMismatch);
            }

            return BuildTrustedChain(certificate, policy.TrustedRoot, utcNow)
                ? new IssuedCertificateValidation(IssuedCertificateValidationResult.Valid)
                : new IssuedCertificateValidation(IssuedCertificateValidationResult.ChainInvalid);
        }
        catch (AsnContentException)
        {
            return new IssuedCertificateValidation(IssuedCertificateValidationResult.InvalidCertificateEncoding);
        }
        catch (CryptographicException)
        {
            return new IssuedCertificateValidation(IssuedCertificateValidationResult.InvalidCertificateEncoding);
        }
    }

    private static bool BuildTrustedChain(X509Certificate2 certificate, X509Certificate2 trustedRoot, DateTime utcNow)
    {
        using var chain = new X509Chain();
        ConfigureOfflineChainPolicy(chain.ChainPolicy, trustedRoot, utcNow);
        return chain.Build(certificate);
    }

    internal static void ConfigureOfflineChainPolicy(X509ChainPolicy policy, X509Certificate2 trustedRoot, DateTime utcNow)
    {
        policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        policy.VerificationTime = utcNow;
        // This preliminary check is intentionally offline. The release path
        // separately applies the pinned signed-CRL verifier.
        policy.RevocationMode = X509RevocationMode.NoCheck;
        policy.DisableCertificateDownloads = true;
        policy.UrlRetrievalTimeout = TimeSpan.Zero;
        policy.CustomTrustStore.Add(trustedRoot);
    }

    private static bool HasClientAuthenticationEku(X509Certificate2 certificate)
    {
        var extensions = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        return extensions.Length == 1 && extensions[0].EnhancedKeyUsages.Count == 1 &&
            extensions[0].EnhancedKeyUsages[0].Value == ClientAuthenticationEku;
    }

    private static bool MatchesSubjectAlternativeNames(X509Certificate2 certificate, ControlledCertificateIdentity expected)
    {
        var expectedUris = expected.SubjectAlternativeNameUris.Select(uri => uri.OriginalString).ToHashSet(StringComparer.Ordinal);
        var expectedDns = (expected.SubjectAlternativeNameDnsNames ?? []).ToHashSet(StringComparer.Ordinal);
        if (expectedUris.Count != expected.SubjectAlternativeNameUris.Count || expectedDns.Count != (expected.SubjectAlternativeNameDnsNames?.Count ?? 0)) return false;
        var extensions = certificate.Extensions.Cast<X509Extension>().Where(e => e.Oid?.Value == SubjectAlternativeNameOid).ToArray();
        if (extensions.Length == 0) return expectedUris.Count + expectedDns.Count == 0;
        if (extensions.Length != 1) return false;

        var reader = new AsnReader(extensions[0].RawData, AsnEncodingRules.DER);
        var names = reader.ReadSequence();
        var uris = new HashSet<string>(StringComparer.Ordinal);
        var dns = new HashSet<string>(StringComparer.Ordinal);
        while (names.HasData)
        {
            if (names.PeekTag().HasSameClassAndValue(UriGeneralNameTag))
            {
                if (!uris.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, UriGeneralNameTag))) return false;
            }
            else if (names.PeekTag().HasSameClassAndValue(DnsGeneralNameTag))
            {
                if (!dns.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, DnsGeneralNameTag))) return false;
            }
            else
            {
                // Unanticipated UPN, IP, email, directoryName, etc. are identities,
                // not ignorable decoration. The configured profile must own all SANs.
                return false;
            }
        }

        reader.ThrowIfNotEmpty();
        return uris.Count + dns.Count > 0 && expectedUris.SetEquals(uris) && expectedDns.SetEquals(dns);
    }
}
