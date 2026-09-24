using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;
using PkiProxy.Signing;

namespace PkiProxy.Protocol.Cmc;

internal sealed record CmcTemplate(string Oid, int MajorVersion, int MinorVersion, string SignerApplicationPolicyOid,
    TimeSpan SignerMinimumRemainingValidity = default, string? BrokerProfileUrn = null);

internal sealed record CmcEnrollmentRequest(
    byte[] EncodedCms,
    byte[] NullSignedPkcs10,
    byte[] SubjectNameDer,
    byte[] SanExtensionDer,
    CsrBinding OriginalRequestBinding,
    byte[]? OriginalEnvelopeSha256 = null);

// Downstream construction only. This is NOT an incoming CMC parser, identity
// authorizer, signer trust/revocation validator or HTTP endpoint. Call only after
// authenticating the device and authorizing an exact CSR + authoritative facts.
// Bare PKCS#10 remains strict; native CMC must enter through ValidatedCmcRequest.
internal static class CmcEnrollmentRequestBuilder
{
    internal const string PkiDataOid = "1.3.6.1.5.5.7.12.2";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private const int MaximumCsrBytes = 65536;
    private static readonly Asn1Tag ContextZero = new(TagClass.ContextSpecific, 0, true);

    public static CmcEnrollmentRequest Build(
        ReadOnlySpan<byte> originalPkcs10,
        CsrBinding approvedBinding,
        ControlledCertificateIdentity authoritativeIdentity,
        CmcTemplate template,
        X509Certificate2 signingCertificate,
        DateTimeOffset now, RSA? signingKey = null, SigningIntentMetadata? signingIntent = null)
    {
        ArgumentNullException.ThrowIfNull(approvedBinding);
        ArgumentNullException.ThrowIfNull(authoritativeIdentity);
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(signingCertificate);
        if (originalPkcs10.IsEmpty || originalPkcs10.Length > MaximumCsrBytes)
            throw new CryptographicException("Unsupported CSR size.");

        // Snapshot before checking: neither key selection nor signature validation
        // may operate on subsequently modified caller-owned bytes.
        var original = originalPkcs10.ToArray();
        var binding = CsrBinding.FromDer(original);
        if (!approvedBinding.HasExpectedLengths() || !binding.Matches(approvedBinding))
            throw new CryptographicException("CSR does not match the authorized transaction.");
        ValidateOriginalProfile(original);
        var incoming = IncomingCsrPolicyValidator.Validate(original, IncomingCsrPolicy.NoClientExtensions);
        if (incoming.Result != IncomingCsrValidationResult.Valid)
            throw new CryptographicException("Original device signature or extension policy is invalid.");
        return BuildCore(original, binding, authoritativeIdentity, template, signingCertificate, now, signingKey, signingIntent);
    }

    public static CmcEnrollmentRequest Build(
        ValidatedCmcRequest request, CmcRequestBinding approvedBinding,
        ControlledCertificateIdentity authoritativeIdentity, CmcTemplate template,
        X509Certificate2 signingCertificate, DateTimeOffset now, RSA? signingKey = null, SigningIntentMetadata? signingIntent = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.Matches(approvedBinding))
            throw new CryptographicException("CMC envelope does not match the authorized transaction.");
        var binding = request.CreateBinding();
        return BuildCore(request.ExportPkcs10(), binding.Csr, authoritativeIdentity, template, signingCertificate, now, signingKey, signingIntent)
            with { OriginalEnvelopeSha256 = binding.EnvelopeSha256 };
    }

    internal static CmcEnrollmentRequest BuildRenewal(
        ValidatedRenewalCmcRequest request, CmcRequestBinding approvedBinding,
        ControlledCertificateIdentity authoritativeIdentity, CmcTemplate template,
        X509Certificate2 signingCertificate, DateTimeOffset now, RSA? signingKey = null, SigningIntentMetadata? signingIntent = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.Matches(approvedBinding))
            throw new CryptographicException("Renewal envelope does not match the authorized transaction.");
        var binding = request.CreateBinding();
        // Rebuild from the proven requested key and authoritative identity only.
        // Neither inherited SAN nor old subject/renewal attributes are copied.
        return BuildCore(request.ExportPkcs10(), binding.Csr, authoritativeIdentity, template, signingCertificate, now, signingKey, signingIntent)
            with { OriginalEnvelopeSha256 = binding.EnvelopeSha256 };
    }

    private static CmcEnrollmentRequest BuildCore(byte[] original, CsrBinding binding,
        ControlledCertificateIdentity authoritativeIdentity, CmcTemplate template,
        X509Certificate2 signingCertificate, DateTimeOffset now, RSA? signingKey, SigningIntentMetadata? signingIntent)
    {
        ArgumentNullException.ThrowIfNull(authoritativeIdentity);
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(signingCertificate);
        var spki = CsrBinding.ExtractSubjectPublicKeyInfoDer(original);
        using var devicePublicKey = RSA.Create();
        devicePublicKey.ImportSubjectPublicKeyInfo(spki, out var consumed);
        if (consumed != spki.Length || devicePublicKey.KeySize is < 2048 or > 8192)
            throw new CryptographicException("Unsupported device public key.");

        ValidateSigner(signingCertificate, template.SignerApplicationPolicyOid, now, template.SignerMinimumRemainingValidity, signingKey);
        if (template.MajorVersion < 0 || template.MinorVersion < 0)
            throw new ArgumentException("Template versions must be nonnegative.", nameof(template));

        var (subject, san) = EncodeIdentity(authoritativeIdentity);
        var templateInfo = new AsnWriter(AsnEncodingRules.DER);
        using (templateInfo.PushSequence())
        {
            templateInfo.WriteObjectIdentifier(template.Oid);
            templateInfo.WriteInteger(template.MajorVersion);
            templateInfo.WriteInteger(template.MinorVersion);
        }

        var info = new AsnWriter(AsnEncodingRules.DER);
        using (info.PushSequence())
        {
            info.WriteInteger(0);
            info.WriteEncodedValue(subject);
            info.WriteEncodedValue(spki);
            using (info.PushSetOf(ContextZero))
            using (info.PushSequence())
            {
                info.WriteObjectIdentifier("1.2.840.113549.1.9.14"); // extensionRequest
                using (info.PushSetOf())
                using (info.PushSequence())
                {
                    WriteExtension(info, "1.3.6.1.4.1.311.21.7", templateInfo.Encode());
                    WriteExtension(info, "2.5.29.17", san);
                }
            }
        }

        // MS-WCCE 2.2.2.6.5: the inner request has a digest, not a device signature.
        // It must never be accepted as client proof of possession or sent bare.
        var infoDer = info.Encode();
        var request = new AsnWriter(AsnEncodingRules.DER);
        using (request.PushSequence())
        {
            request.WriteEncodedValue(infoDer);
            using (request.PushSequence())
            {
                request.WriteObjectIdentifier(Sha256Oid);
                request.WriteNull();
            }
            request.WriteBitString(SHA256.HashData(infoDer));
        }
        var nullSigned = request.Encode();
        var pkiData = EncodePkiData(nullSigned);

        // .NET owns CMS cryptography; only the CMC ASN.1 above is our protocol code.
        // RFC2797 / MS-WCCE: null primary signer plus credential-backed RA signer.
        var cms = new SignedCms(new ContentInfo(new Oid(PkiDataOid), pkiData), detached: false);
        cms.ComputeSignature(new CmsSigner(SubjectIdentifierType.NoSignature)
        {
            DigestAlgorithm = new Oid(Sha256Oid)
        });
        var credential = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signingCertificate)
        {
            DigestAlgorithm = new Oid(Sha256Oid),
            IncludeOption = X509IncludeOption.EndCertOnly,
            SignaturePadding = RSASignaturePadding.Pkcs1
        };
        if (signingKey is not null) credential.PrivateKey = signingKey;
        if (signingKey is UnixSocketRsa isolated)
        {
            if (signingIntent is null || string.IsNullOrWhiteSpace(template.BrokerProfileUrn))
                throw new CryptographicException("A policy-bound isolated signing intent is required.");
            using var intent = isolated.BeginEnrollmentIntent(signingIntent, template.BrokerProfileUrn,
                template.Oid, template.MajorVersion, template.MinorVersion, pkiData);
            cms.ComputeSignature(credential, silent: true);
        }
        else cms.ComputeSignature(credential, silent: true);
        return new CmcEnrollmentRequest(cms.Encode(), nullSigned, subject, san, binding);
    }

    internal static void ValidateSigner(X509Certificate2 certificate, string requiredEku, DateTimeOffset now,
        TimeSpan minimumRemainingValidity = default, RSA? signingKey = null)
        => ValidateSigner(certificate, requiredEku, now, minimumRemainingValidity, requireAttachedPrivateKey: true, signingKey: signingKey);

    internal static void ValidateExternalSigner(X509Certificate2 certificate, string requiredEku, DateTimeOffset now,
        TimeSpan minimumRemainingValidity = default)
        => ValidateSigner(certificate, requiredEku, now, minimumRemainingValidity, requireAttachedPrivateKey: false, signingKey: null);

    private static void ValidateSigner(X509Certificate2 certificate, string requiredEku, DateTimeOffset now,
        TimeSpan minimumRemainingValidity, bool requireAttachedPrivateKey, RSA? signingKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requiredEku);
        using var publicKey = certificate.GetRSAPublicKey();
        var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        if ((requireAttachedPrivateKey && signingKey is null && !certificate.HasPrivateKey) || publicKey is null || publicKey.KeySize is < 2048 or > 8192 ||
            minimumRemainingValidity < TimeSpan.Zero ||
            now.UtcDateTime < certificate.NotBefore.ToUniversalTime() ||
            now.UtcDateTime.Add(minimumRemainingValidity) >= certificate.NotAfter.ToUniversalTime() ||
            eku.Length != 1 || !eku[0].EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == requiredEku) ||
            usage.Length != 1 || !usage[0].KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature) ||
            (usage[0].KeyUsages & (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)) != 0 ||
            certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority))
            throw new CryptographicException("Signing credential does not meet the configured profile.");
        if (signingKey is not null)
        {
            var expected = publicKey.ExportParameters(false);
            var actual = signingKey.ExportParameters(false);
            if (actual.Modulus is null || actual.Exponent is null || expected.Modulus is null || expected.Exponent is null ||
                !CryptographicOperations.FixedTimeEquals(actual.Modulus, expected.Modulus) ||
                !CryptographicOperations.FixedTimeEquals(actual.Exponent, expected.Exponent))
                throw new CryptographicException("Signing key does not match the configured certificate.");
        }
    }

    private static void ValidateOriginalProfile(byte[] original)
    {
        var reader = new AsnReader(original, AsnEncodingRules.DER);
        var request = reader.ReadSequence();
        var info = request.ReadSequence();
        if (info.ReadInteger() != 0) throw new CryptographicException("Unsupported PKCS10 version.");
        _ = info.ReadSequence(); // Subject is signed evidence, never identity authority.
        _ = info.ReadSequence(); // SPKI is validated independently using .NET RSA.
        // Fail closed on ALL attribute families, not just extensionRequest OIDs
        // understood by .NET. Native enrollment hints need a dedicated validator.
        info.ReadSetOf(ContextZero).ThrowIfNotEmpty();
        info.ThrowIfNotEmpty();
        var algorithm = request.ReadSequence();
        if (algorithm.ReadObjectIdentifier() != "1.2.840.113549.1.1.11")
            throw new CryptographicException("Only SHA256/RSA device signatures are currently supported.");
        if (algorithm.HasData) algorithm.ReadNull();
        algorithm.ThrowIfNotEmpty();
        _ = request.ReadBitString(out var unused);
        if (unused != 0) throw new CryptographicException("Invalid device signature encoding.");
        request.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
    }

    // Shared by authorization and construction, so unsupported authoritative
    // identities fail before acquiring a signer or attempting issuance.
    internal static (byte[] Subject, byte[] San) EncodeIdentity(ControlledCertificateIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var dn = identity.SubjectDistinguishedName;
        ArgumentException.ThrowIfNullOrWhiteSpace(dn);
        // Bounded ASCII profile until Unicode/RDN normalization has native fixtures.
        if (dn.Length > 4096 || dn.Any(c => c is < ' ' or > '~'))
            throw new ArgumentException("Unsupported authoritative DN profile.", nameof(identity));
        var subject = CertificateSubjectEncoder.Encode(dn);
        if (subject.Length <= 2)
            throw new ArgumentException("An authoritative subject is required.", nameof(identity));
        return (subject, EncodeSan(identity));
    }

    private static byte[] EncodeSan(ControlledCertificateIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity.SubjectAlternativeNameUris);
        var dnsNames = identity.SubjectAlternativeNameDnsNames?.ToArray() ?? [];
        var uris = identity.SubjectAlternativeNameUris.ToArray();
        if (dnsNames.Length + uris.Length is 0 or > 32)
            throw new ArgumentException("Unsupported SAN count.", nameof(identity));
        var seenDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenUris = new HashSet<string>(StringComparer.Ordinal);
        var san = new AsnWriter(AsnEncodingRules.DER);
        using (san.PushSequence())
        {
            foreach (var dns in dnsNames)
            {
                if (string.IsNullOrEmpty(dns) || dns.Length > 253 || !dns.Contains('.') || !seenDns.Add(dns) ||
                    dns.Split('.').Any(label => label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-' ||
                        label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
                    throw new ArgumentException("Invalid or duplicate authoritative DNS SAN.", nameof(identity));
                san.WriteCharacterString(UniversalTagNumber.IA5String, dns, new Asn1Tag(TagClass.ContextSpecific, 2));
            }
            foreach (var uri in uris)
            {
                if (uri is null || !uri.IsAbsoluteUri || uri.Scheme != "urn" || !IsSupportedUrn(uri.OriginalString) || !seenUris.Add(uri.OriginalString))
                    throw new ArgumentException("Invalid, duplicate or unsupported authoritative URN.", nameof(identity));
                san.WriteCharacterString(UniversalTagNumber.IA5String, uri.OriginalString, new Asn1Tag(TagClass.ContextSpecific, 6));
            }
        }
        return san.Encode();
    }

    // RFC8141 namespace + NSS subset: no r/q/fragment components in device facts.
    private static bool IsSupportedUrn(string value)
    {
        if (value.Length > 2048 || !value.StartsWith("urn:", StringComparison.Ordinal)) return false;
        var separator = value.IndexOf(':', 4);
        if (separator < 6 || separator > 36 || separator == value.Length - 1) return false;
        var nid = value.AsSpan(4, separator - 4);
        if (!char.IsAsciiLetterOrDigit(nid[0]) || !char.IsAsciiLetterOrDigit(nid[^1]) ||
            nid.Equals("urn", StringComparison.OrdinalIgnoreCase)) return false;
        foreach (var c in nid)
            if (!char.IsAsciiLetterOrDigit(c) && c != '-') return false;
        for (var i = separator + 1; i < value.Length; i++)
        {
            var c = value[i];
            if (c == '%')
            {
                if (i + 2 >= value.Length || !char.IsAsciiHexDigit(value[i + 1]) || !char.IsAsciiHexDigit(value[i + 2])) return false;
                i += 2;
            }
            else if (!char.IsAsciiLetterOrDigit(c) && !"-._~!$&'()*+,;=:@".Contains(c) && !(c == '/' && i > separator + 1)) return false;
        }
        return true;
    }

    private static byte[] EncodePkiData(byte[] request)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence()) { } // controlSequence: none; no client controls forwarded.
            using (writer.PushSequence())
            using (writer.PushSequence(ContextZero)) // IMPLICIT [0] TaggedCertificationRequest
            {
                writer.WriteInteger(1); // unique request bodyPartID
                writer.WriteEncodedValue(request);
            }
            using (writer.PushSequence()) { } // cmsSequence
            using (writer.PushSequence()) { } // otherMsgSequence
        }
        return writer.Encode();
    }

    private static void WriteExtension(AsnWriter writer, string oid, byte[] value)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteOctetString(value);
        }
    }
}
