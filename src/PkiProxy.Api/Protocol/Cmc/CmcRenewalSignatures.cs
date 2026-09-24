using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Protocol.Cmc;

// Cryptographic layer only. Callers must independently validate the inner CSR,
// renewal profile, old certificate trust/revocation and authenticated asset.
// In particular, success does not authorize enrollment or inherited SAN facts.
internal static class CmcRenewalSignatures
{
    private const string Sha256 = "2.16.840.1.101.3.4.2.1";
    private const string PkiData = "1.3.6.1.5.5.7.12.2";
    private static readonly Asn1Tag ContextZero = new(TagClass.ContextSpecific, 0, true);

    internal static void Verify(ReadOnlyMemory<byte> envelope, ReadOnlySpan<byte> expectedContent,
        PublicKey requestedKey, X509Certificate2 renewalCertificate)
    {
        Require(envelope.Length is > 0 and <= 131072, "envelope size");
        Require(expectedContent.Length is > 0 and <= 131072, "content size");
        ArgumentNullException.ThrowIfNull(requestedKey);
        ArgumentNullException.ThrowIfNull(renewalCertificate);
        // Snapshot caller-owned buffers before parsing and checking signatures.
        var snapshot = envelope.ToArray();
        var expected = expectedContent.ToArray();
        try { VerifyCore(snapshot, expected, requestedKey, renewalCertificate); }
        catch (AsnContentException exception)
        { throw new CryptographicException("Invalid renewal CMS DER.", exception); }
    }

    private static void VerifyCore(byte[] envelope, byte[] expectedContent,
        PublicKey requestedKey, X509Certificate2 certificate)
    {
        using var primaryKey = requestedKey.GetRSAPublicKey();
        using var oldKey = certificate.GetRSAPublicKey();
        Require(primaryKey is not null && primaryKey.KeySize is >= 2048 and <= 8192,
            "requested RSA key size");
        Require(oldKey is not null && oldKey.KeySize is >= 2048 and <= 8192, "renewal RSA key size");
        var root = new AsnReader(envelope, AsnEncodingRules.DER);
        var contentInfo = root.ReadSequence();
        Require(contentInfo.ReadObjectIdentifier() == "1.2.840.113549.1.7.2", "signedData");
        var wrapper = contentInfo.ReadSequence(ContextZero);
        var signed = wrapper.ReadSequence();
        Require(signed.ReadInteger() == 3, "CMS version");
        var algorithms = signed.ReadSetOf();
        Require(Algorithm(algorithms) == Sha256, "digest algorithm");
        algorithms.ThrowIfNotEmpty();
        var encapsulated = signed.ReadSequence();
        Require(encapsulated.ReadObjectIdentifier() == PkiData, "content type");
        var explicitData = encapsulated.ReadSequence(ContextZero);
        var content = explicitData.ReadOctetString();
        Require(content.AsSpan().SequenceEqual(expectedContent), "validated content binding");
        explicitData.ThrowIfNotEmpty(); encapsulated.ThrowIfNotEmpty();
        var certificates = signed.ReadSetOf(ContextZero);
        Require(certificates.ReadEncodedValue().Span.SequenceEqual(certificate.RawData), "old certificate binding");
        certificates.ThrowIfNotEmpty();
        // No CRLs, extra certificates, counter-signatures or unsigned attributes.
        var signers = signed.ReadSetOf();
        var primarySeen = false;
        var renewalSeen = false;
        while (signers.HasData)
        {
            var signer = signers.ReadSequence();
            var version = signer.ReadInteger();
            RSA key;
            if (version == 3)
            {
                Require(!primarySeen, "one primary signer"); primarySeen = true;
                var identifier = signer.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                // RFC5280 method-1 SKI identifies the CSR key; it is not a signature digest.
#pragma warning disable CA5350
                var expectedIdentifier = SHA1.HashData(requestedKey.EncodedKeyValue.RawData);
#pragma warning restore CA5350
                Require(CryptographicOperations.FixedTimeEquals(identifier, expectedIdentifier), "primary signer key binding");
                key = primaryKey!;
            }
            else
            {
                Require(version == 1 && !renewalSeen, "one renewal signer"); renewalSeen = true;
                var identity = signer.ReadSequence();
                Require(identity.ReadEncodedValue().Span.SequenceEqual(certificate.IssuerName.RawData), "renewal issuer binding");
                Require(identity.ReadInteger() == new BigInteger(certificate.GetSerialNumber(), isUnsigned: true),
                    "renewal serial binding");
                identity.ThrowIfNotEmpty();
                key = oldKey!;
            }
            Require(Algorithm(signer) == Sha256, "signer digest");
            var authenticated = signer.ReadEncodedValue().ToArray();
            VerifyAttributes(authenticated, content);
            Require(Algorithm(signer) is "1.2.840.113549.1.1.1" or "1.2.840.113549.1.1.11", "RSA signature algorithm");
            var signature = signer.ReadOctetString();
            signer.ThrowIfNotEmpty();
            authenticated[0] = 0x31; // CMS signs DER SET OF, not the wire's IMPLICIT [0].
            Require(key.VerifyData(authenticated, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                "signer proof of possession");
        }
        Require(primarySeen && renewalSeen, "both signers required");
        signed.ThrowIfNotEmpty(); wrapper.ThrowIfNotEmpty(); contentInfo.ThrowIfNotEmpty(); root.ThrowIfNotEmpty();
    }

    private static void VerifyAttributes(byte[] encoded, byte[] content)
    {
        var root = new AsnReader(encoded, AsnEncodingRules.DER);
        var attributes = root.ReadSetOf(ContextZero);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (attributes.HasData)
        {
            var attribute = attributes.ReadSequence();
            var oid = attribute.ReadObjectIdentifier();
            Require(seen.Add(oid) && seen.Count <= 2, "unique signed attributes");
            var values = attribute.ReadSetOf();
            if (oid == "1.2.840.113549.1.9.3")
                Require(values.ReadObjectIdentifier() == PkiData, "signed content type");
            else if (oid == "1.2.840.113549.1.9.4")
                Require(CryptographicOperations.FixedTimeEquals(values.ReadOctetString(), SHA256.HashData(content)), "content digest");
            else throw new CryptographicException("Unsupported renewal signed attribute.");
            values.ThrowIfNotEmpty(); attribute.ThrowIfNotEmpty();
        }
        Require(seen.Count == 2, "required signed attributes");
        root.ThrowIfNotEmpty();
    }

    private static string Algorithm(AsnReader reader)
    {
        var algorithm = reader.ReadSequence();
        var oid = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData) algorithm.ReadNull();
        algorithm.ThrowIfNotEmpty();
        return oid;
    }

    private static void Require(bool valid, string detail)
    { if (!valid) throw new CryptographicException("Invalid renewal signatures: " + detail + "."); }
}
