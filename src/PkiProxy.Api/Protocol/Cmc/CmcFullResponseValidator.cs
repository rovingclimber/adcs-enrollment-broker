using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Protocol.Cmc;

// Restricted native LAB direct-root profile, not a general-purpose CMC decoder.
// Leaf identity, chain/currentness and revocation are mandatory separate checks.
internal static class CmcFullResponseValidator
{
    internal static bool Validate(byte[] encoded, X509Certificate2 leaf, X509Certificate2 root)
    {
        if (encoded.Length is 0 or > 786_432) return false;
        try
        {
            var outer = new AsnReader(encoded, AsnEncodingRules.DER);
            _ = outer.ReadSequence(); outer.ThrowIfNotEmpty();
            var cms = new SignedCms(); cms.Decode(encoded);
            if (cms.ContentInfo.ContentType.Value != "1.3.6.1.5.5.7.12.3" || cms.SignerInfos.Count != 1 || cms.Certificates.Count != 2)
                return false;
            var certificates = cms.Certificates.Cast<X509Certificate2>().ToArray();
            try
            {
                if (certificates.Count(c => c.RawDataMemory.Span.SequenceEqual(root.RawDataMemory.Span)) != 1 ||
                    certificates.Count(c => c.RawDataMemory.Span.SequenceEqual(leaf.RawDataMemory.Span)) != 1) return false;
                var signer = cms.SignerInfos[0];
                if (signer.Certificate is not { } signerCertificate ||
                    !signerCertificate.RawDataMemory.Span.SequenceEqual(root.RawDataMemory.Span) ||
                    signer.DigestAlgorithm.Value != "2.16.840.1.101.3.4.2.1" ||
                    signer.CounterSignerInfos.Count != 0 || signer.UnsignedAttributes.Count != 0) return false;
                signer.CheckSignature(verifySignatureOnly: true); // Exact configured root, not embedded trust.
                var reader = new AsnReader(cms.ContentInfo.Content, AsnEncodingRules.DER);
                var response = reader.ReadSequence(); var controls = response.ReadSequence();
                var status = Control(controls, 1, "1.3.6.1.5.5.7.7.1");
                Success(status);
                status.ThrowIfNotEmpty();
                var additional = Control(controls, 2, "1.3.6.1.4.1.311.10.10.1");
                if (additional.ReadInteger() != 0) return false;
                var bodies = additional.ReadSequence();
                if (bodies.ReadInteger() != 1) return false;
                bodies.ThrowIfNotEmpty();
                var attributes = additional.ReadSetOf(); var attribute = attributes.ReadSequence();
                if (attribute.ReadObjectIdentifier() != "1.3.6.1.4.1.311.21.17") return false;
                var hashes = attribute.ReadSetOf();
                // Native response uses SHA1 as a certificate identifier, not a signature.
                if (!CryptographicOperations.FixedTimeEquals(hashes.ReadOctetString(), leaf.GetCertHash(HashAlgorithmName.SHA1))) return false;
                hashes.ThrowIfNotEmpty(); attribute.ThrowIfNotEmpty(); attributes.ThrowIfNotEmpty(); additional.ThrowIfNotEmpty();
                controls.ThrowIfNotEmpty();
                response.ReadSequence().ThrowIfNotEmpty(); // No nested CMS messages.
                response.ReadSequence().ThrowIfNotEmpty(); // No other messages.
                response.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
                return true;
            }
            finally { foreach (var certificate in certificates) certificate.Dispose(); }
        }
        catch (Exception exception) when (exception is AsnContentException or CryptographicException or InvalidOperationException)
        { return false; }
    }

    private static AsnReader Control(AsnReader controls, int bodyId, string oid)
    {
        var control = controls.ReadSequence();
        if (control.ReadInteger() != bodyId || control.ReadObjectIdentifier() != oid) throw new CryptographicException("Unknown CMC response control.");
        var values = control.ReadSetOf(); var value = values.ReadSequence();
        values.ThrowIfNotEmpty(); control.ThrowIfNotEmpty(); return value;
    }

    private static void Success(AsnReader status)
    {
        if (status.ReadInteger() != 0) throw new CryptographicException("CMC status is not success.");
        var bodies = status.ReadSequence();
        if (bodies.ReadInteger() != 1) throw new CryptographicException("Unexpected CMC body reference.");
        bodies.ThrowIfNotEmpty();
        if (status.HasData && status.PeekTag().TagValue == (int)UniversalTagNumber.UTF8String)
            _ = status.ReadCharacterString(UniversalTagNumber.UTF8String); // Localized diagnostic only.
    }
}
