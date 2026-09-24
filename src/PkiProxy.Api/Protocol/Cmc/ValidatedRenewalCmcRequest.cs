using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;

namespace PkiProxy.Protocol.Cmc;

// Validated request shape and signatures, NOT a trusted/authorized renewal.
// Deliberately not accepted by the initial enrollment issuer API. Trust,
// revocation, asset authorization and fresh facts must precede issuer wiring.
internal sealed class ValidatedRenewalCmcRequest
{
    private readonly byte[] envelope;
    private readonly byte[] pkcs10;
    private readonly byte[] oldCertificate;

    private ValidatedRenewalCmcRequest(byte[] envelope, byte[] pkcs10, byte[] oldCertificate)
    { this.envelope = envelope; this.pkcs10 = pkcs10; this.oldCertificate = oldCertificate; }

    internal CmcRequestBinding CreateBinding() => new(SHA256.HashData(envelope), CsrBinding.FromDer(pkcs10));
    internal byte[] ExportPkcs10() => pkcs10.ToArray();
    internal byte[] ExportRenewalCertificate() => oldCertificate.ToArray();
    internal bool Matches(CmcRequestBinding approved)
    {
        var actual = CreateBinding();
        return approved is not null && approved.EnvelopeSha256 is { Length: 32 } &&
            approved.Csr is not null && approved.Csr.HasExpectedLengths() &&
            CryptographicOperations.FixedTimeEquals(actual.EnvelopeSha256, approved.EnvelopeSha256) &&
            actual.Csr.Matches(approved.Csr);
    }

    internal static ValidatedRenewalCmcRequest Validate(ReadOnlySpan<byte> encoded, NativeCmcPolicy policy)
    {
        ValidatedCmcRequest.ValidatePolicy(policy);
        if (policy.AllowLegacySha1ForLab)
            throw new ArgumentException("The renewal profile does not support legacy SHA1.", nameof(policy));
        Require(encoded.Length is > 0 and <= 131072, "CMC size");
        var snapshot = encoded.ToArray();
        try { return Parse(snapshot, policy); }
        catch (AsnContentException exception)
        { throw new CryptographicException("Renewal CMC is not valid DER for the configured profile.", exception); }
    }

    private static ValidatedRenewalCmcRequest Parse(byte[] snapshot, NativeCmcPolicy policy)
    {
        // Extraction only. Strict envelope verification below consumes the full
        // original DER and rejects everything outside the configured profile.
        var cms = new SignedCms(); cms.Decode(snapshot);
        Require(cms.ContentInfo.ContentType.Value == "1.3.6.1.5.5.7.12.2" &&
            cms.Certificates.Count == 1 && cms.SignerInfos.Count == 2, "renewal CMS profile");
        using var old = cms.Certificates[0];
        var content = cms.ContentInfo.Content;
        var reader = new AsnReader(content, AsnEncodingRules.DER);
        var data = reader.ReadSequence();
        var controls = data.ReadSequence();
        var requests = data.ReadSequence();
        var request = requests.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var id = request.ReadInteger();
        Require(id > 0 && id <= uint.MaxValue, "body ID");
        var csr = request.ReadEncodedValue().ToArray();
        Require(csr.Length is > 0 and <= 65536, "CSR size");
        request.ThrowIfNotEmpty(); requests.ThrowIfNotEmpty();
        data.ReadSequence().ThrowIfNotEmpty(); data.ReadSequence().ThrowIfNotEmpty();
        data.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
        ValidatedCmcRequest.ValidateControls(controls, (uint)id);
        using var key = RSA.Create();
        ValidatedCmcRequest.ValidateRenewalCsr(csr, policy, key, old);
        CmcRenewalSignatures.Verify(snapshot, content, new PublicKey(key), old);
        return new(snapshot, csr, old.RawData);
    }

    private static void Require(bool valid, string check)
    { if (!valid) throw new CryptographicException("Invalid renewal request: " + check + "."); }
}
