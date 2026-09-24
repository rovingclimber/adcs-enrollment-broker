using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;

namespace PkiProxy.Protocol.Cmc;

// This is a deliberately narrow initial-enrollment profile, NOT general CMC.
// Policy is trusted server configuration; none of these values comes from a CSR.
internal sealed record NativeCmcPolicy(string TemplateOid, int TemplateMajorVersion, int TemplateMinorVersion,
    X509KeyUsageFlags KeyUsage, bool AllowLegacySha1ForLab = false);

internal sealed record CmcRequestBinding(byte[] EnvelopeSha256, CsrBinding Csr);

// Only successful validation can construct one. Owned request bytes never escape.
// Proof of possession does NOT authenticate a directory object or authorize facts.
internal sealed class ValidatedCmcRequest
{
    private const string SignedDataOid = "1.2.840.113549.1.7.2";
    private const string RsaOid = "1.2.840.113549.1.1.1";
    private const string Sha1Oid = "1.3.14.3.2.26";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private const string ClientInfoOid = "1.3.6.1.4.1.311.21.20";
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    private static readonly Asn1Tag ContextZero = new(TagClass.ContextSpecific, 0, true);
    private readonly byte[] envelope;
    private readonly byte[] pkcs10;

    private ValidatedCmcRequest(byte[] envelope, byte[] pkcs10, bool usedLegacySha1)
    {
        this.envelope = envelope;
        this.pkcs10 = pkcs10;
        UsedLegacySha1 = usedLegacySha1;
    }

    public bool UsedLegacySha1 { get; }
    public CmcRequestBinding CreateBinding() => new(SHA256.HashData(envelope), CsrBinding.FromDer(pkcs10));
    public byte[] ExportPkcs10() => pkcs10.ToArray();

    public bool Matches(CmcRequestBinding approved)
    {
        var actual = CreateBinding();
        return approved is not null && approved.EnvelopeSha256 is { Length: 32 } &&
            approved.Csr is not null && approved.Csr.HasExpectedLengths() &&
            CryptographicOperations.FixedTimeEquals(actual.EnvelopeSha256, approved.EnvelopeSha256) &&
            actual.Csr.Matches(approved.Csr);
    }

    public static ValidatedCmcRequest Validate(ReadOnlySpan<byte> encoded, NativeCmcPolicy policy)
    {
        ValidatePolicy(policy);
        Require(encoded.Length is > 0 and <= 131072, "CMC size");
        var snapshot = encoded.ToArray();
        try { return Parse(snapshot, policy); }
        catch (AsnContentException exception)
        { throw new CryptographicException("CMC is not valid DER for the configured profile.", exception); }
    }

    internal static void ValidatePolicy(NativeCmcPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(policy.TemplateOid);
        if (policy.TemplateMajorVersion < 0 || policy.TemplateMinorVersion < 0 ||
            policy.KeyUsage is not (X509KeyUsageFlags.DigitalSignature or
                (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment)))
            throw new ArgumentException("Unsupported configured initial-enrollment policy.", nameof(policy));
    }

    private static ValidatedCmcRequest Parse(byte[] snapshot, NativeCmcPolicy policy)
    {
        var root = Reader(snapshot);
        var contentInfo = root.ReadSequence();
        Require(contentInfo.ReadObjectIdentifier() == SignedDataOid, "CMS content type");
        var explicitContent = contentInfo.ReadSequence(ContextZero);
        var signed = explicitContent.ReadSequence();
        Require(signed.ReadInteger() == 3, "CMS version");
        var algorithms = signed.ReadSetOf();
        var digestOid = Algorithm(algorithms);
        var digest = Digest(digestOid, policy);
        algorithms.ThrowIfNotEmpty();
        var encapsulated = signed.ReadSequence();
        Require(encapsulated.ReadObjectIdentifier() == CmcEnrollmentRequestBuilder.PkiDataOid, "PKIData content type");
        var explicitData = encapsulated.ReadSequence(ContextZero);
        var data = explicitData.ReadOctetString();
        explicitData.ThrowIfNotEmpty(); encapsulated.ThrowIfNotEmpty();
        // No certificates, CRLs, renewal signers, counter-signatures or extra signers.
        var signers = signed.ReadSetOf();
        var signer = signers.ReadSequence();
        Require(signer.ReadInteger() == 3, "CMS signer version");
        var identifier = signer.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
        Require(identifier.Length == 20, "CMS key identifier");
        Require(Algorithm(signer) == digestOid, "CMS digest algorithm consistency");
        var authenticated = signer.ReadEncodedValue().ToArray();
        var attrReader = Reader(authenticated);
        var attributes = attrReader.ReadSetOf(ContextZero);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (attributes.HasData)
        {
            var attribute = attributes.ReadSequence();
            var oid = attribute.ReadObjectIdentifier();
            Require(seen.Add(oid) && seen.Count <= 2, "CMS signed attributes");
            var values = attribute.ReadSetOf();
            if (oid == "1.2.840.113549.1.9.3")
                Require(values.ReadObjectIdentifier() == CmcEnrollmentRequestBuilder.PkiDataOid, "Signed content type");
            else if (oid == "1.2.840.113549.1.9.4")
                Require(CryptographicOperations.FixedTimeEquals(values.ReadOctetString(), Hash(data, digest)), "CMS content digest");
            else throw new CryptographicException("Unsupported CMS signed attribute.");
            values.ThrowIfNotEmpty(); attribute.ThrowIfNotEmpty();
        }
        Require(seen.Count == 2, "Required CMS signed attributes");
        attrReader.ThrowIfNotEmpty();
        var signatureOid = Algorithm(signer);
        Require(signatureOid == RsaOid || signatureOid == SignatureOid(digest), "CMS RSA signature algorithm");
        var signature = signer.ReadOctetString();
        signer.ThrowIfNotEmpty(); signers.ThrowIfNotEmpty(); signed.ThrowIfNotEmpty();
        explicitContent.ThrowIfNotEmpty(); contentInfo.ThrowIfNotEmpty(); root.ThrowIfNotEmpty();

        var pkiReader = Reader(data);
        var pki = pkiReader.ReadSequence();
        var controls = pki.ReadSequence();
        var requests = pki.ReadSequence();
        var tagged = requests.ReadSequence(ContextZero);
        var requestId = BodyId(tagged);
        var csr = tagged.ReadEncodedValue().ToArray();
        Require(csr.Length <= 65536, "CSR size");
        tagged.ThrowIfNotEmpty(); requests.ThrowIfNotEmpty();
        pki.ReadSequence().ThrowIfNotEmpty(); pki.ReadSequence().ThrowIfNotEmpty();
        pki.ThrowIfNotEmpty(); pkiReader.ThrowIfNotEmpty();
        ValidateControls(controls, requestId);

        using var key = RSA.Create();
        var csrDigest = ValidateCsr(csr, policy, key, out var keyIdentifier);
        Require(CryptographicOperations.FixedTimeEquals(identifier, keyIdentifier), "CMS signer must identify CSR key");
        // CMS signatures cover DER SET OF, not the IMPLICIT [0] tag on the wire.
        authenticated[0] = 0x31;
        Require(key.VerifyData(authenticated, signature, digest, RSASignaturePadding.Pkcs1), "CMC proof of possession");
        return new ValidatedCmcRequest(snapshot, csr, digest == HashAlgorithmName.SHA1 || csrDigest == HashAlgorithmName.SHA1);
    }

    internal static void ValidateControls(AsnReader controls, uint requestId)
    {
        if (!controls.HasData) return;
        var control = controls.ReadSequence();
        Require(BodyId(control) != requestId, "Unique body-part IDs");
        Require(control.ReadObjectIdentifier() == "1.3.6.1.4.1.311.10.10.1", "CMC control allowlist");
        var values = control.ReadSetOf();
        var add = values.ReadSequence();
        Require(add.ReadInteger() == 0, "CMC control cannot target nested data");
        var references = add.ReadSequence();
        Require(BodyId(references) == requestId, "CMC control request reference");
        references.ThrowIfNotEmpty();
        var attributes = add.ReadSetOf();
        var attribute = attributes.ReadSequence();
        Require(attribute.ReadObjectIdentifier() == ClientInfoOid, "Only diagnostic client info control is supported");
        var info = attribute.ReadSetOf();
        ValidateClientInfo(info);
        info.ThrowIfNotEmpty(); attribute.ThrowIfNotEmpty(); attributes.ThrowIfNotEmpty();
        add.ThrowIfNotEmpty(); values.ThrowIfNotEmpty(); control.ThrowIfNotEmpty(); controls.ThrowIfNotEmpty();
    }

    internal static void ValidateRenewalCsr(byte[] csr, NativeCmcPolicy policy, RSA key, X509Certificate2 old)
    {
        ArgumentNullException.ThrowIfNull(old);
        Require(!policy.AllowLegacySha1ForLab, "renewal requires SHA256");
        ValidateCsr(csr, policy, key, out _, old);
    }

    private static HashAlgorithmName ValidateCsr(byte[] csr, NativeCmcPolicy policy, RSA key, out byte[] keyIdentifier,
        X509Certificate2? renewalCertificate = null)
    {
        var reader = Reader(csr);
        var request = reader.ReadSequence();
        var infoDer = request.ReadEncodedValue();
        var infoReader = Reader(infoDer);
        var info = infoReader.ReadSequence();
        Require(info.ReadInteger() == 0, "CSR version");
        if (renewalCertificate is null)
            info.ReadSequence().ThrowIfNotEmpty(); // Initial profile: empty subject only.
        else
            Require(info.ReadEncodedValue().Span.SequenceEqual(renewalCertificate.SubjectName.RawData),
                "Renewal subject must match old certificate; not authoritative identity");
        var spkiDer = info.ReadEncodedValue();
        var spkiReader = Reader(spkiDer);
        var spki = spkiReader.ReadSequence();
        Require(Algorithm(spki) == RsaOid, "RSA public key required");
        var keyBits = spki.ReadBitString(out var unused);
        Require(unused == 0, "RSA key bit string");
        spki.ThrowIfNotEmpty(); spkiReader.ThrowIfNotEmpty();
        var rsaReader = Reader(keyBits);
        var rsa = rsaReader.ReadSequence();
        Require(rsa.ReadInteger() > 0 && rsa.ReadInteger() == 65537, "RSA key profile");
        rsa.ThrowIfNotEmpty(); rsaReader.ThrowIfNotEmpty();
        key.ImportSubjectPublicKeyInfo(spkiDer.Span, out var consumed);
        Require(consumed == spkiDer.Length && key.KeySize is >= 2048 and <= 8192, "RSA key size");
        // SHA1 here is the standard key identifier, not a signature acceptance rule.
#pragma warning disable CA5350 // RFC5280 method-1 SKI interoperability; never an authorization token.
        keyIdentifier = SHA1.HashData(keyBits);
#pragma warning restore CA5350
        var attributes = info.ReadSetOf(ContextZero);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var hasExtensions = false;
        var hasRenewalCertificate = false;
        while (attributes.HasData)
        {
            var attribute = attributes.ReadSequence();
            var oid = attribute.ReadObjectIdentifier();
            Require(seen.Add(oid) && seen.Count <= (renewalCertificate is null ? 4 : 5), "CSR attribute uniqueness/count");
            var values = attribute.ReadSetOf();
            switch (oid)
            {
                case "1.2.840.113549.1.9.14":
                case "1.3.6.1.4.1.311.2.1.14":
                    Require(!hasExtensions, "One extension request only");
                    hasExtensions = true;
                    ValidateExtensions(values.ReadSequence(), policy, keyIdentifier, renewalCertificate);
                    break;
                case "1.3.6.1.4.1.311.13.1" when renewalCertificate is not null:
                    Require(values.ReadEncodedValue().Span.SequenceEqual(renewalCertificate.RawData),
                        "Inner and outer renewal certificates must match");
                    hasRenewalCertificate = true;
                    break;
                case ClientInfoOid: ValidateClientInfo(values); break;
                case "1.3.6.1.4.1.311.13.2.3":
                    Text(values, UniversalTagNumber.IA5String, 128); break;
                case "1.3.6.1.4.1.311.13.2.2":
                    var provider = values.ReadSequence();
                    var keySpec = provider.ReadInteger();
                    Require(keySpec >= 0 && keySpec <= uint.MaxValue, "CSP key spec");
                    Text(provider, UniversalTagNumber.BMPString, 256);
                    var providerSignature = provider.ReadBitString(out var providerUnused);
                    Require(providerUnused == 0 && providerSignature.Length <= 4096, "CSP diagnostic signature");
                    provider.ThrowIfNotEmpty();
                    break;
                default: throw new CryptographicException("Unsupported CSR attribute.");
            }
            values.ThrowIfNotEmpty(); attribute.ThrowIfNotEmpty();
        }
        Require(hasExtensions, "Template-bound extension request required");
        Require(hasRenewalCertificate == (renewalCertificate is not null), "Renewal certificate attribute required");
        info.ThrowIfNotEmpty(); infoReader.ThrowIfNotEmpty();
        var signatureOid = Algorithm(request);
        var digest = signatureOid switch
        {
            "1.2.840.113549.1.1.11" => HashAlgorithmName.SHA256,
            "1.2.840.113549.1.1.5" when policy.AllowLegacySha1ForLab => HashAlgorithmName.SHA1,
            _ => throw new CryptographicException("Unsupported CSR signature algorithm.")
        };
        var signature = request.ReadBitString(out var signatureUnused);
        Require(signatureUnused == 0 && key.VerifyData(infoDer.Span, signature, digest, RSASignaturePadding.Pkcs1), "CSR proof of possession");
        request.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
        return digest;
    }

    private static void ValidateExtensions(AsnReader extensions, NativeCmcPolicy policy, byte[] keyIdentifier,
        X509Certificate2? renewalCertificate)
    {
        var inheritedSans = renewalCertificate?.Extensions.Cast<X509Extension>()
            .Where(extension => extension.Oid?.Value == "2.5.29.17").ToArray() ?? [];
        Require(inheritedSans.Length <= 1, "Unique inherited SAN extension");
        var expectedCount = 5 + inheritedSans.Length;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (extensions.HasData)
        {
            var extension = extensions.ReadSequence();
            var oid = extension.ReadObjectIdentifier();
            Require(seen.Add(oid) && seen.Count <= expectedCount, "CSR extension uniqueness/count");
            var critical = extension.HasData && extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean);
            if (critical) Require(extension.ReadBoolean(), "DER default critical must be omitted");
            Require(critical == (oid == "2.5.29.15"), "CSR extension criticality");
            var value = extension.ReadOctetString();
            extension.ThrowIfNotEmpty();
            Require(value.Length <= 8192, "CSR extension size");
            var encoded = Reader(value);
            switch (oid)
            {
                case "2.5.29.17" when inheritedSans.Length == 1:
                    // Accept only an unchanged inherited hint. It is never
                    // exposed as authoritative facts or copied into issuance.
                    Require(value.AsSpan().SequenceEqual(inheritedSans[0].RawData), "Unchanged inherited SAN required");
                    encoded.ReadEncodedValue(); break;
                case "1.3.6.1.4.1.311.21.7":
                    var template = encoded.ReadSequence();
                    Require(template.ReadObjectIdentifier() == policy.TemplateOid &&
                        template.ReadInteger() == policy.TemplateMajorVersion, "CSR configured template/major version");
                    // MS-WCCE permits optional versions. This profile requires
                    // major; native CertEnroll omits a zero minor. Omission is
                    // accepted only when the server explicitly configures zero.
                    Require(template.HasData ? template.ReadInteger() == policy.TemplateMinorVersion : policy.TemplateMinorVersion == 0,
                        "CSR configured template/minor version");
                    template.ThrowIfNotEmpty(); break;
                case "2.5.29.37":
                    var eku = encoded.ReadSequence();
                    Require(eku.ReadObjectIdentifier() == ClientAuthOid, "CSR clientAuth only");
                    eku.ThrowIfNotEmpty(); break;
                case "2.5.29.15":
                    Require(value.AsSpan().SequenceEqual(new X509KeyUsageExtension(policy.KeyUsage, true).RawData), "CSR key usage");
                    encoded.ReadEncodedValue(); break;
                case "1.3.6.1.4.1.311.21.10":
                    var policies = encoded.ReadSequence();
                    var application = policies.ReadSequence();
                    Require(application.ReadObjectIdentifier() == ClientAuthOid, "CSR application policy");
                    application.ThrowIfNotEmpty(); policies.ThrowIfNotEmpty(); break;
                case "2.5.29.14":
                    Require(CryptographicOperations.FixedTimeEquals(encoded.ReadOctetString(), keyIdentifier), "CSR key identifier"); break;
                default: throw new CryptographicException("Unsupported CSR extension; client identity overrides are prohibited.");
            }
            encoded.ThrowIfNotEmpty();
        }
        Require(seen.Count == expectedCount, "Configured enrollment hints required");
    }

    private static void ValidateClientInfo(AsnReader values)
    {
        var client = values.ReadSequence();
        var id = client.ReadInteger();
        Require(id >= 0 && id <= uint.MaxValue, "Client info ID");
        for (var i = 0; i < 3; i++) Text(client, UniversalTagNumber.UTF8String, 1024);
        client.ThrowIfNotEmpty();
        // MachineName/UserName/ProcessName are diagnostics, never AD identity.
    }

    private static void Text(AsnReader reader, UniversalTagNumber type, int maximum)
    {
        var text = reader.ReadCharacterString(type);
        Require(text.Length <= maximum && !text.Any(char.IsControl), "Bounded diagnostic string");
    }

    private static uint BodyId(AsnReader reader)
    {
        var value = reader.ReadInteger();
        Require(value > 0 && value <= uint.MaxValue, "Body-part ID range");
        return (uint)value;
    }

    private static string Algorithm(AsnReader reader)
    {
        var algorithm = reader.ReadSequence();
        var oid = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData) algorithm.ReadNull();
        algorithm.ThrowIfNotEmpty();
        return oid;
    }

    private static HashAlgorithmName Digest(string oid, NativeCmcPolicy policy) => oid switch
    {
        Sha256Oid => HashAlgorithmName.SHA256,
        Sha1Oid when policy.AllowLegacySha1ForLab => HashAlgorithmName.SHA1,
        _ => throw new CryptographicException("Unsupported CMC digest algorithm.")
    };
    private static string SignatureOid(HashAlgorithmName digest) =>
        digest == HashAlgorithmName.SHA256 ? "1.2.840.113549.1.1.11" : "1.2.840.113549.1.1.5";
#pragma warning disable CA5350 // SHA1 is reachable only through explicit AllowLegacySha1ForLab validation.
    private static byte[] Hash(byte[] data, HashAlgorithmName digest) =>
        digest == HashAlgorithmName.SHA256 ? SHA256.HashData(data) : SHA1.HashData(data);
#pragma warning restore CA5350
    private static AsnReader Reader(ReadOnlyMemory<byte> bytes) => new(bytes, AsnEncodingRules.DER);
    private static void Require(bool condition, string check)
    { if (!condition) throw new CryptographicException("Unsupported or invalid enrollment request: " + check + "."); }
}
