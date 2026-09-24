using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;
using PkiProxy.Protocol.Cmc;

internal static class CmcEnrollmentRequestTests
{
    public static void Run(string? fixtureOutputPath = null)
    {
        var count = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException("CMC: " + label);
            count++;
        }
        void Reject(Action action, string label)
        {
            try { action(); }
            catch (Exception e) when (e is CryptographicException or ArgumentException or AsnContentException)
            {
                count++;
                return;
            }
            throw new InvalidOperationException("CMC accepted: " + label);
        }

        var now = DateTimeOffset.UtcNow;
        const string signerEku = "1.3.6.1.4.1.55555.670.1";
        const string urn = "urn:example:pki-broker:lab:fact:v1:profile:broker-pilot";
        using var signerKey = RSA.Create(2048);
        var signerRequest = new CertificateRequest("CN=Ephemeral offline CMC signer", signerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        signerRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(signerEku) }, false));
        using var signer = signerRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddDays(1));
        using var deviceKey = RSA.Create(2048);
        var device = new CertificateRequest("CN=Untrusted client claim", deviceKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var csr = device.CreateSigningRequest();
        var binding = CsrBinding.FromDer(csr);
        var identity = new ControlledCertificateIdentity("CN=CMC-PROOF-DEVICE,OU=Lab Proof,DC=test,DC=corp", [new Uri(urn)], ["cmc-proof-device.example.test"]);
        var template = new CmcTemplate("1.3.6.1.4.1.55555.670.2", 2, 0, signerEku);
        CmcEnrollmentRequest Build(byte[]? input = null, CsrBinding? approved = null,
            ControlledCertificateIdentity? subject = null, CmcTemplate? policy = null,
            X509Certificate2? signing = null, DateTimeOffset? time = null) =>
            CmcEnrollmentRequestBuilder.Build(input ?? csr, approved ?? binding, subject ?? identity,
                policy ?? template, signing ?? signer, time ?? now);

        var result = Build();
        // Explicit test-only export of synthetic PUBLIC data for native decoder
        // checks. Neither ephemeral private key is persisted or exported.
        if (fixtureOutputPath is not null) File.WriteAllBytes(fixtureOutputPath, result.EncodedCms);
        Check(binding.Matches(result.OriginalRequestBinding), "original transaction binding retained");
        var cms = new SignedCms();
        cms.Decode(result.EncodedCms);
        Check(cms.Version == 3 && cms.ContentInfo.ContentType.Value == CmcEnrollmentRequestBuilder.PkiDataOid && !cms.Detached,
            "encapsulated CMC PKIData with CMS version3");
        Check(cms.Certificates.Count == 1 && cms.Certificates[0].RawData.AsSpan().SequenceEqual(signer.RawData), "only signer certificate included");
        Check(cms.SignerInfos.Count == 2, "null primary and credential signer present");
        var nullSigner = cms.SignerInfos.Cast<SignerInfo>().Single(s => s.SignatureAlgorithm.Value == "1.3.6.1.5.5.7.6.2");
        var raSigner = cms.SignerInfos.Cast<SignerInfo>().Single(s => s.SignatureAlgorithm.Value != "1.3.6.1.5.5.7.6.2");
        nullSigner.CheckHash();
        raSigner.CheckSignature(verifySignatureOnly: true);
        Check(raSigner.Certificate!.RawData.AsSpan().SequenceEqual(signer.RawData), "RA signature verifies against intended certificate");
        Check(cms.SignerInfos.Cast<SignerInfo>().All(s => s.DigestAlgorithm.Value == "2.16.840.1.101.3.4.2.1" && s.UnsignedAttributes.Count == 0), "SHA256 and no unsigned attributes");
        Check(cms.SignerInfos.Cast<SignerInfo>().All(s => s.SignedAttributes.Cast<CryptographicAttributeObject>()
            .Select(a => a.Oid.Value).ToHashSet().SetEquals(["1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4"])), "content type and digest authenticated");

        var envelope = new AsnReader(cms.ContentInfo.Content, AsnEncodingRules.DER);
        var data = envelope.ReadSequence();
        data.ReadSequence().ThrowIfNotEmpty(); // no enrollment controls to smuggle claims
        var requests = data.ReadSequence();
        var tagged = requests.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        Check(tagged.ReadInteger() == 1, "unique request body-part ID");
        Check(tagged.ReadEncodedValue().Span.SequenceEqual(result.NullSignedPkcs10), "single exact inner PKCS10");
        tagged.ThrowIfNotEmpty(); requests.ThrowIfNotEmpty();
        data.ReadSequence().ThrowIfNotEmpty(); data.ReadSequence().ThrowIfNotEmpty();
        data.ThrowIfNotEmpty(); envelope.ThrowIfNotEmpty();

        var reader = new AsnReader(result.NullSignedPkcs10, AsnEncodingRules.DER);
        var request = reader.ReadSequence();
        var infoDer = request.ReadEncodedValue();
        var infoReader = new AsnReader(infoDer, AsnEncodingRules.DER);
        var info = infoReader.ReadSequence();
        Check(info.ReadInteger() == 0, "PKCS10 v1");
        Check(info.ReadEncodedValue().Span.SequenceEqual(result.SubjectNameDer), "controlled subject DER");
        // Matches the native oracle's ASCII PrintableString DN (not formatted text).
        Check(new X500DistinguishedName(result.SubjectNameDer).Name == "CN=CMC-PROOF-DEVICE, OU=Lab Proof, DC=test, DC=corp", "no client subject copied");
        Check(info.ReadEncodedValue().Span.SequenceEqual(deviceKey.ExportSubjectPublicKeyInfo()), "original SPKI unchanged");
        var attributes = info.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var extRequest = attributes.ReadSequence();
        Check(extRequest.ReadObjectIdentifier() == "1.2.840.113549.1.9.14", "extensionRequest only");
        var values = extRequest.ReadSetOf();
        var extensions = values.ReadSequence();
        var templateExtension = extensions.ReadSequence();
        Check(templateExtension.ReadObjectIdentifier() == "1.3.6.1.4.1.311.21.7", "signed template information");
        var templateReader = new AsnReader(templateExtension.ReadOctetString(), AsnEncodingRules.DER);
        var templateInfo = templateReader.ReadSequence();
        Check(templateInfo.ReadObjectIdentifier() == template.Oid && templateInfo.ReadInteger() == 2 && templateInfo.ReadInteger() == 0, "exact template and versions");
        templateInfo.ThrowIfNotEmpty(); templateReader.ThrowIfNotEmpty(); templateExtension.ThrowIfNotEmpty();
        var sanExtension = extensions.ReadSequence();
        Check(sanExtension.ReadObjectIdentifier() == "2.5.29.17" && sanExtension.ReadOctetString().AsSpan().SequenceEqual(result.SanExtensionDer), "exact SAN extension");
        sanExtension.ThrowIfNotEmpty(); extensions.ThrowIfNotEmpty(); values.ThrowIfNotEmpty();
        extRequest.ThrowIfNotEmpty(); attributes.ThrowIfNotEmpty(); info.ThrowIfNotEmpty(); infoReader.ThrowIfNotEmpty();
        var algorithm = request.ReadSequence();
        Check(algorithm.ReadObjectIdentifier() == "2.16.840.1.101.3.4.2.1", "inner digest algorithm");
        algorithm.ReadNull(); algorithm.ThrowIfNotEmpty();
        var digest = request.ReadBitString(out var unusedBits);
        Check(unusedBits == 0 && CryptographicOperations.FixedTimeEquals(digest, SHA256.HashData(infoDer.Span)), "inner null signature is exact digest");
        request.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
        var sanReader = new AsnReader(result.SanExtensionDer, AsnEncodingRules.DER);
        var names = sanReader.ReadSequence();
        Check(names.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 2)) == "cmc-proof-device.example.test" &&
              names.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6)) == urn, "authoritative DNS and URI typed GeneralNames");
        names.ThrowIfNotEmpty(); sanReader.ThrowIfNotEmpty();

        var corrupted = csr.ToArray(); corrupted[^1] ^= 1;
        Reject(() => Build(corrupted), "changed authorized CSR binding");
        Reject(() => Build(corrupted, CsrBinding.FromDer(corrupted)), "invalid signature even with matching hash");
        Reject(() => Build(result.NullSignedPkcs10, CsrBinding.FromDer(result.NullSignedPkcs10)), "null-signed input is not device POP");
        Check(IncomingCsrPolicyValidator.Validate(result.NullSignedPkcs10, IncomingCsrPolicy.NoClientExtensions).Result == IncomingCsrValidationResult.InvalidPkcs10,
            "generic CSR validator returns rejection for unsupported digest-only signature");
        Reject(() => Build([.. csr, 0]), "trailing data");
        Reject(() => Build(new byte[65537]), "oversized CSR");
        Reject(() => Build([]), "empty CSR");
        using var smallKey = RSA.Create(1024);
        var small = new CertificateRequest("CN=small", smallKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();
        Reject(() => Build(small, CsrBinding.FromDer(small)), "weak device key");
        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ec = new CertificateRequest("CN=ec", ecKey, HashAlgorithmName.SHA256).CreateSigningRequest();
        Reject(() => Build(ec, CsrBinding.FromDer(ec)), "unsupported device key profile");
        var pss = new CertificateRequest("CN=pss", deviceKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pss).CreateSigningRequest();
        Reject(() => Build(pss, CsrBinding.FromDer(pss)), "unsupported original signature profile");
        var unknownAttribute = new CertificateRequest("CN=hint", deviceKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        unknownAttribute.OtherRequestAttributes.Add(new AsnEncodedData(new Oid("1.3.6.1.4.1.55555.99"), [0x05, 0x00]));
        var unknown = unknownAttribute.CreateSigningRequest();
        Reject(() => Build(unknown, CsrBinding.FromDer(unknown)), "unknown CSR attribute not silently ignored");
        device.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var withExtension = device.CreateSigningRequest();
        Reject(() => Build(withExtension, CsrBinding.FromDer(withExtension)), "client extensions still gated");
        using var publicOnly = X509CertificateLoader.LoadCertificate(signer.RawData);
        Reject(() => Build(signing: publicOnly), "missing signer private key");
        var caSignerRequest = new CertificateRequest("CN=Wrong CA signer", signerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caSignerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        caSignerRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(signerEku) }, false));
        caSignerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var caSigner = caSignerRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddDays(1));
        Reject(() => Build(signing: caSigner), "CA certificate is not a broker signer");
        var unsignedUsageRequest = new CertificateRequest("CN=No signing usage", signerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        unsignedUsageRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(signerEku) }, false));
        using var noUsageSigner = unsignedUsageRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddDays(1));
        Reject(() => Build(signing: noUsageSigner), "missing signer key usage");
        Reject(() => Build(policy: template with { SignerApplicationPolicyOid = "1.3.6.1.5.5.7.3.2" }), "wrong signer EKU");
        Reject(() => Build(policy: template with { SignerMinimumRemainingValidity = TimeSpan.FromDays(2) }),
            "signer inside configured rotation safety window");
        Reject(() => Build(time: now.AddDays(2)), "expired signer");
        Reject(() => Build(time: now.AddDays(-2)), "not-yet-valid signer");
        Reject(() => Build(policy: template with { MajorVersion = -1 }), "negative template version");
        Reject(() => Build(policy: template with { Oid = "not-an-oid" }), "invalid template OID");
        Reject(() => Build(subject: identity with { SubjectDistinguishedName = "" }), "empty authoritative DN");
        Reject(() => Build(subject: identity with { SubjectDistinguishedName = "CN=\u00e9" }), "unproven Unicode DN profile");
        Reject(() => Build(subject: identity with { SubjectAlternativeNameUris = [], SubjectAlternativeNameDnsNames = [] }), "empty SAN set");
        Reject(() => Build(subject: identity with { SubjectAlternativeNameUris = [new Uri(urn), new Uri(urn)] }), "duplicate URI");
        Reject(() => Build(subject: identity with { SubjectAlternativeNameDnsNames = ["pc.example.test", "PC.example.test"] }), "case-equivalent duplicate DNS");
        foreach (var badDns in new[] { "*.example.test", "pc.example.test.", "pc..corp", "pc_example.test", "-pc.example.test", "\u00e9.example.test" })
            Reject(() => Build(subject: identity with { SubjectAlternativeNameDnsNames = [badDns] }), "invalid DNS " + badDns);
        foreach (var badUri in new[] { "https://example.test/claim", "urn:x:value", "urn:urn:value", "urn:example:", "urn:example:bad%xx", "urn:example:value?+query", "urn:example:value#fragment" })
            Reject(() => Build(subject: identity with { SubjectAlternativeNameUris = [new Uri(badUri)] }), "unsupported URI " + badUri);

        var modifiedCms = result.EncodedCms.ToArray();
        var contentOffset = modifiedCms.AsSpan().IndexOf(cms.ContentInfo.Content);
        Check(contentOffset >= 0, "test locates encapsulated content");
        modifiedCms[contentOffset + cms.ContentInfo.Content.Length - 1] ^= 1;
        Reject(() => { var changed = new SignedCms(); changed.Decode(modifiedCms); changed.SignerInfos.Cast<SignerInfo>()
            .Single(s => s.SignatureAlgorithm.Value != "1.3.6.1.5.5.7.6.2").CheckSignature(true); }, "tampered authenticated content");
        Console.WriteLine($"CMC downstream builder: {count} checks passed (offline, synthetic keys).");
    }
}
