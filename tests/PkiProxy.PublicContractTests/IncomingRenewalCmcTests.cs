using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Protocol.Cmc;

internal static class IncomingRenewalCmcTests
{
    private static readonly NativeCmcPolicy Policy = new("1.3.6.1.4.1.55555.670.3", 101, 0,
        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);

    internal static void Run()
    {
        using var oldKey = RSA.Create(2048);
        using var newKey = RSA.Create(2048);
        var oldRequest = new CertificateRequest("CN=synthetic-device", oldKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        oldRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(oldRequest.PublicKey, false));
        oldRequest.CertificateExtensions.Add(San("urn:example:old-fact"));
        using var old = oldRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        var nextRequest = new CertificateRequest("CN=primary-fixture", newKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        nextRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(nextRequest.PublicKey, false));
        using var next = nextRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        var count = 0;
        void Reject(Action action)
        {
            try { action(); }
            catch (CryptographicException) { count++; return; }
            throw new InvalidOperationException("Renewal profile negative test accepted.");
        }
        byte[] Fixture(string change = "", bool sameKey = false) => Create(
            sameKey ? oldKey : newKey, sameKey ? old : next, old, change);
        var bytes = Fixture();
        var parsed = ValidatedRenewalCmcRequest.Validate(bytes, Policy); count++;
        ValidatedRenewalCmcRequest.Validate(Fixture(sameKey: true), Policy); count++;
        var binding = parsed.CreateBinding();
        var exported = parsed.ExportPkcs10(); exported[0] ^= 1;
        var certExport = parsed.ExportRenewalCertificate(); certExport[0] ^= 1;
        bytes[0] ^= 1;
        if (!parsed.CreateBinding().Csr.Matches(binding.Csr) ||
            !parsed.CreateBinding().EnvelopeSha256.AsSpan().SequenceEqual(binding.EnvelopeSha256) ||
            !parsed.ExportRenewalCertificate().AsSpan().SequenceEqual(old.RawData))
            throw new InvalidOperationException("Renewal request buffers were not isolated.");
        count++;
        foreach (var change in new[] { "missing-old", "wrong-old", "subject", "san", "missing-san", "duplicate-san", "csr-signature", "template", "extra-request", "extra-body" })
            Reject(() => ValidatedRenewalCmcRequest.Validate(Fixture(change), Policy));
        Reject(() => ValidatedCmcRequest.Validate(Fixture(), Policy));
        Reject(() => ValidatedRenewalCmcRequest.Validate(IncomingCmcRequestTests.CreateDomainFixture(newKey), Policy));
        Console.WriteLine($"Incoming renewal CMC profile checks passed: {count} (synthetic; trust and authorization not asserted).");
    }

    internal static byte[] Create(RSA key, X509Certificate2 primary, X509Certificate2 old, string change)
    {
        var request = new CertificateRequest(change == "subject" ? new X500DistinguishedName("CN=other") : old.SubjectName,
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var template = new AsnWriter(AsnEncodingRules.DER);
        using (template.PushSequence()) { template.WriteObjectIdentifier(Policy.TemplateOid); template.WriteInteger(change == "template" ? 102 : 101); }
        request.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.311.21.7", template.Encode(), false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(Policy.KeyUsage, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var application = new AsnWriter(AsnEncodingRules.DER);
        using (application.PushSequence()) using (application.PushSequence()) application.WriteObjectIdentifier("1.3.6.1.5.5.7.3.2");
        request.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.311.21.10", application.Encode(), false));
        if (change != "missing-san") request.CertificateExtensions.Add(San(change == "san" ? "urn:example:forged-fact" : "urn:example:old-fact"));
        if (change == "duplicate-san") request.CertificateExtensions.Add(San("urn:example:old-fact"));
        if (change != "missing-old") request.OtherRequestAttributes.Add(new AsnEncodedData(
            new Oid("1.3.6.1.4.1.311.13.1"), change == "wrong-old" ? primary.RawData : old.RawData));
        var csr = request.CreateSigningRequest();
        if (change == "csr-signature") csr[^1] ^= 1; // Outer signatures remain valid.
        var pki = new AsnWriter(AsnEncodingRules.DER);
        using (pki.PushSequence())
        {
            using (pki.PushSequence()) { }
            using (pki.PushSequence())
                for (var i = 0; i < (change == "extra-request" ? 2 : 1); i++)
                    using (pki.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    { pki.WriteInteger(i + 1); pki.WriteEncodedValue(csr); }
            using (pki.PushSequence()) { if (change == "extra-body") pki.WriteNull(); }
            using (pki.PushSequence()) { }
        }
        return CmcRenewalSignatureTests.Envelope(primary, old, pki.Encode());
    }

    private static X509Extension San(string uri)
    {
        var san = new SubjectAlternativeNameBuilder(); san.AddUri(new Uri(uri)); return san.Build();
    }
}
