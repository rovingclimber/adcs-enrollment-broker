using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;
using PkiProxy.Protocol.Cmc;

internal static class IncomingCmcRequestTests
{
    internal static byte[] CreateDomainFixture(RSA key, bool legacy = false) =>
        CreateFixture(key, new Options(CsrSha1: legacy, CmsSha1: legacy));

    private const string TemplateOid = "1.3.6.1.4.1.55555.670.3";
    private const string ClientInfoOid = "1.3.6.1.4.1.311.21.20";
    private static readonly Asn1Tag ContextZero = new(TagClass.ContextSpecific, 0, true);
    private static readonly NativeCmcPolicy Policy = new(TemplateOid, 101, 0,
        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);

    public static void Run(string? nativeFixturePath = null, byte[]? nativeFixture = null)
    {
        var count = 0;
        void Check(bool condition, string label)
        { if (!condition) throw new InvalidOperationException("Incoming CMC: " + label); count++; }
        void Reject(Action action, string label)
        {
            try { action(); }
            catch (Exception e) when (e is CryptographicException or ArgumentException or AsnContentException)
            { count++; return; }
            throw new InvalidOperationException("Incoming CMC accepted: " + label);
        }
        using var key = RSA.Create(2048);
        byte[] Fixture(Options? options = null) => CreateFixture(key, options ?? new());
        ValidatedCmcRequest Validate(byte[] bytes, bool legacy = false) =>
            ValidatedCmcRequest.Validate(bytes, Policy with { AllowLegacySha1ForLab = legacy });
        var original = Fixture();
        var valid = Validate(original);
        var binding = valid.CreateBinding();
        Check(!valid.UsedLegacySha1 && valid.Matches(binding), "modern CMC and full binding");
        Check(binding.EnvelopeSha256.AsSpan().SequenceEqual(SHA256.HashData(original)), "envelope hash covers exact bytes");
        Check(binding.Csr.Matches(CsrBinding.FromDer(valid.ExportPkcs10())), "inner CSR and SPKI binding");
        Check(CsrBinding.ExtractSubjectPublicKeyInfoDer(valid.ExportPkcs10()).AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo()), "original public key");
        original[^1] ^= 1;
        Check(valid.Matches(binding), "caller input mutation cannot change validated object");
        Reject(() => Validate(original), "outer signature tamper");
        var exposed = valid.ExportPkcs10(); exposed[^1] ^= 1;
        Check(valid.Matches(binding), "export is a copy");
        var copied = valid.CreateBinding(); copied.EnvelopeSha256[0] ^= 1; copied.Csr.CsrSha256[0] ^= 1;
        Check(valid.Matches(binding) && !valid.Matches(copied), "binding arrays do not expose internal state");
        Check(!valid.Matches(new CmcRequestBinding(new byte[31], binding.Csr)), "short envelope binding rejected");
        Check(!valid.Matches(new CmcRequestBinding(binding.EnvelopeSha256, binding.Csr with { SubjectPublicKeyInfoSha256 = new byte[32] })), "SPKI binding checked");
        Check(!valid.Matches(new CmcRequestBinding(binding.EnvelopeSha256, binding.Csr with { CsrSha256 = new byte[32] })), "CSR binding checked");
        foreach (var options in new[] { new Options(CsrSha1: true), new Options(CmsSha1: true), new Options(CsrSha1: true, CmsSha1: true) })
        {
            var legacy = Fixture(options);
            Reject(() => Validate(legacy), "SHA1 disabled by default");
            Check(Validate(legacy, true).UsedLegacySha1, "explicit lab-only legacy acceptance surfaced");
        }
        Check(!Validate(Fixture(new Options(NoControl: true, NoDiagnostics: true))).UsedLegacySha1, "optional diagnostics/control omitted");
        Check(!Validate(Fixture(new Options(MicrosoftExtensionAttribute: true))).UsedLegacySha1, "Microsoft extension attribute alias");
        Check(!Validate(Fixture(new Options(OmitMinorVersion: true))).UsedLegacySha1, "native omitted zero minor version");
        Reject(() => ValidatedCmcRequest.Validate(Fixture(new Options(OmitMinorVersion: true)), Policy with { TemplateMinorVersion = 1 }), "omitted minor cannot select nonzero revision");
        foreach (var bad in new[]
        {
            new Options(NonemptySubject: true), new Options(WrongTemplate: true), new Options(WrongVersion: true),
            new Options(ExtraEku: true), new Options(WrongUsage: true), new Options(WrongApplicationPolicy: true),
            new Options(WrongSki: true), new Options(AddSan: true), new Options(DuplicateExtension: true),
            new Options(MissingExtension: true), new Options(UnknownAttribute: true), new Options(DuplicateAttribute: true),
            new Options(DuplicateExtensionAlias: true), new Options(TamperCsr: true), new Options(NullCsr: true),
            new Options(BadClientInfo: true), new Options(BadProvider: true), new Options(LongDiagnostic: true),
            new Options(ControlOid: "1.3.6.1.5.5.7.7.18"), new Options(ControlAttribute: "1.3.6.1.4.1.311.13.2.1"),
            new Options(ControlBodyId: 1), new Options(ControlReference: 3), new Options(ControlPkiReference: 1),
            new Options(DuplicateControl: true), new Options(DuplicateRequest: true), new Options(ZeroRequestId: true),
            new Options(ExtraCmsBody: true), new Options(ExtraOtherBody: true), new Options(WrongCmsKey: true),
            new Options(IncludeCertificate: true), new Options(IssuerSigner: true), new Options(ExtraSigner: true),
            new Options(UnsignedAttribute: true), new Options(ExtraSignedAttribute: true), new Options(WrongContentType: true),
            new Options(Detached: true), new Options(NullCms: true)
        }) Reject(() => Validate(Fixture(bad), true), bad.ToString());
        using (var shortKey = RSA.Create(1024))
            Reject(() => Validate(CreateFixture(shortKey, new())), "short RSA key");
        Reject(() => Validate([]), "empty");
        Reject(() => Validate(new byte[131073]), "oversized");
        var baseline = Fixture();
        Reject(() => Validate([.. baseline, 0]), "trailing data");
        foreach (var length in new[] { 1, 2, 8, baseline.Length / 2, baseline.Length - 1 })
            Reject(() => Validate(baseline[..length]), "truncated input");
        Reject(() => ValidatedCmcRequest.Validate(baseline, Policy with { TemplateMajorVersion = -1 }), "invalid server policy");

        // Signed diagnostic changes on the same key must invalidate the WHOLE
        // approved transaction, even though their identity claims are discarded.
        var changed = Validate(Fixture(new Options(ControlMachineName: "different.untrusted.invalid")));
        Check(changed.CreateBinding().Csr.Matches(valid.CreateBinding().Csr) && !changed.Matches(binding), "same CSR/different CMC control cannot reuse approval");
        const string signingEku = "1.3.6.1.4.1.55555.670.1";
        using var signerKey = RSA.Create(2048);
        var signingRequest = new CertificateRequest("CN=Ephemeral incoming test signer", signerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signingRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        signingRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(signingEku) }, false));
        var now = DateTimeOffset.UtcNow;
        using var signer = signingRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddDays(1));
        var identity = new ControlledCertificateIdentity("CN=Authoritative,OU=Lab,DC=test,DC=corp",
            [new Uri("urn:example:pki-broker:lab:fact:v1:profile:broker-pilot")], ["authoritative.example.test"]);
        var downstreamTemplate = new CmcTemplate("1.3.6.1.4.1.55555.670.2", 2, 0, signingEku);
        var built = CmcEnrollmentRequestBuilder.Build(valid, binding, identity, downstreamTemplate, signer, now);
        Check(built.OriginalEnvelopeSha256!.AsSpan().SequenceEqual(binding.EnvelopeSha256), "downstream retains exact envelope binding");
        Check(built.OriginalRequestBinding.Matches(binding.Csr), "downstream retains original CSR binding");
        Check(CsrBinding.ExtractSubjectPublicKeyInfoDer(built.NullSignedPkcs10).AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo()), "downstream preserves original device key");
        var builtCms = new SignedCms(); builtCms.Decode(built.EncodedCms);
        Check(builtCms.SignerInfos.Cast<SignerInfo>().All(s => s.DigestAlgorithm.Value == "2.16.840.1.101.3.4.2.1"), "downstream is SHA256 regardless of client compatibility");
        Reject(() => CmcEnrollmentRequestBuilder.Build(changed, binding, identity, downstreamTemplate, signer, now), "changed envelope cannot issue");
        Reject(() => CmcEnrollmentRequestBuilder.Build(valid.ExportPkcs10(), binding.Csr, identity, downstreamTemplate, signer, now), "bare-CSR API cannot bypass native hint validation");

        if (nativeFixturePath is not null || nativeFixture is not null)
        {
            // Only a synthetic public CertEnroll fixture may be supplied, not a
            // real device's enrollment request. No key or enrollment submission.
            var nativeBytes = nativeFixture ?? File.ReadAllBytes(nativeFixturePath!);
            var nativePolicy = Policy with { TemplateOid = "1.3.6.1.4.1.311.21.8.13156823.13412796.14503312.15479153.2552636.41.360034954.1256878080" };
            Reject(() => ValidatedCmcRequest.Validate(nativeBytes, nativePolicy), "native SHA1 default rejection");
            var native = ValidatedCmcRequest.Validate(nativeBytes, nativePolicy with { AllowLegacySha1ForLab = true });
            Check(native.UsedLegacySha1, "native CertEnroll CMC POP and hints validated");
            var downstream = CmcEnrollmentRequestBuilder.Build(native, native.CreateBinding(), identity, downstreamTemplate, signer, now);
            Check(downstream.OriginalRequestBinding.Matches(native.CreateBinding().Csr), "native-to-owned-CMC binding preserved");
            Console.WriteLine("Synthetic native Windows CMC validation and downstream construction passed (not CA issuance).");
        }
        Console.WriteLine($"Incoming CMC checks passed: {count}.");
    }

    private sealed record Options(bool CsrSha1 = false, bool CmsSha1 = false, bool NoControl = false,
        bool NoDiagnostics = false, bool MicrosoftExtensionAttribute = false, bool NonemptySubject = false,
        bool WrongTemplate = false, bool WrongVersion = false, bool ExtraEku = false, bool WrongUsage = false,
        bool WrongApplicationPolicy = false, bool WrongSki = false, bool AddSan = false, bool DuplicateExtension = false,
        bool MissingExtension = false, bool UnknownAttribute = false, bool DuplicateAttribute = false,
        bool DuplicateExtensionAlias = false, bool TamperCsr = false, bool NullCsr = false, bool BadClientInfo = false,
        bool BadProvider = false, bool LongDiagnostic = false, string ControlOid = "1.3.6.1.4.1.311.10.10.1",
        string ControlAttribute = ClientInfoOid, int ControlBodyId = 2, int ControlReference = 1,
        int ControlPkiReference = 0, bool DuplicateControl = false, bool DuplicateRequest = false,
        bool ZeroRequestId = false, bool ExtraCmsBody = false, bool ExtraOtherBody = false, bool WrongCmsKey = false,
        bool IncludeCertificate = false, bool IssuerSigner = false, bool ExtraSigner = false, bool UnsignedAttribute = false,
        bool ExtraSignedAttribute = false, bool WrongContentType = false, bool Detached = false, bool NullCms = false,
        string ControlMachineName = "untrusted.synthetic.invalid", bool OmitMinorVersion = false);

    private static byte[] CreateFixture(RSA key, Options options)
    {
        var ski = new X509SubjectKeyIdentifierExtension(new PublicKey(key), false).RawData;
        var info = new AsnWriter(AsnEncodingRules.DER);
        using (info.PushSequence())
        {
            info.WriteInteger(0);
            info.WriteEncodedValue(new X500DistinguishedName(options.NonemptySubject ? "CN=Client claim" : "").RawData);
            info.WriteEncodedValue(key.ExportSubjectPublicKeyInfo());
            using (info.PushSetOf(ContextZero))
            {
                if (!options.NoDiagnostics)
                {
                    Attribute(info, "1.3.6.1.4.1.311.13.2.3", w => w.WriteCharacterString(UniversalTagNumber.IA5String, "10.0.synthetic"));
                    Attribute(info, ClientInfoOid, w => ClientInfo(w, options, "inner.synthetic.invalid"));
                    Attribute(info, "1.3.6.1.4.1.311.13.2.2", w =>
                    {
                        using (w.PushSequence())
                        { w.WriteInteger(1); w.WriteCharacterString(options.BadProvider ? UniversalTagNumber.UTF8String : UniversalTagNumber.BMPString, "Synthetic provider"); w.WriteBitString([]); }
                    });
                }
                var extensionOid = options.MicrosoftExtensionAttribute ? "1.3.6.1.4.1.311.2.1.14" : "1.2.840.113549.1.9.14";
                Attribute(info, extensionOid, w => Extensions(w, ski, options));
                if (options.DuplicateExtensionAlias) Attribute(info, "1.3.6.1.4.1.311.2.1.14", w => Extensions(w, ski, options));
                if (options.UnknownAttribute) Attribute(info, "1.3.6.1.4.1.311.13.2.1", w => w.WriteCharacterString(UniversalTagNumber.UTF8String, "san:attacker"));
                if (options.DuplicateAttribute) Attribute(info, ClientInfoOid, w => ClientInfo(w, options, "duplicate.invalid"));
            }
        }
        var hash = options.CsrSha1 ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
        var signature = options.NullCsr ? SHA256.HashData(info.Encode()) : key.SignData(info.Encode(), hash, RSASignaturePadding.Pkcs1);
        if (options.TamperCsr) signature[0] ^= 1;
        var csr = new AsnWriter(AsnEncodingRules.DER);
        using (csr.PushSequence())
        {
            csr.WriteEncodedValue(info.Encode());
            Algorithm(csr, options.NullCsr ? "2.16.840.1.101.3.4.2.1" : options.CsrSha1 ? "1.2.840.113549.1.1.5" : "1.2.840.113549.1.1.11");
            csr.WriteBitString(signature);
        }
        var pki = new AsnWriter(AsnEncodingRules.DER);
        using (pki.PushSequence())
        {
            using (pki.PushSequence())
                if (!options.NoControl)
                    for (var i = 0; i < (options.DuplicateControl ? 2 : 1); i++)
                        using (pki.PushSequence())
                        {
                            pki.WriteInteger(options.ControlBodyId); pki.WriteObjectIdentifier(options.ControlOid);
                            using (pki.PushSetOf()) using (pki.PushSequence())
                            {
                                pki.WriteInteger(options.ControlPkiReference);
                                using (pki.PushSequence()) pki.WriteInteger(options.ControlReference);
                                using (pki.PushSetOf()) Attribute(pki, options.ControlAttribute, w => ClientInfo(w, options, options.ControlMachineName));
                            }
                        }
            using (pki.PushSequence())
                for (var i = 0; i < (options.DuplicateRequest ? 2 : 1); i++)
                    using (pki.PushSequence(ContextZero))
                    { pki.WriteInteger(options.ZeroRequestId ? 0 : 1); pki.WriteEncodedValue(csr.Encode()); }
            using (pki.PushSequence()) if (options.ExtraCmsBody) pki.WriteNull();
            using (pki.PushSequence()) if (options.ExtraOtherBody) pki.WriteNull();
        }
        using var wrongKey = options.WrongCmsKey ? RSA.Create(2048) : null;
        var actualKey = wrongKey ?? key;
        var certRequest = new CertificateRequest("CN=Synthetic PUBLIC fixture", actualKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certRequest.PublicKey, false));
        using var certificate = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        var cms = new SignedCms(new ContentInfo(new Oid(options.WrongContentType ? "1.2.840.113549.1.7.1" : CmcEnrollmentRequestBuilder.PkiDataOid), pki.Encode()), options.Detached);
        CmsSigner Signer()
        {
            var signer = new CmsSigner(options.NullCms ? SubjectIdentifierType.NoSignature : options.IssuerSigner ? SubjectIdentifierType.IssuerAndSerialNumber : SubjectIdentifierType.SubjectKeyIdentifier,
                options.NullCms ? null : certificate)
            {
                IncludeOption = options.IncludeCertificate ? X509IncludeOption.EndCertOnly : X509IncludeOption.None,
                DigestAlgorithm = new Oid(options.CmsSha1 ? "1.3.14.3.2.26" : "2.16.840.1.101.3.4.2.1"),
                SignaturePadding = RSASignaturePadding.Pkcs1
            };
            if (options.UnsignedAttribute) signer.UnsignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
            if (options.ExtraSignedAttribute) signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
            return signer;
        }
        cms.ComputeSignature(Signer(), true);
        if (options.ExtraSigner) cms.ComputeSignature(Signer(), true);
        return cms.Encode();
    }

    private static void Extensions(AsnWriter writer, byte[] ski, Options options)
    {
        using (writer.PushSequence())
        {
            Extension(writer, "1.3.6.1.4.1.311.21.7", false, w =>
            { using (w.PushSequence()) { w.WriteObjectIdentifier(options.WrongTemplate ? TemplateOid + ".1" : TemplateOid); w.WriteInteger(options.WrongVersion ? 102 : 101); if (!options.OmitMinorVersion) w.WriteInteger(0); } });
            Extension(writer, "2.5.29.37", false, w =>
            { using (w.PushSequence()) { w.WriteObjectIdentifier("1.3.6.1.5.5.7.3.2"); if (options.ExtraEku) w.WriteObjectIdentifier("1.3.6.1.5.5.7.3.1"); } });
            Extension(writer, "2.5.29.15", true, w => w.WriteEncodedValue(new X509KeyUsageExtension(options.WrongUsage ? X509KeyUsageFlags.KeyCertSign : Policy.KeyUsage, true).RawData));
            Extension(writer, "1.3.6.1.4.1.311.21.10", false, w =>
            { using (w.PushSequence()) using (w.PushSequence()) w.WriteObjectIdentifier(options.WrongApplicationPolicy ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2"); });
            if (!options.MissingExtension)
                Extension(writer, "2.5.29.14", false, w => { if (options.WrongSki) w.WriteOctetString(new byte[20]); else w.WriteEncodedValue(ski); });
            if (options.DuplicateExtension) Extension(writer, "2.5.29.14", false, w => w.WriteEncodedValue(ski));
            if (options.AddSan) Extension(writer, "2.5.29.17", false, w =>
            { using (w.PushSequence()) w.WriteCharacterString(UniversalTagNumber.IA5String, "urn:example:admin", new Asn1Tag(TagClass.ContextSpecific, 6)); });
        }
    }
    private static void ClientInfo(AsnWriter writer, Options options, string machine)
    {
        using (writer.PushSequence())
        {
            writer.WriteInteger(5);
            writer.WriteCharacterString(options.BadClientInfo ? UniversalTagNumber.IA5String : UniversalTagNumber.UTF8String,
                options.LongDiagnostic ? new string('a', 1025) : machine);
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "UNTRUSTED\\synthetic$");
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "fixture.exe");
        }
    }
    private static void Attribute(AsnWriter writer, string oid, Action<AsnWriter> write)
    { using (writer.PushSequence()) { writer.WriteObjectIdentifier(oid); using (writer.PushSetOf()) write(writer); } }
    private static void Extension(AsnWriter writer, string oid, bool critical, Action<AsnWriter> write)
    {
        var encoded = new AsnWriter(AsnEncodingRules.DER); write(encoded);
        using (writer.PushSequence())
        { writer.WriteObjectIdentifier(oid); if (critical) writer.WriteBoolean(true); writer.WriteOctetString(encoded.Encode()); }
    }
    private static void Algorithm(AsnWriter writer, string oid)
    { using (writer.PushSequence()) { writer.WriteObjectIdentifier(oid); writer.WriteNull(); } }
}
