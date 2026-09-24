using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;
using PkiProxy.Protocol.Cmc;

internal static class NativeDomainEnrollmentTests
{
    public static async Task RunAsync(byte[]? nativeFixture = null)
    {
        var checks = 0;
        void Check(bool condition, string label)
        { if (!condition) throw new InvalidOperationException("Native domain: " + label); checks++; }
        var policy = new NativeCmcPolicy("1.3.6.1.4.1.55555.670.3", 101, 0,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
        const string profile = "urn:example:pki-broker:lab:fact:v1:profile:broker-pilot";
        var claims = new CertificateClaimPolicy(profile, "urn:example:device:");
        const string signerEku = "1.3.6.1.4.1.55555.670.1";
        var template = new CmcTemplate("1.3.6.1.4.1.55555.670.2", 2, 0, signerEku);
        var computer = new AuthenticatedDirectoryComputer("ad-object-123",
            "CN=AD-COMPUTER,OU=Computers,DC=test,DC=corp", "ad-computer.example.test");
        // A SOT DN must have no influence over a domain computer certificate.
        var facts = new AuthoritativeDeviceFacts("asset/123", "CN=SOT-MUST-NOT-SELECT-SUBJECT",
            "workstation", "development", "office", "example.test", 17);
        var source = new FactsSource { Facts = facts };
        var authorizer = new NativeDomainEnrollmentAuthorizer(source, claims, policy, template);
        using var key = RSA.Create(2048);
        var bytes = IncomingCmcRequestTests.CreateDomainFixture(key);
        var originalBinding = ValidatedCmcRequest.Validate(bytes, policy).CreateBinding();
        Check((await authorizer.AuthorizeAsync(computer, new byte[] { 0 }, default)).Result ==
            NativeDomainAuthorizationResult.InvalidCmc && source.Calls == 0, "invalid CMC precedes SOT");
        foreach (var badComputer in new[]
        {
            computer with { ObjectId = "" }, computer with { DistinguishedName = "" },
            computer with { DnsHostName = "*.example.test" }, computer with { DnsHostName = "" },
            computer with { DnsHostName = "unqualified" }
        }) Check((await authorizer.AuthorizeAsync(badComputer, bytes, default)).Result ==
            NativeDomainAuthorizationResult.InvalidDirectoryIdentity && source.Calls == 0,
            "invalid directory snapshot rejected before SOT");

        var authorization = await authorizer.AuthorizeAsync(computer, bytes, default);
        Check(authorization.Result == NativeDomainAuthorizationResult.Authorized && authorization.Enrollment is not null,
            "native request reaches domain authorization");
        Check(source.LastHost == computer.DnsHostName && source.Calls == 1,
            "only authenticated AD hostname drives SOT lookup, not CSR diagnostic names");
        var enrollment = authorization.Enrollment!;
        if (OperatingSystem.IsLinux())
        {
            var journalDirectory = System.IO.Directory.CreateTempSubdirectory("pkiproxy-journal-test-");
            File.SetUnixFileMode(journalDirectory.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                var journalComputer = computer with { ObjectId = Guid.NewGuid().ToString() };
                var journalEnrollment = (await authorizer.AuthorizeAsync(journalComputer, bytes, default)).Enrollment!;
                var journal = new EnrollmentSubmissionJournal(journalDirectory.FullName);
                var claimsWon = new System.Collections.Concurrent.ConcurrentBag<EnrollmentSubmissionJournal.SubmissionClaim>();
                Parallel.For(0, 12, _ => { var claim = journal.TryBegin(journalEnrollment, DateTimeOffset.UtcNow); if (claim is not null) claimsWon.Add(claim); });
                Check(claimsWon.Count == 1, "durable journal has one concurrent submission winner");
                Check(new EnrollmentSubmissionJournal(journalDirectory.FullName).TryBegin(journalEnrollment, now: DateTimeOffset.UtcNow) is null,
                    "new journal instance cannot resend uncertain request");
                Check(journal.FindValidatedBinding(Guid.Parse(journalComputer.ObjectId), new string('A', 64)) is null,
                    "submission without validated receipt does not grant certificate binding");
                Check(journal.FindValidatedBinding(new string('A', 64)) is null,
                    "certificate-only lookup cannot use an uncertain submission");
                claimsWon.Single().RecordValidatedResponse("27", new string('A', 64), DateTimeOffset.UtcNow);
                var restarted = new EnrollmentSubmissionJournal(journalDirectory.FullName);
                var receipt = restarted.FindValidatedBinding(Guid.Parse(journalComputer.ObjectId), new string('a', 64));
                Check(receipt?.AssetId == facts.AssetId && receipt.DirectoryObjectId == Guid.Parse(journalComputer.ObjectId),
                    "validated certificate retains directory and authoritative asset binding across restart");
                Check(restarted.FindValidatedBinding(new string('a', 64)) == receipt,
                    "certificate-only lookup resolves durable identity without caller supplied GUID");
                Check(restarted.FindValidatedBinding(new string('B', 64)) is null,
                    "unrecorded certificate has no inferred hostname binding");
                Check(restarted.FindValidatedBinding(Guid.NewGuid(), new string('A', 64)) is null,
                    "another directory identity cannot acquire receipt");
                Check(restarted.FindValidatedBinding(Guid.Parse(journalComputer.ObjectId), new string('B', 64)) is null,
                    "another certificate cannot acquire receipt");
                Check(journal.TryBegin(journalEnrollment, DateTimeOffset.UtcNow) is null, "validated request cannot be reissued");
                var records = System.IO.Directory.GetFiles(journalDirectory.FullName);
                var privateRecords = records.Length == 2;
                foreach (var record in records)
                    privateRecords &= File.GetUnixFileMode(record) == (UnixFileMode.UserRead | UnixFileMode.UserWrite);
                Check(privateRecords, "journal metadata durable files are owner-only");
                var legacyObject = Guid.NewGuid();
                var legacyPath = Path.Combine(journalDirectory.FullName, legacyObject.ToString("N") + "-" + new string('0', 64) + ".validated.json");
                File.WriteAllText(legacyPath, "{\"Version\":1,\"IssuerRequestId\":26,\"CertificateSha256\":\"" + new string('A', 64) + "\"}");
                File.SetUnixFileMode(legacyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                Check(restarted.FindValidatedBinding(legacyObject, new string('A', 64)) is null,
                    "legacy receipt without asset identity cannot authorize renewal");
                Check(restarted.FindValidatedBinding(new string('A', 64)) == receipt,
                    "legacy receipt does not grant or shadow certificate-only binding");
                var duplicatePath = Path.Combine(journalDirectory.FullName,
                    legacyObject.ToString("N") + "-duplicate.validated.json");
                File.WriteAllText(duplicatePath, System.Text.Json.JsonSerializer.Serialize(new {
                    Version = 2, DirectoryObjectId = legacyObject, AssetId = "another-asset",
                    IssuerRequestId = 99, CertificateSha256 = new string('A', 64), ValidatedAt = DateTimeOffset.UtcNow }));
                File.SetUnixFileMode(duplicatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                var ambiguousRejected = false;
                try { restarted.FindValidatedBinding(new string('A', 64)); }
                catch (IOException) { ambiguousRejected = true; }
                Check(ambiguousRejected, "same certificate across two directory identities fails closed");
            }
            finally
            {
                foreach (var file in System.IO.Directory.GetFiles(journalDirectory.FullName)) File.Delete(file);
                journalDirectory.Delete();
            }
        }
        Check(enrollment.DirectoryObjectId == computer.ObjectId && enrollment.AssetId == facts.AssetId &&
            enrollment.FactsSourceVersion == 17 && !enrollment.UsedLegacySha1, "authorization audit binding");

        // Public input and exported audit values are not references to the owned transaction.
        bytes[^1] ^= 1;
        var exposed = enrollment.ExportBinding();
        exposed.EnvelopeSha256[0] ^= 1; exposed.Csr.CsrSha256[0] ^= 1;
        Check(enrollment.ExportBinding().EnvelopeSha256.AsSpan().SequenceEqual(originalBinding.EnvelopeSha256),
            "envelope snapshot survives caller mutation");
        Check(enrollment.ExportBinding().Csr.Matches(originalBinding.Csr), "CSR snapshot survives caller mutation");
        using var signingKey = RSA.Create(2048);
        var signingRequest = new CertificateRequest("CN=Ephemeral domain test signer", signingKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signingRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        signingRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(signerEku) }, false));
        var now = DateTimeOffset.UtcNow;
        using var signer = signingRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddHours(1));
        var built = enrollment.Build(signer, now);
        Check(built.OriginalRequestBinding.Matches(originalBinding.Csr) &&
            built.OriginalEnvelopeSha256!.AsSpan().SequenceEqual(originalBinding.EnvelopeSha256), "signing retains exact original binding");
        var cms = new SignedCms(); cms.Decode(built.EncodedCms);
        cms.SignerInfos.Cast<SignerInfo>().Single(s => s.SignerIdentifier.Type != SubjectIdentifierType.NoSignature)
            .CheckSignature(verifySignatureOnly: true);
        Check(cms.ContentInfo.ContentType.Value == CmcEnrollmentRequestBuilder.PkiDataOid, "signed CMC PKIData output");
        var pki = new AsnReader(cms.ContentInfo.Content, AsnEncodingRules.DER).ReadSequence();
        pki.ReadSequence().ThrowIfNotEmpty();
        var tagged = pki.ReadSequence().ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        Check(tagged.ReadInteger() == 1, "single downstream request body id");
        var info = tagged.ReadSequence().ReadSequence();
        Check(info.ReadInteger() == 0, "downstream PKCS10 version");
        Check(info.ReadEncodedValue().Span.SequenceEqual(CertificateSubjectEncoder.Encode(computer.DistinguishedName)),
            "signed output DN comes from AD, not SOT or CSR");
        Check(info.ReadEncodedValue().Span.SequenceEqual(key.ExportSubjectPublicKeyInfo()), "signed output preserves device key");
        var attribute = info.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
        Check(attribute.ReadObjectIdentifier() == "1.2.840.113549.1.9.14", "controlled extensionRequest");
        var extensions = attribute.ReadSetOf().ReadSequence();
        var templateExtension = extensions.ReadSequence();
        Check(templateExtension.ReadObjectIdentifier() == "1.3.6.1.4.1.311.21.7", "controlled template extension");
        var templateInfo = new AsnReader(templateExtension.ReadOctetString(), AsnEncodingRules.DER).ReadSequence();
        Check(templateInfo.ReadObjectIdentifier() == template.Oid && templateInfo.ReadInteger() == 2 &&
            templateInfo.ReadInteger() == 0, "server-selected downstream template, not incoming template");
        var sanExtension = extensions.ReadSequence();
        Check(sanExtension.ReadObjectIdentifier() == "2.5.29.17", "typed SAN extension");
        var san = new AsnReader(sanExtension.ReadOctetString(), AsnEncodingRules.DER).ReadSequence();
        Check(san.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 2)) ==
            computer.DnsHostName, "signed output DNS is AD dNSHostName");
        var uris = new List<string>();
        while (san.HasData)
            uris.Add(san.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6)));
        Check(uris.SequenceEqual(new[] { profile, "urn:example:device:asset:asset%2F123",
            "urn:example:device:class:workstation", "urn:example:device:use-case:development",
            "urn:example:device:location:office", "urn:example:device:management-domain:example.test" }),
            "exact broker profile and escaped SOT facts, no client claims");
        extensions.ThrowIfNotEmpty();

        if (OperatingSystem.IsLinux())
        {
            using var caKey = RSA.Create(2048);
            var caRequest = new CertificateRequest("CN=Bound release test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
            using var ca = caRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(2));
            byte[] Crl(bool revoked, X509Certificate2 leaf)
            {
                var builder = new CertificateRevocationListBuilder();
                if (revoked) builder.AddEntry(leaf);
                return System.Text.Encoding.ASCII.GetBytes(PemEncoding.WriteString("X509 CRL",
                    builder.Build(ca, 1, now.AddDays(1), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, now.AddMinutes(-1))));
            }
            X509Certificate2 Issue(string variant)
            {
                using var differentKey = RSA.Create(2048);
                var issued = new CertificateRequest(new X500DistinguishedName(CertificateSubjectEncoder.Encode(variant == "subject" ? "CN=Other" : computer.DistinguishedName)),
                    variant == "key" ? differentKey : key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                issued.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                issued.CertificateExtensions.Add(new X509KeyUsageExtension(variant == "usage" ? X509KeyUsageFlags.DigitalSignature :
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
                issued.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(variant == "eku" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, false));
                issued.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(issued.PublicKey, false));
                var authority = new AsnWriter(AsnEncodingRules.DER);
                using (authority.PushSequence()) authority.WriteOctetString(Convert.FromHexString(ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single().SubjectKeyIdentifier!), new Asn1Tag(TagClass.ContextSpecific, 0));
                issued.CertificateExtensions.Add(new X509Extension("2.5.29.35", authority.Encode(), false));
                if (variant != "san") issued.CertificateExtensions.Add(new X509Extension("2.5.29.17", built.SanExtensionDer, false));
                if (variant != "missing-template")
                {
                    var value = new AsnWriter(AsnEncodingRules.DER);
                    using (value.PushSequence())
                    {
                        value.WriteObjectIdentifier(variant == "template" ? "1.2.3.4" : template.Oid);
                        value.WriteInteger(variant == "revision" ? 99 : template.MajorVersion);
                        value.WriteInteger(template.MinorVersion);
                        if (variant == "trailing") value.WriteInteger(9);
                    }
                    issued.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.311.21.7", value.Encode(), false));
                }
                return issued.Create(ca, now.AddMinutes(-1), now.AddHours(1), RandomNumberGenerator.GetBytes(16));
            }
            using var goodLeaf = Issue("valid");
            // Public control structure observed from native CA request23. Replace
            // only its leaf identifier with this synthetic certificate's hash.
            var controlHex = "306D3067302102010106082B060105050707013112301002010030030201010C064973737565643042020102060A2B0601040182370A0A013131302F02010030030201013125302306092B060104018237151131160414" +
                goodLeaf.GetCertHashString(HashAlgorithmName.SHA1) + "30003000";
            byte[] FullResponse(byte[] content)
            {
                var full = new SignedCms(new ContentInfo(new Oid("1.3.6.1.5.5.7.12.3"), content));
                var issuer = new CmsSigner(ca) { IncludeOption = X509IncludeOption.EndCertOnly, DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") };
                issuer.Certificates.Add(goodLeaf); full.ComputeSignature(issuer); return full.Encode();
            }
            var fullBytes = FullResponse(Convert.FromHexString(controlHex));
            Check(CmcFullResponseValidator.Validate(fullBytes, goodLeaf, ca), "signed full CMC response matches exact root/leaf/status");
            var altered = fullBytes.ToArray(); altered[^1] ^= 1;
            Check(!CmcFullResponseValidator.Validate(altered, goodLeaf, ca), "full CMC response signature tampering rejected");
            Check(!CmcFullResponseValidator.Validate([.. fullBytes, 0], goodLeaf, ca), "trailing CMC bytes rejected");
            using var differentLeaf = Issue("subject");
            Check(!CmcFullResponseValidator.Validate(fullBytes, differentLeaf, ca), "full CMC response bound to leaf");
            var wrongHash = controlHex.Replace(goodLeaf.GetCertHashString(HashAlgorithmName.SHA1), new string('0', 40), StringComparison.Ordinal);
            Check(!CmcFullResponseValidator.Validate(FullResponse(Convert.FromHexString(wrongHash)), goodLeaf, ca), "signed mismatched CMC leaf identifier rejected");
            var verifier = new OpenSslCertificateVerifier(ca, Crl(false, goodLeaf));
            Check(enrollment.ValidateIssuedCertificate(goodLeaf, ca, verifier, now), "bound release accepts exact issued identity/profile/current CRL");
            foreach (var variant in new[] { "subject", "key", "usage", "eku", "san", "missing-template", "template", "revision", "trailing" })
            {
                using var badLeaf = Issue(variant);
                Check(!enrollment.ValidateIssuedCertificate(badLeaf, ca, verifier, now), "bound release rejects " + variant);
            }
            Check(!enrollment.ValidateIssuedCertificate(goodLeaf, ca, new(ca, Crl(true, goodLeaf)), now), "bound release rejects revoked exact leaf");
            Check(!enrollment.ValidateIssuedCertificate(goodLeaf, ca, new(ca, [1, 2, 3]), now), "bound release rejects malformed CRL");
            Check(!enrollment.ValidateIssuedCertificate(goodLeaf, ca, verifier, now.AddHours(2)), "bound release rejects expired leaf");
        }

        bytes = IncomingCmcRequestTests.CreateDomainFixture(key);
        source.Facts = null;
        var denied = await authorizer.AuthorizeAsync(computer, bytes, default);
        Check(denied.Result == NativeDomainAuthorizationResult.UnknownDevice && denied.Enrollment is null,
            "unknown SOT device gets no signing transaction");
        source.Facts = facts with { AssetId = "" };
        denied = await authorizer.AuthorizeAsync(computer, bytes, default);
        Check(denied.Result == NativeDomainAuthorizationResult.InvalidAuthoritativeFacts && denied.Enrollment is null,
            "missing authoritative fact fails closed");
        source.Facts = facts with { Location = new string('a', 2050) };
        Check((await authorizer.AuthorizeAsync(computer, bytes, default)).Result ==
            NativeDomainAuthorizationResult.InvalidAuthoritativeFacts, "oversize fact rejected before signing");
        source.Facts = facts;
        var legacyBytes = IncomingCmcRequestTests.CreateDomainFixture(key, legacy: true);
        var calls = source.Calls;
        Check((await authorizer.AuthorizeAsync(computer, legacyBytes, default)).Result ==
            NativeDomainAuthorizationResult.InvalidCmc && source.Calls == calls, "legacy is off before SOT by default");
        var labAuthorizer = new NativeDomainEnrollmentAuthorizer(source, claims,
            policy with { AllowLegacySha1ForLab = true }, template);
        Check((await labAuthorizer.AuthorizeAsync(computer, legacyBytes, default)).Enrollment?.UsedLegacySha1 == true,
            "lab-only legacy flag remains observable through authorization");
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        calls = source.Calls;
        try
        {
            await authorizer.AuthorizeAsync(computer, bytes, cancellation.Token);
            throw new InvalidOperationException("Cancelled enrollment unexpectedly authorized.");
        }
        catch (OperationCanceledException) { Check(source.Calls == calls, "cancellation precedes SOT"); }

        // Mutation and cancellation during asynchronous lookup must also be safe.
        using var midFlight = new CancellationTokenSource();
        source.OnLookup = () => { bytes[^1] ^= 1; midFlight.Cancel(); };
        try
        {
            await authorizer.AuthorizeAsync(computer, bytes, midFlight.Token);
            throw new InvalidOperationException("Mid-flight cancellation unexpectedly authorized.");
        }
        catch (OperationCanceledException) { checks++; }
        bytes = IncomingCmcRequestTests.CreateDomainFixture(key);
        var hash = SHA256.HashData(bytes);
        source.OnLookup = () => bytes[^1] ^= 1;
        var snapshot = await authorizer.AuthorizeAsync(computer, bytes, default);
        Check(snapshot.Enrollment!.ExportBinding().EnvelopeSha256.AsSpan().SequenceEqual(hash),
            "request is owned before asynchronous facts lookup");
        if (nativeFixture is not null)
        {
            source.OnLookup = null;
            var nativePolicy = policy with
            {
                TemplateOid = "1.3.6.1.4.1.311.21.8.13156823.13412796.14503312.15479153.2552636.41.360034954.1256878080"
            };
            var strictNative = new NativeDomainEnrollmentAuthorizer(source, claims, nativePolicy, template);
            calls = source.Calls;
            Check((await strictNative.AuthorizeAsync(computer, nativeFixture, default)).Result ==
                NativeDomainAuthorizationResult.InvalidCmc && source.Calls == calls,
                "actual native SHA1 request cannot bypass the default policy");
            var compatibleNative = new NativeDomainEnrollmentAuthorizer(source, claims,
                nativePolicy with { AllowLegacySha1ForLab = true }, template);
            var nativeAuthorization = await compatibleNative.AuthorizeAsync(computer, nativeFixture, default);
            Check(nativeAuthorization.Enrollment?.UsedLegacySha1 == true && source.LastHost == computer.DnsHostName,
                "native CertEnroll request authorizes against trusted directory identity");
            var nativeRequest = ValidatedCmcRequest.Validate(nativeFixture, nativePolicy with { AllowLegacySha1ForLab = true });
            var nativeOutput = nativeAuthorization.Enrollment!.Build(signer, now);
            Check(CsrBinding.ExtractSubjectPublicKeyInfoDer(nativeOutput.NullSignedPkcs10).AsSpan().SequenceEqual(
                CsrBinding.ExtractSubjectPublicKeyInfoDer(nativeRequest.ExportPkcs10())) &&
                nativeOutput.OriginalEnvelopeSha256!.AsSpan().SequenceEqual(SHA256.HashData(nativeFixture)),
                "native request-to-authorized-signed-CMC preserves the exact device key and envelope binding");
            Console.WriteLine("Native Windows public CMC traversed domain authorization and downstream signing (not issuance).");
        }
        Console.WriteLine($"Native domain authorization / CMC signing checks passed: {checks}.");
    }

    private sealed class FactsSource : IDomainDeviceFactsSource
    {
        public AuthoritativeDeviceFacts? Facts { get; set; }
        public int Calls { get; private set; }
        public string? LastHost { get; private set; }
        public Action? OnLookup { get; set; }
        public async ValueTask<AuthoritativeDeviceFacts?> FindByDnsHostNameAsync(string dnsHostName, CancellationToken cancellationToken)
        {
            Calls++; LastHost = dnsHostName;
            await Task.Yield();
            OnLookup?.Invoke();
            return Facts;
        }
    }
}
