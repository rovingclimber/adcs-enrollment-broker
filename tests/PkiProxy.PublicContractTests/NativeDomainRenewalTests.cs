using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Net;
using System.Xml.Linq;
using PkiProxy.Protocol;
using PkiProxy.Protocol.Wstep;
using Microsoft.AspNetCore.Http;
using PkiProxy.Directory;
using PkiProxy.Authentication;
using PkiProxy.Domain;
using PkiProxy.Protocol.Cmc;

internal static class NativeDomainRenewalTests
{
    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux()) return;
        var now = DateTimeOffset.UtcNow;
        var scratch = System.IO.Directory.CreateTempSubdirectory("renewal-auth-test-");
        var journalPath = Path.Combine(scratch.FullName, "journal");
        System.IO.Directory.CreateDirectory(journalPath);
        File.SetUnixFileMode(journalPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Renewal fixture root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        using var root = rootRequest.CreateSelfSigned(now.AddDays(-2), now.AddDays(3));
        using var oldKey = RSA.Create(2048);
        var oldRequest = new CertificateRequest("CN=synthetic-device", oldKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        oldRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        oldRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        oldRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, false));
        oldRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(oldRequest.PublicKey, false));
        var aki = new AsnWriter(AsnEncodingRules.DER);
        using (aki.PushSequence()) aki.WriteOctetString(Convert.FromHexString(root.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single().SubjectKeyIdentifier!), new Asn1Tag(TagClass.ContextSpecific, 0));
        oldRequest.CertificateExtensions.Add(new X509Extension("2.5.29.35", aki.Encode(), false));
        var san = new SubjectAlternativeNameBuilder(); san.AddUri(new Uri("urn:example:old-fact")); oldRequest.CertificateExtensions.Add(san.Build());
        using var oldPublic = oldRequest.Create(root, now.AddDays(-1), now.AddDays(1), RandomNumberGenerator.GetBytes(16));
        using var old = oldPublic.CopyWithPrivateKey(oldKey);
        using var newKey = RSA.Create(2048);
        var nextRequest = new CertificateRequest("CN=primary", newKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        nextRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(nextRequest.PublicKey, false));
        using var next = nextRequest.CreateSelfSigned(now.AddHours(-1), now.AddDays(1));
        using var signerKey = RSA.Create(2048);
        var signerRequest = new CertificateRequest("CN=renewal broker signer", signerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        signerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        signerRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.2.3.5") }, false));
        signerRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(signerRequest.PublicKey, false));
        signerRequest.CertificateExtensions.Add(new X509Extension("2.5.29.35", aki.Encode(), false));
        using var signerPublic = signerRequest.Create(root, now.AddHours(-1), now.AddDays(1), RandomNumberGenerator.GetBytes(16));
        using var signer = signerPublic.CopyWithPrivateKey(signerKey);
        var crlPath = Path.Combine(scratch.FullName, "crl.pem");
        void WriteCrl(bool revoked = false, bool expired = false, X509Certificate2? revokedLeaf = null)
        {
            var builder = new CertificateRevocationListBuilder(); if (revoked) builder.AddEntry(old);
            if (revokedLeaf is not null) builder.AddEntry(revokedLeaf);
            File.WriteAllText(crlPath, PemEncoding.WriteString("X509 CRL", builder.Build(root, 1,
                expired ? now.AddHours(-1) : now.AddDays(1), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1,
                now.AddDays(-1))), Encoding.ASCII);
        }
        try
        {
            WriteCrl();
            var policy = new NativeCmcPolicy("1.3.6.1.4.1.55555.670.3", 101, 0,
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
            var claims = new CertificateClaimPolicy("urn:example:broker-profile", "urn:example:facts:");
            var computer = new AuthenticatedDirectoryComputer(Guid.NewGuid().ToString(), "CN=current-ad-name", "current.example.test");
            var source = new FactsSource { Facts = new("asset-1", "CN=ignored-sot-dn", "workstation", "engineering", "office", "example.test", 1) };
            var journal = new EnrollmentSubmissionJournal(journalPath);
            var downstreamTemplate = new CmcTemplate("1.2.3.4", 1, 0, "1.2.3.5");
            var authorizer = new NativeDomainRenewalAuthorizer(source, claims, policy, root, crlPath, journal, downstreamTemplate);
            var request = IncomingRenewalCmcTests.Create(newKey, next, old, "");
            var count = 0;
            void Check(bool value, string label) { if (!value) throw new InvalidOperationException("Renewal authorization: " + label); count++; }
            async Task<DomainRenewalAuthorization> Run(AuthenticatedDirectoryComputer? identity = null) =>
                await authorizer.AuthorizeAsync(identity ?? computer, request, default);
            Check((await Run()).Result == DomainRenewalResult.MissingIssuanceBinding && source.Calls == 0, "unregistered old certificate rejected before facts");
            var initial = new NativeDomainEnrollmentAuthorizer(source, claims, policy, new("1.2.3.4", 1, 0, "1.2.3.5"));
            var enrollment = (await initial.AuthorizeAsync(computer, IncomingCmcRequestTests.CreateDomainFixture(oldKey), default)).Enrollment!;
            journal.TryBegin(enrollment, now)!.RecordValidatedResponse("1", old.GetCertHashString(HashAlgorithmName.SHA256), now);
            const string mtlsGroup = "S-1-5-21-1-2-3-1106";
            var mtlsDirectory = new CertificateDirectory { Record = new(Guid.Parse(computer.ObjectId), "CURRENT$",
                computer.DistinguishedName, computer.DnsHostName, 4096, 805306369,
                [ActiveDirectoryComputerResolver.EncodeDomainGroupSid(mtlsGroup)]) };
            var certificateIdentity = new CertificateDomainIdentityResolver(root, crlPath, journal,
                new ActiveDirectoryComputerResolver(mtlsDirectory, mtlsGroup));
            var resolvedPeer = certificateIdentity.Resolve(oldPublic, default);
            Check(resolvedPeer?.Computer == computer && resolvedPeer.AssetId == "asset-1",
                "TLS peer public certificate resolves receipt then current AD identity, ignoring inherited SAN");
            Check(certificateIdentity.Resolve(old, default) is null, "private-key object is not a peer certificate");
            var goodRecord = mtlsDirectory.Record;
            mtlsDirectory.Record = goodRecord with { UserAccountControl = 4098 };
            Check(certificateIdentity.Resolve(oldPublic, default) is null, "disabled AD identity denied despite current certificate");
            mtlsDirectory.Record = goodRecord with { TokenGroups = [] };
            Check(certificateIdentity.Resolve(oldPublic, default) is null, "removed group denied without cached certificate grant");
            mtlsDirectory.Record = goodRecord;
            WriteCrl(revoked: true);
            Check(certificateIdentity.Resolve(oldPublic, default) is null, "revoked TLS credential denied before directory grant");
            WriteCrl(expired: true);
            Check(certificateIdentity.Resolve(oldPublic, default) is null, "stale CRL denied for certificate identity");
            WriteCrl();
            var success = await Run();
            await CertificateHttpTests.RunAsync(root, old, crlPath, certificateIdentity);
            Check((await authorizer.AuthorizeAsync(resolvedPeer!, request, default)).Result == DomainRenewalResult.Authorized,
                "exact peer certificate and CMC renewal signer binding authorized");
            var factsCallsBeforeMismatch = source.Calls;
            Check((await authorizer.AuthorizeAsync(resolvedPeer! with { CertificateSha256 = new string('0', 64) }, request, default)).Result ==
                DomainRenewalResult.TransportCertificateMismatch && source.Calls == factsCallsBeforeMismatch,
                "different TLS credential rejected before facts even for the same computer");
            Check((await authorizer.AuthorizeAsync(resolvedPeer! with { AssetId = "swapped-asset" }, request, default)).Result ==
                DomainRenewalResult.AssetMismatch && source.Calls == factsCallsBeforeMismatch,
                "transport asset must agree with independently reread receipt");
            Check((await authorizer.AuthorizeAsync(resolvedPeer!, IncomingCmcRequestTests.CreateDomainFixture(oldKey), default)).Result ==
                DomainRenewalResult.InvalidRequest, "certificate-authenticated path refuses initial CMC instead of falling back");
            Check(success.Result == DomainRenewalResult.Authorized && success.Enrollment?.AssetId == "asset-1", "registered trusted certificate accepted");
            var identity = success.Enrollment!.ExportIdentity();
            Check(identity.SubjectDistinguishedName == computer.DistinguishedName && identity.SubjectAlternativeNameDnsNames!.Single() == computer.DnsHostName && source.LastHost == computer.DnsHostName, "current AD fields drive identity and lookup");
            Check(identity.SubjectAlternativeNameUris.Any(u => u.OriginalString == "urn:example:facts:use-case:engineering") && !identity.SubjectAlternativeNameUris.Any(u => u.OriginalString == "urn:example:old-fact"), "old SAN facts are not reused");
            source.Facts = source.Facts! with { UseCase = "lab-validation", SourceVersion = 2 };
            var changed = await Run();
            Check(changed.Enrollment!.FactsVersion == 2 && changed.Enrollment.ExportIdentity().SubjectAlternativeNameUris.Any(u => u.OriginalString.EndsWith(":lab-validation")), "fresh facts on next attempt");
            var built = changed.Enrollment.Build(signer, now);
            var signed = new SignedCms(); signed.Decode(built.EncodedCms);
            foreach (SignerInfo entry in signed.SignerInfos)
                if (entry.SignerIdentifier.Type != SubjectIdentifierType.NoSignature) entry.CheckSignature(true);
            Check(built.EncodedCms.AsSpan().IndexOf(Encoding.ASCII.GetBytes("urn:example:facts:use-case:lab-validation")) >= 0 &&
                built.EncodedCms.AsSpan().IndexOf(Encoding.ASCII.GetBytes("urn:example:old-fact")) < 0,
                "signed downstream request carries fresh SAN and omits inherited facts");
            Check(CsrBinding.ExtractSubjectPublicKeyInfoDer(built.NullSignedPkcs10).AsSpan().SequenceEqual(newKey.ExportSubjectPublicKeyInfo()),
                "downstream request preserves new requested key");
            Check(built.SubjectNameDer.AsSpan().SequenceEqual(CertificateSubjectEncoder.Encode(computer.DistinguishedName)) &&
                built.OriginalEnvelopeSha256!.AsSpan().SequenceEqual(changed.Enrollment.ExportBinding().EnvelopeSha256),
                "downstream subject and original envelope bound to authorization");
            var wrongBinding = changed.Enrollment.ExportBinding(); wrongBinding.EnvelopeSha256[0] ^= 1;
            var wrongBindingRejected = false;
            try { CmcEnrollmentRequestBuilder.BuildRenewal(ValidatedRenewalCmcRequest.Validate(request, policy), wrongBinding,
                changed.Enrollment.ExportIdentity(), downstreamTemplate, signer, now); }
            catch (CryptographicException) { wrongBindingRejected = true; }
            Check(wrongBindingRejected, "downstream construction refuses substituted transaction binding");
            X509Certificate2 Replacement(string change = "")
            {
                var response = new CertificateRequest(new X500DistinguishedName(
                    change == "subject" ? old.SubjectName.RawData : built.SubjectNameDer),
                    change == "key" ? oldKey : newKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                response.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                response.CertificateExtensions.Add(new X509KeyUsageExtension(change == "usage" ? X509KeyUsageFlags.DigitalSignature :
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
                response.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {
                    new(change == "eku" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, false));
                response.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(response.PublicKey, false));
                response.CertificateExtensions.Add(new X509Extension("2.5.29.35", aki.Encode(), false));
                response.CertificateExtensions.Add(new X509Extension("2.5.29.17", change == "san" ? san.Build().RawData : built.SanExtensionDer, false));
                var templateDer = new AsnWriter(AsnEncodingRules.DER);
                using (templateDer.PushSequence())
                {
                    templateDer.WriteObjectIdentifier(change == "template" ? "1.2.3.99" : downstreamTemplate.Oid);
                    templateDer.WriteInteger(change == "version" ? 2 : downstreamTemplate.MajorVersion);
                    templateDer.WriteInteger(downstreamTemplate.MinorVersion);
                }
                if (change != "missing-template") response.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.311.21.7", templateDer.Encode(), false));
                return response.Create(root, now.AddHours(-1), change == "expired" ? now.AddMinutes(-1) : now.AddHours(1), RandomNumberGenerator.GetBytes(16));
            }
            using var replacement = Replacement();
            Check(changed.Enrollment.ValidateIssuedCertificate(replacement, now), "exact trusted replacement accepted for release");
            foreach (var mutation in new[] { "key", "subject", "san", "template", "version", "missing-template", "usage", "eku", "expired" })
            {
                using var invalid = Replacement(mutation);
                Check(!changed.Enrollment.ValidateIssuedCertificate(invalid, now), "release rejects " + mutation);
            }
            using (var privateResponse = replacement.CopyWithPrivateKey(newKey))
                Check(!changed.Enrollment.ValidateIssuedCertificate(privateResponse, now), "release refuses attached private key");
            WriteCrl(revokedLeaf: replacement);
            Check(!changed.Enrollment.ValidateIssuedCertificate(replacement, now), "revoked replacement refused");
            WriteCrl();
            var competingClaims = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
                new EnrollmentSubmissionJournal(journalPath).TryBegin(changed.Enrollment, now))));
            Check(competingClaims.Count(c => c is not null) == 1, "one durable winner for concurrent renewal submissions");
            var restartJournal = new EnrollmentSubmissionJournal(journalPath);
            Check(restartJournal.TryBegin(changed.Enrollment, now) is null, "uncertain renewal stays claimed after restart");
            // Facts can change between attempts, but must not bypass the same-CSR claim.
            Check(restartJournal.TryBegin(success.Enrollment, now) is null, "different facts snapshot cannot replay the same CSR");
            var renewalClaimPath = Path.Combine(journalPath, changed.Enrollment.DirectoryObjectId.ToString("N") + "-" +
                Convert.ToHexString(changed.Enrollment.ExportBinding().Csr.CsrSha256) + ".submitted.json");
            using (var claimDocument = JsonDocument.Parse(File.ReadAllBytes(renewalClaimPath)))
            {
                var record = claimDocument.RootElement;
                Check(record.GetProperty("RequestKind").GetString() == "renewal" &&
                    record.GetProperty("OldCertificateSha256").GetString() == old.GetCertHashString(HashAlgorithmName.SHA256) &&
                    record.GetProperty("AssetId").GetString() == "asset-1" && record.GetProperty("FactsVersion").GetInt64() == 2,
                    "claim records renewal provenance and authoritative snapshot");
            }
            var replacementHash = replacement.GetCertHashString(HashAlgorithmName.SHA256);
            Check(restartJournal.FindValidatedBinding(changed.Enrollment.DirectoryObjectId, replacementHash) is null,
                "submission alone cannot grant replacement renewal authority");
            competingClaims.Single(c => c is not null)!.RecordValidatedResponse("2", replacementHash, now);
            Check(new EnrollmentSubmissionJournal(journalPath).FindValidatedBinding(changed.Enrollment.DirectoryObjectId, replacementHash)?.AssetId == "asset-1",
                "validated replacement receipt retains asset binding across restart");
            Check(restartJournal.TryBegin(changed.Enrollment, now) is null, "validated receipt does not reopen submission");
            foreach (var scenario in new[] { "success", "timeout", "correlation", "full-response", "wrong-leaf", "revoked-during-send", "cancel-before-send" })
            {
                var scenarioPath = Path.Combine(scratch.FullName, scenario);
                System.IO.Directory.CreateDirectory(scenarioPath);
                File.SetUnixFileMode(scenarioPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                var scenarioJournal = new EnrollmentSubmissionJournal(scenarioPath);
                var sends = 0;
                var issuer = new NativeCesEnrollmentIssuer(new Uri("https://ces.example.test/fixture"), root, signer, crlPath, scenarioJournal,
                    (_, _, _, soap, _, _) =>
                    {
                        sends++;
                        Check(System.IO.Directory.GetFiles(scenarioPath, "*.submitted.json").Length == 1,
                            "durable claim exists before " + scenario + " send");
                        if (scenario == "timeout") throw new TimeoutException("Synthetic uncertain send");
                        var document = XDocument.Parse(Encoding.UTF8.GetString(soap));
                        var messageId = document.Descendants(XName.Get("MessageID", "http://www.w3.org/2005/08/addressing")).Single().Value;
                        if (scenario == "correlation") messageId = "urn:uuid:" + Guid.NewGuid();
                        if (scenario == "revoked-during-send") WriteCrl(revoked: true);
                        var responseLeaf = scenario == "wrong-leaf" ? oldPublic : replacement;
                        var full = CreateFullResponse(responseLeaf, root);
                        if (scenario == "full-response") full[^1] ^= 1;
                        var response = SoapEnvelopeWriter.CreateResponse(WstepResponseWriter.CreateIssued(responseLeaf.RawData, full, "3", "en-GB"),
                            WstepResponseWriter.ResponseAction, messageId);
                        return Task.FromResult(new CesTransportResponse(HttpStatusCode.OK, Encoding.UTF8.GetBytes(response.ToString(SaveOptions.DisableFormatting))));
                    });
                ValidatedEnrollmentResponse? released = null;
                try { released = await issuer.IssueAsync(changed.Enrollment, new CancellationToken(scenario == "cancel-before-send")); }
                catch (Exception exception) when (exception is TimeoutException or InvalidDataException or CryptographicException or OperationCanceledException) { }
                Check((released is not null) == (scenario == "success"), "issuance release outcome for " + scenario);
                Check(sends == (scenario == "cancel-before-send" ? 0 : 1), "one send or pre-cancel for " + scenario);
                Check((scenarioJournal.FindValidatedBinding(changed.Enrollment.DirectoryObjectId, replacementHash) is not null) == (scenario == "success"),
                    "only validated response recorded for " + scenario);
                WriteCrl();
                if (scenario != "cancel-before-send")
                {
                    var replayRejected = false;
                    try { _ = await issuer.IssueAsync(changed.Enrollment, default); }
                    catch (InvalidOperationException) { replayRejected = true; }
                    Check(replayRejected && sends == 1, "no resend after " + scenario);
                }
                else Check(System.IO.Directory.GetFiles(scenarioPath).Length == 0, "pre-cancel does not claim");
            }
            foreach (var routeCase in new[] { "enabled", "disabled", "unauthorized", "malformed",
                "certificate", "certificate-disabled", "certificate-initial", "certificate-mismatch", "mixed-identities" })
            {
                var routePath = Path.Combine(scratch.FullName, "route-" + routeCase);
                System.IO.Directory.CreateDirectory(routePath);
                File.SetUnixFileMode(routePath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                var routeJournal = new EnrollmentSubmissionJournal(routePath);
                routeJournal.TryBegin(enrollment, now)!.RecordValidatedResponse("1", old.GetCertHashString(HashAlgorithmName.SHA256), now);
                var sends = 0;
                var routeIssuer = new NativeCesEnrollmentIssuer(new Uri("https://ces.example.test/fixture"), root, signer, crlPath, routeJournal,
                    (_, _, _, soap, _, _) => {
                        sends++;
                        var id = XDocument.Parse(Encoding.UTF8.GetString(soap)).Descendants(XName.Get("MessageID", "http://www.w3.org/2005/08/addressing")).Single().Value;
                        var response = SoapEnvelopeWriter.CreateResponse(WstepResponseWriter.CreateIssued(replacement.RawData, CreateFullResponse(replacement, root), "4", "en-GB"),
                            WstepResponseWriter.ResponseAction, id);
                        return Task.FromResult(new CesTransportResponse(HttpStatusCode.OK, Encoding.UTF8.GetBytes(response.ToString(SaveOptions.DisableFormatting))));
                    });
                using var service = new NativeEnrollmentService(X509CertificateLoader.LoadCertificate(root.RawData), signerPublic.CopyWithPrivateKey(signerKey),
                    null, initial, routeIssuer, _ => Task.FromResult(true), claims, downstreamTemplate,
                    routeCase is "disabled" or "certificate-disabled" ? null :
                        new NativeDomainRenewalAuthorizer(source, claims, policy, root, crlPath, routeJournal, downstreamTemplate));
                var context = new DefaultHttpContext();
                if (routeCase.StartsWith("certificate", StringComparison.Ordinal) || routeCase == "mixed-identities")
                    context.Features.Set(new AuthorizedCertificateComputerFeature(routeCase == "certificate-mismatch"
                        ? resolvedPeer! with { CertificateSha256 = new string('0', 64) } : resolvedPeer!));
                if ((!routeCase.StartsWith("certificate", StringComparison.Ordinal) && routeCase != "unauthorized"))
                    context.Features.Set(new AuthorizedComputerFeature(computer));
                var clientMessage = "urn:uuid:" + Guid.NewGuid();
                var clientSoap = NativeCesEnrollmentIssuer.CreateRequest(new Uri("https://broker.example.test/fixture"), clientMessage,
                    routeCase == "malformed" ? new byte[] { 1, 2, 3 } :
                    routeCase == "certificate-initial" ? IncomingCmcRequestTests.CreateDomainFixture(oldKey) : request);
                var reply = await service.HandleAsync(context, SoapEnvelopeReader.Parse(XDocument.Parse(Encoding.UTF8.GetString(clientSoap))), default);
                Check(sends == (routeCase is "enabled" or "certificate" ? 1 : 0), "handler send gate " + routeCase);
                if (routeCase is "enabled" or "certificate")
                {
                    var content = (reply as Microsoft.AspNetCore.Http.HttpResults.ContentHttpResult)?.ResponseContent;
                    Check(content is not null && XDocument.Parse(content).Descendants(XName.Get("RelatesTo", "http://www.w3.org/2005/08/addressing")).Single().Value == clientMessage,
                        "handler returns client-correlated renewal response");
                }
                else Check((reply as IStatusCodeHttpResult)?.StatusCode == 403, "handler refuses " + routeCase);
            }
            var before = source.Calls;
            Check((await Run(computer with { ObjectId = Guid.NewGuid().ToString() })).Result == DomainRenewalResult.MissingIssuanceBinding && source.Calls == before, "same hostname different AD object refused");
            source.Facts = source.Facts! with { AssetId = "replacement-asset" };
            Check((await Run()).Result == DomainRenewalResult.AssetMismatch, "hostname reassignment cannot swap asset");
            source.Facts = null;
            Check((await Run()).Result == DomainRenewalResult.UnknownDevice, "missing current facts refused");
            before = source.Calls; WriteCrl(revoked: true);
            var revokedBuildRejected = false;
            try { changed.Enrollment.Build(signer, now); }
            catch (CryptographicException) { revokedBuildRejected = true; }
            Check(revokedBuildRejected, "revocation after authorization prevents downstream construction");
            Check(!changed.Enrollment.ValidateIssuedCertificate(replacement, now), "old credential revoked before release refused");
            Check((await Run()).Result == DomainRenewalResult.OldCertificateRejected && source.Calls == before, "revocation refresh rejects before facts");
            WriteCrl(expired: true);
            Check(!changed.Enrollment.ValidateIssuedCertificate(replacement, now), "release refuses stale CRL");
            Check((await Run()).Result == DomainRenewalResult.OldCertificateRejected, "stale CRL refused");
            File.Delete(crlPath);
            Check(!changed.Enrollment.ValidateIssuedCertificate(replacement, now), "release refuses missing CRL");
            Check((await Run()).Result == DomainRenewalResult.OldCertificateRejected, "missing CRL refused");
            Console.WriteLine($"Native domain renewal authorization checks passed: {count} (synthetic, no issuance).");
        }
        finally { scratch.Delete(recursive: true); } // Only this test-created directory.
    }

    private static byte[] CreateFullResponse(X509Certificate2 leaf, X509Certificate2 root)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                void Control(int id, string oid, Action value)
                {
                    using (writer.PushSequence())
                    {
                        writer.WriteInteger(id); writer.WriteObjectIdentifier(oid);
                        using (writer.PushSetOf()) using (writer.PushSequence()) value();
                    }
                }
                Control(1, "1.3.6.1.5.5.7.7.1", () => {
                    writer.WriteInteger(0); using (writer.PushSequence()) writer.WriteInteger(1);
                });
                Control(2, "1.3.6.1.4.1.311.10.10.1", () => {
                    writer.WriteInteger(0); using (writer.PushSequence()) writer.WriteInteger(1);
                    using (writer.PushSetOf()) using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("1.3.6.1.4.1.311.21.17");
                        using (writer.PushSetOf()) writer.WriteOctetString(leaf.GetCertHash(HashAlgorithmName.SHA1));
                    }
                });
            }
            using (writer.PushSequence()) { }
            using (writer.PushSequence()) { }
        }
        var cms = new SignedCms(new ContentInfo(new Oid("1.3.6.1.5.5.7.12.3"), writer.Encode()));
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, root) {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"), IncludeOption = X509IncludeOption.EndCertOnly };
        signer.Certificates.Add(leaf);
        cms.ComputeSignature(signer);
        return cms.Encode();
    }

    private sealed class FactsSource : IDomainDeviceFactsSource
    {
        internal AuthoritativeDeviceFacts? Facts;
        internal int Calls;
        internal string? LastHost;
        public ValueTask<AuthoritativeDeviceFacts?> FindByDnsHostNameAsync(string name, CancellationToken token)
        { token.ThrowIfCancellationRequested(); Calls++; LastHost = name; return ValueTask.FromResult(Facts); }
    }

    private sealed class CertificateDirectory : IComputerDirectory
    {
        internal required DirectoryComputerRecord Record { get; set; }
        public DirectoryComputerRecord? FindComputer(Guid id, CancellationToken token) => Record;
        public DirectoryComputerRecord? FindComputer(string name, CancellationToken token) =>
            throw new InvalidOperationException("Certificate identity must not use an asserted name");
    }
}
