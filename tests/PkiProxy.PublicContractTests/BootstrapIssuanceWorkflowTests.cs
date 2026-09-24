using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;
using PkiProxy.Protocol.Cmc;

internal static class BootstrapIssuanceWorkflowTests
{
    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux())
        {
            Console.WriteLine("Bootstrap issuance workflow checks skipped: Linux owner-only store required.");
            return;
        }

        var checks = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException("Bootstrap issuance workflow: " + label);
            checks++;
        }
        // Keep every synthetic transition behind the service's real catch-time
        // re-read so chronology guards test uncertainty rather than future time.
        var now = DateTimeOffset.UtcNow.AddMinutes(-10);
        using var deviceKey = RSA.Create(2048);
        var csr = new CertificateRequest("CN=client-claim-is-not-authority", deviceKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();
        var binding = CsrBinding.FromDer(csr);
        using var signerKey = RSA.Create(2048);
        var signerRequest = new CertificateRequest("CN=Bootstrap test signer", signerKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        const string signerEku = "1.3.6.1.4.1.311.99999.44";
        signerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        signerRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(signerEku) }, false));
        using var signer = signerRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddDays(1));
        using var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=Bootstrap test CA", caKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
        using var ca = caRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(2));
        var crl = System.Text.Encoding.ASCII.GetBytes(PemEncoding.WriteString("X509 CRL",
            new CertificateRevocationListBuilder().Build(ca, 1, now.AddDays(1), HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1, now.AddMinutes(-1))));
        var verifier = new OpenSslCertificateVerifier(ca, crl);
        var claims = new CertificateClaimPolicy("urn:test:bootstrap-profile", "urn:test:device:");
        var template = new CmcTemplate("1.3.6.1.4.1.311.99999.45", 7, 2, signerEku);
        var facts = new AuthoritativeDeviceFacts("asset-44", "", "workstation", "development",
            "office", "test.example", 9, "bootstrap44.test.example");

        var directory = Directory.CreateTempSubdirectory("bootstrap-issuance-");
        File.SetUnixFileMode(directory.FullName,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = new FileBootstrapEnrollmentTransactionStore(directory.FullName);
            var id = new string('A', 32);
            Check(store.Retain(csr, binding, now, TimeSpan.FromMinutes(20), id).Result == BootstrapTransactionResult.Retained,
                "retained exact CSR");
            var source = new Facts(facts);
            var sends = 0;
            BootstrapIssuer goodIssuer = async (enrollment, begin, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _ = enrollment.Build(signer, now, signerKey);
                var claim = begin(now.AddMinutes(2)) ?? throw new InvalidOperationException("claim refused");
                sends++;
                using var leaf = Issue(ca, deviceKey, facts, claims, template, now);
                Check(enrollment.ValidateIssuedCertificate(leaf, ca, verifier, now),
                    "release validator accepts retained key and authoritative identity");
                using var wrongKey = RSA.Create(2048);
                using var wrongLeaf = Issue(ca, wrongKey, facts, claims, template, now);
                Check(!enrollment.ValidateIssuedCertificate(wrongLeaf, ca, verifier, now),
                    "release validator rejects changed SPKI");
                claim.RecordIssuedResponse(44, leaf.RawData, [0x30, 0x00], now.AddMinutes(3));
                await Task.Yield();
                return new(leaf.RawData, [0x30, 0x00], "44");
            };
            var service = new BootstrapEnrollmentIssuanceService(store, source, claims, template, goodIssuer);
            Check((await service.QueryAsync(id, now.AddMinutes(1), default)).Result == BootstrapIssuanceResult.PendingApproval && sends == 0,
                "unapproved transaction cannot submit");
            Check((await service.QueryAsync("123456", now.AddMinutes(1), default)).Result == BootstrapIssuanceResult.Rejected && sends == 0,
                "six-digit display aid is not release authority");
            Check(store.BindAsset(id, binding, facts.AssetId, now.AddMinutes(1)) == BootstrapTransactionResult.AssetBound,
                "approved asset bound");
            var issued = await service.QueryAsync(id, now.AddMinutes(2), default);
            Check(issued.Result == BootstrapIssuanceResult.Issued && issued.Response?.RequestId == "44" && sends == 1,
                "AssetBound transaction submits exactly once and releases validated response");
            foreach (var suffix in new[] { ".certificate.der", ".full-response.der", ".release.json", ".terminal.json" })
                Check(File.GetUnixFileMode(Path.Combine(directory.FullName, "bootstrap-" + id + suffix)) ==
                    (UnixFileMode.UserRead | UnixFileMode.UserWrite),
                    "durable public release artifact remains owner-only " + suffix);

            var replayCalls = 0;
            var restarted = new BootstrapEnrollmentIssuanceService(
                new FileBootstrapEnrollmentTransactionStore(directory.FullName), source, claims, template,
                (_, _, _) => { replayCalls++; throw new InvalidOperationException("must not submit"); });
            var replay = await restarted.QueryAsync(id, now.AddMinutes(4), default);
            Check(replay.Result == BootstrapIssuanceResult.Issued && replayCalls == 0 &&
                replay.Response!.CertificateDer.SequenceEqual(issued.Response!.CertificateDer) &&
                replay.Response.FullPkiResponseDer.SequenceEqual(issued.Response.FullPkiResponseDer),
                "restart replays exact durable public response without CA call");

            var uncertainId = new string('B', 32);
            using var uncertainKey = RSA.Create(2048);
            var uncertainCsr = new CertificateRequest("CN=uncertain-client", uncertainKey,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();
            var uncertainBinding = CsrBinding.FromDer(uncertainCsr);
            Check(store.Retain(uncertainCsr, uncertainBinding, now, TimeSpan.FromMinutes(20), uncertainId).Result == BootstrapTransactionResult.Retained &&
                store.BindAsset(uncertainId, uncertainBinding, facts.AssetId, now.AddMinutes(1)) == BootstrapTransactionResult.AssetBound,
                "uncertain fixture approved");
            var uncertainSends = 0;
            var uncertain = new BootstrapEnrollmentIssuanceService(store, source, claims, template,
                (_, begin, _) =>
                {
                    if (begin(now.AddMinutes(2)) is null) throw new InvalidOperationException("claim refused");
                    uncertainSends++;
                    throw new HttpRequestException("synthetic post-claim uncertainty");
                });
            Check((await uncertain.QueryAsync(uncertainId, now.AddMinutes(2), default)).Result == BootstrapIssuanceResult.Uncertain &&
                uncertainSends == 1, "post-claim exception becomes explicit uncertain state");
            var noRetryCalls = 0;
            var afterCrash = new BootstrapEnrollmentIssuanceService(
                new FileBootstrapEnrollmentTransactionStore(directory.FullName), source, claims, template,
                (_, _, _) => { noRetryCalls++; throw new InvalidOperationException(); });
            Check((await afterCrash.QueryAsync(uncertainId, now.AddMinutes(3), default)).Result == BootstrapIssuanceResult.Uncertain &&
                noRetryCalls == 0, "restart refuses automatic resend of uncertain submission");

            var concurrentId = new string('D', 32);
            using var concurrentKey = RSA.Create(2048);
            var concurrentCsr = new CertificateRequest("CN=concurrent-client", concurrentKey,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();
            var concurrentBinding = CsrBinding.FromDer(concurrentCsr);
            Check(store.Retain(concurrentCsr, concurrentBinding, now, TimeSpan.FromMinutes(20), concurrentId).Result == BootstrapTransactionResult.Retained &&
                store.BindAsset(concurrentId, concurrentBinding, facts.AssetId, now.AddMinutes(1)) == BootstrapTransactionResult.AssetBound,
                "concurrent fixture approved");
            var claimed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var concurrentSends = 0;
            var concurrent = new BootstrapEnrollmentIssuanceService(store, source, claims, template,
                async (_, begin, _) =>
                {
                    var claim = begin(now.AddMinutes(2)) ?? throw new InvalidOperationException("claim refused");
                    concurrentSends++;
                    claimed.SetResult();
                    await release.Task;
                    using var leaf = Issue(ca, concurrentKey, facts, claims, template, now);
                    claim.RecordIssuedResponse(45, leaf.RawData, [0x30, 0x01], now.AddMinutes(3));
                    return new(leaf.RawData, [0x30, 0x01], "45");
                });
            var winner = concurrent.QueryAsync(concurrentId, now.AddMinutes(2), default);
            await claimed.Task;
            var loser = await concurrent.QueryAsync(concurrentId, now.AddMinutes(2), default);
            release.SetResult();
            Check((await winner).Result == BootstrapIssuanceResult.Issued &&
                loser.Result == BootstrapIssuanceResult.Uncertain && concurrentSends == 1,
                "concurrent QTS creates one CA send and one non-resending observer");

            var mismatchId = new string('C', 32);
            using var mismatchKey = RSA.Create(2048);
            var mismatchCsr = new CertificateRequest("CN=mismatch-client", mismatchKey,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();
            var mismatchBinding = CsrBinding.FromDer(mismatchCsr);
            Check(store.Retain(mismatchCsr, mismatchBinding, now, TimeSpan.FromMinutes(20), mismatchId).Result == BootstrapTransactionResult.Retained &&
                store.BindAsset(mismatchId, mismatchBinding, facts.AssetId, now.AddMinutes(1)) == BootstrapTransactionResult.AssetBound,
                "facts mismatch fixture approved");
            source.Value = facts with { AssetId = "different-asset" };
            Check((await service.QueryAsync(mismatchId, now.AddMinutes(2), default)).Result == BootstrapIssuanceResult.Rejected &&
                store.PrepareSubmission(mismatchId, now.AddMinutes(2)).State == BootstrapTransactionState.AssetBound,
                "changed authoritative asset fails before claim");

            var corruptPath = Path.Combine(directory.FullName, "bootstrap-" + id + ".certificate.der");
            File.WriteAllBytes(corruptPath, [1, 2, 3]);
            File.SetUnixFileMode(corruptPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            try
            {
                _ = new FileBootstrapEnrollmentTransactionStore(directory.FullName)
                    .PrepareSubmission(id, now.AddMinutes(5));
                throw new InvalidOperationException("corrupt release was accepted");
            }
            catch (InvalidDataException) { checks++; }
        }
        finally
        {
            foreach (var file in Directory.GetFiles(directory.FullName)) File.Delete(file);
            directory.Delete();
        }
        Console.WriteLine($"Bootstrap issuance/release workflow checks passed ({checks}).");
    }

    private static X509Certificate2 Issue(X509Certificate2 ca, RSA key,
        AuthoritativeDeviceFacts facts, CertificateClaimPolicy claims, CmcTemplate template,
        DateTimeOffset now)
    {
        var identity = ControlledCertificateIdentityMapper.Create(facts with
        {
            DirectoryDistinguishedName = "CN=" + facts.AuthoritativeDnsHostName
        }, claims) with { SubjectAlternativeNameDnsNames = [facts.AuthoritativeDnsHostName!] };
        var request = new CertificateRequest(identity.SubjectDistinguishedName, key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.2") }, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var authority = new AsnWriter(AsnEncodingRules.DER);
        using (authority.PushSequence())
            authority.WriteOctetString(Convert.FromHexString(ca.Extensions
                .OfType<X509SubjectKeyIdentifierExtension>().Single().SubjectKeyIdentifier!),
                new Asn1Tag(TagClass.ContextSpecific, 0));
        request.CertificateExtensions.Add(new X509Extension("2.5.29.35", authority.Encode(), false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(facts.AuthoritativeDnsHostName!);
        foreach (var uri in identity.SubjectAlternativeNameUris) san.AddUri(uri);
        request.CertificateExtensions.Add(san.Build());
        var templateValue = new AsnWriter(AsnEncodingRules.DER);
        using (templateValue.PushSequence())
        {
            templateValue.WriteObjectIdentifier(template.Oid);
            templateValue.WriteInteger(template.MajorVersion);
            templateValue.WriteInteger(template.MinorVersion);
        }
        request.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.311.21.7", templateValue.Encode(), false));
        return request.Create(ca, now.AddMinutes(-1), now.AddHours(1), RandomNumberGenerator.GetBytes(16));
    }

    private sealed class Facts(AuthoritativeDeviceFacts value) : IAuthoritativeDeviceFactsSource
    {
        internal AuthoritativeDeviceFacts? Value { get; set; } = value;
        public ValueTask<AuthoritativeDeviceFacts?> FindByAssetIdAsync(string assetId, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Value);
        public ValueTask<AuthoritativeDeviceFacts?> FindByDirectoryObjectIdAsync(string directoryObjectId,
            CancellationToken cancellationToken) => ValueTask.FromResult<AuthoritativeDeviceFacts?>(null);
    }
}
