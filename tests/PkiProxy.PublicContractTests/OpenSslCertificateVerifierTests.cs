using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PkiProxy.Domain;

internal static class OpenSslCertificateVerifierTests
{
    internal static void Run()
    {
        if (!OperatingSystem.IsLinux()) return;
        var now = DateTimeOffset.UtcNow;
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Revocation test root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        using var root = rootRequest.CreateSelfSigned(now.AddDays(-3), now.AddDays(7));
        using var leafKey = RSA.Create(2048);
        X509Certificate2 Leaf(string eku = "1.3.6.1.5.5.7.3.1", bool expired = false, bool unknownCritical = false)
        {
            var request = new CertificateRequest("CN=ces.invalid", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(eku) }, false));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            var aki = new AsnWriter(AsnEncodingRules.DER);
            using (aki.PushSequence()) aki.WriteOctetString(Convert.FromHexString(root.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single().SubjectKeyIdentifier!), new Asn1Tag(TagClass.ContextSpecific, 0));
            request.CertificateExtensions.Add(new X509Extension("2.5.29.35", aki.Encode(), false));
            var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("ces.invalid"); request.CertificateExtensions.Add(san.Build());
            if (unknownCritical) request.CertificateExtensions.Add(new X509Extension("1.2.3.999", [5, 0], true));
            return request.Create(root, now.AddDays(-2), expired ? now.AddHours(-1) : now.AddHours(2), RandomNumberGenerator.GetBytes(16));
        }
        using var leaf = Leaf(); using var expiredLeaf = Leaf(expired: true);
        using var clientLeaf = Leaf("1.3.6.1.5.5.7.3.2"); using var criticalLeaf = Leaf(unknownCritical: true);
        byte[] Crl(CertificateRevocationListBuilder builder, DateTimeOffset start, DateTimeOffset end) =>
            Encoding.ASCII.GetBytes(PemEncoding.WriteString("X509 CRL", builder.Build(root, 1, end, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, start)));
        var good = Crl(new(), now.AddHours(-1), now.AddDays(1));
        var verifier = new OpenSslCertificateVerifier(root, good);
        var count = 0;
        void Check(bool value, string label) { if (!value) throw new InvalidOperationException("Explicit CRL check: " + label); count++; }
        Check(verifier.Verify(leaf, CertificatePurpose.Server, "ces.invalid"), "current nonrevoked server");
        Check(!verifier.Verify(leaf, CertificatePurpose.Server, "wrong.invalid"), "wrong server name");
        Check(!verifier.Verify(leaf, CertificatePurpose.Server), "missing server name");
        Check(!verifier.Verify(clientLeaf, CertificatePurpose.Server, "ces.invalid"), "wrong EKU");
        Check(verifier.Verify(clientLeaf, CertificatePurpose.Client), "client purpose");
        Check(!verifier.Verify(expiredLeaf, CertificatePurpose.Server, "ces.invalid"), "expired certificate");
        Check(!verifier.Verify(criticalLeaf, CertificatePurpose.Server, "ces.invalid"), "unknown critical extension");
        Check(!verifier.Verify(root, CertificatePurpose.Signing), "CA not admitted as leaf");
        var revoked = new CertificateRevocationListBuilder(); revoked.AddEntry(leaf);
        Check(!new OpenSslCertificateVerifier(root, Crl(revoked, now.AddMinutes(-1), now.AddDays(1))).Verify(leaf, CertificatePurpose.Server, "ces.invalid"), "revoked leaf");
        Check(!new OpenSslCertificateVerifier(root, Crl(new(), now.AddDays(-2), now.AddDays(-1))).Verify(leaf, CertificatePurpose.Server, "ces.invalid"), "expired CRL");
        Check(!new OpenSslCertificateVerifier(root, Crl(new(), now.AddHours(1), now.AddDays(1))).Verify(leaf, CertificatePurpose.Server, "ces.invalid"), "future CRL");
        var badSignature = new CertificateRevocationListBuilder().Build(root, 2, now.AddDays(1), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, now.AddMinutes(-1));
        badSignature[^1] ^= 1;
        Check(!new OpenSslCertificateVerifier(root, Encoding.ASCII.GetBytes(PemEncoding.WriteString("X509 CRL", badSignature))).Verify(leaf, CertificatePurpose.Server, "ces.invalid"), "bad CRL signature");
        Check(!new OpenSslCertificateVerifier(root, [1, 2, 3]).Verify(leaf, CertificatePurpose.Server, "ces.invalid"), "malformed CRL");
        using var otherRoot = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(6));
        // Different root key: same issuer name cannot confer trust.
        using var wrongKey = RSA.Create(2048);
        var wrongRequest = new CertificateRequest(root.SubjectName, wrongKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        wrongRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var wrongRoot = wrongRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(6));
        Check(!new OpenSslCertificateVerifier(wrongRoot, good).Verify(leaf, CertificatePurpose.Server, "ces.invalid"), "wrong trust key");

        // Exercise the actual readiness probe with disposable signing material/files.
        var scratch = System.IO.Directory.CreateTempSubdirectory("readiness-test-");
        try
        {
            const string signingOid = "1.2.3.4.567";
            using var publicSigning = Leaf(signingOid);
            using var signing = publicSigning.CopyWithPrivateKey(leafKey);
            var crlFile = Path.Combine(scratch.FullName, "crl.pem");
            var factsFile = Path.Combine(scratch.FullName, "facts.json");
            File.WriteAllBytes(crlFile, good);
            File.Copy("lab/device-facts/devices.example.json", factsFile);
            var factsSource = new JsonFileDeviceFactsSource(factsFile);
            var rotation = new SignerRotationPolicy(SHA256.HashData(signing.RawData), TimeSpan.FromMinutes(60));
            using var ready = new BrokerReadinessCheck(token =>
                LocalIssuanceReadiness.CheckAsync(root, signing, signingOid, rotation, crlFile, factsSource, token));
            bool IsReady()
            {
                ready.RefreshAsync().GetAwaiter().GetResult();
                return ready.CheckHealthAsync(new()).GetAwaiter().GetResult().Status ==
                    Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Healthy;
            }
            Check(IsReady(), "valid local prerequisites");
            File.WriteAllText(factsFile, "malformed");
            Check(!IsReady(), "bad facts invalidate readiness without restart");
            File.Copy("lab/device-facts/devices.example.json", factsFile, overwrite: true);
            var revokedSigner = new CertificateRevocationListBuilder(); revokedSigner.AddEntry(signing);
            File.WriteAllBytes(crlFile, Crl(revokedSigner, now.AddMinutes(-1), now.AddDays(1)));
            Check(!IsReady(), "signer revocation invalidates readiness");
            File.WriteAllBytes(crlFile, Crl(new(), now.AddDays(-2), now.AddDays(-1)));
            Check(!IsReady(), "expired CRL invalidates readiness");
            File.WriteAllBytes(crlFile, good);
            Check(IsReady(), "valid refresh restores readiness");
            using var wrongEku = new BrokerReadinessCheck(token =>
                LocalIssuanceReadiness.CheckAsync(root, signing, "1.2.3.4.999", rotation, crlFile, factsSource, token));
            wrongEku.RefreshAsync().GetAwaiter().GetResult();
            Check(wrongEku.CheckHealthAsync(new()).GetAwaiter().GetResult().Status ==
                Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Unhealthy, "wrong signer policy");
            using var expiredSigning = expiredLeaf.CopyWithPrivateKey(leafKey);
            using var expiredReady = new BrokerReadinessCheck(token =>
                LocalIssuanceReadiness.CheckAsync(root, expiredSigning, "1.3.6.1.5.5.7.3.1",
                    new(SHA256.HashData(expiredSigning.RawData), TimeSpan.FromMinutes(60)), crlFile, factsSource, token));
            expiredReady.RefreshAsync().GetAwaiter().GetResult();
            Check(expiredReady.CheckHealthAsync(new()).GetAwaiter().GetResult().Status ==
                Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Unhealthy, "expired signer");
            File.Delete(crlFile);
            Check(!IsReady(), "missing CRL invalidates readiness");
        }
        finally { scratch.Delete(recursive: true); } // Unique test-owned directory only.
        Console.WriteLine($"Explicit OpenSSL chain/revocation checks passed: {count}.");
    }
}
