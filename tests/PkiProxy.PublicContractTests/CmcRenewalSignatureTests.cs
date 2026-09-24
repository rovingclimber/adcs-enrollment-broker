using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Protocol.Cmc;

internal static class CmcRenewalSignatureTests
{
    internal static void Run()
    {
        using var oldKey = RSA.Create(2048);
        using var newKey = RSA.Create(2048);
        using var old = Certificate(oldKey, "CN=old");
        using var next = Certificate(newKey, "CN=new");
        // Only the signature layer is under test: this is not a valid PKIData
        // request, nor a trusted certificate, and must never authorize issuance.
        byte[] content = [0x30, 0x00];
        var checks = 0;
        void Accept(byte[] envelope, X509Certificate2 requested)
        {
            CmcRenewalSignatures.Verify(envelope, content, requested.PublicKey, old);
            checks++;
        }
        void Reject(Action action)
        {
            try { action(); }
            catch (CryptographicException) { checks++; return; }
            throw new InvalidOperationException("Renewal signature negative test accepted.");
        }
        var same = Envelope(old, old, content);
        var different = Envelope(next, old, content);
        Accept(same, old);
        Accept(different, next);
        // New-key renewal must not depend on resolving the primary signer to
        // an embedded certificate. Only the old certificate is transmitted.
        var decoded = new SignedCms(); decoded.Decode(different);
        if (decoded.Certificates.Count != 1 || decoded.Certificates[0].Thumbprint != old.Thumbprint ||
            decoded.SignerInfos.Cast<SignerInfo>().Single(s => s.SignerIdentifier.Type ==
                SubjectIdentifierType.SubjectKeyIdentifier).Certificate is not null)
            throw new InvalidOperationException("Synthetic new-key fixture does not isolate CSR-key verification.");
        checks++;
        Reject(() => CmcRenewalSignatures.Verify(different, content, old.PublicKey, old));
        Reject(() => CmcRenewalSignatures.Verify(different, content, next.PublicKey, next));
        Reject(() => CmcRenewalSignatures.Verify(different, new byte[] { 0x30, 1 }, next.PublicKey, old));
        Reject(() => CmcRenewalSignatures.Verify(different.Concat(new byte[] { 0 }).ToArray(), content, next.PublicKey, old));
        Reject(() => CmcRenewalSignatures.Verify(different.AsMemory(0, different.Length - 1), content, next.PublicKey, old));
        Reject(() => CmcRenewalSignatures.Verify(Array.Empty<byte>(), content, next.PublicKey, old));
        Reject(() => CmcRenewalSignatures.Verify(new byte[131073], content, next.PublicKey, old));
        Reject(() => CmcRenewalSignatures.Verify(Envelope(next, old, content, includePrimaryCertificate: true), content, next.PublicKey, old));
        Reject(() => CmcRenewalSignatures.Verify(Envelope(next, old, content, omitPrimary: true), content, next.PublicKey, old));
        Reject(() => CmcRenewalSignatures.Verify(Envelope(next, old, content, extraPrimary: true), content, next.PublicKey, old));
        Reject(() => CmcRenewalSignatures.Verify(Envelope(next, old, content, digest: "2.16.840.1.101.3.4.2.2"), content, next.PublicKey, old));
        // Corrupt each signature independently, retaining well-formed CMS DER.
        foreach (SignerInfo signer in decoded.SignerInfos)
        {
            var signature = signer.GetSignature();
            var offset = different.AsSpan().IndexOf(signature);
            if (offset < 0 || different.AsSpan(offset + 1).IndexOf(signature) >= 0)
                throw new InvalidOperationException("Ambiguous synthetic signature location.");
            var mutated = different.ToArray(); mutated[offset] ^= 1;
            Reject(() => CmcRenewalSignatures.Verify(mutated, content, next.PublicKey, old));
        }
        Console.WriteLine($"Renewal dual-key signature checks passed: {checks} (synthetic; no enrollment authorization).");
    }

    private static X509Certificate2 Certificate(RSA key, string name)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    }

    internal static byte[] Envelope(X509Certificate2 primary, X509Certificate2 old, byte[] content,
        bool includePrimaryCertificate = false, bool omitPrimary = false, bool extraPrimary = false,
        string digest = "2.16.840.1.101.3.4.2.1")
    {
        var cms = new SignedCms(new ContentInfo(new Oid("1.3.6.1.5.5.7.12.2"), content), false);
        var primarySigner = new CmsSigner(SubjectIdentifierType.SubjectKeyIdentifier, primary) {
            IncludeOption = includePrimaryCertificate ? X509IncludeOption.EndCertOnly : X509IncludeOption.None,
            DigestAlgorithm = new Oid(digest)
        };
        if (!omitPrimary) cms.ComputeSignature(primarySigner);
        if (extraPrimary) cms.ComputeSignature(primarySigner);
        cms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, old) {
            IncludeOption = X509IncludeOption.EndCertOnly, DigestAlgorithm = new Oid(digest)
        });
        return cms.Encode();
    }
}
