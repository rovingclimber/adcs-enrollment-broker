using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;
using PkiProxy.Protocol.Wstep;

internal static class IssuedCertificateValidationTests
{
    public static void Run(X509Certificate2 root, ControlledCertificateIdentity identity)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = DateTimeOffset.UtcNow;
        var assertions = 0;

        void Check(X509KeyUsageFlags? actual, X509KeyUsageFlags expected, IssuedCertificateValidationResult result,
            string label, DateTimeOffset? verificationTime = null, DateTimeOffset? notAfter = null)
        {
            var request = new CertificateRequest(new X500DistinguishedName(CertificateSubjectEncoder.Encode(identity.SubjectDistinguishedName)), key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));
            if (actual is { } usage)
            {
                request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
            }

            var san = new SubjectAlternativeNameBuilder();
            foreach (var uri in identity.SubjectAlternativeNameUris)
            {
                san.AddUri(uri);
            }

            request.CertificateExtensions.Add(san.Build());
            using var certificate = request.Create(root, now.AddMinutes(-1), notAfter ?? now.AddDays(1),
                RandomNumberGenerator.GetBytes(16));
            var validation = IssuedCertificateValidator.Validate(certificate, request.CreateSigningRequest(), identity,
                new IssuedCertificateValidationPolicy(root, expected), verificationTime ?? now);
            if (validation.Result != result)
            {
                throw new InvalidOperationException($"{label}: expected {result}, got {validation.Result}.");
            }

            assertions++;
        }

        const X509KeyUsageFlags signing = X509KeyUsageFlags.DigitalSignature;
        const X509KeyUsageFlags signingAndEncipherment = signing | X509KeyUsageFlags.KeyEncipherment;
        Check(signing, signing, IssuedCertificateValidationResult.Valid, "Exact signing usage");
        Check(null, signing, IssuedCertificateValidationResult.KeyUsageMismatch, "Missing key usage");
        Check(X509KeyUsageFlags.KeyEncipherment, signing, IssuedCertificateValidationResult.KeyUsageMismatch,
            "Missing digital signature");
        Check(signingAndEncipherment, signing, IssuedCertificateValidationResult.KeyUsageMismatch, "Unexpected usage");
        Check(signing, signingAndEncipherment, IssuedCertificateValidationResult.KeyUsageMismatch, "Incomplete usage");
        Check(signing | X509KeyUsageFlags.KeyCertSign, signing | X509KeyUsageFlags.KeyCertSign,
            IssuedCertificateValidationResult.KeyUsageMismatch, "Policy cannot authorize a CA signing key");
        Check(X509KeyUsageFlags.None, X509KeyUsageFlags.None, IssuedCertificateValidationResult.KeyUsageMismatch,
            "Policy cannot omit digital signature");
        Check(signing, signing, IssuedCertificateValidationResult.Valid, "Chain uses supplied historical time",
            now.AddSeconds(-10), now.AddSeconds(-1));
        Check(signing, signing, IssuedCertificateValidationResult.CertificateNotCurrent, "Expiry boundary",
            now.AddDays(1));
        Console.WriteLine($"Issued certificate key-usage/time checks passed ({assertions}).");
        var sanChecks = 0;
        var withDns = identity with { SubjectAlternativeNameDnsNames = ["device.example.test"] };
        void CheckSan(ControlledCertificateIdentity expected, Action<SubjectAlternativeNameBuilder> alter,
            IssuedCertificateValidationResult result, string label, bool extraEku = false)
        {
            var request = new CertificateRequest(new X500DistinguishedName(CertificateSubjectEncoder.Encode(identity.SubjectDistinguishedName)), key, HashAlgorithmName.SHA256);
            var usages = new OidCollection { new("1.3.6.1.5.5.7.3.2") };
            if (extraEku) usages.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, false));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(signing, true));
            var san = new SubjectAlternativeNameBuilder();
            foreach (var uri in identity.SubjectAlternativeNameUris) san.AddUri(uri);
            alter(san);
            request.CertificateExtensions.Add(san.Build());
            using var certificate = request.Create(root, now.AddMinutes(-1), now.AddDays(1), RandomNumberGenerator.GetBytes(16));
            var actual = IssuedCertificateValidator.Validate(certificate, request.CreateSigningRequest(), expected,
                new IssuedCertificateValidationPolicy(root), now).Result;
            if (actual != result) throw new InvalidOperationException($"{label}: expected {result}, got {actual}.");
            sanChecks++;
        }
        CheckSan(withDns, s => s.AddDnsName("device.example.test"), IssuedCertificateValidationResult.Valid, "Exact DNS plus URI");
        CheckSan(withDns, _ => { }, IssuedCertificateValidationResult.SubjectAlternativeNameMismatch, "Missing required DNS");
        CheckSan(identity, s => s.AddDnsName("unexpected.example.test"), IssuedCertificateValidationResult.SubjectAlternativeNameMismatch, "Unexpected DNS");
        CheckSan(withDns, s => s.AddDnsName("other.example.test"), IssuedCertificateValidationResult.SubjectAlternativeNameMismatch, "Wrong DNS");
        CheckSan(identity, s => s.AddUri(identity.SubjectAlternativeNameUris.First()), IssuedCertificateValidationResult.SubjectAlternativeNameMismatch, "Duplicate URI");
        CheckSan(withDns, s => { s.AddDnsName("device.example.test"); s.AddDnsName("device.example.test"); }, IssuedCertificateValidationResult.SubjectAlternativeNameMismatch, "Duplicate DNS");
        CheckSan(identity, s => s.AddUserPrincipalName("other@example.test"), IssuedCertificateValidationResult.SubjectAlternativeNameMismatch, "Unexpected UPN");
        CheckSan(identity, s => s.AddIpAddress(System.Net.IPAddress.Loopback), IssuedCertificateValidationResult.SubjectAlternativeNameMismatch, "Unexpected IP");
        CheckSan(identity, s => s.AddEmailAddress("other@example.test"), IssuedCertificateValidationResult.SubjectAlternativeNameMismatch, "Unexpected email");
        CheckSan(identity, _ => { }, IssuedCertificateValidationResult.MissingClientAuthenticationEku, "Extra serverAuth prohibited", extraEku: true);
        Console.WriteLine($"Issued certificate DNS/SAN/EKU checks passed ({sanChecks}).");
        CheckOfflineChainPolicies(root, now);
    }

    private static void CheckOfflineChainPolicies(X509Certificate2 root, DateTimeOffset now)
    {
        using var issuedPolicyChain = new X509Chain();
        IssuedCertificateValidator.ConfigureOfflineChainPolicy(issuedPolicyChain.ChainPolicy, root, now.UtcDateTime);
        var issuedPolicy = issuedPolicyChain.ChainPolicy;
        var tlsPolicy = KerberosCesTransport.CreatePreliminaryTlsChainPolicy(root);
        if (!issuedPolicy.DisableCertificateDownloads || issuedPolicy.RevocationMode != X509RevocationMode.NoCheck ||
            !tlsPolicy.DisableCertificateDownloads || tlsPolicy.RevocationMode != X509RevocationMode.NoCheck)
            throw new InvalidOperationException("Every preliminary NoCheck chain must explicitly disable certificate downloads.");

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var intermediateRequest = new CertificateRequest("CN=Offline Test Intermediate", intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var intermediatePublic = intermediateRequest.Create(root, now.AddMinutes(-1), now.AddHours(1),
            RandomNumberGenerator.GetBytes(16));
        using var intermediate = intermediatePublic.CopyWithPrivateKey(intermediateKey);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=Offline AIA Leaf", leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var aia = new AsnWriter(AsnEncodingRules.DER);
        using (aia.PushSequence())
        using (aia.PushSequence())
        {
            aia.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2");
            aia.WriteCharacterString(UniversalTagNumber.IA5String,
                $"http://127.0.0.1:{port}/intermediate.cer", new Asn1Tag(TagClass.ContextSpecific, 6));
        }
        leafRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.1", aia.Encode(), false));
        using var leaf = leafRequest.Create(intermediate, now.AddMinutes(-1), now.AddMinutes(30),
            RandomNumberGenerator.GetBytes(16));
        using var chain = new X509Chain();
        IssuedCertificateValidator.ConfigureOfflineChainPolicy(chain.ChainPolicy, root, now.UtcDateTime);
        if (chain.Build(leaf)) throw new InvalidOperationException("A missing intermediate was unexpectedly accepted.");
        Thread.Sleep(100);
        if (listener.Pending()) throw new InvalidOperationException("Preliminary chain validation attempted an AIA download.");

        using var direct = leafRequest.Create(root, now.AddMinutes(-1), now.AddMinutes(30),
            RandomNumberGenerator.GetBytes(16));
        using var directChain = new X509Chain();
        IssuedCertificateValidator.ConfigureOfflineChainPolicy(directChain.ChainPolicy, root, now.UtcDateTime);
        if (!directChain.Build(direct)) throw new InvalidOperationException("Pinned-root offline chain validation regressed.");
        Console.WriteLine("Offline preliminary chain policies rejected AIA retrieval and retained pinned-root validation.");
    }
}
