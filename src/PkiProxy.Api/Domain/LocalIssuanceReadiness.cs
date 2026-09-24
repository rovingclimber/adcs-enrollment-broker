using System.Security.Cryptography.X509Certificates;
using PkiProxy.Protocol.Cmc;
using System.Security.Cryptography;
using PkiProxy.Signing;

namespace PkiProxy.Domain;

// Read-only local prerequisites, not a synthetic enrollment or remote CES test.
internal static class LocalIssuanceReadiness
{
    internal static async Task<bool> CheckAsync(X509Certificate2 root, X509Certificate2 signer,
        string signerOid, SignerRotationPolicy rotation, string crlPath, JsonFileDeviceFactsSource facts,
        CancellationToken cancellationToken, RSA? signingKey = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        rotation.Validate(signer, now);
        CmcEnrollmentRequestBuilder.ValidateSigner(signer, signerOid, now, rotation.MinimumRemainingValidity, signingKey);
        // For isolated credentials this crosses the authenticated socket and
        // verifies that the process holding the private key matches this exact
        // pinned public generation. Direct credentials exercise the same proof.
        using (var certificateKey = signingKey is null ? signer.GetRSAPrivateKey() : null)
        {
            var key = signingKey ?? certificateKey ?? throw new CryptographicException("Signer key unavailable.");
            var challenge = SHA256.HashData(SigningIntentPolicy.SelfTestPayload);
            byte[]? signature = null;
            using var intent = (key as UnixSocketRsa)?.BeginSelfTest();
            try
            {
                signature = key.SignHash(challenge, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using var publicKey = signer.GetRSAPublicKey();
                if (publicKey is null || !publicKey.VerifyHash(challenge, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                    return false;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(challenge);
                if (signature is not null) CryptographicOperations.ZeroMemory(signature);
            }
        }
        using var publicSigner = X509CertificateLoader.LoadCertificate(signer.RawData);
        if (!OpenSslCertificateVerifier.Load(root, crlPath).Verify(publicSigner, CertificatePurpose.Signing)) return false;
        await facts.ValidateAsync(cancellationToken);
        return true;
    }
}
