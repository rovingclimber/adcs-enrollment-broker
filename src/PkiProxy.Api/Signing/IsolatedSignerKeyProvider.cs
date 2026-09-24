using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Signing;

internal interface IIsolatedSignerKeyProvider : IDisposable
{
    X509Certificate2 Certificate { get; }
    ReadOnlyMemory<byte> SubjectPublicKeyInfo { get; }
    byte[] SignSha256Pkcs1(ReadOnlySpan<byte> hash);
}

internal static class IsolatedSignerKeyProvider
{
    private static readonly byte[] ReadinessHash =
        SHA256.HashData("pkiproxy-isolated-signer-provider-readiness-v1"u8);

    internal static IIsolatedSignerKeyProvider Load(IConfigurationSection section)
    {
        var provider = section["Provider"];
        if (string.IsNullOrWhiteSpace(provider))
            throw new InvalidOperationException("Explicit isolated signer Provider is required.");
        if (string.Equals(provider, "pem-file", StringComparison.Ordinal))
        {
            RejectPresent(section, "ModulePath", "PinFile", "TokenLabel", "TokenSerial", "KeyId", "MaximumSessions");
            var certificatePath = RequiredAbsolute(section, "CertificateFile");
            var privateKeyPath = RequiredAbsolute(section, "PrivateKeyFile");
            return new PemFileIsolatedSignerKeyProvider(certificatePath, privateKeyPath);
        }

        if (string.Equals(provider, "pkcs11", StringComparison.Ordinal))
        {
            RejectPresent(section, "CertificateFile", "PrivateKeyFile");
            return Pkcs11IsolatedSignerKeyProvider.Load(section);
        }

        throw new InvalidOperationException($"Unsupported isolated signer provider '{provider}'.");
    }

    private static void RejectPresent(IConfigurationSection section, params string[] keys)
    {
        if (keys.Any(key => section[key] is not null))
            throw new InvalidOperationException("Conflicting isolated signer provider settings.");
    }

    internal static void VerifyReadiness(IIsolatedSignerKeyProvider provider)
    {
        var signature = provider.SignSha256Pkcs1(ReadinessHash);
        try
        {
            using var publicKey = provider.Certificate.GetRSAPublicKey() ??
                throw new CryptographicException("RSA signer certificate required.");
            if (!publicKey.VerifyHash(ReadinessHash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                throw new CryptographicException("Isolated signer provider readiness signature rejected.");
            if (!provider.SubjectPublicKeyInfo.Span.SequenceEqual(publicKey.ExportSubjectPublicKeyInfo()))
                throw new CryptographicException("Isolated signer provider public key does not match its certificate.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    internal static string RequiredAbsolute(IConfigurationSection section, string key)
    {
        var value = section[key];
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException($"Missing isolated signer setting {key}.");
        if (!Path.IsPathFullyQualified(value))
            throw new InvalidOperationException("Absolute isolated signer paths required.");
        return value;
    }
}

internal sealed class PemFileIsolatedSignerKeyProvider : IIsolatedSignerKeyProvider
{
    private readonly X509Certificate2 certificate;
    private readonly RSA privateKey;
    private readonly byte[] subjectPublicKeyInfo;

    internal PemFileIsolatedSignerKeyProvider(string certificatePath, string privateKeyPath)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The isolated signer key provider requires Linux.");
        LinuxSecretFile.Validate(privateKeyPath, "Owner-only isolated signer key required.");

        using var certificateWithKey = X509Certificate2.CreateFromPemFile(certificatePath, privateKeyPath);
        privateKey = certificateWithKey.GetRSAPrivateKey() ??
            throw new CryptographicException("Signer key unavailable.");
        certificate = X509CertificateLoader.LoadCertificate(certificateWithKey.RawData);
        using var publicKey = certificate.GetRSAPublicKey() ??
            throw new CryptographicException("RSA signer certificate required.");
        subjectPublicKeyInfo = publicKey.ExportSubjectPublicKeyInfo();
    }

    public X509Certificate2 Certificate => certificate;
    public ReadOnlyMemory<byte> SubjectPublicKeyInfo => subjectPublicKeyInfo;

    public byte[] SignSha256Pkcs1(ReadOnlySpan<byte> hash)
    {
        if (hash.Length != 32)
            throw new CryptographicException("The signer accepts only SHA-256 hashes.");
        return privateKey.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public void Dispose()
    {
        privateKey.Dispose();
        certificate.Dispose();
        CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
    }
}
