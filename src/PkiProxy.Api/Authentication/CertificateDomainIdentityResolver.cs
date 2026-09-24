using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Directory;
using PkiProxy.Domain;

namespace PkiProxy.Authentication;

internal sealed record CertificateDomainIdentity(AuthenticatedDirectoryComputer Computer,
    string AssetId, string CertificateSha256);

// Set only by the certificate transport after TLS possession and resolution.
internal sealed record AuthorizedCertificateComputerFeature(CertificateDomainIdentity Identity);

// Input must be the actual TLS peer certificate after proof of possession. This
// class supplies application trust/identity checks, not a TLS authentication claim.
// No cached grants, forwarded certificate headers, SAN names or caller GUIDs.
internal sealed class CertificateDomainIdentityResolver(X509Certificate2 root, string crlPath,
    EnrollmentSubmissionJournal journal, ActiveDirectoryComputerResolver directory)
{
    internal CertificateDomainIdentity? Resolve(X509Certificate2 peer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(peer);
        cancellationToken.ThrowIfCancellationRequested();
        if (peer.HasPrivateKey || peer.RawDataMemory.Length > 65_536) return null;
        var eku = peer.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        if (eku.Length != 1 || !eku[0].EnhancedKeyUsages.Cast<Oid>().Any(x => x.Value == "1.3.6.1.5.5.7.3.2"))
            return null;
        if (!OpenSslCertificateVerifier.Load(root, crlPath).Verify(peer, CertificatePurpose.Client)) return null;
        cancellationToken.ThrowIfCancellationRequested();
        var hash = peer.GetCertHashString(HashAlgorithmName.SHA256);
        var binding = journal.FindValidatedBinding(hash);
        if (binding is null) return null;
        var computer = directory.Resolve(binding.DirectoryObjectId, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return computer is null ? null : new(computer, binding.AssetId, hash);
    }
}
