using System.Security.Cryptography;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text;
using PkiProxy.Authentication;
using PkiProxy.Protocol.Cmc;
using PkiProxy.Signing;
using System.Globalization;

namespace PkiProxy.Domain;

internal enum DomainRenewalResult
{
    Authorized, InvalidRequest, InvalidDirectoryIdentity, OldCertificateRejected,
    MissingIssuanceBinding, InvalidIssuanceBinding, UnknownDevice, AssetMismatch, InvalidFacts,
    TransportCertificateMismatch
}

internal sealed record DomainRenewalAuthorization(DomainRenewalResult Result,
    AuthorizedDomainRenewal? Enrollment = null);

// Not accepted by the initial issuer. Owns the exact renewal request and fresh
// server-owned identity. Transport/group authorization must supply the AD snapshot.
internal sealed class AuthorizedDomainRenewal
{
    private readonly ValidatedRenewalCmcRequest request;
    private readonly ControlledCertificateIdentity identity;
    private readonly CmcTemplate template;
    private readonly byte[] rootDer;
    private readonly string crlPath;
    internal AuthorizedDomainRenewal(ValidatedRenewalCmcRequest request, ControlledCertificateIdentity identity,
        Guid objectId, string assetId, long factsVersion, CmcTemplate template, X509Certificate2 root, string crlPath)
    {
        this.request = request;
        this.identity = Copy(identity);
        DirectoryObjectId = objectId; AssetId = assetId; FactsVersion = factsVersion;
        this.template = template; rootDer = root.RawData; this.crlPath = crlPath;
    }
    internal Guid DirectoryObjectId { get; }
    internal string AssetId { get; }
    internal long FactsVersion { get; }
    internal string OldCertificateSha256 => Convert.ToHexString(SHA256.HashData(request.ExportRenewalCertificate()));
    internal CmcRequestBinding ExportBinding() => request.CreateBinding();
    internal ControlledCertificateIdentity ExportIdentity() => Copy(identity);
    // Use the same owned request/identity as construction. Re-read revocation
    // at release, including the old credential that authorized this renewal.
    internal bool ValidateIssuedCertificate(X509Certificate2 certificate, DateTimeOffset now)
    {
        if (certificate.HasPrivateKey) return false;
        try
        {
            using var root = X509CertificateLoader.LoadCertificate(rootDer);
            using var old = X509CertificateLoader.LoadCertificate(request.ExportRenewalCertificate());
            var revocation = OpenSslCertificateVerifier.Load(root, crlPath);
            return IssuedCertificateValidator.MatchesTemplate(certificate, template) &&
                IssuedCertificateValidator.Validate(certificate, request.ExportPkcs10(), identity,
                    new(root, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment), now).Result ==
                    IssuedCertificateValidationResult.Valid &&
                revocation.Verify(old, CertificatePurpose.Client) &&
                revocation.Verify(certificate, CertificatePurpose.Client);
        }
        catch (Exception exception) when (exception is AsnContentException or CryptographicException or
            IOException or UnauthorizedAccessException)
        { return false; }
    }
    internal CmcEnrollmentRequest Build(X509Certificate2 signer, DateTimeOffset now, RSA? signingKey = null)
    {
        using var root = X509CertificateLoader.LoadCertificate(rootDer);
        using var old = X509CertificateLoader.LoadCertificate(request.ExportRenewalCertificate());
        using var signerPublic = X509CertificateLoader.LoadCertificate(signer.RawData);
        var revocation = OpenSslCertificateVerifier.Load(root, crlPath);
        if (!revocation.Verify(old, CertificatePurpose.Client) || !revocation.Verify(signerPublic, CertificatePurpose.Signing))
            throw new CryptographicException("Renewal or signing certificate trust/revocation rejected before construction.");
        var binding = request.CreateBinding();
        var correlation = SigningIntentMetadata.Correlate(SigningOperation.DomainRenewal,
            binding.EnvelopeSha256, Encoding.ASCII.GetBytes(DirectoryObjectId.ToString("D")),
            Encoding.UTF8.GetBytes(AssetId), Encoding.ASCII.GetBytes(FactsVersion.ToString(CultureInfo.InvariantCulture)),
            Encoding.ASCII.GetBytes(OldCertificateSha256));
        try
        {
            return CmcEnrollmentRequestBuilder.BuildRenewal(request, binding, identity, template, signer, now, signingKey,
                new(SigningOperation.DomainRenewal, correlation));
        }
        finally { CryptographicOperations.ZeroMemory(correlation); }
    }
    private static ControlledCertificateIdentity Copy(ControlledCertificateIdentity value) => value with {
        SubjectAlternativeNameUris = value.SubjectAlternativeNameUris.ToArray(),
        SubjectAlternativeNameDnsNames = value.SubjectAlternativeNameDnsNames?.ToArray()
    };
}

internal sealed class NativeDomainRenewalAuthorizer(IDomainDeviceFactsSource factsSource,
    CertificateClaimPolicy claims, NativeCmcPolicy incomingPolicy, X509Certificate2 root,
    string crlPath, EnrollmentSubmissionJournal journal, CmcTemplate downstreamTemplate)
{
    internal ValueTask<DomainRenewalAuthorization> AuthorizeAsync(AuthenticatedDirectoryComputer computer,
        ReadOnlyMemory<byte> encoded, CancellationToken cancellationToken) =>
        AuthorizeCoreAsync(computer, encoded, null, cancellationToken);

    internal ValueTask<DomainRenewalAuthorization> AuthorizeAsync(CertificateDomainIdentity peer,
        ReadOnlyMemory<byte> encoded, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(peer);
        return AuthorizeCoreAsync(peer.Computer, encoded, peer, cancellationToken);
    }

    private async ValueTask<DomainRenewalAuthorization> AuthorizeCoreAsync(AuthenticatedDirectoryComputer computer,
        ReadOnlyMemory<byte> encoded, CertificateDomainIdentity? peer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(computer);
        cancellationToken.ThrowIfCancellationRequested();
        claims.Validate();
        if (!Guid.TryParse(computer.ObjectId, out var objectId) || objectId == Guid.Empty)
            return new(DomainRenewalResult.InvalidDirectoryIdentity);
        try
        {
            _ = CmcEnrollmentRequestBuilder.EncodeIdentity(new(computer.DistinguishedName,
                [new Uri(claims.BrokerProfileUrn)], [computer.DnsHostName]));
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        { return new(DomainRenewalResult.InvalidDirectoryIdentity); }

        ValidatedRenewalCmcRequest request;
        try { request = ValidatedRenewalCmcRequest.Validate(encoded.Span, incomingPolicy); }
        catch (CryptographicException) { return new(DomainRenewalResult.InvalidRequest); }
        using var old = X509CertificateLoader.LoadCertificate(request.ExportRenewalCertificate());
        // Domain Kerberos renewal has no TLS leaf binding. Certificate-authenticated
        // renewal must use this exact credential as its old CMC signer, even when
        // two separately valid credentials happen to identify the same asset.
        if (peer is not null && !string.Equals(peer.CertificateSha256,
            old.GetCertHashString(HashAlgorithmName.SHA256), StringComparison.OrdinalIgnoreCase))
            return new(DomainRenewalResult.TransportCertificateMismatch);
        try
        {
            // Fixed trusted source only; refresh for every attempt. A receipt or
            // embedded certificate never replaces chain, validity and CRL checks.
            if (!OpenSslCertificateVerifier.Load(root, crlPath).Verify(old, CertificatePurpose.Client))
                return new(DomainRenewalResult.OldCertificateRejected);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        { return new(DomainRenewalResult.OldCertificateRejected); }
        cancellationToken.ThrowIfCancellationRequested();
        RecordedDomainCertificate? binding;
        try { binding = journal.FindValidatedBinding(objectId, old.GetCertHashString(HashAlgorithmName.SHA256)); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or
            InvalidOperationException or KeyNotFoundException or FormatException)
        { return new(DomainRenewalResult.InvalidIssuanceBinding); }
        if (binding is null) return new(DomainRenewalResult.MissingIssuanceBinding);
        if (peer is not null && !string.Equals(peer.AssetId, binding.AssetId, StringComparison.Ordinal))
            return new(DomainRenewalResult.AssetMismatch);

        var facts = await factsSource.FindByDnsHostNameAsync(computer.DnsHostName, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (facts is null) return new(DomainRenewalResult.UnknownDevice);
        if (!string.Equals(facts.AssetId, binding.AssetId, StringComparison.Ordinal))
            return new(DomainRenewalResult.AssetMismatch);
        try
        {
            if (facts.SourceVersion <= 0) return new(DomainRenewalResult.InvalidFacts);
            var identity = ControlledCertificateIdentityMapper.Create(
                facts with { DirectoryDistinguishedName = computer.DistinguishedName }, claims)
                with { SubjectAlternativeNameDnsNames = new[] { computer.DnsHostName } };
            _ = CmcEnrollmentRequestBuilder.EncodeIdentity(identity);
            return new(DomainRenewalResult.Authorized,
                new(request, identity, objectId, facts.AssetId, facts.SourceVersion, downstreamTemplate, root, crlPath));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or CryptographicException)
        { return new(DomainRenewalResult.InvalidFacts); }
    }
}
