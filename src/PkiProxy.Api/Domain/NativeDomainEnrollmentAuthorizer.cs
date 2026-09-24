using System.Security.Cryptography;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Protocol.Cmc;
using PkiProxy.Signing;
using System.Text;
using System.Globalization;

namespace PkiProxy.Domain;

// Only the Kerberos/AD adapter may supply this snapshot, after resolving the
// authenticated principal to an enabled, authorized computer object. It is not
// a request DTO, and no fields may be populated from SOAP/CSR/client diagnostics.
internal sealed record AuthenticatedDirectoryComputer(
    string ObjectId, string DistinguishedName, string DnsHostName);

internal interface IDomainDeviceFactsSource
{
    // The lookup key is AD's authenticated dNSHostName, never a claimed hostname.
    // Implementations must reject ambiguous/mismatched SOT results, not pick one.
    ValueTask<AuthoritativeDeviceFacts?> FindByDnsHostNameAsync(
        string dnsHostName, CancellationToken cancellationToken);
}

internal enum NativeDomainAuthorizationResult
{
    Authorized,
    InvalidCmc,
    InvalidDirectoryIdentity,
    UnknownDevice,
    InvalidAuthoritativeFacts
}

internal sealed record NativeDomainAuthorization(
    NativeDomainAuthorizationResult Result, AuthorizedDomainCmcEnrollment? Enrollment = null);

// Owns the validated request and identity selected together. Subsequent code
// cannot substitute a CSR, a subject/SAN or a downstream template at signing.
// This is not a durable/single-use issuance record or a transport authenticator.
internal sealed class AuthorizedDomainCmcEnrollment
{
    private readonly ValidatedCmcRequest request;
    private readonly ControlledCertificateIdentity identity;
    private readonly CmcTemplate template;

    internal AuthorizedDomainCmcEnrollment(ValidatedCmcRequest request,
        ControlledCertificateIdentity identity, CmcTemplate template,
        string directoryObjectId, string assetId, long factsSourceVersion)
    {
        this.request = request;
        this.identity = identity with
        {
            SubjectAlternativeNameUris = identity.SubjectAlternativeNameUris.ToArray(),
            SubjectAlternativeNameDnsNames = identity.SubjectAlternativeNameDnsNames?.ToArray()
        };
        this.template = template;
        DirectoryObjectId = directoryObjectId;
        AssetId = assetId;
        FactsSourceVersion = factsSourceVersion;
    }

    public string DirectoryObjectId { get; }
    public string AssetId { get; }
    public long FactsSourceVersion { get; }
    public bool UsedLegacySha1 => request.UsedLegacySha1;
    public CmcRequestBinding ExportBinding() => request.CreateBinding();

    // Validate against the same owned identity/request used for signing. Callers
    // cannot replace the expected subject, SANs, key or template on release.
    // Revocation must be a fresh snapshot; this method is not submission journaling.
    public bool ValidateIssuedCertificate(X509Certificate2 certificate,
        X509Certificate2 trustedRoot, OpenSslCertificateVerifier revocation, DateTimeOffset now)
    {
        if (certificate.HasPrivateKey) return false;
        try
        {
            if (!IssuedCertificateValidator.MatchesTemplate(certificate, template)) return false;
            return IssuedCertificateValidator.Validate(certificate, request.ExportPkcs10(), identity,
                new(trustedRoot, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment), now).Result ==
                IssuedCertificateValidationResult.Valid && revocation.Verify(certificate, CertificatePurpose.Client);
        }
        catch (Exception exception) when (exception is AsnContentException or CryptographicException)
        { return false; }
    }

    // Caller still has to validate signer trust/revocation and authorization to
    // use that credential; Build performs only the existing signer profile checks.
    public CmcEnrollmentRequest Build(X509Certificate2 signer, DateTimeOffset now, RSA? signingKey = null)
    {
        var binding = request.CreateBinding();
        var correlation = SigningIntentMetadata.Correlate(SigningOperation.DomainEnrollment,
            binding.EnvelopeSha256, Encoding.UTF8.GetBytes(DirectoryObjectId), Encoding.UTF8.GetBytes(AssetId),
            Encoding.ASCII.GetBytes(FactsSourceVersion.ToString(CultureInfo.InvariantCulture)));
        try
        {
            return CmcEnrollmentRequestBuilder.Build(request, binding, identity, template, signer, now, signingKey,
                new(SigningOperation.DomainEnrollment, correlation));
        }
        finally { CryptographicOperations.ZeroMemory(correlation); }
    }
}

internal sealed class NativeDomainEnrollmentAuthorizer(
    IDomainDeviceFactsSource deviceFactsSource,
    CertificateClaimPolicy claimPolicy,
    NativeCmcPolicy incomingPolicy,
    CmcTemplate downstreamTemplate)
{
    public async ValueTask<NativeDomainAuthorization> AuthorizeAsync(
        AuthenticatedDirectoryComputer computer,
        ReadOnlyMemory<byte> encodedCmc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(computer);
        cancellationToken.ThrowIfCancellationRequested();
        claimPolicy.Validate(); // Configuration errors are not client failures.
        ValidatedCmcRequest request;
        try { request = ValidatedCmcRequest.Validate(encodedCmc.Span, incomingPolicy); }
        catch (CryptographicException)
        { return new(NativeDomainAuthorizationResult.InvalidCmc); }

        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(computer.ObjectId);
            // Validate AD-owned fields before consulting SOT. The same encoder
            // checks the final identity; no alternate DN/DNS normalization path.
            _ = CmcEnrollmentRequestBuilder.EncodeIdentity(new(
                computer.DistinguishedName, [new Uri(claimPolicy.BrokerProfileUrn)], [computer.DnsHostName]));
        }
        catch (Exception e) when (e is ArgumentException or CryptographicException)
        { return new(NativeDomainAuthorizationResult.InvalidDirectoryIdentity); }

        var facts = await deviceFactsSource.FindByDnsHostNameAsync(computer.DnsHostName, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (facts is null) return new(NativeDomainAuthorizationResult.UnknownDevice);
        try
        {
            // SOT controls device facts, not the domain computer's DN or DNS SAN.
            var identity = ControlledCertificateIdentityMapper.Create(
                facts with { DirectoryDistinguishedName = computer.DistinguishedName }, claimPolicy)
                with { SubjectAlternativeNameDnsNames = new[] { computer.DnsHostName } };
            _ = CmcEnrollmentRequestBuilder.EncodeIdentity(identity);
            return new(NativeDomainAuthorizationResult.Authorized,
                new(request, identity, downstreamTemplate, computer.ObjectId, facts.AssetId, facts.SourceVersion));
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or CryptographicException)
        { return new(NativeDomainAuthorizationResult.InvalidAuthoritativeFacts); }
    }
}
