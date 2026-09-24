using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Protocol.Cmc;
using PkiProxy.Signing;
using System.Text;

namespace PkiProxy.Domain;

internal enum BootstrapIssuanceResult
{
    PendingApproval,
    Issued,
    Uncertain,
    Rejected
}

internal sealed record BootstrapIssuanceOutcome(
    BootstrapIssuanceResult Result,
    BootstrapIssuedResponse? Response = null);

internal delegate Task<ValidatedEnrollmentResponse> BootstrapIssuer(
    AuthorizedBootstrapEnrollment enrollment,
    Func<DateTimeOffset, FileBootstrapEnrollmentTransactionStore.SubmissionClaim?> beginSubmission,
    CancellationToken cancellationToken);

// An exact retained PKCS#10 request and one server-selected identity travel as
// one object from authorization through signing and release validation.
internal sealed class AuthorizedBootstrapEnrollment
{
    private readonly byte[] csr;
    private readonly CsrBinding binding;
    private readonly ControlledCertificateIdentity identity;
    private readonly CmcTemplate template;

    internal AuthorizedBootstrapEnrollment(ReadOnlySpan<byte> csr, CsrBinding binding,
        ControlledCertificateIdentity identity, CmcTemplate template,
        string transactionId, string assetId, long factsSourceVersion)
    {
        this.csr = csr.ToArray();
        this.binding = binding.Snapshot();
        this.identity = identity with
        {
            SubjectAlternativeNameUris = identity.SubjectAlternativeNameUris.ToArray(),
            SubjectAlternativeNameDnsNames = identity.SubjectAlternativeNameDnsNames?.ToArray()
        };
        this.template = template;
        TransactionId = transactionId;
        AssetId = assetId;
        FactsSourceVersion = factsSourceVersion;
    }

    internal string TransactionId { get; }
    internal string AssetId { get; }
    internal long FactsSourceVersion { get; }
    internal CsrBinding ExportBinding() => binding.Snapshot();

    internal CmcEnrollmentRequest Build(X509Certificate2 signer, DateTimeOffset now, RSA? signingKey = null)
    {
        var correlation = SigningIntentMetadata.Correlate(SigningOperation.BootstrapEnrollment,
            Encoding.ASCII.GetBytes(TransactionId), binding.CsrSha256, Encoding.UTF8.GetBytes(AssetId),
            Encoding.ASCII.GetBytes(FactsSourceVersion.ToString(CultureInfo.InvariantCulture)));
        try
        {
            return CmcEnrollmentRequestBuilder.Build(csr, binding, identity, template, signer, now, signingKey,
                new(SigningOperation.BootstrapEnrollment, correlation));
        }
        finally { CryptographicOperations.ZeroMemory(correlation); }
    }

    internal bool ValidateIssuedCertificate(X509Certificate2 certificate, X509Certificate2 trustedRoot,
        OpenSslCertificateVerifier revocation, DateTimeOffset now)
    {
        if (certificate.HasPrivateKey) return false;
        try
        {
            return IssuedCertificateValidator.MatchesTemplate(certificate, template) &&
                IssuedCertificateValidator.Validate(certificate, csr, identity,
                    new(trustedRoot, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment), now).Result ==
                    IssuedCertificateValidationResult.Valid &&
                revocation.Verify(certificate, CertificatePurpose.Client);
        }
        catch (Exception error) when (error is AsnContentException or CryptographicException)
        { return false; }
    }
}

internal sealed class BootstrapEnrollmentIssuanceService(
    FileBootstrapEnrollmentTransactionStore transactions,
    IAuthoritativeDeviceFactsSource factsSource,
    CertificateClaimPolicy claimPolicy,
    CmcTemplate template,
    BootstrapIssuer issuer)
{
    internal async Task<BootstrapIssuanceOutcome> QueryAsync(
        string transactionId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var preparation = transactions.PrepareSubmission(transactionId, now);
        if (preparation.State == BootstrapTransactionState.Issued && preparation.IssuedResponse is not null)
            return new(BootstrapIssuanceResult.Issued, preparation.IssuedResponse);
        if (preparation.State == BootstrapTransactionState.RetainedUnbound)
            return new(BootstrapIssuanceResult.PendingApproval);
        if (preparation.State is BootstrapTransactionState.SubmissionClaimed or BootstrapTransactionState.Pending)
            return new(BootstrapIssuanceResult.Uncertain);
        if (preparation.State != BootstrapTransactionState.AssetBound || preparation.AssetId is null ||
            preparation.Binding is null || preparation.CsrDer is null)
            return new(BootstrapIssuanceResult.Rejected);

        var facts = await factsSource.FindByAssetIdAsync(preparation.AssetId, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (facts is null || !string.Equals(facts.AssetId, preparation.AssetId, StringComparison.Ordinal) ||
            facts.AuthoritativeDnsHostName is not { } dnsName)
            return new(BootstrapIssuanceResult.Rejected);

        ControlledCertificateIdentity identity;
        try
        {
            // The validated facts hostname is the explicit non-AD naming
            // contract: exact CN and exact DNS SAN. Client subject/SAN values
            // from the retained CSR are never copied.
            var subject = new X500DistinguishedName("CN=" + dnsName).Name;
            identity = ControlledCertificateIdentityMapper.Create(
                facts with { DirectoryDistinguishedName = subject }, claimPolicy) with
            {
                SubjectAlternativeNameDnsNames = [dnsName]
            };
            _ = CmcEnrollmentRequestBuilder.EncodeIdentity(identity);
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or CryptographicException)
        { return new(BootstrapIssuanceResult.Rejected); }

        var enrollment = new AuthorizedBootstrapEnrollment(preparation.CsrDer, preparation.Binding,
            identity, template, transactionId, preparation.AssetId, facts.SourceVersion);
        try
        {
            var issued = await issuer(enrollment, claimTime =>
            {
                var claimed = transactions.TryClaimSubmission(transactionId, enrollment.ExportBinding(),
                    enrollment.AssetId, claimTime);
                return claimed.Result == BootstrapTransactionResult.Claimed ? claimed.Claim : null;
            }, cancellationToken);
            return new(BootstrapIssuanceResult.Issued,
                new(issued.CertificateDer.ToArray(), issued.FullPkiResponse.ToArray(), issued.RequestId));
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or
            CryptographicException or InvalidOperationException or ArgumentException or OperationCanceledException or
            HttpRequestException)
        {
            // A durable claim means the CA outcome may be unknown. Re-reading
            // can replay an already committed response, but must never submit.
            var after = transactions.PrepareSubmission(transactionId, DateTimeOffset.UtcNow);
            if (after.State == BootstrapTransactionState.Issued && after.IssuedResponse is not null)
                return new(BootstrapIssuanceResult.Issued, after.IssuedResponse);
            return new(after.State is BootstrapTransactionState.SubmissionClaimed or BootstrapTransactionState.Pending
                ? BootstrapIssuanceResult.Uncertain : BootstrapIssuanceResult.Rejected);
        }
    }
}
