using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using PkiProxy.Protocol;
using PkiProxy.Protocol.Cmc;
using PkiProxy.Protocol.Wstep;

namespace PkiProxy.Domain;

internal sealed record ValidatedEnrollmentResponse(byte[] CertificateDer, byte[] FullPkiResponse, string RequestId);

internal delegate Task<CesTransportResponse> CesSender(Uri endpoint, X509Certificate2 root,
    OpenSslCertificateVerifier revocation, byte[] soap, string action, CancellationToken cancellationToken);

// Staged orchestration. Host wiring must require the Kerberos/AD/facts authorizer
// before supplying an enrollment and own the lifetime of signer/root credentials.
internal sealed class NativeCesEnrollmentIssuer(Uri endpoint, X509Certificate2 root,
    X509Certificate2 signer, string crlPath, EnrollmentSubmissionJournal journal, CesSender? sender = null,
    RSA? signingKey = null)
{
    internal Task<ValidatedEnrollmentResponse> IssueAsync(AuthorizedDomainCmcEnrollment enrollment,
        CancellationToken cancellationToken) => IssueCoreAsync(
            now => enrollment.Build(signer, now, signingKey), now =>
            {
                var claim = journal.TryBegin(enrollment, now);
                if (claim is null) return null;
                return (response, leaf, completedAt) => claim.RecordValidatedResponse(response.RequestId,
                    leaf.GetCertHashString(HashAlgorithmName.SHA256), completedAt);
            },
            (leaf, revocation, now) => enrollment.ValidateIssuedCertificate(leaf, root, revocation, now), cancellationToken);

    internal Task<ValidatedEnrollmentResponse> IssueAsync(AuthorizedDomainRenewal enrollment,
        CancellationToken cancellationToken) => IssueCoreAsync(
            now => enrollment.Build(signer, now, signingKey), now =>
            {
                var claim = journal.TryBegin(enrollment, now);
                if (claim is null) return null;
                return (response, leaf, completedAt) => claim.RecordValidatedResponse(response.RequestId,
                    leaf.GetCertHashString(HashAlgorithmName.SHA256), completedAt);
            },
            (leaf, _, now) => enrollment.ValidateIssuedCertificate(leaf, now), cancellationToken);

    internal Task<ValidatedEnrollmentResponse> IssueAsync(AuthorizedBootstrapEnrollment enrollment,
        Func<DateTimeOffset, FileBootstrapEnrollmentTransactionStore.SubmissionClaim?> beginSubmission,
        CancellationToken cancellationToken) => IssueCoreAsync(
            now => enrollment.Build(signer, now, signingKey), now =>
            {
                var claim = beginSubmission(now);
                if (claim is null) return null;
                return (response, _, completedAt) =>
                {
                    if (!int.TryParse(response.RequestId, NumberStyles.None, CultureInfo.InvariantCulture,
                            out var requestId) || requestId <= 0)
                        throw new InvalidDataException("Positive issuer request identifier required.");
                    claim.RecordIssuedResponse(requestId, response.CertificateDer,
                        response.FullPkiResponse, completedAt);
                };
            },
            (leaf, revocation, now) => enrollment.ValidateIssuedCertificate(leaf, root, revocation, now),
            cancellationToken);

    private async Task<ValidatedEnrollmentResponse> IssueCoreAsync(
        Func<DateTimeOffset, CmcEnrollmentRequest> build,
        Func<DateTimeOffset, Action<ValidatedEnrollmentResponse, X509Certificate2, DateTimeOffset>?> begin,
        Func<X509Certificate2, OpenSslCertificateVerifier, DateTimeOffset, bool> validate,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var revocation = OpenSslCertificateVerifier.Load(root, crlPath);
        using var signerPublic = X509CertificateLoader.LoadCertificate(signer.RawData);
        if (!revocation.Verify(signerPublic, CertificatePurpose.Signing))
            throw new CryptographicException("Signing credential trust/revocation rejected.");
        // Build enforces the configured template's exact signer EKU and key usage.
        var built = build(DateTimeOffset.UtcNow);
        var messageId = "urn:uuid:" + Guid.NewGuid().ToString();
        var soap = CreateRequest(endpoint, messageId, built.EncodedCms);
        cancellationToken.ThrowIfCancellationRequested();
        var complete = begin(DateTimeOffset.UtcNow)
            ?? throw new InvalidOperationException("Enrollment already submitted or requires reconciliation.");
        // Any exception from here leaves the durable claim in place. Never retry
        // SendAsync: receipt of an error is not proof that the CA did not issue.
        var transport = await (sender ?? KerberosCesTransport.SendAsync)(endpoint, root, revocation, soap,
            WstepRequestContract.EnrollmentAction, cancellationToken);
        var parsed = CesResponseReader.ReadIssued(transport, messageId);
        using var leaf = X509CertificateLoader.LoadCertificate(parsed.CertificateDer);
        // Refresh again after transport; do not release against a now-stale CRL.
        var releaseRevocation = OpenSslCertificateVerifier.Load(root, crlPath);
        if (!validate(leaf, releaseRevocation, DateTimeOffset.UtcNow) ||
            !CmcFullResponseValidator.Validate(parsed.FullPkiResponse, leaf, root))
            throw new CryptographicException("Issued response does not match authorized enrollment.");
        var requestId = parsed.RequestId.ToString(CultureInfo.InvariantCulture);
        var result = new ValidatedEnrollmentResponse(parsed.CertificateDer, parsed.FullPkiResponse, requestId);
        complete(result, leaf, DateTimeOffset.UtcNow);
        return result;
    }

    internal static byte[] CreateRequest(Uri endpoint, string messageId, byte[] cmc)
    {
        XNamespace soap = "http://www.w3.org/2003/05/soap-envelope";
        XNamespace address = "http://www.w3.org/2005/08/addressing";
        XNamespace trust = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
        XNamespace security = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        const string enrollment = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
        var document = new XDocument(new XElement(soap + "Envelope",
            new XElement(soap + "Header",
                new XElement(address + "Action", new XAttribute(soap + "mustUnderstand", "1"), WstepRequestContract.EnrollmentAction),
                new XElement(address + "MessageID", messageId),
                new XElement(address + "ReplyTo", new XElement(address + "Address", address.NamespaceName + "/anonymous")),
                new XElement(address + "To", new XAttribute(soap + "mustUnderstand", "1"), endpoint.AbsoluteUri)),
            new XElement(soap + "Body", new XElement(trust + "RequestSecurityToken",
                new XElement(trust + "TokenType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"),
                new XElement(trust + "RequestType", trust.NamespaceName + "/Issue"),
                new XElement(security + "BinarySecurityToken", new XAttribute("ValueType", enrollment + "#PKCS10"),
                    new XAttribute("EncodingType", security.NamespaceName + "#base64binary"), Convert.ToBase64String(cmc))))));
        return Encoding.UTF8.GetBytes(document.ToString(SaveOptions.DisableFormatting));
    }
}
