using System.Formats.Asn1;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using PkiProxy.Directory;
using PkiProxy.Authentication;
using PkiProxy.Protocol;
using PkiProxy.Protocol.Cmc;
using PkiProxy.Protocol.Wstep;
using PkiProxy.Protocol.Xcep;
using PkiProxy.Signing;

namespace PkiProxy.Domain;

internal sealed class NativeEnrollmentService : IDisposable
{
    private readonly X509Certificate2 root;
    private readonly X509Certificate2 signer;
    private readonly RSA? signingKey;
    private readonly NativeDomainEnrollmentAuthorizer authorizer;
    private readonly NativeDomainRenewalAuthorizer? renewalAuthorizer;
    private readonly NativeCesEnrollmentIssuer issuer;
    private readonly CertificateClaimPolicy claims;
    private readonly CmcTemplate downstreamTemplate;
    private readonly Func<CancellationToken, Task<bool>> readinessProbe;
    private readonly SemaphoreSlim slots = new(2, 2);

    internal NativeEnrollmentService(X509Certificate2 root, X509Certificate2 signer, RSA? signingKey,
        NativeDomainEnrollmentAuthorizer authorizer, NativeCesEnrollmentIssuer issuer,
        Func<CancellationToken, Task<bool>> readinessProbe, CertificateClaimPolicy claims,
        CmcTemplate downstreamTemplate, NativeDomainRenewalAuthorizer? renewalAuthorizer = null)
    { this.root = root; this.signer = signer; this.signingKey = signingKey; this.authorizer = authorizer; this.issuer = issuer; this.readinessProbe = readinessProbe;
        this.claims = claims; this.downstreamTemplate = downstreamTemplate; this.renewalAuthorizer = renewalAuthorizer; }

    internal Task<bool> CheckLocalReadinessAsync(CancellationToken cancellationToken) => readinessProbe(cancellationToken);

    internal BootstrapEnrollmentIssuanceService CreateBootstrapIssuance(
        FileBootstrapEnrollmentTransactionStore transactions,
        IAuthoritativeDeviceFactsSource facts) =>
        new(transactions, facts, claims, downstreamTemplate, async (enrollment, begin, cancellationToken) =>
        {
            if (!await slots.WaitAsync(0, cancellationToken))
                throw new InvalidOperationException("Enrollment concurrency limit reached.");
            try { return await issuer.IssueAsync(enrollment, begin, cancellationToken); }
            finally { slots.Release(); }
        });

    internal static NativeEnrollmentService? Load(IConfiguration configuration, BrokerEnrollmentPolicy? policy,
        IDomainDeviceFactsSource? facts, bool authenticatedDirectoryEnabled)
    {
        var section = configuration.GetSection("Broker:Issuance");
        if (!section.GetChildren().Any()) return null;
        string[] allowed = ["Enabled", "RenewalEnabled", "CesEndpoint", "SignerCertificateFile", "SignerPrivateKeyFile",
            "SignerSocketPath", "SignerAuthenticationTokenFile",
            "CrlFile", "JournalDirectory", "SignerApplicationPolicyOid", "SignerCertificateSha256",
            "SignerMinimumRemainingValidityMinutes", "BrokerProfileUrn", "FactUrnPrefix"];
        if (section.GetChildren().Any(c => !allowed.Contains(c.Key, StringComparer.OrdinalIgnoreCase)) ||
            !bool.TryParse(section["Enabled"], out var enabled)) throw new InvalidOperationException("Invalid issuance configuration.");
        var renewalEnabled = false;
        if (section["RenewalEnabled"] is { } renewalValue && !bool.TryParse(renewalValue, out renewalEnabled))
            throw new InvalidOperationException("Explicit boolean renewal opt-in required.");
        if (renewalEnabled && !enabled) throw new InvalidOperationException("Renewal requires issuance enabled.");
        if (!enabled) return null;
        if (!OperatingSystem.IsLinux() || !authenticatedDirectoryEnabled || policy is null || facts is null)
            throw new InvalidOperationException("Issuance requires Linux Kerberos, directory authorization, policy and authoritative facts.");
        string Required(string key) => !string.IsNullOrWhiteSpace(section[key]) ? section[key]! :
            throw new InvalidOperationException("Incomplete issuance configuration.");
        string PathValue(string key)
        {
            var value = Required(key);
            if (!Path.IsPathFullyQualified(value)) throw new InvalidOperationException("Absolute issuance paths required.");
            return value;
        }
        var endpoint = new Uri(Required("CesEndpoint"), UriKind.Absolute);
        if (endpoint.Scheme != "https" || endpoint.Port != 443 || Uri.CheckHostName(endpoint.Host) != UriHostNameType.Dns ||
            !endpoint.Host.Contains('.') || endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0)
            throw new InvalidOperationException("Explicit canonical HTTPS CES endpoint required.");
        var claims = new CertificateClaimPolicy(Required("BrokerProfileUrn"), Required("FactUrnPrefix")); claims.Validate();
        var signerOid = Required("SignerApplicationPolicyOid");
        var oidWriter = new AsnWriter(AsnEncodingRules.DER); oidWriter.WriteObjectIdentifier(signerOid);
        if (signerOid == "1.3.6.1.4.1.311.20.2.1" || signerOid == "2.5.29.37.0")
            throw new InvalidOperationException("Restricted custom signing policy required, not generic enrollment-agent authority.");
        var rotation = SignerRotationPolicy.Load(section);
        var isolated = !string.IsNullOrWhiteSpace(section["SignerSocketPath"]) || !string.IsNullOrWhiteSpace(section["SignerAuthenticationTokenFile"]);
        if (isolated && !string.IsNullOrWhiteSpace(section["SignerPrivateKeyFile"]))
            throw new InvalidOperationException("Broker listeners cannot combine isolated signing with a mounted private key.");
        var crlPath = PathValue("CrlFile");
        var journal = new EnrollmentSubmissionJournal(PathValue("JournalDirectory"));
        var root = X509CertificateLoader.LoadCertificate(policy.IssuingCaCertificateDer);
        X509Certificate2? signer = null;
        RSA? signingKey = null;
        try
        {
            var certificatePath = PathValue("SignerCertificateFile");
            if (isolated)
            {
                var publicCertificate = X509CertificateLoader.LoadCertificateFromFile(certificatePath);
                try
                {
                    signingKey = new UnixSocketRsa(PathValue("SignerSocketPath"),
                        SignerProtocol.LoadToken(PathValue("SignerAuthenticationTokenFile")), publicCertificate);
                    signer = X509CertificateLoader.LoadCertificate(publicCertificate.RawData);
                }
                finally { publicCertificate.Dispose(); }
            }
            else
            {
                var keyPath = PathValue("SignerPrivateKeyFile");
                if (new FileInfo(keyPath).LinkTarget is not null || File.GetUnixFileMode(keyPath) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
                    throw new InvalidOperationException("Owner-only signer key required.");
                signer = X509Certificate2.CreateFromPemFile(certificatePath, keyPath);
            }
            rotation.Validate(signer, DateTimeOffset.UtcNow);
            using var publicSigner = X509CertificateLoader.LoadCertificate(signer.RawData);
            if (!OpenSslCertificateVerifier.Load(root, crlPath).Verify(publicSigner, CertificatePurpose.Signing))
                throw new CryptographicException("Signer trust/currentness/revocation rejected at startup.");
            var major = checked((int)policy.MajorRevision); var minor = checked((int)(policy.MinorRevision ?? 0));
            var incoming = new NativeCmcPolicy(policy.TemplateOid, major, minor, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
            var downstream = new CmcTemplate(policy.TemplateOid, major, minor, signerOid,
                rotation.MinimumRemainingValidity, claims.BrokerProfileUrn);
            return new(root, signer, signingKey, new(facts, claims, incoming, downstream),
                new(endpoint, root, signer, crlPath, journal, signingKey: signingKey),
                token => facts is JsonFileDeviceFactsSource json
                    ? LocalIssuanceReadiness.CheckAsync(root, signer, signerOid, rotation, crlPath, json, token, signingKey)
                    : Task.FromResult(false), claims, downstream,
                renewalEnabled ? new(facts, claims, incoming, root, crlPath, journal, downstream) : null);
        }
        catch { signingKey?.Dispose(); signer?.Dispose(); root.Dispose(); throw; }
    }

    internal async Task<IResult> HandleAsync(HttpContext context, SoapReadResult envelope, CancellationToken cancellationToken)
    {
        var computer = context.Features.Get<AuthorizedComputerFeature>()?.Computer;
        var certificatePeer = context.Features.Get<AuthorizedCertificateComputerFeature>()?.Identity;
        if ((computer is null && certificatePeer is null) || (computer is not null && certificatePeer is not null))
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        if (envelope.WsAddressingMessageId is not { Length: > 0 and <= 256 } messageId ||
            !Uri.TryCreate(messageId, UriKind.Absolute, out _) ||
            !WstepRequestContract.TryParse(envelope.Operation!, envelope.WsAddressingAction,
                envelope.MaximumDecodedBinaryBytes, out var request, out _) ||
            request!.Kind != WstepRequestKind.Issue || request.Context?.Length > 2048 ||
            request.Context?.Any(char.IsControl) == true)
            return SoapFaults.Sender(context.TraceIdentifier, "UnsupportedEnrollmentRequest", "A correlated Issue request is required.");
        if (!await slots.WaitAsync(0, cancellationToken)) return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        try
        {
            ValidatedEnrollmentResponse result;
            if (certificatePeer is not null)
            {
                // Certificate transport is renewal-only. No fallback to initial
                // authorization, even for otherwise valid broker-template requests.
                if (renewalAuthorizer is null) return Results.StatusCode(StatusCodes.Status403Forbidden);
                var renewal = await renewalAuthorizer.AuthorizeAsync(certificatePeer, request.CertificateRequestDer!, cancellationToken);
                if (renewal.Enrollment is null) return Results.StatusCode(StatusCodes.Status403Forbidden);
                result = await issuer.IssueAsync(renewal.Enrollment, cancellationToken);
            }
            else
            {
                var authorization = await authorizer.AuthorizeAsync(computer!, request.CertificateRequestDer!, cancellationToken);
                if (authorization.Enrollment is not null)
                    result = await issuer.IssueAsync(authorization.Enrollment, cancellationToken);
                else if (authorization.Result == NativeDomainAuthorizationResult.InvalidCmc && renewalAuthorizer is not null)
                {
                    var renewal = await renewalAuthorizer.AuthorizeAsync(computer!, request.CertificateRequestDer!, cancellationToken);
                    if (renewal.Enrollment is null) return Results.StatusCode(StatusCodes.Status403Forbidden);
                    result = await issuer.IssueAsync(renewal.Enrollment, cancellationToken);
                }
                else return Results.StatusCode(StatusCodes.Status403Forbidden);
            }
            var body = WstepResponseWriter.CreateIssued(result.CertificateDer, result.FullPkiResponse, result.RequestId, "en-GB");
            if (request.Context is not null) body.Elements().Single().SetAttributeValue("Context", request.Context);
            return Results.Text(SoapEnvelopeWriter.CreateResponse(body, WstepResponseWriter.ResponseAction, messageId)
                .ToString(SaveOptions.DisableFormatting), "application/soap+xml", Encoding.UTF8);
        }
        catch (Exception exception) when (exception is InvalidDataException or UnauthorizedAccessException or IOException or CryptographicException or AuthenticationException or
            HttpRequestException or InvalidOperationException or ArgumentException or OperationCanceledException)
        {
            // No raw exception/request/response/credential logging. A submission
            // claim, if created, remains for explicit CA reconciliation.
            return SoapFaults.ProcessingFailure(context.TraceIdentifier);
        }
        finally { slots.Release(); }
    }

    public void Dispose() { signingKey?.Dispose(); signer.Dispose(); root.Dispose(); slots.Dispose(); }
}
