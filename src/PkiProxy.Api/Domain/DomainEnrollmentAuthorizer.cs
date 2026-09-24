namespace PkiProxy.Domain;

internal enum DomainEnrollmentAuthorizationResult
{
    Authorized,
    InvalidCsr,
    UnknownDirectoryMachine,
    InvalidAuthoritativeFacts
}

internal sealed record DomainEnrollmentAuthorization(
    DomainEnrollmentAuthorizationResult Result,
    AuthoritativeDeviceFacts? Facts,
    ControlledCertificateIdentity? ControlledIdentity,
    string? Detail);

// The caller directory ID is accepted only from the future Kerberos transport
// authenticator. This service deliberately has no method accepting hostname,
// subject or SAN from a client request.
internal sealed class DomainEnrollmentAuthorizer(
    IAuthoritativeDeviceFactsSource deviceFactsSource,
    CertificateClaimPolicy claimPolicy,
    IncomingCsrPolicy csrPolicy)
{
    public async ValueTask<DomainEnrollmentAuthorization> AuthorizeAsync(
        string directoryObjectId,
        ReadOnlyMemory<byte> certificationRequestDer,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryObjectId);
        var csrValidation = IncomingCsrPolicyValidator.Validate(certificationRequestDer.Span, csrPolicy);
        if (csrValidation.Result != IncomingCsrValidationResult.Valid)
        {
            return new DomainEnrollmentAuthorization(
                DomainEnrollmentAuthorizationResult.InvalidCsr,
                null,
                null,
                csrValidation.Result.ToString());
        }

        var facts = await deviceFactsSource.FindByDirectoryObjectIdAsync(directoryObjectId, cancellationToken);
        if (facts is null)
        {
            return new DomainEnrollmentAuthorization(
                DomainEnrollmentAuthorizationResult.UnknownDirectoryMachine,
                null,
                null,
                null);
        }

        try
        {
            var identity = ControlledCertificateIdentityMapper.Create(facts, claimPolicy);
            return new DomainEnrollmentAuthorization(
                DomainEnrollmentAuthorizationResult.Authorized,
                facts,
                identity,
                null);
        }
        catch (ArgumentException exception)
        {
            return new DomainEnrollmentAuthorization(
                DomainEnrollmentAuthorizationResult.InvalidAuthoritativeFacts,
                facts,
                null,
                exception.GetType().Name);
        }
        catch (InvalidOperationException exception)
        {
            return new DomainEnrollmentAuthorization(
                DomainEnrollmentAuthorizationResult.InvalidAuthoritativeFacts,
                facts,
                null,
                exception.GetType().Name);
        }
    }
}
