using System.Security.Cryptography;

namespace PkiProxy.Domain;

internal enum BootstrapEnrollmentAuthorizationResult
{
    Authorized,
    InvalidCsr,
    AttestationUnavailable,
    UnknownAuthoritativeAsset,
    InvalidAuthoritativeFacts,
    AttestationAlreadyConsumed,
    AttestationExpired,
    AttestationBindingMismatch
}

internal sealed record BootstrapEnrollmentAuthorization(
    BootstrapEnrollmentAuthorizationResult Result,
    AuthoritativeDeviceFacts? Facts,
    ControlledCertificateIdentity? ControlledIdentity);

internal sealed class BootstrapEnrollmentAuthorizer(
    IBootstrapAttestationStore attestationStore,
    IAuthoritativeDeviceFactsSource deviceFactsSource,
    CertificateClaimPolicy claimPolicy,
    IncomingCsrPolicy csrPolicy,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    public async ValueTask<BootstrapEnrollmentAuthorization> AuthorizeAsync(
        ReadOnlyMemory<byte> certificationRequestDer,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var started = clock.GetTimestamp();
        if (IncomingCsrPolicyValidator.Validate(certificationRequestDer.Span, csrPolicy).Result != IncomingCsrValidationResult.Valid)
        {
            return new BootstrapEnrollmentAuthorization(BootstrapEnrollmentAuthorizationResult.InvalidCsr, null, null);
        }

        CsrBinding binding;
        try
        {
            binding = CsrBinding.FromDer(certificationRequestDer.Span);
        }
        catch (CryptographicException)
        {
            return new BootstrapEnrollmentAuthorization(BootstrapEnrollmentAuthorizationResult.InvalidCsr, null, null);
        }

        var attestation = attestationStore.GetAttestedAsset(binding, now);
        if (attestation.Result != BootstrapStoreResult.Attested || attestation.AuthoritativeAssetId is null)
        {
            return new BootstrapEnrollmentAuthorization(BootstrapEnrollmentAuthorizationResult.AttestationUnavailable, null, null);
        }

        var facts = await deviceFactsSource.FindByAssetIdAsync(attestation.AuthoritativeAssetId, cancellationToken);
        if (facts is null)
        {
            return new BootstrapEnrollmentAuthorization(BootstrapEnrollmentAuthorizationResult.UnknownAuthoritativeAsset, null, null);
        }

        // An adapter lookup key is not proof that its returned row is that asset.
        // Asset IDs are opaque and case-sensitive, unlike AD DNS hostnames.
        if (!string.Equals(facts.AssetId, attestation.AuthoritativeAssetId, StringComparison.Ordinal))
            return new(BootstrapEnrollmentAuthorizationResult.InvalidAuthoritativeFacts, null, null);

        ControlledCertificateIdentity identity;
        try
        {
            identity = ControlledCertificateIdentityMapper.Create(facts, claimPolicy);
        }
        catch (ArgumentException)
        {
            return new BootstrapEnrollmentAuthorization(BootstrapEnrollmentAuthorizationResult.InvalidAuthoritativeFacts, facts, null);
        }
        catch (InvalidOperationException)
        {
            return new BootstrapEnrollmentAuthorization(BootstrapEnrollmentAuthorizationResult.InvalidAuthoritativeFacts, facts, null);
        }

        cancellationToken.ThrowIfCancellationRequested();
        // Advance the caller's trusted request time by monotonic elapsed time.
        // An asynchronous facts lookup must not freeze approval validity.
        var consumed = attestationStore.Consume(binding, now + clock.GetElapsedTime(started));
        if (consumed.Result == BootstrapStoreResult.Expired)
            return new(BootstrapEnrollmentAuthorizationResult.AttestationExpired, null, null);
        if (consumed.Result == BootstrapStoreResult.Consumed &&
            !string.Equals(consumed.AuthoritativeAssetId, attestation.AuthoritativeAssetId, StringComparison.Ordinal))
            return new(BootstrapEnrollmentAuthorizationResult.AttestationBindingMismatch, null, null);
        return consumed.Result == BootstrapStoreResult.Consumed
            ? new BootstrapEnrollmentAuthorization(BootstrapEnrollmentAuthorizationResult.Authorized, facts, identity)
            : new BootstrapEnrollmentAuthorization(BootstrapEnrollmentAuthorizationResult.AttestationAlreadyConsumed, null, null);
    }
}
