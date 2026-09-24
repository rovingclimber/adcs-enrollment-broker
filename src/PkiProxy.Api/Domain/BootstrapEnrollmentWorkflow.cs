using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using PkiProxy.Authentication;

namespace PkiProxy.Domain;

internal enum BootstrapWorkflowResult
{
    PendingApproval,
    Approved,
    InvalidRequest,
    AuthenticationRejected,
    PairingRejected,
    TransactionRejected
}

internal sealed record BootstrapWorkflowIntake(
    BootstrapWorkflowResult Result,
    BootstrapPairingTicket? Ticket = null);

internal sealed record BootstrapWorkflowApproval(
    BootstrapWorkflowResult Result,
    BootstrapPairingResult? PairingResult = null,
    BootstrapTransactionResult? TransactionResult = null,
    BootstrapPairingAudit? Audit = null);

// Composes the independently hardened stores into one shared-ID bootstrap
// boundary. It intentionally stops at durable asset approval: no CA transport
// or issuance claim is reachable from this class.
internal sealed class BootstrapEnrollmentWorkflow
{
    private readonly FileBootstrapEnrollmentTransactionStore transactions;
    private readonly FileBootstrapPairingCoordinator pairings;
    private readonly FileBootstrapIntakeLedger intake;
    private readonly BootstrapTechnicianAuthenticator technicians;
    private readonly IncomingCsrPolicy csrPolicy;
    private readonly TimeSpan lifetime;
    private readonly Action<string>? checkpoint;

    internal BootstrapEnrollmentWorkflow(
        FileBootstrapEnrollmentTransactionStore transactions,
        FileBootstrapPairingCoordinator pairings,
        FileBootstrapIntakeLedger intake,
        BootstrapTechnicianAuthenticator technicians,
        IncomingCsrPolicy csrPolicy,
        TimeSpan lifetime,
        Action<string>? checkpoint = null)
    {
        this.transactions = transactions ?? throw new ArgumentNullException(nameof(transactions));
        this.pairings = pairings ?? throw new ArgumentNullException(nameof(pairings));
        this.intake = intake ?? throw new ArgumentNullException(nameof(intake));
        this.technicians = technicians ?? throw new ArgumentNullException(nameof(technicians));
        this.csrPolicy = csrPolicy ?? throw new ArgumentNullException(nameof(csrPolicy));
        this.checkpoint = checkpoint;
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(24))
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        this.lifetime = lifetime;
    }

    internal BootstrapWorkflowIntake Begin(ReadOnlyMemory<byte> csrDer, DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Durable bootstrap workflow requires Linux.");
        cancellationToken.ThrowIfCancellationRequested();
        if (csrDer.IsEmpty || csrDer.Length > FileBootstrapEnrollmentTransactionStore.MaximumCsrBytes ||
            IncomingCsrPolicyValidator.Validate(csrDer.Span, csrPolicy).Result != IncomingCsrValidationResult.Valid)
            return new(BootstrapWorkflowResult.InvalidRequest);

        CsrBinding binding;
        try { binding = CsrBinding.FromDer(csrDer.Span); }
        catch (Exception error) when (error is ArgumentException or CryptographicException)
        { return new(BootstrapWorkflowResult.InvalidRequest); }

        var transactionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        checkpoint?.Invoke("before-reservation");
        using var reservation = intake.TryReserve(transactionId, binding, csrDer.Length, now, lifetime,
            value => Cleanup(value, now));
        if (reservation is null) return new(BootstrapWorkflowResult.PairingRejected);
        checkpoint?.Invoke("after-reservation");
        cancellationToken.ThrowIfCancellationRequested();
        var retained = transactions.Retain(csrDer.Span, binding, now, lifetime, transactionId);
        if (retained.Result != BootstrapTransactionResult.Retained || retained.TransactionId != transactionId)
            return new(BootstrapWorkflowResult.TransactionRejected);
        checkpoint?.Invoke("after-transaction");
        cancellationToken.ThrowIfCancellationRequested();
        var pairing = pairings.BeginReserved(binding, now, transactionId, reservation.Ordinal);
        if (pairing.Result != BootstrapPairingResult.Created || pairing.Ticket is null ||
            pairing.Ticket.RequestId != transactionId)
            return new(BootstrapWorkflowResult.PairingRejected);
        checkpoint?.Invoke("after-pairing");
        cancellationToken.ThrowIfCancellationRequested();
        reservation.Commit(now);
        return new(BootstrapWorkflowResult.PendingApproval, pairing.Ticket);
    }

    internal BootstrapWorkflowApproval Approve(
        AuthenticateResult authentication,
        string transactionId,
        string displayedCode,
        string authoritativeAssetId,
        DateTimeOffset now)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Durable bootstrap workflow requires Linux.");
        var authorized = technicians.Authorize(authentication, now);
        if (authorized.Result != BootstrapTechnicianAuthenticationResult.Authorized || authorized.Technician is null)
            return new(BootstrapWorkflowResult.AuthenticationRejected);

        var pairing = pairings.Approve(transactionId, displayedCode, authoritativeAssetId,
            authorized.Technician, now);
        var audit = pairing.Audit;
        if (pairing.Result == BootstrapPairingResult.InvalidState)
        {
            var lookup = pairings.Lookup(transactionId, now);
            audit = lookup.Result == BootstrapPairingResult.Approved ? lookup.Audit : null;
            if (audit is null || audit.AuthoritativeAssetId != authoritativeAssetId ||
                audit.TechnicianSubject != authorized.Technician.Subject ||
                audit.AuthenticationMethod != authorized.Technician.AuthenticationMethod)
                return new(BootstrapWorkflowResult.PairingRejected, pairing.Result);
            if (audit.Capability != authorized.Technician.Capability)
                return new(BootstrapWorkflowResult.PairingRejected, pairing.Result);
        }
        else if (pairing.Result != BootstrapPairingResult.Approved || audit is null)
            return new(BootstrapWorkflowResult.PairingRejected, pairing.Result);

        if (audit.RequestId != transactionId || audit.AuthoritativeAssetId != authoritativeAssetId)
            return new(BootstrapWorkflowResult.PairingRejected, BootstrapPairingResult.InvalidState);

        CsrBinding binding;
        try
        {
            binding = new CsrBinding(Convert.FromHexString(audit.CsrSha256),
                Convert.FromHexString(audit.SubjectPublicKeyInfoSha256));
        }
        catch (FormatException)
        {
            return new(BootstrapWorkflowResult.PairingRejected, BootstrapPairingResult.InvalidState);
        }
        if (!binding.HasExpectedLengths())
            return new(BootstrapWorkflowResult.PairingRejected, BootstrapPairingResult.InvalidState);

        var bound = transactions.BindAsset(transactionId, binding, authoritativeAssetId, now);
        if (bound is BootstrapTransactionResult.AssetBound or BootstrapTransactionResult.AlreadyBound)
        {
            intake.MarkTrusted(transactionId, now);
            return new(BootstrapWorkflowResult.Approved, BootstrapPairingResult.Approved, bound, audit);
        }
        return new(BootstrapWorkflowResult.TransactionRejected, BootstrapPairingResult.Approved, bound, audit);
    }

    private FileBootstrapIntakeLedger.RecoveryDisposition Cleanup(
        FileBootstrapIntakeLedger.Reservation reservation, DateTimeOffset now)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Durable bootstrap workflow requires Linux.");
        var binding = new CsrBinding(Convert.FromHexString(reservation.CsrSha256),
            Convert.FromHexString(reservation.SpkiSha256));
        var pairing = pairings.Lookup(reservation.TransactionId, now);
        if (pairing is { Result: BootstrapPairingResult.Approved, Audit: not null })
        {
            return transactions.HasDurableAssetBinding(reservation.TransactionId, binding,
                pairing.Audit.AuthoritativeAssetId)
                ? FileBootstrapIntakeLedger.RecoveryDisposition.Trusted
                : FileBootstrapIntakeLedger.RecoveryDisposition.RetainActive;
        }
        if (pairings.HasTrustedTransition(reservation.TransactionId))
            return FileBootstrapIntakeLedger.RecoveryDisposition.RetainActive;
        pairings.DeleteUntrusted(reservation.TransactionId, binding, now, requireExpiry: false);
        transactions.DeleteUntrusted(reservation.TransactionId, binding, now, requireExpiry: false);
        return FileBootstrapIntakeLedger.RecoveryDisposition.Removed;
    }
}
