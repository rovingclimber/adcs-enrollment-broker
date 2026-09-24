using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace PkiProxy.Domain;

internal enum BootstrapPairingResult
{
    Created,
    AlreadyExists,
    Approved,
    NotFound,
    InvalidCode,
    AssetUnavailable,
    AttemptsExhausted,
    Expired,
    InvalidState,
    AuthenticationStale,
    CapacityExceeded,
    StoreRejected
}

internal enum BootstrapPairingStatus
{
    PendingAttestation,
    Pending,
    ApprovalClaimed,
    Approved,
    AttemptsExhausted,
    Expired,
    Failed
}

internal sealed record BootstrapPairingPolicy(
    TimeSpan Lifetime,
    int MaximumAttempts,
    int MaximumRetainedSessions,
    TimeSpan MaximumTechnicianAuthenticationAge)
{
    internal void Validate()
    {
        if (Lifetime <= TimeSpan.Zero || Lifetime > TimeSpan.FromMinutes(30))
            throw new ArgumentOutOfRangeException(nameof(Lifetime));
        if (MaximumAttempts is < 1 or > 10)
            throw new ArgumentOutOfRangeException(nameof(MaximumAttempts));
        if (MaximumRetainedSessions is < 1 or > 10_000)
            throw new ArgumentOutOfRangeException(nameof(MaximumRetainedSessions));
        if (MaximumTechnicianAuthenticationAge <= TimeSpan.Zero ||
            MaximumTechnicianAuthenticationAge > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(MaximumTechnicianAuthenticationAge));
    }
}

internal sealed record AuthenticatedTechnician(
    string Subject,
    string AuthenticationMethod,
    DateTimeOffset AuthenticatedAt,
    string Capability = "bootstrap-approve");

internal sealed record BootstrapPairingTicket(
    string RequestId,
    string DisplayCode,
    DateTimeOffset ExpiresAt);

internal sealed record BootstrapPairingAudit(
    string RequestId,
    string TechnicianSubject,
    string AuthenticationMethod,
    string AuthoritativeAssetId,
    DateTimeOffset ApprovedAt,
    string CsrSha256,
    string SubjectPublicKeyInfoSha256,
    string Capability = "bootstrap-approve");

internal sealed record BootstrapPairingAttempt(
    BootstrapPairingResult Result,
    BootstrapPairingAudit? Audit = null);

internal sealed record BootstrapPairingLookup(
    BootstrapPairingResult Result,
    BootstrapPairingStatus? Status,
    DateTimeOffset? ExpiresAt,
    int AttemptsRemaining,
    BootstrapPairingAudit? Audit = null);

internal interface IImmutableAssetCatalog
{
    bool Contains(string authoritativeAssetId);
}

internal interface IBootstrapPairingCodeGenerator
{
    string Generate();
}

internal sealed class CryptoBootstrapPairingCodeGenerator : IBootstrapPairingCodeGenerator
{
    public string Generate() => RandomNumberGenerator.GetInt32(1_000_000)
        .ToString("D6", CultureInfo.InvariantCulture);
}

// Process-local coordination seam. It deliberately exposes no HTTP endpoint and
// grants no issuance. A hosted implementation must persist the same fail-closed
// transitions and audit before it can be used across restarts.
internal sealed class BootstrapPairingCoordinator
{
    private readonly object gate = new();
    private readonly IBootstrapAttestationStore attestations;
    private readonly IImmutableAssetCatalog assets;
    private readonly IBootstrapPairingCodeGenerator codes;
    private readonly BootstrapPairingPolicy policy;
    private readonly Dictionary<string, Session> sessions = new(StringComparer.Ordinal);
    private readonly HashSet<string> activeCodes = new(StringComparer.Ordinal);

    internal BootstrapPairingCoordinator(
        IBootstrapAttestationStore attestations,
        IImmutableAssetCatalog assets,
        BootstrapPairingPolicy policy,
        IBootstrapPairingCodeGenerator? codes = null)
    {
        this.attestations = attestations ?? throw new ArgumentNullException(nameof(attestations));
        this.assets = assets ?? throw new ArgumentNullException(nameof(assets));
        this.policy = policy ?? throw new ArgumentNullException(nameof(policy));
        policy.Validate();
        this.codes = codes ?? new CryptoBootstrapPairingCodeGenerator();
    }

    internal (BootstrapPairingResult Result, BootstrapPairingTicket? Ticket) Begin(
        CsrBinding binding,
        DateTimeOffset now)
        => Begin(binding, now, UniqueRequestId());

    internal (BootstrapPairingResult Result, BootstrapPairingTicket? Ticket) Begin(
        CsrBinding binding,
        DateTimeOffset now,
        string requestId)
    {
        ArgumentNullException.ThrowIfNull(binding);
        binding = binding.Snapshot();
        if (!binding.HasExpectedLengths()) throw new ArgumentException("Exact SHA256 bindings required.", nameof(binding));
        if (!IsRequestId(requestId)) throw new ArgumentException("Exact bootstrap request identifier required.", nameof(requestId));
        lock (gate)
        {
            Expire(now);
            if (sessions.Count >= policy.MaximumRetainedSessions)
                return (BootstrapPairingResult.CapacityExceeded, null);

            if (sessions.ContainsKey(requestId))
                return (BootstrapPairingResult.AlreadyExists, null);
            var code = UniqueCode();
            var recorded = attestations.Record(binding, now, policy.Lifetime);
            if (recorded != BootstrapStoreResult.Recorded)
                return (recorded == BootstrapStoreResult.AlreadyExists
                    ? BootstrapPairingResult.AlreadyExists
                    : BootstrapPairingResult.StoreRejected, null);

            var session = new Session(binding, code, now.Add(policy.Lifetime));
            sessions.Add(requestId, session);
            activeCodes.Add(code);
            return (BootstrapPairingResult.Created,
                new BootstrapPairingTicket(requestId, code, session.ExpiresAt));
        }
    }

    internal BootstrapPairingAttempt Approve(
        string requestId,
        string displayedCode,
        string authoritativeAssetId,
        AuthenticatedTechnician technician,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(technician);
        ValidateIdentifier(technician.Subject, nameof(technician.Subject), 256);
        ValidateIdentifier(technician.AuthenticationMethod, nameof(technician.AuthenticationMethod), 64);
        if (technician.Capability != PkiProxy.Authentication.TechnicianCapabilities.BootstrapApprove)
            throw new ArgumentException("Bootstrap approval capability required.", nameof(technician));
        ValidateIdentifier(authoritativeAssetId, nameof(authoritativeAssetId), 256);
        if (technician.AuthenticatedAt > now || now - technician.AuthenticatedAt > policy.MaximumTechnicianAuthenticationAge)
            return new(BootstrapPairingResult.AuthenticationStale);

        lock (gate)
        {
            if (!IsRequestId(requestId) || !sessions.TryGetValue(requestId, out var session))
                return new(BootstrapPairingResult.NotFound);
            if (now >= session.ExpiresAt)
            {
                Expire(session);
                return new(BootstrapPairingResult.Expired);
            }
            if (session.Status != BootstrapPairingStatus.Pending)
                return new(BootstrapPairingResult.InvalidState);
            if (!CodeMatches(session.Code, displayedCode))
                return Fail(session, BootstrapPairingResult.InvalidCode);
            if (!assets.Contains(authoritativeAssetId))
                return Fail(session, BootstrapPairingResult.AssetUnavailable);

            var attested = attestations.Attest(session.Binding, authoritativeAssetId, now);
            if (attested == BootstrapStoreResult.Expired)
            {
                Expire(session);
                return new(BootstrapPairingResult.Expired);
            }
            if (attested != BootstrapStoreResult.Attested)
                return new(attested == BootstrapStoreResult.InvalidState
                    ? BootstrapPairingResult.InvalidState
                    : BootstrapPairingResult.StoreRejected);

            session.Status = BootstrapPairingStatus.Approved;
            activeCodes.Remove(session.Code);
            var audit = new BootstrapPairingAudit(
                requestId,
                technician.Subject,
                technician.AuthenticationMethod,
                authoritativeAssetId,
                now,
                Convert.ToHexString(session.Binding.CsrSha256),
                Convert.ToHexString(session.Binding.SubjectPublicKeyInfoSha256),
                technician.Capability);
            session.Audit = audit;
            return new(BootstrapPairingResult.Approved, audit);
        }
    }

    internal BootstrapPairingLookup Lookup(string requestId, DateTimeOffset now)
    {
        lock (gate)
        {
            if (!IsRequestId(requestId) || !sessions.TryGetValue(requestId, out var session))
                return new(BootstrapPairingResult.NotFound, null, null, 0);
            if (now >= session.ExpiresAt) Expire(session);
            return new(
                session.Status switch
                {
                    BootstrapPairingStatus.Pending => BootstrapPairingResult.Created,
                    BootstrapPairingStatus.Approved => BootstrapPairingResult.Approved,
                    BootstrapPairingStatus.AttemptsExhausted => BootstrapPairingResult.AttemptsExhausted,
                    _ => BootstrapPairingResult.Expired
                },
                session.Status,
                session.ExpiresAt,
                session.Status == BootstrapPairingStatus.Pending
                    ? policy.MaximumAttempts - session.FailedAttempts
                    : 0,
                session.Audit);
        }
    }

    private BootstrapPairingAttempt Fail(
        Session session,
        BootstrapPairingResult result)
    {
        session.FailedAttempts++;
        if (session.FailedAttempts < policy.MaximumAttempts) return new(result);
        session.Status = BootstrapPairingStatus.AttemptsExhausted;
        activeCodes.Remove(session.Code);
        return new(BootstrapPairingResult.AttemptsExhausted);
    }

    private void Expire(DateTimeOffset now)
    {
        foreach (var entry in sessions.Where(entry =>
                     entry.Value.Status == BootstrapPairingStatus.Pending && now >= entry.Value.ExpiresAt))
            Expire(entry.Value);
    }

    private void Expire(Session session)
    {
        session.Status = BootstrapPairingStatus.Expired;
        activeCodes.Remove(session.Code);
    }

    private string UniqueRequestId()
    {
        for (var attempt = 0; attempt < 32; attempt++)
        {
            var requestId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            if (!sessions.ContainsKey(requestId)) return requestId;
        }
        throw new InvalidOperationException("Unable to allocate a bootstrap request identifier.");
    }

    private string UniqueCode()
    {
        for (var attempt = 0; attempt < 32; attempt++)
        {
            var code = codes.Generate();
            if (!IsCode(code)) throw new InvalidOperationException("Pairing code generator returned an invalid code.");
            if (!activeCodes.Contains(code)) return code;
        }
        throw new InvalidOperationException("Unable to allocate a unique active pairing code.");
    }

    private static bool CodeMatches(string expected, string candidate)
    {
        if (!IsCode(candidate)) return false;
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(candidate));
    }

    private static bool IsCode(string value) =>
        value is { Length: 6 } && value.All(char.IsAsciiDigit);

    private static bool IsRequestId(string value) =>
        value is { Length: 32 } && value.All(char.IsAsciiHexDigit);

    private static void ValidateIdentifier(string value, string name, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(char.IsControl))
            throw new ArgumentException("A bounded printable identifier is required.", name);
    }

    private sealed class Session
    {
        internal Session(CsrBinding binding, string code, DateTimeOffset expiresAt)
        {
            Binding = binding;
            Code = code;
            ExpiresAt = expiresAt;
        }

        internal CsrBinding Binding { get; }
        internal string Code { get; }
        internal DateTimeOffset ExpiresAt { get; }
        internal BootstrapPairingStatus Status { get; set; } = BootstrapPairingStatus.Pending;
        internal int FailedAttempts { get; set; }
        internal BootstrapPairingAudit? Audit { get; set; }
    }
}
