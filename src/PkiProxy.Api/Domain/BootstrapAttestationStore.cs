using System.Collections.Concurrent;

namespace PkiProxy.Domain;

internal enum BootstrapRequestStatus
{
    Pending,
    Attested,
    Consumed,
    Expired
}

internal enum BootstrapStoreResult
{
    Recorded,
    AlreadyExists,
    Attested,
    Consumed,
    NotFound,
    BindingMismatch,
    InvalidState,
    Expired
}

internal sealed record BootstrapAttestation(
    CsrBinding Binding,
    BootstrapRequestStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    string? AuthoritativeAssetId);

internal sealed record BootstrapConsumeResult(
    BootstrapStoreResult Result,
    string? AuthoritativeAssetId);

internal sealed record BootstrapAttestationLookup(
    BootstrapStoreResult Result,
    string? AuthoritativeAssetId);

// The in-memory implementation is deliberately a development seam. Production
// storage must provide the same atomic transitions in durable storage; device
// facts remain outside this state machine and are fetched after asset binding.
internal interface IBootstrapAttestationStore
{
    BootstrapStoreResult Record(CsrBinding binding, DateTimeOffset now, TimeSpan lifetime);
    BootstrapStoreResult Attest(CsrBinding binding, string authoritativeAssetId, DateTimeOffset now);
    BootstrapConsumeResult Consume(CsrBinding binding, DateTimeOffset now);
    BootstrapAttestationLookup GetAttestedAsset(CsrBinding binding, DateTimeOffset now);
}

internal sealed class InMemoryBootstrapAttestationStore : IBootstrapAttestationStore
{
    private readonly ConcurrentDictionary<string, BootstrapAttestation> _requests = new(StringComparer.Ordinal);

    public BootstrapStoreResult Record(CsrBinding binding, DateTimeOffset now, TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (!binding.HasExpectedLengths() || lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        }

        var key = RequestKey(binding);
        var request = new BootstrapAttestation(
            binding.Snapshot(),
            BootstrapRequestStatus.Pending,
            now,
            now.Add(lifetime),
            null);

        return _requests.TryAdd(key, request)
            ? BootstrapStoreResult.Recorded
            : BootstrapStoreResult.AlreadyExists;
    }

    public BootstrapStoreResult Attest(CsrBinding binding, string authoritativeAssetId, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentException.ThrowIfNullOrWhiteSpace(authoritativeAssetId);

        return Transition(binding, now, current =>
        {
            if (current.Status != BootstrapRequestStatus.Pending)
            {
                return (BootstrapStoreResult.InvalidState, current);
            }

            return (BootstrapStoreResult.Attested, current with
            {
                Status = BootstrapRequestStatus.Attested,
                AuthoritativeAssetId = authoritativeAssetId
            });
        });
    }

    public BootstrapConsumeResult Consume(CsrBinding binding, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(binding);
        string? assetId = null;
        var result = Transition(binding, now, current =>
        {
            if (current.Status != BootstrapRequestStatus.Attested || current.AuthoritativeAssetId is null)
            {
                return (BootstrapStoreResult.InvalidState, current);
            }

            assetId = current.AuthoritativeAssetId;
            return (BootstrapStoreResult.Consumed, current with { Status = BootstrapRequestStatus.Consumed });
        });

        return new BootstrapConsumeResult(result, result == BootstrapStoreResult.Consumed ? assetId : null);
    }

    public BootstrapAttestationLookup GetAttestedAsset(CsrBinding binding, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(binding);
        string? assetId = null;
        var result = Transition(binding, now, current =>
        {
            if (current.Status != BootstrapRequestStatus.Attested || current.AuthoritativeAssetId is null)
            {
                return (BootstrapStoreResult.InvalidState, current);
            }

            assetId = current.AuthoritativeAssetId;
            return (BootstrapStoreResult.Attested, current);
        });

        return new BootstrapAttestationLookup(result, result == BootstrapStoreResult.Attested ? assetId : null);
    }

    private BootstrapStoreResult Transition(
        CsrBinding binding,
        DateTimeOffset now,
        Func<BootstrapAttestation, (BootstrapStoreResult Result, BootstrapAttestation Replacement)> action)
    {
        var key = RequestKey(binding);
        while (_requests.TryGetValue(key, out var current))
        {
            if (!current.Binding.Matches(binding))
            {
                return BootstrapStoreResult.BindingMismatch;
            }

            if (now >= current.ExpiresAt)
            {
                var expired = current with { Status = BootstrapRequestStatus.Expired };
                if (_requests.TryUpdate(key, expired, current))
                {
                    return BootstrapStoreResult.Expired;
                }

                continue;
            }

            var (result, replacement) = action(current);
            if (_requests.TryUpdate(key, replacement, current))
            {
                return result;
            }
        }

        return BootstrapStoreResult.NotFound;
    }

    private static string RequestKey(CsrBinding binding) => Convert.ToHexString(binding.CsrSha256);
}
