using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;

namespace PkiProxy.Authentication;

internal sealed record BootstrapIngressAdmissionPolicy
{
    private readonly ReadOnlyCollection<IPAddress> allowedPeers;

    internal BootstrapIngressAdmissionPolicy(
        string brokerHost,
        IReadOnlyCollection<IPAddress> allowedPeers,
        TimeSpan rateWindow,
        int perPeerRequestLimit,
        int perPeerConcurrency,
        int globalConcurrency,
        int externalAuthorityPort,
        int internalListenerPort)
    {
        ArgumentNullException.ThrowIfNull(brokerHost);
        ArgumentNullException.ThrowIfNull(allowedPeers);
        if (Uri.CheckHostName(brokerHost) != UriHostNameType.Dns ||
            brokerHost.Length is < 3 or > 253 ||
            !brokerHost.Contains('.') ||
            brokerHost.EndsWith('.') ||
            brokerHost.Any(c => c > 0x7f || c is >= 'A' and <= 'Z'))
            throw new ArgumentException("Canonical lowercase ASCII broker DNS host required.", nameof(brokerHost));
        if (externalAuthorityPort is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(externalAuthorityPort));
        if (internalListenerPort is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(internalListenerPort));
        if (rateWindow < TimeSpan.FromSeconds(1) || rateWindow > TimeSpan.FromMinutes(10))
            throw new ArgumentOutOfRangeException(nameof(rateWindow));
        if (perPeerRequestLimit is < 1 or > 1000)
            throw new ArgumentOutOfRangeException(nameof(perPeerRequestLimit));
        if (perPeerConcurrency is < 1 or > 16)
            throw new ArgumentOutOfRangeException(nameof(perPeerConcurrency));
        if (globalConcurrency < perPeerConcurrency || globalConcurrency > 256)
            throw new ArgumentOutOfRangeException(nameof(globalConcurrency));

        var peers = allowedPeers.ToArray();
        if (peers.Length is < 1 or > 64 || peers.Any(peer =>
                peer is null ||
                peer.AddressFamily != AddressFamily.InterNetwork ||
                peer.IsIPv4MappedToIPv6 ||
                peer.Equals(IPAddress.Any) ||
                peer.Equals(IPAddress.Broadcast)) ||
            peers.Distinct().Count() != peers.Length)
            throw new ArgumentException("One to 64 unique exact IPv4 peers required.", nameof(allowedPeers));

        BrokerHost = brokerHost;
        ExternalAuthorityPort = externalAuthorityPort;
        InternalListenerPort = internalListenerPort;
        RateWindow = rateWindow;
        PerPeerRequestLimit = perPeerRequestLimit;
        PerPeerConcurrency = perPeerConcurrency;
        GlobalConcurrency = globalConcurrency;
        this.allowedPeers = Array.AsReadOnly(peers);
    }

    internal string BrokerHost { get; }
    internal int ExternalAuthorityPort { get; }
    internal int InternalListenerPort { get; }
    internal TimeSpan RateWindow { get; }
    internal int PerPeerRequestLimit { get; }
    internal int PerPeerConcurrency { get; }
    internal int GlobalConcurrency { get; }
    internal IReadOnlyList<IPAddress> AllowedPeers => allowedPeers;
}

// Reusable admission seam only. A caller must hold the returned lease in an
// exception-safe using scope around all later parsing or request-state work.
internal sealed class BootstrapIngressAdmission
{
    internal sealed class PeerState
    {
        internal long? WindowStartUtcTicks;
        internal long RequestsInWindow;
        internal int Active;
    }

    internal sealed class Lease : IDisposable
    {
        private BootstrapIngressAdmission? owner;
        private readonly PeerState peer;

        private Lease(BootstrapIngressAdmission owner, PeerState peer)
        {
            this.owner = owner;
            this.peer = peer;
        }

        internal static Lease Create(BootstrapIngressAdmission owner, PeerState peer) => new(owner, peer);

        public void Dispose()
        {
            var current = Interlocked.Exchange(ref owner, null);
            if (current is not null) current.Release(peer);
        }
    }

    private readonly object gate = new();
    private readonly Dictionary<IPAddress, PeerState> peers;
    private readonly string authority;
    private readonly string authorityWithPort;
    private readonly BootstrapIngressAdmissionPolicy policy;
    private long? lastObservedUtcTicks;
    private int active;

    internal BootstrapIngressAdmission(BootstrapIngressAdmissionPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        this.policy = policy;
        authority = policy.BrokerHost;
        authorityWithPort = $"{policy.BrokerHost}:{policy.ExternalAuthorityPort}";
        peers = policy.AllowedPeers.ToDictionary(peer => peer, _ => new PeerState());
    }

    internal BootstrapIngressAdmissionResult TryAcquire(HttpContext context, DateTimeOffset now, out Lease? lease)
    {
        ArgumentNullException.ThrowIfNull(context);
        lease = null;
        var peerAddress = context.Connection.RemoteIpAddress;
        if (!context.Request.IsHttps ||
            context.Request.Protocol != "HTTP/1.1" ||
            context.Connection.LocalIpAddress is null ||
            context.Connection.LocalPort != policy.InternalListenerPort ||
            peerAddress is null ||
            peerAddress.AddressFamily != AddressFamily.InterNetwork ||
            peerAddress.IsIPv4MappedToIPv6 ||
            !peers.TryGetValue(peerAddress, out var peer) ||
            !HasExactAuthority(context.Request.Host.Value) ||
            context.Request.Headers.Keys.Any(name =>
                name.Equals("Forwarded", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase)))
            return BootstrapIngressAdmissionResult.TransportRejected;

        var utcTicks = now.UtcDateTime.Ticks;
        lock (gate)
        {
            if (lastObservedUtcTicks is { } last && utcTicks < last)
                return BootstrapIngressAdmissionResult.ClockRollback;
            lastObservedUtcTicks = utcTicks;

            if (peer.WindowStartUtcTicks is null ||
                utcTicks - peer.WindowStartUtcTicks.Value >= policy.RateWindow.Ticks)
            {
                peer.WindowStartUtcTicks = utcTicks;
                peer.RequestsInWindow = 0;
            }

            // Every transport-valid attempt spends a rate token, including an
            // attempt denied by a concurrency cap. Once over limit, the counter
            // remains latched above the limit until the exact window boundary.
            if (peer.RequestsInWindow <= policy.PerPeerRequestLimit)
                peer.RequestsInWindow++;
            if (peer.RequestsInWindow > policy.PerPeerRequestLimit)
                return BootstrapIngressAdmissionResult.RateLimited;
            if (peer.Active >= policy.PerPeerConcurrency || active >= policy.GlobalConcurrency)
                return BootstrapIngressAdmissionResult.ConcurrencyLimited;

            peer.Active++;
            active++;
            lease = Lease.Create(this, peer);
            return BootstrapIngressAdmissionResult.Admitted;
        }
    }

    private bool HasExactAuthority(string? value) =>
        string.Equals(value, authorityWithPort, StringComparison.OrdinalIgnoreCase) ||
        policy.ExternalAuthorityPort == 443 && string.Equals(value, authority, StringComparison.OrdinalIgnoreCase);

    private void Release(PeerState peer)
    {
        lock (gate)
        {
            if (peer.Active <= 0 || active <= 0)
                throw new InvalidOperationException("Bootstrap ingress lease accounting is inconsistent.");
            peer.Active--;
            active--;
        }
    }
}

internal enum BootstrapIngressAdmissionResult
{
    Admitted,
    TransportRejected,
    ClockRollback,
    RateLimited,
    ConcurrencyLimited
}
