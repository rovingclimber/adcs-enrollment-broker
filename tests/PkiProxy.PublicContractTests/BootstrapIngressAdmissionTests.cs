using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Http;
using PkiProxy.Authentication;

internal static class BootstrapIngressAdmissionTests
{
    private static readonly IPAddress PeerOne = IPAddress.Parse("192.0.2.52");
    private static readonly IPAddress PeerTwo = IPAddress.Parse("192.0.2.53");
    private const string Host = "ct-pki-broker-dev-01.example.test";

    internal static void Run()
    {
        var checks = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException("Bootstrap ingress admission: " + label);
            checks++;
        }

        var start = new DateTimeOffset(2026, 9, 14, 9, 0, 0, TimeSpan.Zero);
        var transportGuard = Guard(requestLimit: 1);
        foreach (var denied in DeniedTransportContexts())
            Check(transportGuard.TryAcquire(denied, start, out var deniedLease) ==
                    BootstrapIngressAdmissionResult.TransportRejected && deniedLease is null,
                "transport, source, authority, and forwarded metadata fail before lease allocation");
        Check(transportGuard.TryAcquire(Context(PeerOne), start, out var validLease) ==
                BootstrapIngressAdmissionResult.Admitted,
            "external 443 authority reaches the internal 8443 listener after transport denials");
        validLease!.Dispose();
        Check(transportGuard.TryAcquire(Context(PeerOne), start, out _) == BootstrapIngressAdmissionResult.RateLimited,
            "transport denials did not consume the sole rate token");

        var explicitPortGuard = Guard();
        using (Acquire(explicitPortGuard, Context(PeerOne, explicitPort: true), start,
                   "explicit external broker authority port admitted")) { }

        var nonDefaultAuthorityGuard = Guard(externalAuthorityPort: 9443);
        using (Acquire(nonDefaultAuthorityGuard,
                   Context(PeerOne, authorityPort: 9443), start,
                   "explicit non-default external authority reaches internal listener")) { }
        Check(nonDefaultAuthorityGuard.TryAcquire(Context(PeerOne), start, out _) ==
                BootstrapIngressAdmissionResult.TransportRejected,
            "omitted authority port means public HTTPS 443 and cannot alias external 9443");

        var equalPortGuard = Guard(internalListenerPort: 443);
        var equalPortContext = Context(PeerOne); equalPortContext.Connection.LocalPort = 443;
        using (Acquire(equalPortGuard, equalPortContext, start,
                   "equal external and internal ports remain a valid direct binding")) { }

        var isolationGuard = Guard(requestLimit: 1);
        using (Acquire(isolationGuard, Context(PeerOne), start, "first exact peer admitted")) { }
        Check(isolationGuard.TryAcquire(Context(PeerOne), start, out _) == BootstrapIngressAdmissionResult.RateLimited,
            "first peer rate limit enforced");
        using (Acquire(isolationGuard, Context(PeerTwo), start, "second exact peer has isolated rate state")) { }

        var boundaryGuard = Guard(requestLimit: 1, window: TimeSpan.FromSeconds(2));
        using (Acquire(boundaryGuard, Context(PeerOne), start, "fixed window first request admitted")) { }
        Check(boundaryGuard.TryAcquire(Context(PeerOne), start.AddSeconds(1), out _) ==
                BootstrapIngressAdmissionResult.RateLimited,
            "over-limit attempt denied inside fixed window");
        using (Acquire(boundaryGuard, Context(PeerOne), start.AddSeconds(2),
                   "fixed window resets at exact start plus duration boundary")) { }
        Check(boundaryGuard.TryAcquire(Context(PeerOne), start.AddSeconds(2).AddTicks(-1), out _) ==
                BootstrapIngressAdmissionResult.ClockRollback,
            "clock rollback rejected without a lease");

        var disposalGuard = Guard(requestLimit: 10, perPeerConcurrency: 1, globalConcurrency: 1);
        var firstLease = Acquire(disposalGuard, Context(PeerOne), start, "first concurrency lease admitted");
        Check(disposalGuard.TryAcquire(Context(PeerOne), start, out _) ==
                BootstrapIngressAdmissionResult.ConcurrencyLimited,
            "held per-peer lease enforces cap");
        firstLease.Dispose();
        firstLease.Dispose();
        try
        {
            using var exceptionLease = Acquire(disposalGuard, Context(PeerOne), start,
                "single-dispose release restores capacity");
            throw new OperationCanceledException("Expected test interruption.");
        }
        catch (OperationCanceledException) { }
        using (Acquire(disposalGuard, Context(PeerOne), start, "using releases capacity when request work throws")) { }

        var conservativeGuard = Guard(requestLimit: 2, perPeerConcurrency: 1, globalConcurrency: 1);
        using (var held = Acquire(conservativeGuard, Context(PeerOne), start, "conservative rate first request admitted"))
        {
            Check(conservativeGuard.TryAcquire(Context(PeerOne), start, out _) ==
                    BootstrapIngressAdmissionResult.ConcurrencyLimited,
                "concurrency denial spends a rate token without allocating a lease");
        }
        Check(conservativeGuard.TryAcquire(Context(PeerOne), start, out _) ==
                BootstrapIngressAdmissionResult.RateLimited,
            "spent concurrency-denial token keeps the fixed window closed");

        RacePerPeerCap(Check, start);
        RaceGlobalCap(Check, start);
        ValidatePolicyBounds(Check);
        Console.WriteLine($"Bootstrap ingress admission checks passed: {checks}.");
    }

    private static IEnumerable<DefaultHttpContext> DeniedTransportContexts()
    {
        var cleartext = Context(PeerOne); cleartext.Request.Scheme = "http"; yield return cleartext;
        var missingRemote = Context(PeerOne); missingRemote.Connection.RemoteIpAddress = null; yield return missingRemote;
        var missingLocalAddress = Context(PeerOne); missingLocalAddress.Connection.LocalIpAddress = null; yield return missingLocalAddress;
        var missingLocal = Context(PeerOne); missingLocal.Connection.LocalPort = 0; yield return missingLocal;
        var wrongLocal = Context(PeerOne); wrongLocal.Connection.LocalPort = 443; yield return wrongLocal;
        var wrongProtocol = Context(PeerOne); wrongProtocol.Request.Protocol = "HTTP/2"; yield return wrongProtocol;
        yield return Context(IPAddress.Parse("192.0.2.54"));
        yield return Context(IPAddress.Parse("2001:db8::52"));
        yield return Context(IPAddress.Parse("::ffff:192.0.2.52"));
        var missingHost = Context(PeerOne); missingHost.Request.Host = default; yield return missingHost;
        var wrongHost = Context(PeerOne); wrongHost.Request.Host = new HostString("other.example.test"); yield return wrongHost;
        var wrongPort = Context(PeerOne); wrongPort.Request.Host = new HostString(Host, 8443); yield return wrongPort;
        var userInfo = Context(PeerOne); userInfo.Request.Host = new HostString("user@" + Host); yield return userInfo;
        var ambiguous = Context(PeerOne); ambiguous.Request.Host = new HostString(Host + ",other.example.test"); yield return ambiguous;
        var forwarded = Context(PeerOne); forwarded.Request.Headers["fOrWaRdEd"] = "for=192.0.2.52"; yield return forwarded;
        var xForwarded = Context(PeerOne); xForwarded.Request.Headers["x-FORWARDED-for"] = "192.0.2.52"; yield return xForwarded;
    }

    private static void RacePerPeerCap(Action<bool, string> check, DateTimeOffset now)
    {
        var guard = Guard(requestLimit: 100, perPeerConcurrency: 4, globalConcurrency: 32);
        var leases = Race(32, index => Context(PeerOne), guard, now);
        check(leases.Count == 4, "simultaneous acquisition has exactly the per-peer winners");
        foreach (var lease in leases) lease.Dispose();
    }

    private static void RaceGlobalCap(Action<bool, string> check, DateTimeOffset now)
    {
        var guard = Guard(requestLimit: 100, perPeerConcurrency: 8, globalConcurrency: 10);
        var peers = new ConcurrentDictionary<IPAddress, int>();
        using var start = new ManualResetEventSlim();
        var leases = new ConcurrentBag<IDisposable>();
        var tasks = Enumerable.Range(0, 32).Select(index => Task.Run(() =>
        {
            var address = index % 2 == 0 ? PeerOne : PeerTwo;
            start.Wait();
            if (guard.TryAcquire(Context(address), now, out var lease) == BootstrapIngressAdmissionResult.Admitted)
            {
                leases.Add(lease!);
                peers.AddOrUpdate(address, 1, (_, count) => count + 1);
            }
        })).ToArray();
        start.Set();
        Task.WaitAll(tasks);
        check(leases.Count == 10 && peers.Values.All(count => count <= 8),
            "simultaneous acquisition has exactly the global winners without violating peer cap");
        foreach (var lease in leases) lease.Dispose();
    }

    private static ConcurrentBag<IDisposable> Race(int count, Func<int, DefaultHttpContext> context,
        BootstrapIngressAdmission guard, DateTimeOffset now)
    {
        using var start = new ManualResetEventSlim();
        var leases = new ConcurrentBag<IDisposable>();
        var tasks = Enumerable.Range(0, count).Select(index => Task.Run(() =>
        {
            var request = context(index);
            start.Wait();
            if (guard.TryAcquire(request, now, out var lease) == BootstrapIngressAdmissionResult.Admitted)
                leases.Add(lease!);
        })).ToArray();
        start.Set();
        Task.WaitAll(tasks);
        return leases;
    }

    private static void ValidatePolicyBounds(Action<bool, string> check)
    {
        _ = Policy([PeerOne], TimeSpan.FromSeconds(1), 1, 1, 1);
        _ = Policy([PeerOne], TimeSpan.FromSeconds(1), 1, 1, 1, 443, 443);
        _ = Policy(Enumerable.Range(1, 64).Select(index => IPAddress.Parse($"192.0.2.{index}")).ToArray(),
            TimeSpan.FromMinutes(10), 1000, 16, 256);
        check(true, "policy accepts every inclusive minimum and maximum bound");

        var invalid = new Action[]
        {
            () => _ = new BootstrapIngressAdmissionPolicy("BROKER.example.test", [PeerOne], TimeSpan.FromSeconds(1), 1, 1, 1, 443, 8443),
            () => _ = new BootstrapIngressAdmissionPolicy("*.example.test", [PeerOne], TimeSpan.FromSeconds(1), 1, 1, 1, 443, 8443),
            () => _ = new BootstrapIngressAdmissionPolicy("192.0.2.13", [PeerOne], TimeSpan.FromSeconds(1), 1, 1, 1, 443, 8443),
            () => _ = Policy([], TimeSpan.FromSeconds(1), 1, 1, 1),
            () => _ = Policy([PeerOne, PeerOne], TimeSpan.FromSeconds(1), 1, 1, 1),
            () => _ = Policy([IPAddress.IPv6Loopback], TimeSpan.FromSeconds(1), 1, 1, 1),
            () => _ = Policy([IPAddress.Parse("::ffff:192.0.2.52")], TimeSpan.FromSeconds(1), 1, 1, 1),
            () => _ = Policy([IPAddress.Any], TimeSpan.FromSeconds(1), 1, 1, 1),
            () => _ = Policy(Enumerable.Range(1, 65).Select(index => IPAddress.Parse($"198.51.100.{index}")).ToArray(), TimeSpan.FromSeconds(1), 1, 1, 1),
            () => _ = Policy([PeerOne], TimeSpan.FromSeconds(1).Add(TimeSpan.FromTicks(-1)), 1, 1, 1),
            () => _ = Policy([PeerOne], TimeSpan.FromMinutes(10).Add(TimeSpan.FromTicks(1)), 1, 1, 1),
            () => _ = Policy([PeerOne], TimeSpan.FromSeconds(1), 0, 1, 1),
            () => _ = Policy([PeerOne], TimeSpan.FromSeconds(1), 1001, 1, 1),
            () => _ = Policy([PeerOne], TimeSpan.FromSeconds(1), 1, 0, 1),
            () => _ = Policy([PeerOne], TimeSpan.FromSeconds(1), 1, 17, 17),
            () => _ = Policy([PeerOne], TimeSpan.FromSeconds(1), 1, 2, 1),
            () => _ = Policy([PeerOne], TimeSpan.FromSeconds(1), 1, 16, 257),
            () => _ = new BootstrapIngressAdmissionPolicy(Host, [PeerOne], TimeSpan.FromSeconds(1), 1, 1, 1, 0, 8443),
            () => _ = new BootstrapIngressAdmissionPolicy(Host, [PeerOne], TimeSpan.FromSeconds(1), 1, 1, 1, 443, 0)
        };
        foreach (var reject in invalid)
        {
            try { reject(); throw new InvalidOperationException("Invalid bootstrap policy accepted."); }
            catch (ArgumentException) { }
        }
        check(true, "policy rejects noncanonical authority, non-exact peers, duplicates, and every out-of-range bound");
    }

    private static BootstrapIngressAdmission Guard(int requestLimit = 100,
        int perPeerConcurrency = 16, int globalConcurrency = 32, TimeSpan? window = null,
        int externalAuthorityPort = 443, int internalListenerPort = 8443) =>
        new(Policy([PeerOne, PeerTwo], window ?? TimeSpan.FromMinutes(1), requestLimit,
            perPeerConcurrency, globalConcurrency, externalAuthorityPort, internalListenerPort));

    private static BootstrapIngressAdmissionPolicy Policy(IReadOnlyCollection<IPAddress> peers,
        TimeSpan window, int requestLimit, int perPeerConcurrency, int globalConcurrency,
        int externalAuthorityPort = 443, int internalListenerPort = 8443) =>
        new(Host, peers, window, requestLimit, perPeerConcurrency, globalConcurrency,
            externalAuthorityPort, internalListenerPort);

    private static DefaultHttpContext Context(IPAddress peer, bool explicitPort = false,
        int? authorityPort = null)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = peer;
        context.Connection.LocalIpAddress = IPAddress.Parse("192.0.2.13");
        context.Connection.LocalPort = 8443;
        context.Request.Scheme = "https";
        context.Request.Protocol = "HTTP/1.1";
        context.Request.Host = authorityPort is { } port ? new HostString(Host, port) :
            explicitPort ? new HostString(Host, 443) : new HostString(Host);
        return context;
    }

    private static BootstrapIngressAdmission.Lease Acquire(BootstrapIngressAdmission guard, DefaultHttpContext context,
        DateTimeOffset now, string label)
    {
        if (guard.TryAcquire(context, now, out var lease) != BootstrapIngressAdmissionResult.Admitted)
            throw new InvalidOperationException("Bootstrap ingress admission: " + label);
        return lease!;
    }
}
