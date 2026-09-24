using System.Security.Cryptography;
using PkiProxy.Domain;

internal static class BootstrapPairingTests
{
    internal static void Run()
    {
        var now = DateTimeOffset.Parse("2026-09-13T16:00:00Z");
        var policy = new BootstrapPairingPolicy(
            TimeSpan.FromMinutes(10), 3, 8, TimeSpan.FromMinutes(5));
        var checks = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException("Bootstrap pairing: " + label);
            checks++;
        }
        CsrBinding Binding() => new(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
        AuthenticatedTechnician Technician(DateTimeOffset? authenticatedAt = null) =>
            new("technician:avery", "webauthn", authenticatedAt ?? now);

        var store = new InMemoryBootstrapAttestationStore();
        var coordinator = new BootstrapPairingCoordinator(
            store, new Assets("asset-physical-001"), policy,
            new Codes("042731", "571002", "661993", "779421"));
        try
        {
            coordinator.Begin(new CsrBinding(RandomNumberGenerator.GetBytes(31), RandomNumberGenerator.GetBytes(32)), now);
            throw new InvalidOperationException("Bootstrap pairing: invalid binding was accepted");
        }
        catch (ArgumentException) { checks++; }
        var binding = Binding();
        var created = coordinator.Begin(binding, now);
        Check(created.Result == BootstrapPairingResult.Created && created.Ticket is not null,
            "creates bounded session");
        Check(created.Ticket!.DisplayCode == "042731" && created.Ticket.RequestId.Length == 32 &&
            created.Ticket.ExpiresAt == now.AddMinutes(10), "returns random display aid and expiry");
        var pending = coordinator.Lookup(created.Ticket.RequestId, now);
        Check(pending.Status == BootstrapPairingStatus.Pending && pending.AttemptsRemaining == 3,
            "lookup omits code and reports attempt budget");
        try
        {
            coordinator.Approve(created.Ticket.RequestId, "042731", "asset-physical-001",
                Technician() with { Capability = "facts-write" }, now);
            throw new InvalidOperationException("Facts capability reached pairing approval.");
        }
        catch (ArgumentException) { checks++; }
        Check(coordinator.Lookup(created.Ticket.RequestId, now).AttemptsRemaining == 3,
            "wrong capability is rejected before pairing lookup or mutation");
        var approved = coordinator.Approve(created.Ticket.RequestId, "042731", "asset-physical-001",
            Technician(), now.AddMinutes(1));
        Check(approved.Result == BootstrapPairingResult.Approved && approved.Audit is not null,
            "authenticated technician approves exact request");
        Check(approved.Audit!.TechnicianSubject == "technician:avery" &&
            approved.Audit.AuthenticationMethod == "webauthn" &&
            approved.Audit.Capability == "bootstrap-approve" &&
            approved.Audit.AuthoritativeAssetId == "asset-physical-001" &&
            approved.Audit.CsrSha256 == Convert.ToHexString(binding.CsrSha256) &&
            approved.Audit.SubjectPublicKeyInfoSha256 == Convert.ToHexString(binding.SubjectPublicKeyInfoSha256),
            "audit binds actor asset CSR and SPKI without code");
        Check(coordinator.Approve(created.Ticket.RequestId, "042731", "asset-physical-001",
            Technician(), now.AddMinutes(2)).Result == BootstrapPairingResult.InvalidState,
            "approval is single-use");
        Check(store.GetAttestedAsset(binding, now.AddMinutes(2)).AuthoritativeAssetId == "asset-physical-001",
            "approval reaches attestation seam");

        var locked = coordinator.Begin(Binding(), now).Ticket!;
        Check(coordinator.Approve(locked.RequestId, "000000", "asset-physical-001", Technician(), now).Result ==
            BootstrapPairingResult.InvalidCode, "wrong code consumes attempt");
        Check(coordinator.Approve(locked.RequestId, "bad", "asset-physical-001", Technician(), now).Result ==
            BootstrapPairingResult.InvalidCode, "malformed code consumes attempt without parsing detail");
        Check(coordinator.Approve(locked.RequestId, "999999", "asset-physical-001", Technician(), now).Result ==
            BootstrapPairingResult.AttemptsExhausted, "attempt budget locks session");
        Check(coordinator.Approve(locked.RequestId, locked.DisplayCode, "asset-physical-001", Technician(), now).Result ==
            BootstrapPairingResult.InvalidState, "correct code cannot recover locked session");

        var wrongAsset = coordinator.Begin(Binding(), now).Ticket!;
        Check(coordinator.Approve(wrongAsset.RequestId, wrongAsset.DisplayCode, "asset-invented", Technician(), now).Result ==
            BootstrapPairingResult.AssetUnavailable, "unverified asset rejected");
        Check(coordinator.Lookup(wrongAsset.RequestId, now).AttemptsRemaining == 2,
            "asset probing shares bounded attempt budget");
        Check(coordinator.Approve(wrongAsset.RequestId, wrongAsset.DisplayCode, "ASSET-PHYSICAL-001",
            Technician(), now).Result == BootstrapPairingResult.AssetUnavailable,
            "asset identity comparison is exact");

        var expiry = coordinator.Begin(Binding(), now).Ticket!;
        Check(coordinator.Approve(expiry.RequestId, expiry.DisplayCode, "asset-physical-001", Technician(now.AddMinutes(10)),
            now.AddMinutes(10)).Result == BootstrapPairingResult.Expired, "expiry boundary fails closed");
        Check(coordinator.Lookup(expiry.RequestId, now.AddMinutes(11)).Status == BootstrapPairingStatus.Expired,
            "expired status retained");

        var stale = new BootstrapPairingCoordinator(new InMemoryBootstrapAttestationStore(),
            new Assets("asset-physical-001"), policy, new Codes("310001"));
        var staleTicket = stale.Begin(Binding(), now).Ticket!;
        Check(stale.Approve(staleTicket.RequestId, staleTicket.DisplayCode, "asset-physical-001",
            Technician(now.AddMinutes(-6)), now).Result == BootstrapPairingResult.AuthenticationStale,
            "stale technician authentication rejected");
        Check(stale.Lookup(staleTicket.RequestId, now).AttemptsRemaining == 3,
            "authentication boundary fails before code attempt");
        Check(stale.Approve(staleTicket.RequestId, staleTicket.DisplayCode, "asset-physical-001",
            Technician(now.AddMinutes(1)), now).Result == BootstrapPairingResult.AuthenticationStale,
            "future technician authentication rejected");

        var duplicates = new BootstrapPairingCoordinator(new InMemoryBootstrapAttestationStore(),
            new Assets("asset-physical-001"), policy, new Codes("123456", "123456", "654321"));
        var first = duplicates.Begin(Binding(), now).Ticket!;
        var second = duplicates.Begin(Binding(), now).Ticket!;
        Check(first.DisplayCode == "123456" && second.DisplayCode == "654321",
            "active code collision retries to unique code");

        var concurrent = new BootstrapPairingCoordinator(new InMemoryBootstrapAttestationStore(),
            new Assets("asset-physical-001"), policy, new Codes("730001"));
        var concurrentTicket = concurrent.Begin(Binding(), now).Ticket!;
        var approvals = Enumerable.Range(0, 8).Select(_ => Task.Run(() => concurrent.Approve(
            concurrentTicket.RequestId, concurrentTicket.DisplayCode, "asset-physical-001",
            Technician(), now))).ToArray();
        Task.WaitAll(approvals);
        Check(approvals.Count(task => task.Result.Result == BootstrapPairingResult.Approved) == 1 &&
            approvals.Where(task => task.Result.Result != BootstrapPairingResult.Approved)
                .All(task => task.Result.Result == BootstrapPairingResult.InvalidState),
            "concurrent approvals have exactly one winner");

        var capacity = new BootstrapPairingCoordinator(new InMemoryBootstrapAttestationStore(),
            new Assets("asset-physical-001"), policy with { MaximumRetainedSessions = 1 },
            new Codes("800001"));
        Check(capacity.Begin(Binding(), now).Result == BootstrapPairingResult.Created,
            "first retained session admitted");
        Check(capacity.Begin(Binding(), now).Result == BootstrapPairingResult.CapacityExceeded,
            "retained session quota fails closed");

        Console.WriteLine($"Bootstrap technician pairing checks passed: {checks}.");
    }

    private sealed class Assets(params string[] ids) : IImmutableAssetCatalog
    {
        private readonly HashSet<string> values = new(ids, StringComparer.Ordinal);
        public bool Contains(string authoritativeAssetId) => values.Contains(authoritativeAssetId);
    }

    private sealed class Codes(params string[] values) : IBootstrapPairingCodeGenerator
    {
        private readonly Queue<string> remaining = new(values);
        public string Generate() => remaining.Dequeue();
    }
}
