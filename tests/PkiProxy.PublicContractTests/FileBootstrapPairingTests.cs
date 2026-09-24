using System.Security.Cryptography;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using PkiProxy.Domain;

internal static class FileBootstrapPairingTests
{
    internal static void Run()
    {
        if (!OperatingSystem.IsLinux())
        {
            Console.WriteLine("Durable pairing checks skipped: Linux filesystem semantics required.");
            return;
        }

        var now = DateTimeOffset.Parse("2026-09-13T18:00:00Z");
        var policy = new BootstrapPairingPolicy(TimeSpan.FromMinutes(10), 3, 8, TimeSpan.FromMinutes(5));
        var scratch = Directory.CreateTempSubdirectory("bootstrap-pairing-test-");
        File.SetUnixFileMode(scratch.FullName,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var checks = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException("Durable pairing: " + label);
            checks++;
        }
        CsrBinding Binding() => new(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
        AuthenticatedTechnician Technician(DateTimeOffset? at = null) => new("technician:avery", "webauthn", at ?? now);

        try
        {
            MarkerIoChecks(policy, Check);
            GraphChecks(policy, Check);
            var attestation = new InMemoryBootstrapAttestationStore();
            FileBootstrapPairingCoordinator Reopen(IBootstrapAttestationStore? store = null) =>
                new(scratch.FullName, store ?? attestation, new Assets("asset-physical-001"), policy,
                    new Codes("042731", "571002", "661993", "779421"));

            var binding = Binding();
            var created = Reopen().Begin(binding, now);
            Check(created.Result == BootstrapPairingResult.Created && created.Ticket is not null,
                "creates durable request");
            var ticket = created.Ticket!;
            Check(Reopen().Lookup(ticket.RequestId, now).Status == BootstrapPairingStatus.Pending,
                "pending state survives reopen");
            Check(Directory.EnumerateFiles(scratch.FullName).All(IsOwnerOnly),
                "all records are owner-only");
            Check(Directory.EnumerateFiles(scratch.FullName).All(path =>
                    !File.ReadAllText(path).Contains(ticket.DisplayCode, StringComparison.Ordinal)),
                "display code is never stored in plaintext");
            Check(Reopen().Begin(binding, now).Result == BootstrapPairingResult.AlreadyExists,
                "CSR binding cannot acquire a second transaction");

            Check(Reopen().Approve(ticket.RequestId, "000000", "asset-physical-001", Technician(), now).Result ==
                BootstrapPairingResult.InvalidCode, "wrong code consumes durable attempt");
            Check(Reopen().Lookup(ticket.RequestId, now).AttemptsRemaining == 2,
                "attempt budget survives reopen");
            Check(Reopen().Approve(ticket.RequestId, ticket.DisplayCode, "asset-invented", Technician(), now).Result ==
                BootstrapPairingResult.AssetUnavailable, "unknown asset consumes same budget");
            var approved = Reopen().Approve(ticket.RequestId, ticket.DisplayCode, "asset-physical-001",
                Technician(), now.AddMinutes(1));
            Check(approved.Result == BootstrapPairingResult.Approved &&
                approved.Audit?.AuthoritativeAssetId == "asset-physical-001", "third valid attempt can approve");
            Check(Reopen().Lookup(ticket.RequestId, now.AddMinutes(1)).Status == BootstrapPairingStatus.Approved,
                "approval survives reopen");
            Check(Reopen().Approve(ticket.RequestId, ticket.DisplayCode, "asset-physical-001",
                Technician(), now.AddMinutes(2)).Result == BootstrapPairingResult.InvalidState,
                "approved request cannot replay");
            Check(attestation.GetAttestedAsset(binding, now.AddMinutes(2)).AuthoritativeAssetId == "asset-physical-001",
                "durable claim reaches exact attestation binding");

            var uncertainRoot = Directory.CreateTempSubdirectory("bootstrap-pairing-uncertain-");
            File.SetUnixFileMode(uncertainRoot.FullName,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                var rejecting = new RejectAttestStore();
                var uncertain = new FileBootstrapPairingCoordinator(uncertainRoot.FullName, rejecting,
                    new Assets("asset-physical-001"), policy, new Codes("310001"));
                var uncertainTicket = uncertain.Begin(Binding(), now).Ticket!;
                Check(uncertain.Approve(uncertainTicket.RequestId, uncertainTicket.DisplayCode,
                        "asset-physical-001", Technician(), now).Result == BootstrapPairingResult.StoreRejected,
                    "attestation failure refuses approval");
                Check(new FileBootstrapPairingCoordinator(uncertainRoot.FullName, rejecting,
                        new Assets("asset-physical-001"), policy, new Codes("310002"))
                    .Lookup(uncertainTicket.RequestId, now).Status == BootstrapPairingStatus.ApprovalClaimed,
                    "uncertain transition remains claimed after restart");
            }
            finally { uncertainRoot.Delete(recursive: true); }

            var expiryRoot = Directory.CreateTempSubdirectory("bootstrap-pairing-expiry-");
            File.SetUnixFileMode(expiryRoot.FullName,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                var expiring = new FileBootstrapPairingCoordinator(expiryRoot.FullName,
                    new InMemoryBootstrapAttestationStore(), new Assets("asset-physical-001"), policy,
                    new Codes("410001"));
                var expiry = expiring.Begin(Binding(), now).Ticket!;
                Check(expiring.Approve(expiry.RequestId, expiry.DisplayCode, "asset-physical-001",
                    Technician(now.AddMinutes(10)), now.AddMinutes(10)).Result == BootstrapPairingResult.Expired,
                    "expiry boundary survives durable state");
            }
            finally { expiryRoot.Delete(recursive: true); }

            var raceRoot = Directory.CreateTempSubdirectory("bootstrap-pairing-race-");
            File.SetUnixFileMode(raceRoot.FullName,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                var raceStore = new InMemoryBootstrapAttestationStore();
                var first = new FileBootstrapPairingCoordinator(raceRoot.FullName, raceStore,
                    new Assets("asset-physical-001"), policy, new Codes("510001"));
                var raceTicket = first.Begin(Binding(), now).Ticket!;
                var contenders = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
                    new FileBootstrapPairingCoordinator(raceRoot.FullName, raceStore,
                        new Assets("asset-physical-001"), policy, new Codes("unused0"))
                    .Approve(raceTicket.RequestId, raceTicket.DisplayCode, "asset-physical-001",
                        Technician(), now))).ToArray();
                Task.WaitAll(contenders);
                Check(contenders.Count(task => task.Result.Result == BootstrapPairingResult.Approved) == 1,
                    "cross-instance approval has one winner");
                Check(contenders.Where(task => task.Result.Result != BootstrapPairingResult.Approved)
                    .All(task => task.Result.Result is BootstrapPairingResult.InvalidState or
                        BootstrapPairingResult.AttemptsExhausted), "losers receive no authority");
            }
            finally { raceRoot.Delete(recursive: true); }

            var quotaRoot = Directory.CreateTempSubdirectory("bootstrap-pairing-quota-");
            File.SetUnixFileMode(quotaRoot.FullName,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                var quota = new FileBootstrapPairingCoordinator(quotaRoot.FullName,
                    new InMemoryBootstrapAttestationStore(), new Assets("asset-physical-001"),
                    policy with { MaximumRetainedSessions = 1 }, new Codes("610001", "610002"));
                Check(quota.Begin(Binding(), now).Result == BootstrapPairingResult.Created, "first quota slot admitted");
                Check(quota.Begin(Binding(), now).Result == BootstrapPairingResult.CapacityExceeded,
                    "quota reservation remains fail closed");
            }
            finally { quotaRoot.Delete(recursive: true); }
        }
        finally { scratch.Delete(recursive: true); }
        Console.WriteLine($"Durable technician pairing checks passed: {checks}.");
    }

    private static void MarkerIoChecks(BootstrapPairingPolicy policy, Action<bool, string> check)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        // Every fault has an independent directory; retained corrupt markers must
        // not accidentally become the precondition of a later case.
        void WithStore(Action<string, FileBootstrapPairingCoordinator> action)
        {
            var root = Directory.CreateTempSubdirectory("pairing-marker-io-");
            File.SetUnixFileMode(root.FullName,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                action(root.FullName, new FileBootstrapPairingCoordinator(root.FullName,
                    new InMemoryBootstrapAttestationStore(), new Assets("asset-physical-001"), policy));
            }
            finally { ReadProbe.DuringRead = null; root.Delete(recursive: true); }
        }

        void Reject(Action action, string label)
        {
            try { action(); }
            catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException)
            { check(true, label); return; }
            check(false, label);
        }

        WithStore((root, store) =>
        {
            var path = Path.Combine(root, "marker.json");
            var value = new WriteProbe { DuringWrite = () =>
            {
                check(!File.Exists(path), "final name is absent throughout serialization");
                check(Directory.EnumerateFiles(root).All(IsOwnerOnly), "staging is owner-only");
            } };
            check(InvokeCreate(store, "marker.json", value), "complete marker published");
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            check(document.RootElement.GetProperty("Value").GetString() == "complete",
                "final marker contains complete JSON");
            check(Directory.EnumerateFiles(root).Count() == 1, "successful publication removes staging");
        });
        WithStore((root, store) =>
        {
            Reject(() => InvokeCreate(store, "marker.json", new WriteProbe
                { DuringWrite = () => throw new IOException("synthetic write failure") }),
                "serialization failure propagates");
            check(!Directory.EnumerateFiles(root).Any(), "serialization failure leaves no partial final or staging file");
        });
        WithStore((root, store) =>
        {
            var contenders = Enumerable.Range(0, 12).Select(i => Task.Run(() =>
                InvokeCreate(store, "marker.json", new IoRecord(i.ToString())))).ToArray();
            Task.WaitAll(contenders);
            check(contenders.Count(task => task.Result) == 1, "atomic publication has exactly one winner");
            var winner = InvokeRead<IoRecord>(store, "marker.json");
            check(!InvokeCreate(store, "marker.json", new IoRecord("replacement")) &&
                InvokeRead<IoRecord>(store, "marker.json") == winner, "EEXIST preserves and reads the winner");
            check(Directory.EnumerateFiles(root).Count() == 1 && Directory.EnumerateFiles(root).All(IsOwnerOnly),
                "concurrent publication retains one owner-only final file");
        });

        foreach (var json in new[] { "", new string(' ', 16_385), "[]", "null", "{", "{\"Value\":\"a\",\"Value\":\"b\"}",
                     "{\"Value\":\"a\",\"Extra\":true}", "{}" })
        {
            WithStore((root, store) =>
            {
                WritePrivate(Path.Combine(root, "marker.json"), json);
                Reject(() => InvokeRead<IoRecord>(store, "marker.json"), "strict generic reader rejects malformed or unbounded JSON");
                Reject(() => InvokeCreate(store, "marker.json", new IoRecord("safe")), "collision cannot hide corrupt winner");
            });
        }
        WithStore((root, store) =>
        {
            var path = Path.Combine(root, "marker.json");
            WritePrivate(path, "{\"Value\":\"a\"}");
            foreach (var mode in new[] { UnixFileMode.UserRead, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead,
                         UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute })
            {
                File.SetUnixFileMode(path, mode);
                Reject(() => InvokeRead<IoRecord>(store, "marker.json"), "reader requires exact mode 0600");
            }
        });
        foreach (var dangling in new[] { false, true })
        {
            WithStore((root, store) =>
            {
                var target = Path.Combine(root, "target.json");
                if (!dangling) WritePrivate(target, "{\"Value\":\"a\"}");
                var path = Path.Combine(root, "marker.json");
                File.CreateSymbolicLink(path, target);
                check(File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint), "Linux symlink exposes reparse attribute");
                Reject(() => InvokeRead<IoRecord>(store, "marker.json"), "reader rejects symlink including dangling target");
                Reject(() => InvokeCreate(store, "marker.json", new IoRecord("safe")), "publication loser rejects symlink");
            });
        }
        WithStore((root, store) =>
        {
            Directory.CreateDirectory(Path.Combine(root, "marker.json"));
            Reject(() => InvokeRead<IoRecord>(store, "marker.json"), "directory cannot be a regular marker");
        });
        foreach (var replacement in new[] { "{\"Value\":\"b\"}", "{\"Value\":\"longer\"}" })
        {
            WithStore((root, store) =>
            {
                var path = Path.Combine(root, "marker.json");
                WritePrivate(path, "{\"Value\":\"a\"}");
                var timestamp = File.GetLastWriteTimeUtc(path);
                ReadProbe.DuringRead = () =>
                {
                    var swap = Path.Combine(root, "swap.json");
                    WritePrivate(swap, replacement);
                    File.SetLastWriteTimeUtc(swap, timestamp);
                    File.Move(swap, path, overwrite: true);
                };
                Reject(() => InvokeRead<ReadProbe>(store, "marker.json"),
                    "reader rejects changed/swapped marker even with preserved write time");
            });
        }

        foreach (var stage in new[] { "created", "ready", "attempt-01", "approved" })
        {
            WithStore((root, store) =>
            {
                var now = DateTimeOffset.Parse("2026-09-13T18:00:00Z");
                var binding = new CsrBinding(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
                var ticket = store.Begin(binding, now).Ticket!;
                check(store.Lookup(ticket.RequestId, now).Status == BootstrapPairingStatus.Pending, "valid marker path read before mutation");
                WritePrivate(Path.Combine(root, "pairing-" + ticket.RequestId + "." + stage + ".json"), "{}");
                Reject(() => store.Lookup(ticket.RequestId, now), "same coordinator rechecks marker structure");
                var reopened = new FileBootstrapPairingCoordinator(root, new InMemoryBootstrapAttestationStore(),
                    new Assets("asset-physical-001"), policy);
                Reject(() => reopened.Lookup(ticket.RequestId, now), "reopened coordinator rejects malformed marker");
            });
        }
    }

    private static void GraphChecks(BootstrapPairingPolicy policy, Action<bool, string> check)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var now = DateTimeOffset.Parse("2026-09-13T18:00:00Z");
        const string asset = "asset-physical-001";
        var technician = new AuthenticatedTechnician("technician:avery", "webauthn", now);

        void Edit(string path, Action<JsonObject> edit)
        {
            var value = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
            edit(value);
            WritePrivate(path, value.ToJsonString());
        }
        void Reject(Action action, string label)
        {
            try { action(); }
            catch (Exception error) when (error is IOException or InvalidDataException)
            { check(true, label); return; }
            check(false, label);
        }
        void Corrupt(string label, Action<string, BootstrapPairingTicket> corrupt, bool claim = false,
            bool checkReservationLosers = false)
        {
            var root = Directory.CreateTempSubdirectory("pairing-graph-");
            File.SetUnixFileMode(root.FullName,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                var attestations = new InMemoryBootstrapAttestationStore();
                FileBootstrapPairingCoordinator Reopen(string code = "823741") => new(root.FullName, attestations,
                    new Assets(asset), policy, new Codes(code, "823742"));
                var store = Reopen();
                var binding = new CsrBinding(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
                var ticket = store.Begin(binding, now).Ticket!;
                if (claim)
                {
                    check(store.Approve(ticket.RequestId, ticket.DisplayCode, asset, technician, now.AddMinutes(1))
                        .Result == BootstrapPairingResult.Approved, label + ": valid approval setup");
                    File.Delete(Stage(root.FullName, ticket, "approved"));
                }
                check(store.Lookup(ticket.RequestId, now.AddMinutes(2)).Status == (claim
                    ? BootstrapPairingStatus.ApprovalClaimed : BootstrapPairingStatus.Pending), label + ": valid graph before mutation");
                corrupt(root.FullName, ticket);
                void RejectBegin(FileBootstrapPairingCoordinator reader, CsrBinding candidate, string message)
                {
                    var retained = Directory.GetFiles(root.FullName).ToHashSet(StringComparer.Ordinal);
                    try
                    {
                        var result = reader.Begin(candidate, now.AddMinutes(2));
                        // A valid orphan reservation can only return a refusal;
                        // it is never repaired or used to grant a new ticket.
                        check(result.Result != BootstrapPairingResult.Created && result.Ticket is null, message);
                    }
                    catch (Exception error) when (error is IOException or InvalidDataException)
                    { check(true, message); }
                    finally
                    {
                        // Begin can retain new orphan reservations before it sees
                        // the fault. Remove only this test call's additions.
                        foreach (var path in Directory.GetFiles(root.FullName).Where(path => !retained.Contains(path)))
                            File.Delete(path);
                    }
                }
                foreach (var reader in new[] { store, Reopen() })
                {
                    Reject(() => reader.Lookup(ticket.RequestId, now.AddMinutes(2)), label + ": lookup rejects graph");
                    Reject(() => reader.Approve(ticket.RequestId, ticket.DisplayCode, asset, technician, now.AddMinutes(2)),
                        label + ": approval rejects graph");
                    RejectBegin(reader, binding, label + ": binding publication loser rejects graph");
                }
                if (checkReservationLosers)
                    foreach (var code in new[] { "823741", "823742" })
                        RejectBegin(Reopen(code), new CsrBinding(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32)),
                            label + ": code/slot publication loser rejects graph");
            }
            finally { root.Delete(recursive: true); }
        }
        static string Stage(string root, BootstrapPairingTicket ticket, string stage) =>
            Path.Combine(root, "pairing-" + ticket.RequestId + "." + stage + ".json");
        void Attempt(string root, BootstrapPairingTicket ticket, int ordinal, DateTimeOffset at) =>
            WritePrivate(Stage(root, ticket, "attempt-" + ordinal.ToString("D2")), JsonSerializer.Serialize(
                new { Version = 1, ticket.RequestId, Attempt = ordinal, At = at }));

        Corrupt("v1 created record", (root, ticket) => Edit(Stage(root, ticket, "created"), value =>
        {
            value["Version"] = 1;
            value.Remove("CodeReservationSha256");
        }));
        foreach (var field in new[] { "CsrSha256", "SpkiSha256", "CodeSalt", "CodeVerifierSha256", "CodeReservationSha256" })
            Corrupt("invalid created hash " + field, (root, ticket) =>
                Edit(Stage(root, ticket, "created"), value => value[field] = "invalid"));
        foreach (var field in new[] { "Slot", "MaximumAttempts" })
            Corrupt("created policy bound " + field, (root, ticket) =>
                Edit(Stage(root, ticket, "created"), value => value[field] = 0));
        Corrupt("created lifetime policy bound", (root, ticket) =>
            Edit(Stage(root, ticket, "created"), value => value["ExpiresAt"] = now.AddMinutes(11)));
        foreach (var prefix in new[] { "pairing-binding-", "pairing-code-", "pairing-slot-" })
        {
            Corrupt("missing " + prefix, (root, _) => File.Delete(Directory.GetFiles(root, prefix + "*.json").Single()));
            Corrupt("mismatched " + prefix, (root, _) => Edit(Directory.GetFiles(root, prefix + "*.json").Single(),
                value => value["RequestId"] = new string('A', 32)));
            Corrupt("reservation version " + prefix, (root, _) => Edit(Directory.GetFiles(root, prefix + "*.json").Single(),
                value => value["Version"] = 2));
        }
        Corrupt("missing ready", (root, ticket) => File.Delete(Stage(root, ticket, "ready")), checkReservationLosers: true);
        Corrupt("ready and failed", (root, ticket) =>
            WritePrivate(Stage(root, ticket, "failed"), File.ReadAllText(Stage(root, ticket, "ready"))));
        foreach (var stage in new[] { "ready", "failed" })
        {
            foreach (var field in new[] { "Version", "RequestId", "TechnicianSubject", "AuthenticationMethod", "AssetId", "CsrSha256", "SpkiSha256", "TechnicianCapability", "At" })
                Corrupt("invalid " + stage + " " + field, (root, ticket) =>
                {
                    if (stage == "failed") File.Move(Stage(root, ticket, "ready"), Stage(root, ticket, "failed"));
                    Edit(Stage(root, ticket, stage), value =>
                    {
                        if (field == "Version") value[field] = 2;
                        else if (field == "At") value[field] = now.AddSeconds(-1);
                        else value[field] = "unexpected";
                    });
                });
        }
        Corrupt("attempt gap", (root, ticket) => Attempt(root, ticket, 2, now));
        Corrupt("attempt wrong ordinal", (root, ticket) =>
        {
            Attempt(root, ticket, 1, now);
            Edit(Stage(root, ticket, "attempt-01"), value => value["Attempt"] = 2);
        });
        foreach (var field in new[] { "Version", "RequestId" })
            Corrupt("attempt wrong " + field, (root, ticket) =>
            {
                Attempt(root, ticket, 1, now);
                Edit(Stage(root, ticket, "attempt-01"), value =>
                {
                    if (field == "Version") value[field] = 2;
                    else value[field] = new string('A', 32);
                });
            });
        foreach (var at in new[] { now.AddSeconds(-1), now.AddMinutes(10) })
            Corrupt("attempt lifecycle bound", (root, ticket) => Attempt(root, ticket, 1, at));
        Corrupt("attempt time regression", (root, ticket) =>
        {
            Attempt(root, ticket, 1, now.AddSeconds(2));
            Attempt(root, ticket, 2, now.AddSeconds(1));
        });
        Corrupt("attempt beyond budget", (root, ticket) => Attempt(root, ticket, 11, now));
        foreach (var field in new[] { "TechnicianSubject", "AuthenticationMethod", "AssetId", "CsrSha256", "SpkiSha256", "TechnicianCapability" })
        {
            Corrupt("null claim " + field, (root, ticket) => Edit(Stage(root, ticket, "claimed"),
                value => value[field] = null), claim: true);
            Corrupt("malformed claim " + field, (root, ticket) => Edit(Stage(root, ticket, "claimed"),
                value => value[field] = "\n"), claim: true);
        }
        foreach (var field in new[] { "TechnicianSubject", "AuthenticationMethod", "AssetId" })
            Corrupt("unbounded claim " + field, (root, ticket) => Edit(Stage(root, ticket, "claimed"),
                value => value[field] = new string('a', field == "AuthenticationMethod" ? 65 : 257)), claim: true);
        Corrupt("claimed before ready", (root, ticket) =>
        {
            Edit(Stage(root, ticket, "ready"), value => value["At"] = now.AddSeconds(30));
            Edit(Stage(root, ticket, "claimed"), value => value["At"] = now.AddSeconds(20));
        }, claim: true);
        Corrupt("claimed at expiry", (root, ticket) => Edit(Stage(root, ticket, "claimed"),
            value => value["At"] = ticket.ExpiresAt), claim: true);
        Corrupt("claimed before latest attempt", (root, ticket) => Attempt(root, ticket, 2, now.AddMinutes(2)), claim: true);
        Corrupt("claimed without attempts", (root, ticket) => File.Delete(Stage(root, ticket, "attempt-01")), claim: true);
        Corrupt("claim with failed", (root, ticket) => File.Move(Stage(root, ticket, "ready"), Stage(root, ticket, "failed")), claim: true);
        Corrupt("approved without claim", (root, ticket) => File.Move(Stage(root, ticket, "claimed"), Stage(root, ticket, "approved")), claim: true);
        foreach (var field in new[] { "Version", "RequestId", "TechnicianSubject", "AuthenticationMethod", "AssetId", "CsrSha256", "SpkiSha256", "TechnicianCapability", "At" })
            Corrupt("approval mismatch " + field, (root, ticket) =>
            {
                WritePrivate(Stage(root, ticket, "approved"), File.ReadAllText(Stage(root, ticket, "claimed")));
                Edit(Stage(root, ticket, "approved"), value =>
                {
                    if (field == "Version") value[field] = 1;
                    else if (field == "At") value[field] = now.AddMinutes(2);
                    else value[field] = new string('A', 64);
                });
            }, claim: true);

        var timeRoot = Directory.CreateTempSubdirectory("pairing-graph-time-");
        File.SetUnixFileMode(timeRoot.FullName,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var attestations = new InMemoryBootstrapAttestationStore();
            var store = new FileBootstrapPairingCoordinator(timeRoot.FullName, attestations, new Assets(asset), policy);
            var ticket = store.Begin(new CsrBinding(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32)), now).Ticket!;
            Reject(() => store.Lookup(ticket.RequestId, now.AddSeconds(-1)), "lookup rejects future created state");
            Edit(Stage(timeRoot.FullName, ticket, "ready"), value => value["At"] = now.AddSeconds(1));
            Reject(() => store.Lookup(ticket.RequestId, now), "lookup rejects future ready state");
            Attempt(timeRoot.FullName, ticket, 1, now.AddSeconds(2));
            Reject(() => store.Lookup(ticket.RequestId, now.AddSeconds(1)), "lookup rejects future attempt state");
            check(store.Approve(ticket.RequestId, ticket.DisplayCode, asset, technician, now.AddSeconds(3))
                .Result == BootstrapPairingResult.Approved, "chronological graph approves");
            Reject(() => store.Lookup(ticket.RequestId, now.AddSeconds(2)), "lookup rejects future approved state");
            File.Delete(Stage(timeRoot.FullName, ticket, "approved"));
            Reject(() => store.Lookup(ticket.RequestId, now.AddSeconds(2)), "lookup rejects future claim state");
            check(store.Lookup(ticket.RequestId, now.AddSeconds(3)).Status == BootstrapPairingStatus.ApprovalClaimed,
                "claimed state is visible at its timestamp");
            File.Delete(Stage(timeRoot.FullName, ticket, "claimed"));
            File.Delete(Stage(timeRoot.FullName, ticket, "attempt-01"));
            File.Delete(Stage(timeRoot.FullName, ticket, "attempt-02"));
            File.Move(Stage(timeRoot.FullName, ticket, "ready"), Stage(timeRoot.FullName, ticket, "failed"));
            check(store.Lookup(ticket.RequestId, now.AddSeconds(3)).Status == BootstrapPairingStatus.Failed,
                "coherent failed transaction remains failed");
        }
        finally { timeRoot.Delete(recursive: true); }
    }

    private static void WritePrivate(string path, string value)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Create, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
        });
        using var writer = new StreamWriter(stream);
        writer.Write(value);
    }

    private static bool InvokeCreate<T>(FileBootstrapPairingCoordinator store, string name, T value) =>
        (bool)InvokeGeneric(store, "Create", typeof(T), [name, value!])!;

    private static T InvokeRead<T>(FileBootstrapPairingCoordinator store, string name) =>
        (T)InvokeGeneric(store, "ReadJson", typeof(T), [name])!;

    private static object? InvokeGeneric(FileBootstrapPairingCoordinator store, string method, Type type, object[] args)
    {
        try
        {
            return typeof(FileBootstrapPairingCoordinator).GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!
                .MakeGenericMethod(type).Invoke(store, args);
        }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
            throw;
        }
    }

    private sealed record IoRecord(string Value);
    private sealed class WriteProbe
    {
        internal Action DuringWrite { get; init; } = () => { };
        public string Value { get { DuringWrite(); return "complete"; } }
    }
    private sealed class ReadProbe
    {
        internal static Action? DuringRead { get; set; }
        public string Value { get; }
        public ReadProbe(string value) { Value = value; DuringRead?.Invoke(); }
    }

    private sealed class Assets(params string[] ids) : IImmutableAssetCatalog
    {
        private readonly HashSet<string> values = new(ids, StringComparer.Ordinal);
        public bool Contains(string authoritativeAssetId) => values.Contains(authoritativeAssetId);
    }

    private static bool IsOwnerOnly(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        return File.GetUnixFileMode(path) == (UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private sealed class Codes(params string[] values) : IBootstrapPairingCodeGenerator
    {
        private readonly Queue<string> remaining = new(values);
        public string Generate() => remaining.Dequeue();
    }

    private sealed class RejectAttestStore : IBootstrapAttestationStore
    {
        private readonly InMemoryBootstrapAttestationStore inner = new();
        public BootstrapStoreResult Record(CsrBinding binding, DateTimeOffset now, TimeSpan lifetime) =>
            inner.Record(binding, now, lifetime);
        public BootstrapStoreResult Attest(CsrBinding binding, string authoritativeAssetId, DateTimeOffset now) =>
            BootstrapStoreResult.InvalidState;
        public BootstrapConsumeResult Consume(CsrBinding binding, DateTimeOffset now) => inner.Consume(binding, now);
        public BootstrapAttestationLookup GetAttestedAsset(CsrBinding binding, DateTimeOffset now) =>
            inner.GetAttestedAsset(binding, now);
    }
}
