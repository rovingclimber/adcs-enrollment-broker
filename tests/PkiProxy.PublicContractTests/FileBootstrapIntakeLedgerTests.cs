using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using PkiProxy.Domain;

internal static class FileBootstrapIntakeLedgerTests
{
    internal static void Run()
    {
        if (!OperatingSystem.IsLinux())
        {
            Console.WriteLine("Bootstrap intake ledger checks skipped: Linux filesystem semantics required.");
            return;
        }

        var checks = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException("Bootstrap intake ledger: " + label);
            checks++;
        }

        using (var generationRoot = Root())
        {
            var intakeDirectory = PrivateDirectory(generationRoot.Path, "intake");
            var attestationDirectory = PrivateDirectory(generationRoot.Path, "attestations");
            var pairingDirectory = PrivateDirectory(generationRoot.Path, "pairings");
            var transactionDirectory = PrivateDirectory(generationRoot.Path, "transactions");
            var generation = new FileBootstrapIntakeLedger(intakeDirectory,
                new BootstrapIntakeQuota(1, 3 * 1024 * 1024, 4, 12 * 1024 * 1024));
            generation.BindStoreGeneration(attestationDirectory, pairingDirectory, transactionDirectory);
            generation.BindStoreGeneration(attestationDirectory, pairingDirectory, transactionDirectory);
            Check(Directory.EnumerateFiles(intakeDirectory).Select(Path.GetFileName)
                    .Order(StringComparer.Ordinal).SequenceEqual([".intake.lock", ".stores.json"]),
                "fresh store generation is durably bound and exactly replayable");
        }

        using (var legacyRoot = Root())
        {
            var intakeDirectory = PrivateDirectory(legacyRoot.Path, "intake");
            var attestationDirectory = PrivateDirectory(legacyRoot.Path, "attestations");
            var pairingDirectory = PrivateDirectory(legacyRoot.Path, "pairings");
            var transactionDirectory = PrivateDirectory(legacyRoot.Path, "transactions");
            var legacy = Path.Combine(transactionDirectory, "legacy.json");
            File.WriteAllText(legacy, "{}");
            File.SetUnixFileMode(legacy, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            try
            {
                new FileBootstrapIntakeLedger(intakeDirectory,
                        new BootstrapIntakeQuota(1, 3 * 1024 * 1024, 4, 12 * 1024 * 1024))
                    .BindStoreGeneration(attestationDirectory, pairingDirectory, transactionDirectory);
                throw new InvalidOperationException("Legacy unmetered store generation was accepted.");
            }
            catch (InvalidDataException) { checks++; }
        }
        var now = DateTimeOffset.Parse("2026-09-20T12:00:00Z");
        using var root = Root();
        var quota = new BootstrapIntakeQuota(1, 3 * 1024 * 1024, 2, 6 * 1024 * 1024);
        var ledger = new FileBootstrapIntakeLedger(root.Path, quota);
        var firstBinding = Binding();
        var firstId = Id();
        var first = ledger.TryReserve(firstId, firstBinding, 1024, now, TimeSpan.FromMinutes(10), Removed);
        Check(first is not null, "first request reserves capacity");
        first!.Commit(now);
        Check(ledger.Inspect(now) is { ActiveRecords: 1, HistoryRecords: 1, Committed: 1, Trusted: 0 },
            "committed anonymous request remains quota charged");
        Check(ledger.TryReserve(Id(), Binding(), 1024, now, TimeSpan.FromMinutes(10), Removed) is null,
            "exact active record capacity rejects without residue");

        ledger.MarkTrusted(firstId, now.AddMinutes(1));
        Check(ledger.Inspect(now.AddMinutes(1)) is { ActiveRecords: 0, HistoryRecords: 1, Trusted: 1 },
            "durable trusted transition releases active capacity but retains history budget");
        using (var second = ledger.TryReserve(Id(), Binding(), 1024, now.AddMinutes(1), TimeSpan.FromMinutes(10), Removed))
        {
            Check(second is not null, "released active ordinal is reusable");
            second!.Commit(now.AddMinutes(1));
        }
        Check(ledger.TryReserve(Id(), Binding(), 1024, now.AddMinutes(1), TimeSpan.FromMinutes(10), Removed) is null,
            "active capacity remains bounded by the untrusted request");

        using var byteRoot = Root();
        const int exactCsrBytes = 8192;
        var exactBytes = FileBootstrapIntakeLedger.FixedTransactionReservationBytes + exactCsrBytes;
        var byteLedger = new FileBootstrapIntakeLedger(byteRoot.Path,
            new BootstrapIntakeQuota(2, exactBytes, 4, exactBytes * 4));
        var byteLease = byteLedger.TryReserve(Id(), Binding(), exactCsrBytes, now, TimeSpan.FromMinutes(10), Removed)!;
        byteLease.Commit(now);
        Check(byteLedger.TryReserve(Id(), Binding(), 1, now, TimeSpan.FromMinutes(10), Removed) is null,
            "one byte beyond the exact active budget is rejected without overbooking");
        try
        {
            _ = byteLedger.TryReserve(Id(), Binding(), FileBootstrapEnrollmentTransactionStore.MaximumCsrBytes + 1,
                now, TimeSpan.FromMinutes(10), Removed);
            throw new InvalidOperationException("Oversized CSR reservation was accepted.");
        }
        catch (ArgumentException) { checks++; }

        using var historyRoot = Root();
        var historyLedger = new FileBootstrapIntakeLedger(historyRoot.Path,
            new BootstrapIntakeQuota(1, 3 * 1024 * 1024, 1, 3 * 1024 * 1024));
        var historyId = Id();
        var historyLease = historyLedger.TryReserve(historyId, Binding(), 1024, now, TimeSpan.FromMinutes(10), Removed)!;
        historyLease.Commit(now);
        historyLedger.MarkTrusted(historyId, now.AddMinutes(1));
        Check(historyLedger.Inspect(now.AddMinutes(1)).ActiveRecords == 0 &&
            historyLedger.TryReserve(Id(), Binding(), 1024, now.AddMinutes(1), TimeSpan.FromMinutes(10), Removed) is null,
            "trusted history releases active capacity but cannot bypass the total history ceiling");

        using var duplicateRoot = Root();
        var duplicateLedger = new FileBootstrapIntakeLedger(duplicateRoot.Path,
            new BootstrapIntakeQuota(2, 6 * 1024 * 1024, 4, 12 * 1024 * 1024));
        var duplicateId = Id();
        var duplicateLease = duplicateLedger.TryReserve(duplicateId, Binding(), 1024, now, TimeSpan.FromMinutes(10), Removed)!;
        duplicateLease.Commit(now);
        try
        {
            _ = duplicateLedger.TryReserve(duplicateId, Binding(), 1024, now, TimeSpan.FromMinutes(10), Removed);
            throw new InvalidOperationException("Duplicate transaction ID was accepted.");
        }
        catch (IOException) { }
        Check(duplicateLedger.Inspect(now).HistoryRecords == 1,
            "duplicate ID failure cannot create or replace a reservation");

        using var expiredRoot = Root();
        var expired = new FileBootstrapIntakeLedger(expiredRoot.Path,
            new BootstrapIntakeQuota(1, 3 * 1024 * 1024, 4, 12 * 1024 * 1024));
        var expiredLease = expired.TryReserve(Id(), Binding(), 2048, now, TimeSpan.FromMinutes(1), Removed)!;
        expiredLease.Commit(now);
        var collected = 0;
        var replacement = expired.TryReserve(Id(), Binding(), 2048, now.AddMinutes(1), TimeSpan.FromMinutes(1), _ =>
        { Interlocked.Increment(ref collected); return FileBootstrapIntakeLedger.RecoveryDisposition.Removed; });
        Check(replacement is not null && collected == 1, "expired anonymous state is collected before replacement");
        replacement!.Commit(now.AddMinutes(1));
        Check(expired.Inspect(now.AddMinutes(1)).ActiveRecords == 1,
            "expired anonymous state is collected under the lock before replacement");

        using var ambiguousRoot = Root();
        var ambiguous = new FileBootstrapIntakeLedger(ambiguousRoot.Path,
            new BootstrapIntakeQuota(1, 3 * 1024 * 1024, 4, 12 * 1024 * 1024));
        var ambiguousLease = ambiguous.TryReserve(Id(), Binding(), 2048, now, TimeSpan.FromMinutes(1), Removed)!;
        ambiguousLease.Commit(now);
        Check(ambiguous.TryReserve(Id(), Binding(), 2048, now.AddMinutes(1), TimeSpan.FromMinutes(1),
                _ => FileBootstrapIntakeLedger.RecoveryDisposition.RetainActive) is null &&
            ambiguous.Inspect(now.AddMinutes(1)) is { ActiveRecords: 1, Trusted: 0 },
            "ambiguous approved-without-binding recovery stays charged as active");

        using var recoveredTrustRoot = Root();
        var recoveredTrust = new FileBootstrapIntakeLedger(recoveredTrustRoot.Path,
            new BootstrapIntakeQuota(1, 3 * 1024 * 1024, 4, 12 * 1024 * 1024));
        var recoveredTrustLease = recoveredTrust.TryReserve(Id(), Binding(), 2048, now,
            TimeSpan.FromMinutes(1), Removed)!;
        recoveredTrustLease.Commit(now);
        using var afterTrustedRecovery = recoveredTrust.TryReserve(Id(), Binding(), 2048,
            now.AddMinutes(1), TimeSpan.FromMinutes(1),
            _ => FileBootstrapIntakeLedger.RecoveryDisposition.Trusted);
        Check(afterTrustedRecovery is not null,
            "recovery accepts a new active request only after proving both trusted transitions");
        afterTrustedRecovery!.Commit(now.AddMinutes(1));
        Check(recoveredTrust.Inspect(now.AddMinutes(1)) is { ActiveRecords: 1, HistoryRecords: 2, Trusted: 1 },
            "recovery releases active capacity only after the caller proves both trusted transitions");

        using var raceRoot = Root();
        var raceQuota = new BootstrapIntakeQuota(1, 3 * 1024 * 1024, 8, 24 * 1024 * 1024);
#pragma warning disable CA1416 // The enclosing runtime guard applies before these Linux worker tasks are created.
        var contenders = Enumerable.Range(0, 24)
            .Select(_ => Task.Run(() => ReserveRace(raceRoot.Path, raceQuota, now))).ToArray();
#pragma warning restore CA1416
        Task.WaitAll(contenders);
        Check(contenders.Count(value => value.Result) == 1 &&
            new FileBootstrapIntakeLedger(raceRoot.Path, raceQuota).Inspect(now).ActiveRecords == 1,
            "cross-instance exact-capacity race has one durable winner");

        using var abortRoot = Root();
        var abort = new FileBootstrapIntakeLedger(abortRoot.Path, raceQuota);
        using (abort.TryReserve(Id(), Binding(), 4096, now, TimeSpan.FromMinutes(10), Removed)) { }
        Check(abort.Inspect(now).HistoryRecords == 0 &&
            Directory.EnumerateFiles(abortRoot.Path).Select(Path.GetFileName).SequenceEqual([".intake.lock"]),
            "failed request leaves only the fixed lock and no durable residue");

        foreach (var stage in new[] { "before-reservation-publish", "after-reservation-publish" })
        {
            using var faultRoot = Root();
            var faulted = new FileBootstrapIntakeLedger(faultRoot.Path, raceQuota,
                observed => { if (observed == stage) throw new IOException("simulated storage fault"); });
            try
            {
                _ = faulted.TryReserve(Id(), Binding(), 4096, now, TimeSpan.FromMinutes(10), Removed);
                throw new InvalidOperationException("Injected reservation fault did not fail.");
            }
            catch (IOException) { }
            Check(new FileBootstrapIntakeLedger(faultRoot.Path, raceQuota).Inspect(now).HistoryRecords == 0,
                stage + " leaves no durable request residue");
        }

        foreach (var stage in new[] { "before-commit-publish", "after-commit-publish" })
        {
            using var faultRoot = Root();
            var faulted = new FileBootstrapIntakeLedger(faultRoot.Path, raceQuota,
                observed => { if (observed == stage) throw new IOException("simulated durability fault"); });
            try
            {
                using var lease = faulted.TryReserve(Id(), Binding(), 4096, now, TimeSpan.FromMinutes(10), Removed)!;
                lease.Commit(now);
                throw new InvalidOperationException("Injected commit fault did not fail.");
            }
            catch (IOException) { }
            Check(new FileBootstrapIntakeLedger(faultRoot.Path, raceQuota).Inspect(now).HistoryRecords == 0,
                stage + " rolls back the unaccepted transaction");
        }

        using var restartRoot = Root();
        var interrupted = new FileBootstrapIntakeLedger(restartRoot.Path, raceQuota,
            stage => { if (stage == "before-abort-cleanup") throw new IOException("simulated process loss"); });
        using (interrupted.TryReserve(Id(), Binding(), 4096, now, TimeSpan.FromMinutes(10), Removed)) { }
        Check(new FileBootstrapIntakeLedger(restartRoot.Path, raceQuota).Inspect(now).HistoryRecords == 1,
            "uncertain abort remains quota charged");
        var recovered = new FileBootstrapIntakeLedger(restartRoot.Path, raceQuota)
            .TryReserve(Id(), Binding(), 4096, now, TimeSpan.FromMinutes(10), Removed);
        Check(recovered is not null, "restart reconciliation removes abandoned uncommitted reservation");
        recovered!.Commit(now);

        using var linkRoot = Root();
        var linked = new FileBootstrapIntakeLedger(linkRoot.Path, raceQuota);
        var linkedId = Id();
        var linkedLease = linked.TryReserve(linkedId, Binding(), 4096, now, TimeSpan.FromMinutes(10), Removed)!;
        linkedLease.Commit(now);
        Check(Link(Path.Combine(linkRoot.Path, "intake-" + linkedId + ".reserved.json"),
            Path.Combine(linkRoot.Path, "intake-" + Id() + ".reserved.json")) == 0,
            "hardlink attack fixture is created");
        try
        {
            _ = linked.Inspect(now);
            throw new InvalidOperationException("Hardlinked reservation was accepted.");
        }
        catch (IOException) { checks++; }

        Console.WriteLine($"Bootstrap intake ledger checks passed ({checks}).");
    }

    private static string Id() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
    private static CsrBinding Binding() => new(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
    [SupportedOSPlatform("linux")]
    private static FileBootstrapIntakeLedger.RecoveryDisposition Removed(FileBootstrapIntakeLedger.Reservation _) =>
        FileBootstrapIntakeLedger.RecoveryDisposition.Removed;

    [SupportedOSPlatform("linux")]
    private static string PrivateDirectory(string parent, string name)
    {
        var directory = Directory.CreateDirectory(Path.Combine(parent, name));
        File.SetUnixFileMode(directory.FullName,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return directory.FullName;
    }

    [SupportedOSPlatform("linux")]
    private static bool ReserveRace(string path, BootstrapIntakeQuota quota, DateTimeOffset now)
    {
        var candidate = new FileBootstrapIntakeLedger(path, quota);
        var lease = candidate.TryReserve(Id(), Binding(), 4096, now, TimeSpan.FromMinutes(10), Removed);
        if (lease is null) return false;
        lease.Commit(now);
        return true;
    }

    [SupportedOSPlatform("linux")]
    private static TemporaryRoot Root()
    {
        var root = Directory.CreateTempSubdirectory("bootstrap-intake-");
        File.SetUnixFileMode(root.FullName,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return new(root);
    }

    private sealed class TemporaryRoot(DirectoryInfo directory) : IDisposable
    {
        internal string Path => directory.FullName;
        public void Dispose() => directory.Delete(recursive: true);
    }

    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int Link(string oldPath, string newPath);
}
