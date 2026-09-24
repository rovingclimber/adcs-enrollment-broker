using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PkiProxy.Domain;

internal sealed record BootstrapIntakeQuota(int MaximumActiveRecords, long MaximumActiveBytes,
    int MaximumHistoryRecords, long MaximumHistoryBytes)
{
    internal const long MinimumReservationBytes = 2_097_153;

    internal void Validate()
    {
        if (MaximumActiveRecords is < 1 or > 10_000 || MaximumHistoryRecords < MaximumActiveRecords ||
            MaximumHistoryRecords > 100_000)
            throw new ArgumentOutOfRangeException(nameof(MaximumActiveRecords));
        if (MaximumActiveBytes < MinimumReservationBytes || MaximumHistoryBytes < MaximumActiveBytes ||
            MaximumHistoryBytes > 64L * 1024 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(MaximumActiveBytes));
    }
}

// Serializes anonymous intake across processes and reserves the complete
// worst-case transaction footprint before any CSR bytes are published. The
// immutable reservation is the recovery root for a crash during cross-store
// commit. Expired anonymous entries may be collected; trusted/approved entries
// remain retained and continue to consume the explicit history budget.
[SupportedOSPlatform("linux")]
internal sealed class FileBootstrapIntakeLedger
{
    internal enum RecoveryDisposition
    {
        Removed,
        RetainActive,
        Trusted
    }

    internal const long FixedTransactionReservationBytes = 2_097_152;
    private const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode FileModeOwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const int MaximumRecordBytes = 4096;
    private const int LockExclusive = 2;
    private const int LockUnlock = 8;
    private const int OpenReadWrite = 2;
    private const int OpenCreate = 0x40;
    private const int OpenCloseOnExec = 0x80000;
    private const int OpenNoFollow = 0x20000;
    private const uint OwnerReadWrite = 0x180; // 0600
    private const string StoreBindingName = ".stores.json";
    private static readonly JsonSerializerOptions Options = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 4
    };

    private readonly string directory;
    private readonly BootstrapIntakeQuota quota;
    private readonly Action<string>? fault;

    internal FileBootstrapIntakeLedger(string directory, BootstrapIntakeQuota quota,
        Action<string>? fault = null)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux local intake ledger required.");
        if (!Path.IsPathFullyQualified(directory)) throw new ArgumentException("Absolute intake directory required.");
        this.directory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        this.quota = quota ?? throw new ArgumentNullException(nameof(quota));
        this.fault = fault;
        quota.Validate();
        CheckDirectory();
        EnsureLockFile();
    }

    internal Lease? TryReserve(string transactionId, CsrBinding binding, int csrLength,
        DateTimeOffset now, TimeSpan lifetime, Func<Reservation, RecoveryDisposition> recover)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(recover);
        if (!IsId(transactionId) || !binding.HasExpectedLengths() || csrLength is < 1 or > FileBootstrapEnrollmentTransactionStore.MaximumCsrBytes ||
            lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(24))
            throw new ArgumentException("Valid bounded intake reservation required.");

        var locked = AcquireLock();
        Lease? lease = null;
        try
        {
            RecoverAbandoned(now, recover);
            var records = ReadReservations();
            var active = records.Where(value => !Exists(TrustedName(value.TransactionId))).ToArray();
            var bytes = checked(FixedTransactionReservationBytes + csrLength);
            if (active.Length >= quota.MaximumActiveRecords ||
                active.Sum(value => value.ReservedBytes) > quota.MaximumActiveBytes - bytes ||
                records.Count >= quota.MaximumHistoryRecords ||
                records.Sum(value => value.ReservedBytes) > quota.MaximumHistoryBytes - bytes)
            {
                locked.Dispose();
                return null;
            }

            var ordinal = Enumerable.Range(1, quota.MaximumActiveRecords)
                .First(candidate => active.All(value => value.Ordinal != candidate));
            var snapshot = binding.Snapshot();
            var reservation = new Reservation(1, transactionId,
                Convert.ToHexString(snapshot.CsrSha256), Convert.ToHexString(snapshot.SubjectPublicKeyInfoSha256),
                csrLength, bytes, ordinal, now, now.Add(lifetime));
            fault?.Invoke("before-reservation-publish");
            CreateRequired(ReservedName(transactionId), reservation);
            lease = new Lease(this, locked, reservation, recover);
            fault?.Invoke("after-reservation-publish");
            return lease;
        }
        catch
        {
            if (lease is not null) lease.Dispose(); else locked.Dispose();
            throw;
        }
    }

    // A v4 ledger owns one fresh state-store generation. This prevents an
    // operator from attaching legacy unmetered v3 files to an empty ledger or
    // later redirecting a populated ledger to different stores.
    internal void BindStoreGeneration(params string[] storeDirectories)
    {
        if (storeDirectories is not { Length: 3 })
            throw new ArgumentException("Exactly three bootstrap stores are required.", nameof(storeDirectories));
        var stores = storeDirectories.Select(CanonicalDirectory).ToArray();
        if (stores.Append(directory).Distinct(StringComparer.Ordinal).Count() != stores.Length + 1)
            throw new InvalidDataException("Bootstrap store generation requires distinct directories.");

        using var locked = AcquireLock();
        if (Exists(StoreBindingName))
        {
            var existing = ReadJson<StoreBinding>(StoreBindingName);
            if (existing.Version != 1 || existing.StoreDirectories is null ||
                !existing.StoreDirectories.SequenceEqual(stores, StringComparer.Ordinal))
                throw new InvalidDataException("Bootstrap store generation binding changed.");
            return;
        }

        if (ReadReservations().Count != 0)
            throw new InvalidDataException("Unbound intake ledger contains transaction records.");
        foreach (var store in stores)
        {
            CheckPrivateDirectory(store);
            if (System.IO.Directory.EnumerateFileSystemEntries(store).Any())
                throw new InvalidDataException("Legacy bootstrap state requires a fresh bounded generation.");
        }
        CreateRequired(StoreBindingName, new StoreBinding(1, stores));
    }

    internal void MarkTrusted(string transactionId, DateTimeOffset now)
    {
        using var locked = AcquireLock();
        var reservation = ReadReservation(transactionId);
        if (now < reservation.CreatedAt || now >= reservation.ExpiresAt)
            throw new InvalidOperationException("Expired intake cannot become trusted history.");
        if (Exists(TrustedName(transactionId)))
        {
            Validate(ReadJson<Transition>(TrustedName(transactionId)), transactionId, reservation);
            return;
        }
        CreateRequired(TrustedName(transactionId), new Transition(1, transactionId, now));
    }

    internal Snapshot Inspect(DateTimeOffset now)
    {
        using var locked = AcquireLock();
        var records = ReadReservations();
        var trusted = records.Count(value => Exists(TrustedName(value.TransactionId)));
        return new(records.Count - trusted,
            records.Where(value => !Exists(TrustedName(value.TransactionId))).Sum(value => value.ReservedBytes),
            records.Count, records.Sum(value => value.ReservedBytes),
            records.Count(value => Exists(CommittedName(value.TransactionId))),
            trusted,
            records.Count(value => value.ExpiresAt <= now && !Exists(TrustedName(value.TransactionId))));
    }

    private void RecoverAbandoned(DateTimeOffset now, Func<Reservation, RecoveryDisposition> recover)
    {
        foreach (var reservation in ReadReservations())
        {
            var committed = Exists(CommittedName(reservation.TransactionId));
            var trusted = Exists(TrustedName(reservation.TransactionId));
            if (trusted && !committed) throw new InvalidDataException("Trusted intake has no commit marker.");
            if (committed && reservation.ExpiresAt > now) continue;
            if (trusted) continue;

            // Holding the process-shared lock proves there is no live Begin
            // still constructing this request. Recovery validates and removes
            // only the exact untrusted graph before releasing its reservation.
            var disposition = recover(reservation);
            if (disposition != RecoveryDisposition.Removed)
            {
                if (!committed)
                    throw new InvalidDataException("Uncommitted intake unexpectedly acquired trusted state.");
                if (disposition == RecoveryDisposition.Trusted)
                    CreateRequired(TrustedName(reservation.TransactionId),
                        new Transition(1, reservation.TransactionId,
                            now < reservation.ExpiresAt ? now : reservation.ExpiresAt.AddTicks(-1)));
                continue;
            }
            DeleteIfPresent(CommittedName(reservation.TransactionId));
            DeleteIfPresent(ReservedName(reservation.TransactionId));
            SyncDirectory();
        }
    }

    private List<Reservation> ReadReservations()
    {
        CheckDirectory();
        var transitionIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var path in System.IO.Directory.EnumerateFileSystemEntries(directory))
        {
            var name = Path.GetFileName(path);
            if (name == ".intake.lock") { _ = CheckRegularSingleLink(path, allowEmpty: true); continue; }
            if (name == StoreBindingName)
            {
                var binding = ReadJson<StoreBinding>(StoreBindingName);
                if (binding.Version != 1 || binding.StoreDirectories is not { Length: 3 } ||
                    binding.StoreDirectories.Any(value => string.IsNullOrWhiteSpace(value) || !Path.IsPathFullyQualified(value)) ||
                    binding.StoreDirectories.Distinct(StringComparer.Ordinal).Count() != 3)
                    throw new InvalidDataException("Invalid bootstrap store generation binding.");
                continue;
            }
            if (name.StartsWith(".intake-write-", StringComparison.Ordinal) && name.EndsWith(".tmp", StringComparison.Ordinal))
            {
                _ = CheckRegularSingleLink(path, allowEmpty: true);
                File.Delete(path);
                continue;
            }
            if (TryLedgerName(name, ".reserved.json", out _)) continue;
            if (TryLedgerName(name, ".committed.json", out var committedId))
            { transitionIds.Add(committedId!); continue; }
            if (TryLedgerName(name, ".trusted.json", out var trustedId))
            { transitionIds.Add(trustedId!); continue; }
            throw new InvalidDataException("Unexpected intake ledger entry.");
        }
        var records = new List<Reservation>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var path in System.IO.Directory.EnumerateFiles(directory, "intake-*.reserved.json"))
        {
            var name = Path.GetFileName(path);
            if (name.Length != 32 + "intake-.reserved.json".Length)
                throw new InvalidDataException("Unexpected intake ledger record.");
            var id = name[7..^14];
            var record = ReadJson<Reservation>(name);
            Validate(record, id);
            if (!ids.Add(record.TransactionId)) throw new InvalidDataException("Duplicate intake reservation identity.");
            if (Exists(CommittedName(id))) Validate(ReadJson<Transition>(CommittedName(id)), id, record);
            if (Exists(TrustedName(id))) Validate(ReadJson<Transition>(TrustedName(id)), id, record);
            records.Add(record);
        }
        if (transitionIds.Any(id => !ids.Contains(id)))
            throw new InvalidDataException("Intake transition has no reservation.");
        if (records.Where(value => !Exists(TrustedName(value.TransactionId)))
            .GroupBy(value => value.Ordinal).Any(group => group.Count() != 1))
            throw new InvalidDataException("Duplicate active intake ordinal.");
        return records;
    }

    private static bool TryLedgerName(string name, string suffix, out string? id)
    {
        id = null;
        if (!name.StartsWith("intake-", StringComparison.Ordinal) || !name.EndsWith(suffix, StringComparison.Ordinal))
            return false;
        var candidate = name[7..^suffix.Length];
        if (!IsId(candidate)) return false;
        id = candidate;
        return true;
    }

    private Reservation ReadReservation(string id)
    {
        if (!IsId(id)) throw new ArgumentException("Exact transaction identifier required.", nameof(id));
        var value = ReadJson<Reservation>(ReservedName(id));
        Validate(value, id);
        if (!Exists(CommittedName(id))) throw new InvalidDataException("Intake is not committed.");
        return value;
    }

    private void Validate(Reservation value, string id)
    {
        if (value.Version != 1 || value.TransactionId != id || !IsId(id) || !IsHash(value.CsrSha256) ||
            !IsHash(value.SpkiSha256) || value.CsrLength is < 1 or > FileBootstrapEnrollmentTransactionStore.MaximumCsrBytes ||
            value.ReservedBytes != FixedTransactionReservationBytes + value.CsrLength || value.Ordinal < 1 ||
            value.Ordinal > quota.MaximumActiveRecords ||
            value.ExpiresAt <= value.CreatedAt || value.ExpiresAt - value.CreatedAt > TimeSpan.FromHours(24))
            throw new InvalidDataException("Invalid intake reservation.");
    }

    private static void Validate(Transition value, string id, Reservation reservation)
    {
        if (value.Version != 1 || value.TransactionId != id || value.At < reservation.CreatedAt || value.At >= reservation.ExpiresAt)
            throw new InvalidDataException("Invalid intake transition.");
    }

    private void Commit(Reservation reservation, DateTimeOffset now)
    {
        if (now < reservation.CreatedAt || now >= reservation.ExpiresAt)
            throw new InvalidOperationException("Intake commit is outside its lifetime.");
        fault?.Invoke("before-commit-publish");
        CreateRequired(CommittedName(reservation.TransactionId), new Transition(1, reservation.TransactionId, now));
        fault?.Invoke("after-commit-publish");
    }

    private void Abort(Reservation reservation, Func<Reservation, RecoveryDisposition> recover)
    {
        try
        {
            fault?.Invoke("before-abort-cleanup");
            if (recover(reservation) != RecoveryDisposition.Removed) return;
            DeleteIfPresent(CommittedName(reservation.TransactionId));
            DeleteIfPresent(ReservedName(reservation.TransactionId));
            SyncDirectory();
            fault?.Invoke("after-abort-cleanup");
        }
        catch
        {
            // Preserve the durable reservation on uncertainty. A later locked
            // recovery pass retries cleanup and the quota remains charged.
        }
    }

    private FileLock AcquireLock()
    {
        CheckDirectory();
        var path = Path.Combine(directory, ".intake.lock");
        var fd = Open(path, OpenReadWrite | OpenCreate | OpenCloseOnExec | OpenNoFollow, OwnerReadWrite);
        if (fd < 0) throw new IOException("Cannot open intake lock.");
        try
        {
            CheckRegularSingleLink(path, allowEmpty: true);
            if (Flock(fd, LockExclusive) != 0) throw new IOException("Cannot acquire intake lock.");
            return new FileLock(fd);
        }
        catch { _ = Close(fd); throw; }
    }

    private void EnsureLockFile()
    {
        using var locked = AcquireLock();
        if (File.GetUnixFileMode(Path.Combine(directory, ".intake.lock")) != FileModeOwnerOnly)
            throw new IOException("Owner-only intake lock required.");
    }

    private void CreateRequired(string name, object value)
    {
        var staging = ".intake-write-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + ".tmp";
        var stagingPath = Path.Combine(directory, staging);
        var finalPath = Path.Combine(directory, name);
        try
        {
            using (var stream = new FileStream(stagingPath, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
                Options = FileOptions.WriteThrough, UnixCreateMode = FileModeOwnerOnly
            }))
            {
                JsonSerializer.Serialize(stream, value, Options);
                stream.Flush(flushToDisk: true);
            }
            CheckRegularSingleLink(stagingPath, allowEmpty: false);
            if (!LinuxAtomicPublish.TryRenameNoReplace(stagingPath, finalPath))
                throw new IOException("Intake marker already exists or cannot be published.");
            SyncDirectory();
        }
        finally { if (File.Exists(stagingPath)) File.Delete(stagingPath); }
    }

    private T ReadJson<T>(string name)
    {
        var path = Path.Combine(directory, name);
        var info = CheckRegularSingleLink(path, allowEmpty: false);
        if (info.Length > MaximumRecordBytes) throw new IOException("Oversized intake marker.");
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length != info.Length) throw new IOException("Intake marker changed while reading.");
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Intake marker must be an object.");
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate intake marker property.");
            return document.RootElement.Deserialize<T>(Options) ?? throw new InvalidDataException("Missing intake marker.");
        }
        catch (JsonException error) { throw new InvalidDataException("Invalid intake marker JSON.", error); }
    }

    private bool Exists(string name)
    {
        var path = Path.Combine(directory, name);
        if (!File.Exists(path)) return false;
        _ = CheckRegularSingleLink(path, allowEmpty: false);
        return true;
    }

    private void DeleteIfPresent(string name)
    {
        var path = Path.Combine(directory, name);
        if (!File.Exists(path)) return;
        _ = CheckRegularSingleLink(path, allowEmpty: false);
        File.Delete(path);
    }

    private static FileInfo CheckRegularSingleLink(string path, bool allowEmpty)
    {
        var info = new FileInfo(path);
        info.Refresh();
        if (!info.Exists || info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            (!allowEmpty && info.Length <= 0) || File.GetUnixFileMode(path) != FileModeOwnerOnly)
            throw new IOException("Invalid private intake file.");
        if (!LinuxFileLinkGuard.IsSingleRegular(path))
            throw new IOException("Intake file must be one regular non-hardlinked inode.");
        return info;
    }

    private void CheckDirectory()
    {
        CheckPrivateDirectory(directory);
    }

    private static string CanonicalDirectory(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathFullyQualified(value))
            throw new ArgumentException("Absolute bootstrap store directory required.", nameof(value));
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(value));
    }

    private static void CheckPrivateDirectory(string value)
    {
        var info = new DirectoryInfo(value);
        info.Refresh();
        if (!info.Exists || info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            File.GetUnixFileMode(value) != DirectoryMode)
            throw new IOException("Pre-provisioned owner-only bootstrap directory required.");
    }

    private void SyncDirectory()
    {
        var fd = Open(directory, 0x10000 | OpenCloseOnExec | OpenNoFollow, 0);
        if (fd < 0) throw new IOException("Cannot open intake directory for durability.");
        int closeResult;
        try { if (Fsync(fd) != 0) throw new IOException("Cannot flush intake directory."); }
        finally { closeResult = Close(fd); }
        if (closeResult != 0) throw new IOException("Cannot close intake directory.");
    }

    private static string ReservedName(string id) => "intake-" + id + ".reserved.json";
    private static string CommittedName(string id) => "intake-" + id + ".committed.json";
    private static string TrustedName(string id) => "intake-" + id + ".trusted.json";
    private static bool IsId(string? value) => value is { Length: 32 } && value.All(char.IsAsciiHexDigit);
    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);

    internal sealed record Reservation(int Version, string TransactionId, string CsrSha256, string SpkiSha256,
        int CsrLength, long ReservedBytes, int Ordinal, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);
    private sealed record Transition(int Version, string TransactionId, DateTimeOffset At);
    private sealed record StoreBinding(int Version, string[] StoreDirectories);
    internal sealed record Snapshot(int ActiveRecords, long ActiveReservedBytes,
        int HistoryRecords, long HistoryReservedBytes, int Committed, int Trusted, int ExpiredAnonymous);

    internal sealed class Lease : IDisposable
    {
        private readonly FileBootstrapIntakeLedger owner;
        private IDisposable? locked;
        private Func<Reservation, RecoveryDisposition>? recover;
        internal Reservation Value { get; }
        internal int Ordinal => Value.Ordinal;
        internal Lease(FileBootstrapIntakeLedger owner, IDisposable locked, Reservation value,
            Func<Reservation, RecoveryDisposition> recover)
        { this.owner = owner; this.locked = locked; Value = value; this.recover = recover; }
        internal void Commit(DateTimeOffset now)
        {
            ObjectDisposedException.ThrowIf(locked is null, this);
            owner.Commit(Value, now);
            recover = null;
            locked.Dispose();
            locked = null;
        }
        public void Dispose()
        {
            if (locked is null) return;
            if (recover is not null) owner.Abort(Value, recover);
            locked.Dispose();
            locked = null;
            recover = null;
        }
    }

    private sealed class FileLock : IDisposable
    {
        private int descriptor;
        internal FileLock(int descriptor) => this.descriptor = descriptor;
        public void Dispose()
        {
            var fd = Interlocked.Exchange(ref descriptor, -1);
            if (fd < 0) return;
            _ = Flock(fd, LockUnlock);
            _ = Close(fd);
        }
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)] private static extern int Open(string path, int flags, uint mode);
    [DllImport("libc", EntryPoint = "flock", SetLastError = true)] private static extern int Flock(int fd, int operation);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)] private static extern int Fsync(int fd);
    [DllImport("libc", EntryPoint = "close")] private static extern int Close(int fd);
}

[SupportedOSPlatform("linux")]
internal static class LinuxAtomicPublish
{
    private const int CurrentWorkingDirectory = -100;
    private const uint NoReplace = 1;

    internal static bool TryRenameNoReplace(string stagingPath, string finalPath)
    {
        if (RenameAt2(CurrentWorkingDirectory, stagingPath, CurrentWorkingDirectory, finalPath, NoReplace) == 0)
            return true;
        if (Marshal.GetLastPInvokeError() == 17) return false;
        throw new IOException("Cannot atomically publish owner-only state.");
    }

    [DllImport("libc", EntryPoint = "renameat2", SetLastError = true)]
    private static extern int RenameAt2(int oldDirectory, string oldPath,
        int newDirectory, string newPath, uint flags);
}

[SupportedOSPlatform("linux")]
internal static class LinuxFileLinkGuard
{
    internal static bool IsSingleRegular(string path) =>
        Lstat(path, out var stat) == 0 && stat.LinkCount == 1 && (stat.Mode & 0xF000) == 0x8000;

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStat
    {
        internal ulong Device;
        internal ulong Inode;
        internal ulong LinkCount;
        internal uint Mode;
        internal uint User;
        internal uint Group;
        internal uint Padding;
        internal ulong DeviceType;
        internal long Size;
        internal long BlockSize;
        internal long Blocks;
        internal long AccessSeconds;
        internal long AccessNanoseconds;
        internal long ModifySeconds;
        internal long ModifyNanoseconds;
        internal long ChangeSeconds;
        internal long ChangeNanoseconds;
        internal long Reserved1;
        internal long Reserved2;
        internal long Reserved3;
    }

    [DllImport("libc", EntryPoint = "lstat", SetLastError = true)]
    private static extern int Lstat(string path, out LinuxStat stat);
}
