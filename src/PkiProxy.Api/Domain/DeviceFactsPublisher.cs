using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace PkiProxy.Domain;

internal sealed record FactsPublication(string Transaction, long Revision, string PreviousSha256,
    string PublishedSha256, string RecoveryDirectory);
internal sealed record FactsRecoverySummary(int Committed, int RecoveredCommitted, int RecoveredAborted);

// Linux operator-side publisher. All writers must share its advisory lock.
// Never called by enrollment routes or the draft-only workbench.
internal static partial class DeviceFactsPublisher
{
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectory = PrivateFile | UnixFileMode.UserExecute;
    private const UnixFileMode UntrustedWrite = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
    private const string HistoryName = ".facts-history";
    private const string HistoryLockName = ".facts-history.publish.lock";
    private const string BundleStagingName = ".bundle-staging";
    private const string OutcomeStagingName = ".outcome-staging";
    private const string BeforeName = "before.json";
    private const string AfterName = "after.json";
    private const string IntentName = "intent.json";
    private const string CommittedName = "committed.json";
    private const string AbortedName = "aborted.json";
    private const int MaximumFactsBytes = 1_048_576;
    private const int MaximumRecordBytes = 65_536;
    private const int MaximumHistoryEntries = 10_000;
    private const long MaximumHistoryBytes = 128L * MaximumFactsBytes;
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 8
    };

    internal static FactsPublication Publish(string target, ReadOnlyMemory<byte> draft,
        string expectedSourceHash, string expectedDraftHash, Action<string>? checkpoint = null,
        string? operatorIdentity = null, string? operatorCapability = null)
    {
        if (operatorIdentity is not null && !ValidOperatorIdentity(operatorIdentity))
            throw new ArgumentException("Bounded authenticated operator identity required.", nameof(operatorIdentity));
        if (operatorCapability is not null &&
            !string.Equals(operatorCapability, PkiProxy.Authentication.TechnicianCapabilities.FactsWrite,
                StringComparison.Ordinal))
            throw new ArgumentException("Exact facts-write capability required.", nameof(operatorCapability));
        if (operatorIdentity is null && operatorCapability is not null)
            throw new ArgumentException("Operator capability requires an authenticated identity.");
        return Publish(target, draft, expectedSourceHash, expectedDraftHash, checkpoint,
            (operatorIdentity, operatorCapability), (MaximumHistoryEntries, MaximumHistoryBytes));
    }

    // Exercise admission boundaries on small synthetic histories. Callers cannot raise the limits.
    internal static FactsPublication Publish(string target, ReadOnlyMemory<byte> draft,
        string expectedSourceHash, string expectedDraftHash, (int Entries, long Bytes) lowerHistoryLimits) =>
        Publish(target, draft, expectedSourceHash, expectedDraftHash, null, (null, null),
            (Math.Clamp(lowerHistoryLimits.Entries, 1, MaximumHistoryEntries),
                Math.Min(lowerHistoryLimits.Bytes, MaximumHistoryBytes)));

    private static FactsPublication Publish(string target, ReadOnlyMemory<byte> draft,
        string expectedSourceHash, string expectedDraftHash, Action<string>? checkpoint,
        (string? Identity, string? Capability) actor, (int Entries, long Bytes) limits)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Facts publication requires Linux.");
        var (operatorIdentity, operatorCapability) = actor;
        if (!Path.IsPathFullyQualified(target)) throw new ArgumentException("Absolute target required.");
        target = Path.GetFullPath(target);
        var parent = CheckPublicationDirectory(target);
        CheckFile(target);
        using var guard = AcquireLock(target + ".publish.lock");

        var current = Read(target);
        if (draft.Length is 0 or > MaximumFactsBytes)
            throw new InvalidDataException("Unsupported draft facts file size.");
        VerifyHash(current, expectedSourceHash, "Source changed; review the current facts.");
        VerifyHash(draft.Span, expectedDraftHash, "Draft differs from the reviewed file.");
        var revision = ValidateDraft(current, draft);
        checkpoint?.Invoke("validated");
        var mode = File.GetUnixFileMode(target);
        var history = Path.Combine(parent, HistoryName);
        var id = Guid.NewGuid().ToString("N");
        var recovery = Path.Combine(history, id);
        var sourceHash = Convert.ToHexString(SHA256.HashData(current));
        var draftHash = Convert.ToHexString(SHA256.HashData(draft.Span));
        var receipt = new FactsPublication(id, revision, sourceHash, draftHash, recovery);
        var intent = JsonSerializer.SerializeToUtf8Bytes(new RecoveryIntent(1, receipt,
            Path.GetFileName(target), GetUid(), DateTimeOffset.UtcNow, operatorIdentity, operatorCapability));
        if (intent.Length > MaximumRecordBytes) throw new InvalidDataException("Facts intent exceeds its size limit.");
        // Reserve a bounded outcome and a pending copy even if a crash leaves that copy retained.
        var prospectiveBytes = current.Length + 2L * draft.Length + intent.Length + MaximumRecordBytes;
        using var historyGuard = AcquireLock(Path.Combine(parent, HistoryLockName));
        CheckHistoryAdmission(target, history, prospectiveBytes, limits);
        System.IO.Directory.CreateDirectory(history, PrivateDirectory);
        CheckPrivateDirectory(history);
        StageBundle(history, recovery, current, draft, intent, checkpoint);
        SyncDirectory(parent);
        checkpoint?.Invoke("bundle-published");
        var pending = PendingPath(parent, id);
        WriteNew(pending, draft.Span, mode);
        SyncDirectory(parent);
        checkpoint?.Invoke("before-rename");
        // Cooperating writers are serialized. Detect out-of-band edits up to here.
        // No claim of atomic CAS against writers which deliberately ignore the lock.
        CheckFile(target);
        VerifyHash(Read(target), sourceHash, "Source changed during preparation; publication refused.");
        File.Move(pending, target, overwrite: true); // Same-directory atomic rename.
        SyncDirectory(parent);
        checkpoint?.Invoke("after-rename");
        VerifyHash(Read(target), draftHash, "Published file changed; reconcile retained recovery records.");
        WriteOutcome(recovery, CommittedName, JsonSerializer.SerializeToUtf8Bytes(new {
            Version = 1, Transaction = id, PublishedSha256 = draftHash,
            OperatorIdentity = operatorIdentity, OperatorCapability = operatorCapability,
            CommittedAt = DateTimeOffset.UtcNow }), checkpoint);
        return receipt;
    }

    internal static void Revalidate(string target, string expectedSourceHash, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Facts revalidation requires Linux.");
        if (!Path.IsPathFullyQualified(target)) throw new ArgumentException("Absolute target required.");
        target = Path.GetFullPath(target);
        _ = CheckPublicationDirectory(target);
        using var guard = AcquireLock(target + ".publish.lock");
        if (GetPathStatus(target) is not { IsSingleRegular: true } entry ||
            (entry.Permissions & UntrustedWrite) != 0)
            throw new IOException("Existing operator-controlled regular facts file required.");
        using var file = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        VerifyHash(Read(file), expectedSourceHash, "Source changed during connector refresh; revalidation refused.");
        cancellationToken.ThrowIfCancellationRequested();
        // The digest covers the revision. A rename after open must not give its replacement this timestamp.
        var handle = file.SafeFileHandle;
        File.SetLastWriteTimeUtc(handle, DateTime.UtcNow);
        RandomAccess.FlushToDisk(handle);
    }

    [SupportedOSPlatform("linux")]
    private static void StageBundle(string history, string recovery, ReadOnlyMemory<byte> current,
        ReadOnlyMemory<byte> draft, byte[] intent, Action<string>? checkpoint)
    {
        var staging = Path.Combine(history, BundleStagingName);
        System.IO.Directory.CreateDirectory(staging, PrivateDirectory);
        CheckPrivateDirectory(staging);
        WriteNew(Path.Combine(staging, BeforeName), current.Span, PrivateFile);
        checkpoint?.Invoke("bundle-staging");
        WriteNew(Path.Combine(staging, AfterName), draft.Span, PrivateFile);
        WriteNew(Path.Combine(staging, IntentName), intent, PrivateFile);
        SyncDirectory(staging);
        if (!LinuxAtomicPublish.TryRenameNoReplace(staging, recovery))
            throw new IOException("Facts recovery directory already exists.");
        SyncDirectory(history);
    }

    // Resolve only outcomes proved by durable images and the current target.
    internal static FactsRecoverySummary Reconcile(string target)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Facts recovery requires Linux.");
        target = Path.GetFullPath(target);
        var parent = Path.GetDirectoryName(target)!;
        CheckDirectory(parent);
        CheckFile(target);
        using var guard = AcquireLock(target + ".publish.lock");
        var history = Path.Combine(parent, HistoryName);
        if (GetPathStatus(history) is null) return new(0, 0, 0);
        using var historyGuard = AcquireLock(Path.Combine(parent, HistoryLockName));
        var directories = HistoryDirectories(history, MaximumHistoryEntries);
        var staging = Path.Combine(history, BundleStagingName);
        if (GetPathStatus(staging) is not null)
            DiscardBundleStaging(staging);
        // A previous process can stop after a rename but before its directory sync.
        SyncDirectory(history);
        SyncDirectory(parent);
        var committed = 0;
        var recoveredCommitted = 0;
        var recoveredAborted = 0;
        foreach (var recovery in directories.Order(StringComparer.Ordinal))
        {
            var intent = ReadIntent(target, recovery);
            VerifyRecoveryImage(recovery, BeforeName, intent.Publication.PreviousSha256);
            VerifyRecoveryImage(recovery, AfterName, intent.Publication.PublishedSha256);
            var outcome = ReadOutcome(recovery, intent);
            var outcomeStaging = Path.Combine(recovery, OutcomeStagingName);
            if (GetPathStatus(outcomeStaging) is not null)
            {
                CheckScratchFile(outcomeStaging);
                File.Delete(outcomeStaging);
            }
            if (outcome is null)
            {
                outcome = RecoverOutcome(target, recovery, intent);
                if (outcome == CommittedName)
                {
                    recoveredCommitted++;
                    continue;
                }
                recoveredAborted++;
                continue;
            }
            SyncDirectory(recovery);
            if (outcome == CommittedName) committed++;
            else recoveredAborted++;
        }
        return new(committed, recoveredCommitted, recoveredAborted);
    }

    [SupportedOSPlatform("linux")]
    private static string RecoverOutcome(string target, string recovery, RecoveryIntent intent)
    {
        var publication = intent.Publication;
        var currentHash = Convert.ToHexString(SHA256.HashData(Read(target)));
        if (currentHash == publication.PublishedSha256)
        {
            WriteOutcome(recovery, CommittedName, JsonSerializer.SerializeToUtf8Bytes(new RecoveryCommit(1,
                publication.Transaction, publication.PublishedSha256, DateTimeOffset.UtcNow,
                true, intent.OperatorIdentity, intent.OperatorCapability)));
            return CommittedName;
        }
        if (currentHash != publication.PreviousSha256)
            throw new IOException("Facts recovery target matches neither retained image.");
        WriteOutcome(recovery, AbortedName, JsonSerializer.SerializeToUtf8Bytes(new RecoveryAbort(1,
            publication.Transaction, publication.PreviousSha256, intent.OperatorIdentity,
            DateTimeOffset.UtcNow, intent.OperatorCapability)));
        return AbortedName;
    }

    [SupportedOSPlatform("linux")]
    private static void WriteOutcome(string recovery, string name, ReadOnlySpan<byte> bytes,
        Action<string>? checkpoint = null)
    {
        var staging = Path.Combine(recovery, OutcomeStagingName);
        WriteNew(staging, bytes, PrivateFile);
        checkpoint?.Invoke("outcome-staged");
        if (!LinuxAtomicPublish.TryRenameNoReplace(staging, Path.Combine(recovery, name)))
            throw new IOException("Facts recovery outcome already exists.");
        SyncDirectory(recovery);
    }

    private static void CheckHistoryAdmission(string target, string history, long bytes,
        (int Entries, long Bytes) limits)
    {
        if (bytes > limits.Bytes)
            throw new IOException("Facts history byte limit reached.");
        var directories = GetPathStatus(history) is null ? [] : HistoryDirectories(history, limits.Entries - 1);
        if (GetPathStatus(Path.Combine(history, BundleStagingName)) is not null)
            throw new IOException("Unpublished facts recovery staging requires reconciliation.");
        var parent = Path.GetDirectoryName(target)!;
        foreach (var recovery in directories)
        {
            var intent = ReadIntent(target, recovery);
            var outcome = ReadOutcome(recovery, intent);
            if (outcome is null || GetPathStatus(Path.Combine(recovery, OutcomeStagingName)) is not null)
                throw new IOException("Unresolved facts recovery requires reconciliation.");
            bytes += PrivateFileSize(Path.Combine(recovery, BeforeName), MaximumFactsBytes)
                + PrivateFileSize(Path.Combine(recovery, AfterName), MaximumFactsBytes)
                + PrivateFileSize(Path.Combine(recovery, IntentName), MaximumRecordBytes)
                + PrivateFileSize(Path.Combine(recovery, outcome), MaximumRecordBytes)
                + PendingSize(PendingPath(parent, intent.Publication.Transaction));
            if (bytes > limits.Bytes)
                throw new IOException("Facts history byte limit reached.");
        }
        // A marker observed after an interrupted marker rename might not have been synced yet.
        foreach (var recovery in directories)
            SyncDirectory(recovery);
    }

    private static List<string> HistoryDirectories(string history, int maximumEntries)
    {
        CheckPrivateDirectory(history);
        var directories = new List<string>();
        foreach (var entry in System.IO.Directory.EnumerateFileSystemEntries(history))
        {
            var name = Path.GetFileName(entry);
            if (name == BundleStagingName) continue;
            if (!Guid.TryParseExact(name, "N", out _))
                throw new IOException("Invalid facts recovery directory.");
            if (directories.Count == maximumEntries)
                throw new IOException("Facts history transaction limit reached.");
            directories.Add(entry);
        }
        return directories;
    }

    private static RecoveryIntent ReadIntent(string target, string recovery)
    {
        CheckPrivateDirectory(recovery);
        if (System.IO.Directory.EnumerateFileSystemEntries(recovery).Any(entry =>
            Path.GetFileName(entry) is not (BeforeName or AfterName or IntentName or
                CommittedName or AbortedName or OutcomeStagingName)))
            throw new IOException("Unknown facts recovery entry.");
        var intent = ReadPrivateJson<RecoveryIntent>(Path.Combine(recovery, IntentName));
        var publication = intent.Publication;
        if (intent.Version != 1 || publication is null || publication.Transaction != Path.GetFileName(recovery) ||
            intent.TargetName != Path.GetFileName(target) || publication.Revision < 1 ||
            !ValidHash(publication.PreviousSha256) || !ValidHash(publication.PublishedSha256) ||
            !ValidRecoveryActor(intent.OperatorIdentity, intent.OperatorCapability))
            throw new InvalidDataException("Invalid facts recovery intent.");
        return intent;
    }

    private static bool ValidRecoveryActor(string? identity, string? capability) =>
        (identity is null || ValidOperatorIdentity(identity)) &&
        (capability is null || identity is not null &&
            capability == PkiProxy.Authentication.TechnicianCapabilities.FactsWrite);

    private static string? ReadOutcome(string recovery, RecoveryIntent intent)
    {
        var committedPath = Path.Combine(recovery, CommittedName);
        var abortedPath = Path.Combine(recovery, AbortedName);
        if (GetPathStatus(committedPath) is not null)
        {
            if (GetPathStatus(abortedPath) is not null)
                throw new InvalidDataException("Conflicting facts recovery outcome markers.");
            var marker = ReadPrivateJson<RecoveryCommit>(committedPath);
            if (marker.Version != 1 || marker.Transaction != intent.Publication.Transaction ||
                marker.PublishedSha256 != intent.Publication.PublishedSha256 ||
                marker.OperatorIdentity != intent.OperatorIdentity ||
                marker.OperatorCapability != intent.OperatorCapability)
                throw new InvalidDataException("Invalid facts commit marker.");
            return CommittedName;
        }
        if (GetPathStatus(abortedPath) is null) return null;
        var abort = ReadPrivateJson<RecoveryAbort>(abortedPath);
        if (abort.Version != 1 || abort.Transaction != intent.Publication.Transaction ||
            abort.PreviousSha256 != intent.Publication.PreviousSha256 ||
            abort.OperatorIdentity != intent.OperatorIdentity ||
            abort.OperatorCapability != intent.OperatorCapability)
            throw new InvalidDataException("Invalid facts abort marker.");
        return AbortedName;
    }

    private static void VerifyRecoveryImage(string recovery, string name, string expectedHash)
    {
        var bytes = ReadPrivate(Path.Combine(recovery, name), MaximumFactsBytes);
        VerifyHash(bytes, expectedHash, "Facts recovery image hash mismatch.");
        _ = JsonFileDeviceFactsSource.Parse(bytes, null);
    }

    private static void DiscardBundleStaging(string staging)
    {
        CheckPrivateDirectory(staging);
        if (GetPathStatus(staging) is not { IsNonMountRoot: true } entry || entry.Owner != GetEffectiveUid())
            throw new IOException("Facts bundle staging must be owned by the publisher.");
        var files = System.IO.Directory.EnumerateFileSystemEntries(staging).Take(4).ToArray();
        foreach (var file in files)
        {
            if (Path.GetFileName(file) is not (BeforeName or AfterName or IntentName))
                throw new IOException("Unknown facts bundle staging entry.");
            CheckScratchFile(file);
        }
        foreach (var file in files)
            File.Delete(file);
        System.IO.Directory.Delete(staging);
    }

    private static void CheckScratchFile(string path)
    {
        // Failed writes may be empty and a restrictive umask can remove owner access.
        var status = GetPathStatus(path);
        if (status is not { IsSingleRegular: true, IsNonMountRoot: true } entry || entry.Owner != GetEffectiveUid() ||
            (entry.Permissions & ~PrivateFile) != 0)
            throw new IOException("Facts staging entry is not a private regular file owned by the publisher.");
    }

    private static string PendingPath(string parent, string transaction) =>
        Path.Combine(parent, ".facts-" + transaction + ".pending");

    private static long PendingSize(string path)
    {
        var status = GetPathStatus(path);
        if (status is null) return 0;
        if (status is not { IsSingleRegular: true, Size: >= 0 and <= MaximumFactsBytes } entry)
            throw new IOException("Invalid retained facts pending file.");
        return entry.Size;
    }

    internal static long ValidateDraft(ReadOnlyMemory<byte> current, ReadOnlyMemory<byte> draft)
    {
        _ = JsonFileDeviceFactsSource.Parse(current, null);
        _ = JsonFileDeviceFactsSource.Parse(draft, null);
        static JsonObject Document(ReadOnlyMemory<byte> bytes)
        {
            var span = bytes.Span;
            if (span.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) span = span[3..];
            return JsonNode.Parse(span)!.AsObject();
        }
        var before = Document(current);
        var proposed = Document(draft);
        var originalRevision = before["revision"]!.GetValue<long>();
        var next = checked(originalRevision + 1);
        if (proposed["revision"]!.GetValue<long>() != next)
            throw new InvalidDataException("Draft revision must be exactly the current revision plus one.");
        proposed["revision"] = originalRevision;
        _ = DeviceFactsEditor.PrepareDocument(current, Convert.ToHexString(SHA256.HashData(current.Span)),
            JsonSerializer.SerializeToUtf8Bytes(proposed));
        return next;
    }

    internal static byte[] Read(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        return Read(file);
    }

    private static byte[] Read(FileStream file)
    {
        if (file.Length is 0 or > MaximumFactsBytes) throw new InvalidDataException("Unsupported facts file size.");
        var bytes = new byte[(int)file.Length]; file.ReadExactly(bytes);
        if (file.ReadByte() != -1) throw new IOException("File changed during read.");
        return bytes;
    }
    private static void VerifyHash(ReadOnlySpan<byte> bytes, string expected, string error)
    {
        if (expected.Length != 64 || !expected.All(char.IsAsciiHexDigit) ||
            !Convert.ToHexString(SHA256.HashData(bytes)).Equals(expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(error);
    }
    private static bool ValidHash(string? value) => value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool ValidOperatorIdentity(string value) =>
        value is { Length: >= 3 and <= 320 } && !value.Any(char.IsWhiteSpace) &&
        !value.Any(char.IsControl) && (value.Contains('@') ||
            value.StartsWith("ad:", StringComparison.Ordinal) &&
            Guid.TryParseExact(value.AsSpan(3), "D", out _));
    private static byte[] ReadPrivate(string path, int maximumBytes)
    {
        var size = PrivateFileSize(path, maximumBytes);
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var bytes = new byte[(int)size]; input.ReadExactly(bytes);
        if (input.ReadByte() != -1) throw new IOException("Facts recovery file changed during read.");
        return bytes;
    }

    private static long PrivateFileSize(string path, int maximumBytes)
    {
        if (GetPathStatus(path) is not { IsSingleRegular: true, Permissions: PrivateFile, Size: > 0 } entry ||
            entry.Size > maximumBytes)
            throw new IOException("Owner-only regular facts recovery file required.");
        return entry.Size;
    }

    private static T ReadPrivateJson<T>(string path)
    {
        try
        {
            var bytes = ReadPrivate(path, MaximumRecordBytes);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            RejectDuplicateProperties(document.RootElement);
            return JsonSerializer.Deserialize<T>(bytes, StrictJson)
                ?? throw new InvalidDataException("Missing facts recovery record.");
        }
        catch (JsonException error) { throw new InvalidDataException("Invalid facts recovery JSON.", error); }
    }
    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    throw new InvalidDataException("Duplicate facts recovery JSON property.");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) RejectDuplicateProperties(item);
    }
    private static string CheckPublicationDirectory(string target)
    {
        var parent = Path.GetDirectoryName(target)!;
        if (parent == "/" || Path.GetFileName(target) == HistoryLockName)
            throw new ArgumentException("Dedicated facts directory required.");
        CheckDirectory(parent);
        return parent;
    }

    private static void CheckDirectory(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new DirectoryInfo(path);
        if (!info.Exists || info.LinkTarget is not null || (File.GetUnixFileMode(path) & UntrustedWrite) != 0)
            throw new IOException("Existing operator-controlled directory required; links and shared write access refused.");
    }
    private static void CheckPrivateDirectory(string path)
    {
        if (GetPathStatus(path) is not { IsDirectory: true, Permissions: PrivateDirectory })
            throw new IOException("Owner-only regular facts recovery directory required.");
    }
    private static void CheckFile(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || (File.GetUnixFileMode(path) & UntrustedWrite) != 0)
            throw new IOException("Existing operator-controlled facts file required; links and shared write access refused.");
    }
    private static FileStream AcquireLock(string lockPath)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        if (GetPathStatus(lockPath) is { IsSingleRegular: false })
            throw new IOException("Linked or nonregular publication lock refused.");
        var guard = new FileStream(lockPath, new FileStreamOptions {
            Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.ReadWrite,
            UnixCreateMode = PrivateFile });
        try
        {
            if (File.GetUnixFileMode(guard.SafeFileHandle) != PrivateFile)
                throw new IOException("Private publication lock required.");
            if (Flock(guard.SafeFileHandle, 2 | 4) != 0)
                throw new IOException("Another facts publisher holds the lock; reload before retrying.");
            return guard;
        }
        catch { guard.Dispose(); throw; }
    }
    private static void WriteNew(string path, ReadOnlySpan<byte> bytes, UnixFileMode mode)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        using var output = new FileStream(path, new FileStreamOptions {
            Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
            Options = FileOptions.WriteThrough, UnixCreateMode = mode });
        output.Write(bytes); output.Flush(flushToDisk: true);
        File.SetUnixFileMode(path, mode); // Preserve intended read access despite umask.
        output.Flush(flushToDisk: true);
    }
    private static void SyncDirectory(string directory)
    {
        var fd = Open(directory, 0x10000 | 0x20000 | 0x80000); // O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        if (fd < 0) throw new IOException("Cannot open publication directory for durable sync.");
        try { if (Fsync(fd) != 0) throw new IOException("Cannot durably sync publication directory."); }
        finally { _ = Close(fd); }
    }
    [DllImport("libc", EntryPoint = "open", SetLastError = true)] private static extern int Open(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)] private static extern int Fsync(int fd);
    [DllImport("libc", EntryPoint = "close")] private static extern int Close(int fd);
    [DllImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static extern int Flock(Microsoft.Win32.SafeHandles.SafeFileHandle fd, int operation);
    [DllImport("libc", EntryPoint = "getuid")] private static extern uint GetUid();
    [LibraryImport("libc", EntryPoint = "geteuid")] private static partial uint GetEffectiveUid();

    private static LinuxFileStatus? GetPathStatus(string path)
    {
        const int currentWorkingDirectory = -100;
        const int noFollow = 0x100;
        const uint requiredStats = 0x20f; // Type, mode, link count, UID and size.
        if (Statx(currentWorkingDirectory, path, noFollow, requiredStats, out var status) == 0)
        {
            if ((status.Mask & requiredStats) != requiredStats)
                throw new IOException("Required facts recovery metadata is unavailable.");
            return status;
        }
        if (Marshal.GetLastPInvokeError() == 2) return null; // ENOENT
        throw new IOException("Cannot inspect facts recovery path.");
    }

    // Linux statx has a fixed layout across architectures.
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxFileStatus
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(8)] private ulong attributes;
        [FieldOffset(16)] private uint linkCount;
        [FieldOffset(20)] internal uint Owner;
        [FieldOffset(28)] private ushort mode;
        [FieldOffset(40)] internal long Size;
        [FieldOffset(56)] private ulong attributesMask;

        internal bool IsDirectory => (mode & 0xF000) == 0x4000;
        internal bool IsSingleRegular => (mode & 0xF000) == 0x8000 && linkCount == 1;
        internal bool IsNonMountRoot => (attributesMask & 0x2000) != 0 && (attributes & 0x2000) == 0;
        internal UnixFileMode Permissions => (UnixFileMode)(mode & 0xFFF);
    }

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Statx(int directory, string path, int flags, uint mask, out LinuxFileStatus status);

    private sealed record RecoveryIntent(int Version, FactsPublication Publication,
        string TargetName, uint OperatorUid, DateTimeOffset PreparedAt, string? OperatorIdentity = null,
        string? OperatorCapability = null);
    private sealed record RecoveryCommit(int Version, string Transaction, string PublishedSha256,
        DateTimeOffset CommittedAt, bool Recovered = false, string? OperatorIdentity = null,
        string? OperatorCapability = null);
    private sealed record RecoveryAbort(int Version, string Transaction, string PreviousSha256,
        string? OperatorIdentity, DateTimeOffset RecoveredAt, string? OperatorCapability = null);
}
