using System.Runtime.InteropServices;
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
internal static class DeviceFactsPublisher
{
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectory = PrivateFile | UnixFileMode.UserExecute;
    private const UnixFileMode UntrustedWrite = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
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
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Facts publication requires Linux.");
        if (!Path.IsPathFullyQualified(target)) throw new ArgumentException("Absolute target required.");
        if (operatorIdentity is not null && !ValidOperatorIdentity(operatorIdentity))
            throw new ArgumentException("Bounded authenticated operator identity required.", nameof(operatorIdentity));
        if (operatorCapability is not null &&
            !string.Equals(operatorCapability, PkiProxy.Authentication.TechnicianCapabilities.FactsWrite,
                StringComparison.Ordinal))
            throw new ArgumentException("Exact facts-write capability required.", nameof(operatorCapability));
        if (operatorIdentity is null && operatorCapability is not null)
            throw new ArgumentException("Operator capability requires an authenticated identity.");
        target = Path.GetFullPath(target);
        var parent = Path.GetDirectoryName(target)!;
        if (parent == "/") throw new ArgumentException("Dedicated facts directory required.");
        CheckDirectory(parent);
        CheckFile(target);
        using var guard = AcquireLock(target);

        var current = Read(target);
        VerifyHash(current, expectedSourceHash, "Source changed; review the current facts.");
        VerifyHash(draft.Span, expectedDraftHash, "Draft differs from the reviewed file.");
        var revision = ValidateDraft(current, draft);
        checkpoint?.Invoke("validated");
        var mode = File.GetUnixFileMode(target);
        var history = Path.Combine(parent, ".facts-history");
        if (!System.IO.Directory.Exists(history)) System.IO.Directory.CreateDirectory(history, PrivateDirectory);
        CheckDirectory(history);
        if (File.GetUnixFileMode(history) != PrivateDirectory) throw new IOException("Private history directory required.");
        var id = Guid.NewGuid().ToString("N");
        var recovery = Path.Combine(history, id);
        System.IO.Directory.CreateDirectory(recovery, PrivateDirectory);
        SyncDirectory(history);
        var sourceHash = Convert.ToHexString(SHA256.HashData(current));
        var draftHash = Convert.ToHexString(SHA256.HashData(draft.Span));
        var receipt = new FactsPublication(id, revision, sourceHash, draftHash, recovery);
        WriteNew(Path.Combine(recovery, "before.json"), current, PrivateFile);
        WriteNew(Path.Combine(recovery, "after.json"), draft.Span, PrivateFile);
        WriteNew(Path.Combine(recovery, "intent.json"), JsonSerializer.SerializeToUtf8Bytes(new {
            Version = 1, Publication = receipt, TargetName = Path.GetFileName(target),
            OperatorUid = GetUid(), OperatorIdentity = operatorIdentity,
            OperatorCapability = operatorCapability, PreparedAt = DateTimeOffset.UtcNow }), PrivateFile);
        SyncDirectory(recovery);
        SyncDirectory(parent);
        var pending = Path.Combine(parent, ".facts-" + id + ".pending");
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
        WriteNew(Path.Combine(recovery, "committed.json"), JsonSerializer.SerializeToUtf8Bytes(new {
            Version = 1, Transaction = id, PublishedSha256 = draftHash,
            OperatorIdentity = operatorIdentity, OperatorCapability = operatorCapability,
            CommittedAt = DateTimeOffset.UtcNow }), PrivateFile);
        SyncDirectory(recovery);
        return receipt;
    }

    // Resolve only outcomes that can be proved from the durable before/after
    // images and current target. Ambiguous state is a startup failure; no
    // guessed retry or rollback is performed.
    internal static FactsRecoverySummary Reconcile(string target)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Facts recovery requires Linux.");
        target = Path.GetFullPath(target);
        var parent = Path.GetDirectoryName(target)!;
        CheckDirectory(parent); CheckFile(target);
        using var guard = AcquireLock(target);
        var history = Path.Combine(parent, ".facts-history");
        if (!System.IO.Directory.Exists(history)) return new(0, 0, 0);
        CheckDirectory(history);
        if (File.GetUnixFileMode(history) != PrivateDirectory)
            throw new IOException("Private facts recovery history required.");

        var directories = System.IO.Directory.GetDirectories(history);
        if (directories.Length > 10_000) throw new IOException("Facts recovery history is unbounded.");
        var committed = 0; var recoveredCommitted = 0; var recoveredAborted = 0;
        foreach (var recovery in directories.Order(StringComparer.Ordinal))
        {
            var info = new DirectoryInfo(recovery);
            if (info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
                File.GetUnixFileMode(recovery) != PrivateDirectory ||
                !Guid.TryParseExact(info.Name, "N", out _))
                throw new IOException("Invalid facts recovery directory.");
            var intent = ReadPrivateJson<RecoveryIntent>(Path.Combine(recovery, "intent.json"));
            if (intent.Version != 1 || intent.Publication.Transaction != info.Name ||
                intent.TargetName != Path.GetFileName(target) ||
                intent.Publication.Revision < 1 || !ValidHash(intent.Publication.PreviousSha256) ||
                !ValidHash(intent.Publication.PublishedSha256) ||
                intent.OperatorIdentity is not null && !ValidOperatorIdentity(intent.OperatorIdentity) ||
                intent.OperatorCapability is not null &&
                    intent.OperatorCapability != PkiProxy.Authentication.TechnicianCapabilities.FactsWrite ||
                intent.OperatorIdentity is null && intent.OperatorCapability is not null)
                throw new InvalidDataException("Invalid facts recovery intent.");
            var before = ReadPrivate(Path.Combine(recovery, "before.json"), 1_048_576);
            var after = ReadPrivate(Path.Combine(recovery, "after.json"), 1_048_576);
            VerifyHash(before, intent.Publication.PreviousSha256, "Facts recovery before-image hash mismatch.");
            VerifyHash(after, intent.Publication.PublishedSha256, "Facts recovery after-image hash mismatch.");
            _ = JsonFileDeviceFactsSource.Parse(before, null);
            _ = JsonFileDeviceFactsSource.Parse(after, null);
            var committedPath = Path.Combine(recovery, "committed.json");
            var abortedPath = Path.Combine(recovery, "aborted.json");
            if (File.Exists(committedPath) && File.Exists(abortedPath))
                throw new InvalidDataException("Conflicting facts recovery outcome markers.");
            if (File.Exists(committedPath))
            {
                var marker = ReadPrivateJson<RecoveryCommit>(committedPath);
                if (marker.Version != 1 || marker.Transaction != info.Name ||
                    marker.PublishedSha256 != intent.Publication.PublishedSha256 ||
                    marker.OperatorIdentity != intent.OperatorIdentity ||
                    marker.OperatorCapability != intent.OperatorCapability)
                    throw new InvalidDataException("Invalid facts commit marker.");
                committed++; continue;
            }
            if (File.Exists(abortedPath))
            {
                var marker = ReadPrivateJson<RecoveryAbort>(abortedPath);
                if (marker.Version != 1 || marker.Transaction != info.Name ||
                    marker.PreviousSha256 != intent.Publication.PreviousSha256 ||
                    marker.OperatorIdentity != intent.OperatorIdentity ||
                    marker.OperatorCapability != intent.OperatorCapability)
                    throw new InvalidDataException("Invalid facts abort marker.");
                recoveredAborted++; continue;
            }
            var currentHash = Convert.ToHexString(SHA256.HashData(Read(target)));
            if (currentHash == intent.Publication.PublishedSha256)
            {
                WriteNew(committedPath, JsonSerializer.SerializeToUtf8Bytes(new RecoveryCommit(1,
                    info.Name, intent.Publication.PublishedSha256, DateTimeOffset.UtcNow,
                    true, intent.OperatorIdentity, intent.OperatorCapability)), PrivateFile);
                SyncDirectory(recovery); recoveredCommitted++;
            }
            else if (currentHash == intent.Publication.PreviousSha256)
            {
                WriteNew(abortedPath, JsonSerializer.SerializeToUtf8Bytes(new RecoveryAbort(1,
                    info.Name, intent.Publication.PreviousSha256, intent.OperatorIdentity,
                    DateTimeOffset.UtcNow, intent.OperatorCapability)), PrivateFile);
                SyncDirectory(recovery); recoveredAborted++;
            }
            else throw new IOException("Facts recovery target matches neither retained image.");
        }
        return new(committed, recoveredCommitted, recoveredAborted);
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
        if (file.Length is 0 or > 1048576) throw new InvalidDataException("Unsupported facts file size.");
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
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            info.Length is <= 0 || info.Length > maximumBytes || File.GetUnixFileMode(path) != PrivateFile)
            throw new IOException("Owner-only regular facts recovery file required.");
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var bytes = new byte[(int)input.Length]; input.ReadExactly(bytes);
        if (input.ReadByte() != -1) throw new IOException("Facts recovery file changed during read.");
        return bytes;
    }
    private static T ReadPrivateJson<T>(string path)
    {
        try
        {
            var bytes = ReadPrivate(path, 65_536);
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
    private static void CheckDirectory(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new DirectoryInfo(path);
        if (!info.Exists || info.LinkTarget is not null || (File.GetUnixFileMode(path) & UntrustedWrite) != 0)
            throw new IOException("Existing operator-controlled directory required; links and shared write access refused.");
    }
    private static void CheckFile(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || (File.GetUnixFileMode(path) & UntrustedWrite) != 0)
            throw new IOException("Existing operator-controlled facts file required; links and shared write access refused.");
    }
    private static FileStream AcquireLock(string target)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var lockPath = target + ".publish.lock";
        if (new FileInfo(lockPath).LinkTarget is not null) throw new IOException("Linked publication lock refused.");
        var guard = new FileStream(lockPath, new FileStreamOptions {
            Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.ReadWrite,
            UnixCreateMode = PrivateFile });
        try
        {
            if (File.GetUnixFileMode(lockPath) != PrivateFile)
                throw new IOException("Private publication lock required.");
            if (Flock(guard.SafeFileHandle.DangerousGetHandle().ToInt32(), 2 | 4) != 0)
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
        var fd = Open(directory, 0x10000 | 0x80000);
        if (fd < 0) throw new IOException("Cannot open publication directory for durable sync.");
        try { if (Fsync(fd) != 0) throw new IOException("Cannot durably sync publication directory."); }
        finally { _ = Close(fd); }
    }
    [DllImport("libc", EntryPoint = "open", SetLastError = true)] private static extern int Open(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)] private static extern int Fsync(int fd);
    [DllImport("libc", EntryPoint = "close")] private static extern int Close(int fd);
    [DllImport("libc", EntryPoint = "flock", SetLastError = true)] private static extern int Flock(int fd, int operation);
    [DllImport("libc", EntryPoint = "getuid")] private static extern uint GetUid();

    private sealed record RecoveryIntent(int Version, FactsPublication Publication,
        string TargetName, uint OperatorUid, DateTimeOffset PreparedAt, string? OperatorIdentity = null,
        string? OperatorCapability = null);
    private sealed record RecoveryCommit(int Version, string Transaction, string PublishedSha256,
        DateTimeOffset CommittedAt, bool Recovered = false, string? OperatorIdentity = null,
        string? OperatorCapability = null);
    private sealed record RecoveryAbort(int Version, string Transaction, string PreviousSha256,
        string? OperatorIdentity, DateTimeOffset RecoveredAt, string? OperatorCapability = null);
}
