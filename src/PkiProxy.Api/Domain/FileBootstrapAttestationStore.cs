using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PkiProxy.Domain;

// Linux local durable filesystem only. Trusted operator-owned directory; never
// a device-selected path. Immutable markers deliberately favor refusal after an
// uncertain write over automatically resurrecting a consumed approval.
internal sealed class FileBootstrapAttestationStore : IBootstrapAttestationStore
{
    private readonly string directory;
    private static readonly JsonSerializerOptions Options = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 4
    };
    private const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode RecordMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal FileBootstrapAttestationStore(string directory)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux local durable store required.");
        if (!Path.IsPathFullyQualified(directory)) throw new ArgumentException("Absolute bootstrap directory required.");
        this.directory = Path.GetFullPath(directory);
        CheckDirectory();
    }

    public BootstrapStoreResult Record(CsrBinding binding, DateTimeOffset now, TimeSpan lifetime)
    {
        binding = binding.Snapshot();
        ValidateBinding(binding);
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(24))
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        var record = new Entry(1, Convert.ToHexString(binding.CsrSha256),
            Convert.ToHexString(binding.SubjectPublicKeyInfoSha256), now, now.Add(lifetime), null, null);
        return Create(Name(binding, "pending"), record) ? BootstrapStoreResult.Recorded : BootstrapStoreResult.AlreadyExists;
    }

    public BootstrapStoreResult Attest(CsrBinding binding, string authoritativeAssetId, DateTimeOffset now)
    {
        binding = binding.Snapshot();
        ValidateAsset(authoritativeAssetId);
        var (result, pending) = ReadPending(binding, now);
        if (result != BootstrapStoreResult.Recorded) return result;
        if (Read(Name(binding, "consumed")) is not null) return BootstrapStoreResult.InvalidState;
        // Caller must already authenticate/authorize the technician and resolve
        // this ID against the authoritative catalogue. This is not a portal API.
        var approved = pending! with { AssetId = authoritativeAssetId, TransitionAt = now };
        return Create(Name(binding, "attested"), approved)
            ? BootstrapStoreResult.Attested : BootstrapStoreResult.InvalidState;
    }

    public BootstrapAttestationLookup GetAttestedAsset(CsrBinding binding, DateTimeOffset now)
    {
        binding = binding.Snapshot();
        var (result, pending) = ReadPending(binding, now);
        if (result != BootstrapStoreResult.Recorded) return new(result, null);
        if (Read(Name(binding, "consumed")) is not null) return new(BootstrapStoreResult.InvalidState, null);
        var approved = Read(Name(binding, "attested"));
        if (approved is null) return new(BootstrapStoreResult.InvalidState, null);
        if (!SameRequest(pending!, approved) || approved.TransitionAt is null ||
            approved.TransitionAt < pending!.CreatedAt || approved.TransitionAt >= pending.ExpiresAt ||
            approved.TransitionAt > now)
            throw new InvalidDataException("Invalid bootstrap approval record.");
        ValidateAsset(approved.AssetId);
        return new(BootstrapStoreResult.Attested, approved.AssetId);
    }

    public BootstrapConsumeResult Consume(CsrBinding binding, DateTimeOffset now)
    {
        binding = binding.Snapshot();
        var approved = GetAttestedAsset(binding, now);
        if (approved.Result != BootstrapStoreResult.Attested) return new(approved.Result, null);
        var pending = Read(Name(binding, "pending")) ?? throw new InvalidDataException("Bootstrap request disappeared.");
        var consumed = pending with { AssetId = approved.AuthoritativeAssetId, TransitionAt = now };
        return Create(Name(binding, "consumed"), consumed)
            ? new(BootstrapStoreResult.Consumed, approved.AuthoritativeAssetId)
            : new(BootstrapStoreResult.InvalidState, null);
    }

    // Called only while the process-shared intake lock is held. Anonymous
    // pending material has no accepted audit value and may be removed during a
    // failed commit or after expiry. Any technician or consumption transition
    // makes the record permanent and cleanup fails closed.
    internal void DeleteUntrusted(CsrBinding binding, DateTimeOffset now, bool requireExpiry)
    {
        binding = binding.Snapshot();
        ValidateBinding(binding);
        var pendingPath = Name(binding, "pending");
        var pending = Read(pendingPath);
        if (pending is null) return;
        if (!SameRequest(pending, pending) || pending.AssetId is not null || pending.TransitionAt is not null ||
            (requireExpiry && now < pending.ExpiresAt))
            throw new InvalidDataException("Bootstrap attestation is not collectable.");
        if (Read(Name(binding, "attested")) is not null || Read(Name(binding, "consumed")) is not null)
            throw new InvalidDataException("Trusted bootstrap attestation cannot be collected.");
        CheckFile(pendingPath);
        File.Delete(pendingPath);
        SyncDirectory();
    }

    private (BootstrapStoreResult Result, Entry? Entry) ReadPending(CsrBinding binding, DateTimeOffset now)
    {
        ValidateBinding(binding);
        var pending = Read(Name(binding, "pending"));
        if (pending is null) return (BootstrapStoreResult.NotFound, null);
        if (!new CsrBinding(Convert.FromHexString(pending.CsrSha256), Convert.FromHexString(pending.SpkiSha256)).Matches(binding))
            return (BootstrapStoreResult.BindingMismatch, null);
        if (pending.AssetId is not null || pending.TransitionAt is not null || now < pending.CreatedAt)
            throw new InvalidDataException("Invalid bootstrap request state or time.");
        return now >= pending.ExpiresAt ? (BootstrapStoreResult.Expired, null) : (BootstrapStoreResult.Recorded, pending);
    }

    private bool Create<T>(string name, T value)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        CheckDirectory();
        var path = Path.Combine(directory, name);
        var stagingPath = Path.Combine(directory,
            ".bootstrap-write-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + ".tmp");
        try
        {
            using (var stream = new FileStream(stagingPath, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
                Options = FileOptions.WriteThrough, UnixCreateMode = RecordMode
            }))
            {
                JsonSerializer.Serialize(stream, value, Options);
                stream.Flush(flushToDisk: true);
            }
            _ = CheckFile(stagingPath);
            if (!LinuxAtomicPublish.TryRenameNoReplace(stagingPath, path))
            {
                _ = ReadJson<T>(name);
                return false;
            }
            SyncDirectory();
            return true;
        }
        finally { File.Delete(stagingPath); }
    }

    private Entry? Read(string path)
    {
        CheckDirectory();
        var info = new FileInfo(path);
        info.Refresh();
        if (info.LinkTarget is not null || (info.Exists && info.Attributes.HasFlag(FileAttributes.ReparsePoint)))
            throw new IOException("Symbolic-link bootstrap marker rejected.");
        if (!info.Exists)
        {
            // GetAttributes distinguishes an absent path from inaccessible state.
            try { _ = File.GetAttributes(path); }
            catch (FileNotFoundException) { return null; }
            throw new IOException("Invalid bootstrap marker.");
        }
        return ReadJson<Entry>(path);
    }

    private static FileInfo CheckFile(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new FileInfo(path);
        info.Refresh();
        if (!info.Exists || info.LinkTarget is not null ||
            (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            info.Length is <= 0 or > 4096 || File.GetUnixFileMode(path) != RecordMode ||
            !LinuxFileLinkGuard.IsSingleRegular(path))
            throw new IOException("Invalid private bootstrap marker.");
        return info;
    }

    private T ReadJson<T>(string name)
    {
        CheckDirectory();
        var path = Path.Combine(directory, name);
        var before = CheckFile(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!stream.CanSeek) throw new IOException("Regular bootstrap marker required.");
        var bytes = new byte[(int)before.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("Bootstrap marker changed while reading.");
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("Bootstrap JSON must be an object.");
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate bootstrap JSON property.");
            var value = document.RootElement.Deserialize<T>(Options)
                ?? throw new InvalidDataException("Missing bootstrap marker.");
            if (value is Entry entry && (entry.Version != 1 || !IsHash(entry.CsrSha256) || !IsHash(entry.SpkiSha256) ||
                entry.ExpiresAt <= entry.CreatedAt || entry.ExpiresAt - entry.CreatedAt > TimeSpan.FromHours(24)))
                throw new InvalidDataException("Invalid bootstrap record.");
            // Reopen the pathname as well as checking metadata: a replacement
            // can leave the first stream reading an unlinked, stale inode.
            var after = CheckFile(path);
            if (before.Length != after.Length || before.LastWriteTimeUtc != after.LastWriteTimeUtc ||
                before.CreationTimeUtc != after.CreationTimeUtc)
                throw new IOException("Bootstrap marker changed while reading.");
            using var verify = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!verify.CanSeek) throw new IOException("Regular bootstrap marker required.");
            var verifiedBytes = new byte[bytes.Length];
            verify.ReadExactly(verifiedBytes);
            var final = CheckFile(path);
            if (verify.ReadByte() != -1 || !bytes.AsSpan().SequenceEqual(verifiedBytes) ||
                after.Length != final.Length || after.LastWriteTimeUtc != final.LastWriteTimeUtc ||
                after.CreationTimeUtc != final.CreationTimeUtc)
                throw new IOException("Bootstrap marker changed while reading.");
            return value;
        }
        catch (JsonException error) { throw new InvalidDataException("Invalid bootstrap marker JSON.", error); }
    }

    private void CheckDirectory()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new DirectoryInfo(directory);
        if (!info.Exists || info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint) || File.GetUnixFileMode(directory) != DirectoryMode)
            throw new IOException("Pre-provisioned owner-only bootstrap directory required.");
    }

    private void SyncDirectory()
    {
        var fd = Open(directory, 0x10000 | 0x80000);
        if (fd < 0) throw new IOException("Cannot open bootstrap directory for durability.");
        int closeResult;
        try { if (Fsync(fd) != 0) throw new IOException("Cannot flush bootstrap directory."); }
        finally { closeResult = Close(fd); }
        if (closeResult != 0) throw new IOException("Cannot close bootstrap directory.");
    }

    private string Name(CsrBinding binding, string stage) => Path.Combine(directory, Convert.ToHexString(binding.CsrSha256) + "." + stage + ".json");
    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    private static bool SameRequest(Entry left, Entry right) => left.Version == right.Version &&
        left.CsrSha256 == right.CsrSha256 && left.SpkiSha256 == right.SpkiSha256 &&
        left.CreatedAt == right.CreatedAt && left.ExpiresAt == right.ExpiresAt;
    private static void ValidateBinding(CsrBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (!binding.HasExpectedLengths()) throw new ArgumentException("Exact SHA256 bindings required.");
    }
    private static void ValidateAsset(string? asset)
    {
        if (string.IsNullOrWhiteSpace(asset) || asset.Length > 256 || asset.Any(char.IsControl))
            throw new ArgumentException("Bounded authoritative asset ID required.");
    }
    private sealed record Entry(int Version, string CsrSha256, string SpkiSha256,
        DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, string? AssetId, DateTimeOffset? TransitionAt);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int fd);
    [DllImport("libc", EntryPoint = "close")]
    private static extern int Close(int fd);
}
