using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PkiProxy.Domain;

// Linux-local durable pairing coordinator. Every transition is an immutable,
// owner-only marker. A crash can strand reservations or an ApprovalClaimed
// transaction, but can never make the request reusable or authorize a retry.
internal sealed class FileBootstrapPairingCoordinator
{
    private const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode RecordMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly JsonSerializerOptions Options = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 4
    };

    private readonly string directory;
    private readonly IBootstrapAttestationStore attestations;
    private readonly IImmutableAssetCatalog assets;
    private readonly BootstrapPairingPolicy policy;
    private readonly IBootstrapPairingCodeGenerator codes;

    internal FileBootstrapPairingCoordinator(string directory,
        IBootstrapAttestationStore attestations, IImmutableAssetCatalog assets,
        BootstrapPairingPolicy policy, IBootstrapPairingCodeGenerator? codes = null)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux local durable pairing store required.");
        if (!Path.IsPathFullyQualified(directory)) throw new ArgumentException("Absolute pairing directory required.");
        this.directory = Path.GetFullPath(directory);
        this.attestations = attestations ?? throw new ArgumentNullException(nameof(attestations));
        this.assets = assets ?? throw new ArgumentNullException(nameof(assets));
        this.policy = policy ?? throw new ArgumentNullException(nameof(policy));
        policy.Validate();
        this.codes = codes ?? new CryptoBootstrapPairingCodeGenerator();
        CheckDirectory();
    }

    internal (BootstrapPairingResult Result, BootstrapPairingTicket? Ticket) Begin(
        CsrBinding binding, DateTimeOffset now)
        => Begin(binding, now, UniqueRequestId());

    internal (BootstrapPairingResult Result, BootstrapPairingTicket? Ticket) Begin(
        CsrBinding binding, DateTimeOffset now, string requestId)
        => BeginCore(binding, now, requestId, null);

    internal (BootstrapPairingResult Result, BootstrapPairingTicket? Ticket) BeginReserved(
        CsrBinding binding, DateTimeOffset now, string requestId, int reservedOrdinal)
        => BeginCore(binding, now, requestId, reservedOrdinal);

    private (BootstrapPairingResult Result, BootstrapPairingTicket? Ticket) BeginCore(
        CsrBinding binding, DateTimeOffset now, string requestId, int? reservedOrdinal)
    {
        ArgumentNullException.ThrowIfNull(binding);
        binding = binding.Snapshot();
        if (!binding.HasExpectedLengths()) throw new ArgumentException("Exact SHA256 bindings required.", nameof(binding));
        if (!IsRequestId(requestId)) throw new ArgumentException("Exact bootstrap request identifier required.", nameof(requestId));
        if (reservedOrdinal is < 1 || reservedOrdinal > policy.MaximumRetainedSessions)
            throw new ArgumentOutOfRangeException(nameof(reservedOrdinal));
        if (ReadGraph(requestId) is not null) return (BootstrapPairingResult.AlreadyExists, null);
        var slot = reservedOrdinal ?? ReserveSlot(requestId);
        if (slot == 0) return (BootstrapPairingResult.CapacityExceeded, null);
        var bindingName = "pairing-binding-" + Convert.ToHexString(binding.CsrSha256) + ".json";
        if (!CreateReservation(bindingName, requestId))
            return (BootstrapPairingResult.AlreadyExists, null);

        string code;
        string codeKey;
        for (var attempt = 0; ; attempt++)
        {
            if (attempt >= 32) throw new InvalidOperationException("Unable to allocate a unique pairing code.");
            code = codes.Generate();
            if (!IsCode(code)) throw new InvalidOperationException("Pairing code generator returned an invalid code.");
            codeKey = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(code)));
            if (CreateReservation("pairing-code-" + codeKey + ".json", requestId)) break;
        }

        var salt = RandomNumberGenerator.GetBytes(32);
        var expiresAt = now.Add(policy.Lifetime);
        var created = new CreatedRecord(reservedOrdinal is null ? 2 : 3, requestId,
            Convert.ToHexString(binding.CsrSha256), Convert.ToHexString(binding.SubjectPublicKeyInfoSha256),
            Convert.ToHexString(salt), Verifier(salt, code), codeKey, now, expiresAt,
            policy.MaximumAttempts, slot);
        CreateRequired(CreatedName(requestId), created);

        BootstrapStoreResult attestation;
        try { attestation = attestations.Record(binding, now, policy.Lifetime); }
        catch
        {
            // No ready marker means approval is impossible. Preserve all markers
            // for explicit operator reconciliation and rethrow the storage fault.
            throw;
        }
        if (attestation != BootstrapStoreResult.Recorded)
        {
            CreateRequired(MarkerName(requestId, "failed"),
                new TransitionRecord(1, requestId, now, null, null, null, null, null));
            _ = ReadGraph(requestId);
            return (attestation == BootstrapStoreResult.AlreadyExists
                ? BootstrapPairingResult.AlreadyExists : BootstrapPairingResult.StoreRejected, null);
        }
        CreateRequired(MarkerName(requestId, "ready"),
            new TransitionRecord(1, requestId, now, null, null, null, null, null));
        _ = ReadGraph(requestId);
        return (BootstrapPairingResult.Created, new BootstrapPairingTicket(requestId, code, expiresAt));
    }

    internal BootstrapPairingAttempt Approve(string requestId, string displayedCode,
        string authoritativeAssetId, AuthenticatedTechnician technician, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(technician);
        ValidateIdentifier(technician.Subject, nameof(technician.Subject), 256);
        ValidateIdentifier(technician.AuthenticationMethod, nameof(technician.AuthenticationMethod), 64);
        if (technician.Capability != PkiProxy.Authentication.TechnicianCapabilities.BootstrapApprove)
            throw new ArgumentException("Bootstrap approval capability required.", nameof(technician));
        ValidateIdentifier(authoritativeAssetId, nameof(authoritativeAssetId), 256);
        if (technician.AuthenticatedAt > now || now - technician.AuthenticatedAt > policy.MaximumTechnicianAuthenticationAge)
            return new(BootstrapPairingResult.AuthenticationStale);
        if (!IsRequestId(requestId)) return new(BootstrapPairingResult.NotFound);

        var graph = ReadGraph(requestId);
        if (graph is null) return new(BootstrapPairingResult.NotFound);
        ValidateObservationTime(graph, now);
        var created = graph.Created;
        if (graph.Failed is not null || graph.Claimed is not null)
            return new(BootstrapPairingResult.InvalidState);
        if (now >= created.ExpiresAt) return new(BootstrapPairingResult.Expired);
        var attempt = ReserveAttempt(created, now);
        if (attempt == 0) return new(BootstrapPairingResult.AttemptsExhausted);
        if (!Matches(created, displayedCode)) return new(attempt == created.MaximumAttempts
            ? BootstrapPairingResult.AttemptsExhausted : BootstrapPairingResult.InvalidCode);
        if (!assets.Contains(authoritativeAssetId)) return new(attempt == created.MaximumAttempts
            ? BootstrapPairingResult.AttemptsExhausted : BootstrapPairingResult.AssetUnavailable);

        graph = ReadGraph(requestId)!;
        if (graph.Created != created) throw new InvalidDataException("Pairing record changed.");
        if (graph.Claimed is not null) return new(BootstrapPairingResult.InvalidState);

        var audit = new BootstrapPairingAudit(requestId, technician.Subject,
            technician.AuthenticationMethod, authoritativeAssetId, now,
            created.CsrSha256, created.SpkiSha256, technician.Capability);
        var claim = new TransitionRecord(2, requestId, now, technician.Subject,
            technician.AuthenticationMethod, authoritativeAssetId,
            created.CsrSha256, created.SpkiSha256, technician.Capability);
        if (!Create(MarkerName(requestId, "claimed"), claim))
        {
            _ = ReadGraph(requestId);
            return new(BootstrapPairingResult.InvalidState);
        }

        ValidateOwnClaim(created, claim);

        var binding = new CsrBinding(Convert.FromHexString(created.CsrSha256), Convert.FromHexString(created.SpkiSha256));
        var attested = attestations.Attest(binding, authoritativeAssetId, now);
        if (attested != BootstrapStoreResult.Attested)
            return new(BootstrapPairingResult.StoreRejected);
        ValidateOwnClaim(created, claim);
        CreateRequired(MarkerName(requestId, "approved"), claim);
        ValidateOwnClaim(created, claim);
        return new(BootstrapPairingResult.Approved, audit);
    }

    internal BootstrapPairingLookup Lookup(string requestId, DateTimeOffset now)
    {
        if (!IsRequestId(requestId)) return new(BootstrapPairingResult.NotFound, null, null, 0);
        var graph = ReadGraph(requestId);
        if (graph is null) return new(BootstrapPairingResult.NotFound, null, null, 0);
        ValidateObservationTime(graph, now);
        var created = graph.Created;
        if (graph.Failed is not null)
            return new(BootstrapPairingResult.InvalidState, BootstrapPairingStatus.Failed, created.ExpiresAt, 0);
        if (graph.Approved is not null)
            return new(BootstrapPairingResult.Approved, BootstrapPairingStatus.Approved, created.ExpiresAt, 0,
                Audit(created, graph.Approved));
        if (graph.Claimed is not null)
            return new(BootstrapPairingResult.InvalidState, BootstrapPairingStatus.ApprovalClaimed, created.ExpiresAt, 0);
        if (now >= created.ExpiresAt)
            return new(BootstrapPairingResult.Expired, BootstrapPairingStatus.Expired, created.ExpiresAt, 0);
        var attempts = graph.Attempts;
        if (attempts >= created.MaximumAttempts)
            return new(BootstrapPairingResult.AttemptsExhausted, BootstrapPairingStatus.AttemptsExhausted, created.ExpiresAt, 0);
        return new(BootstrapPairingResult.Created, BootstrapPairingStatus.Pending,
            created.ExpiresAt, created.MaximumAttempts - attempts);
    }

    // Called only while the process-shared intake lock is held. It removes an
    // incomplete or expired anonymous graph. A technician claim or approval is
    // permanent evidence and makes cleanup fail closed.
    internal void DeleteUntrusted(string requestId, CsrBinding binding,
        DateTimeOffset now, bool requireExpiry)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (!IsRequestId(requestId) || !binding.HasExpectedLengths())
            throw new ArgumentException("Exact pairing identity required.");
        var created = ReadCreated(requestId);
        if (created is not null)
        {
            if (created.CsrSha256 != Convert.ToHexString(binding.CsrSha256) ||
                created.SpkiSha256 != Convert.ToHexString(binding.SubjectPublicKeyInfoSha256) ||
                (requireExpiry && now < created.ExpiresAt))
                throw new InvalidDataException("Pairing graph is not collectable.");
        }
        if (HasTrustedTransition(requestId))
            throw new InvalidDataException("Trusted pairing graph cannot be collected.");

        if (attestations is FileBootstrapAttestationStore fileAttestations)
            fileAttestations.DeleteUntrusted(binding, now, requireExpiry);

        var names = System.IO.Directory.EnumerateFiles(directory)
            .Select(Path.GetFileName)
            .Where(name => name is not null &&
                (name.StartsWith("pairing-" + requestId + ".", StringComparison.Ordinal) ||
                 name.StartsWith("pairing-binding-", StringComparison.Ordinal) ||
                 name.StartsWith("pairing-code-", StringComparison.Ordinal) ||
                 name.StartsWith("pairing-slot-", StringComparison.Ordinal)))
            .Cast<string>().ToArray();
        foreach (var name in names)
        {
            var path = Path.Combine(directory, name);
            if (name.StartsWith("pairing-" + requestId + ".", StringComparison.Ordinal))
            {
                _ = CheckFile(path);
                File.Delete(path);
                continue;
            }
            Reservation reservation;
            try { reservation = ReadReservation(name); }
            catch (InvalidDataException) { throw; }
            if (reservation.RequestId == requestId) File.Delete(path);
        }
        SyncDirectory();
    }

    internal bool HasTrustedTransition(string requestId)
    {
        if (!IsRequestId(requestId)) throw new ArgumentException("Exact pairing identifier required.");
        return ExistsChecked<TransitionRecord>(MarkerName(requestId, "claimed")) ||
            ExistsChecked<TransitionRecord>(MarkerName(requestId, "approved"));
    }

    private static BootstrapPairingAudit Audit(CreatedRecord created, TransitionRecord approved) => new(
        created.RequestId,
        approved.TechnicianSubject ?? throw new InvalidDataException("Approved pairing has no technician."),
        approved.AuthenticationMethod ?? throw new InvalidDataException("Approved pairing has no authentication method."),
        approved.AssetId ?? throw new InvalidDataException("Approved pairing has no asset."),
        approved.At,
        approved.CsrSha256 ?? throw new InvalidDataException("Approved pairing has no CSR binding."),
        approved.SpkiSha256 ?? throw new InvalidDataException("Approved pairing has no SPKI binding."),
        approved.TechnicianCapability ?? PkiProxy.Authentication.TechnicianCapabilities.BootstrapApprove);

    private int ReserveAttempt(CreatedRecord created, DateTimeOffset now)
    {
        for (var attempt = 1; attempt <= created.MaximumAttempts; attempt++)
        {
            var graph = ReadGraph(created.RequestId)!;
            if (graph.Created != created) throw new InvalidDataException("Pairing record changed.");
            if (graph.Claimed is not null) return 0;
            if (now < graph.LastAttemptAt) throw new InvalidDataException("Pairing attempt time regressed.");
            var marker = MarkerName(created.RequestId, "attempt-" + attempt.ToString("D2"));
            if (Create(marker, new AttemptRecord(1, created.RequestId, attempt, now)))
            {
                _ = ReadGraph(created.RequestId);
                return attempt;
            }
            _ = ReadGraph(created.RequestId);
        }
        return 0;
    }

    private int ReserveSlot(string requestId)
    {
        for (var slot = 1; slot <= policy.MaximumRetainedSessions; slot++)
            if (CreateReservation("pairing-slot-" + slot.ToString("D5") + ".json", requestId)) return slot;
        return 0;
    }

    private CreatedRecord? ReadCreated(string requestId)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        if (!ExistsChecked<CreatedRecord>(CreatedName(requestId))) return null;
        var value = ReadJson<CreatedRecord>(CreatedName(requestId));
        if (value.Version is not 2 and not 3 || !IsRequestId(value.RequestId) || value.RequestId != requestId || !IsHash(value.CsrSha256) ||
            !IsHash(value.SpkiSha256) || !IsHash(value.CodeSalt) || !IsHash(value.CodeVerifierSha256) ||
            !IsHash(value.CodeReservationSha256) ||
            value.ExpiresAt <= value.CreatedAt || value.ExpiresAt - value.CreatedAt > policy.Lifetime ||
            value.MaximumAttempts < 1 || value.MaximumAttempts > policy.MaximumAttempts ||
            value.Slot < 1 || value.Slot > policy.MaximumRetainedSessions)
            throw new InvalidDataException("Invalid pairing record.");
        return value;
    }

    private bool CreateReservation(string name, string requestId)
    {
        if (Create(name, new Reservation(1, requestId))) return true;
        var winner = ReadReservation(name);
        // Orphans remain reserved after partial Begin failures. If their created
        // record exists, the complete graph and this reservation edge must agree.
        var graph = ReadGraph(winner.RequestId);
        if (graph is not null && !ReservationNames(graph.Created).Contains(name, StringComparer.Ordinal))
            throw new InvalidDataException("Pairing reservation does not belong to its request.");
        return false;
    }

    private Reservation ReadReservation(string name)
    {
        var value = ReadJson<Reservation>(name);
        if (value.Version != 1 || !IsRequestId(value.RequestId))
            throw new InvalidDataException("Invalid pairing reservation.");
        return value;
    }

    private static string[] ReservationNames(CreatedRecord created) => created.Version == 3
        ? ["pairing-binding-" + created.CsrSha256 + ".json",
            "pairing-code-" + created.CodeReservationSha256 + ".json"]
        : ["pairing-binding-" + created.CsrSha256 + ".json",
            "pairing-code-" + created.CodeReservationSha256 + ".json",
            "pairing-slot-" + created.Slot.ToString("D5") + ".json"];

    private PairingGraph? ReadGraph(string requestId)
    {
        var created = ReadCreated(requestId);
        if (created is null) return null;
        foreach (var name in ReservationNames(created))
            if (ReadReservation(name).RequestId != requestId)
                throw new InvalidDataException("Mismatched pairing reservation.");

        // Read successors before predecessors so concurrent forward publication
        // cannot fabricate an approved-without-claim or attempt-prefix gap.
        var approved = ReadTransition(created, "approved");
        var claimed = ReadTransition(created, "claimed");
        var failed = ReadTransition(created, "failed");
        var ready = ReadTransition(created, "ready");
        if ((ready is null) == (failed is null))
            throw new InvalidDataException("Pairing requires exactly one ready or failed transition.");
        foreach (var transition in new[] { ready, failed })
            if (transition is not null && (transition.Version != 1 ||
                transition.TechnicianSubject is not null ||
                transition.AuthenticationMethod is not null || transition.AssetId is not null ||
                transition.CsrSha256 is not null || transition.SpkiSha256 is not null ||
                transition.TechnicianCapability is not null))
                throw new InvalidDataException("Unexpected pairing transition authority.");

        var count = 0;
        var nextAt = created.ExpiresAt;
        var lastAt = ready?.At ?? created.CreatedAt;
        var attemptNames = Enumerable.Range(1, created.MaximumAttempts)
            .Select(ordinal => Path.GetFileName(MarkerName(requestId, "attempt-" + ordinal.ToString("D2"))))
            .ToHashSet(StringComparer.Ordinal);
        foreach (var path in System.IO.Directory.EnumerateFileSystemEntries(directory, "pairing-" + requestId + ".attempt-*.json"))
            if (!attemptNames.Contains(Path.GetFileName(path)))
                throw new InvalidDataException("Pairing attempt is outside its budget.");
        // Ten is the schema's absolute attempt bound, including markers beyond
        // this request's smaller configured budget.
        for (var ordinal = 10; ordinal >= 1; ordinal--)
        {
            var name = MarkerName(requestId, "attempt-" + ordinal.ToString("D2"));
            if (!ExistsChecked<AttemptRecord>(name))
            {
                if (count != 0) throw new InvalidDataException("Pairing attempt prefix has a gap.");
                continue;
            }
            var attempt = ReadJson<AttemptRecord>(name);
            if (ready is null || ordinal > created.MaximumAttempts || attempt.Version != 1 ||
                attempt.RequestId != requestId || attempt.Attempt != ordinal ||
                attempt.At < ready.At || attempt.At >= created.ExpiresAt || attempt.At > nextAt)
                throw new InvalidDataException("Invalid pairing attempt.");
            if (count == 0) lastAt = attempt.At;
            nextAt = attempt.At;
            count++;
        }
        if (claimed is not null)
        {
            if (ready is null || count == 0 || claimed.At < ready.At || claimed.At < lastAt ||
                !IsIdentifier(claimed.TechnicianSubject, 256) || !IsIdentifier(claimed.AuthenticationMethod, 64) ||
                !IsIdentifier(claimed.AssetId, 256) || claimed.CsrSha256 != created.CsrSha256 ||
                claimed.SpkiSha256 != created.SpkiSha256 ||
                claimed.Version == 2 && claimed.TechnicianCapability !=
                    PkiProxy.Authentication.TechnicianCapabilities.BootstrapApprove ||
                claimed.Version == 1 && claimed.TechnicianCapability is not null)
                throw new InvalidDataException("Invalid pairing approval claim.");
        }
        if (approved is not null && (claimed is null || approved != claimed))
            throw new InvalidDataException("Pairing approval does not equal its claim.");
        return new(created, ready, failed, claimed, approved, count, lastAt);
    }

    private TransitionRecord? ReadTransition(CreatedRecord created, string stage)
    {
        var name = MarkerName(created.RequestId, stage);
        if (!ExistsChecked<TransitionRecord>(name)) return null;
        var value = ReadJson<TransitionRecord>(name);
        if (value.Version is not 1 and not 2 || value.RequestId != created.RequestId ||
            value.At < created.CreatedAt || value.At >= created.ExpiresAt)
            throw new InvalidDataException("Invalid pairing transition.");
        return value;
    }

    private void ValidateOwnClaim(CreatedRecord created, TransitionRecord claim)
    {
        var graph = ReadGraph(created.RequestId);
        if (graph is null || graph.Created != created || graph.Claimed != claim)
            throw new InvalidDataException("Pairing approval claim changed.");
    }

    private static void ValidateObservationTime(PairingGraph graph, DateTimeOffset now)
    {
        if (now < graph.Created.CreatedAt || now < graph.Ready?.At || now < graph.Failed?.At ||
            now < graph.LastAttemptAt || now < graph.Claimed?.At || now < graph.Approved?.At)
            throw new InvalidDataException("Pairing state is later than the observation time.");
    }

    private bool Create<T>(string name, T value)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        CheckDirectory();
        var path = Path.Combine(directory, name);
        var stagingPath = Path.Combine(directory,
            ".pairing-write-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + ".tmp");
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

    private bool ExistsChecked<T>(string name)
    {
        CheckDirectory();
        var path = Path.Combine(directory, name);
        var info = new FileInfo(path);
        info.Refresh();
        if (info.LinkTarget is not null || (info.Exists && info.Attributes.HasFlag(FileAttributes.ReparsePoint)))
            throw new IOException("Symbolic-link pairing marker rejected.");
        if (!info.Exists)
        {
            // A competing coordinator can publish an immutable marker between the
            // metadata refresh and this probe. Revalidate that object instead of
            // treating the legitimate publication race as malformed state.
            try { _ = File.GetAttributes(path); }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
            info.Refresh();
            if (!info.Exists) return false;
            if (info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("Symbolic-link pairing marker rejected.");
        }
        _ = ReadJson<T>(name);
        return true;
    }

    private static FileInfo CheckFile(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new FileInfo(path);
        info.Refresh();
        if (!info.Exists || info.LinkTarget is not null ||
            (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            info.Length is <= 0 or > 16_384 || File.GetUnixFileMode(path) != RecordMode ||
            !LinuxFileLinkGuard.IsSingleRegular(path))
            throw new IOException("Invalid private pairing marker.");
        return info;
    }

    private T ReadJson<T>(string name)
    {
        CheckDirectory();
        var path = Path.Combine(directory, name);
        var before = CheckFile(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!stream.CanSeek) throw new IOException("Regular pairing marker required.");
        var bytes = new byte[(int)before.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("Pairing marker changed while reading.");
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("Pairing JSON must be an object.");
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate pairing JSON property.");
            var value = document.RootElement.Deserialize<T>(Options)
                ?? throw new InvalidDataException("Missing pairing marker.");
            // Reopen the pathname as well as checking metadata: a replacement
            // can leave the first stream reading an unlinked, stale inode.
            var after = CheckFile(path);
            if (before.Length != after.Length || before.LastWriteTimeUtc != after.LastWriteTimeUtc ||
                before.CreationTimeUtc != after.CreationTimeUtc)
                throw new IOException("Pairing marker changed while reading.");
            using var verify = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!verify.CanSeek) throw new IOException("Regular pairing marker required.");
            var verifiedBytes = new byte[bytes.Length];
            verify.ReadExactly(verifiedBytes);
            var final = CheckFile(path);
            if (verify.ReadByte() != -1 || !bytes.AsSpan().SequenceEqual(verifiedBytes) ||
                after.Length != final.Length || after.LastWriteTimeUtc != final.LastWriteTimeUtc ||
                after.CreationTimeUtc != final.CreationTimeUtc)
                throw new IOException("Pairing marker changed while reading.");
            return value;
        }
        catch (JsonException error) { throw new InvalidDataException("Invalid pairing marker JSON.", error); }
    }

    private void CreateRequired<T>(string name, T value)
    {
        if (!Create(name, value)) throw new IOException("Pairing transition already exists and requires reconciliation.");
    }

    private string UniqueRequestId()
    {
        for (var attempt = 0; attempt < 32; attempt++)
        {
            var value = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            if (ReadGraph(value) is null) return value;
        }
        throw new InvalidOperationException("Unable to allocate a bootstrap request identifier.");
    }

    private void CheckDirectory()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new DirectoryInfo(directory);
        if (!info.Exists || info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            File.GetUnixFileMode(directory) != DirectoryMode)
            throw new IOException("Pre-provisioned owner-only pairing directory required.");
    }

    private void SyncDirectory()
    {
        var fd = Open(directory, 0x10000 | 0x80000);
        if (fd < 0) throw new IOException("Cannot open pairing directory for durability.");
        int closeResult;
        try { if (Fsync(fd) != 0) throw new IOException("Cannot flush pairing directory."); }
        finally { closeResult = Close(fd); }
        if (closeResult != 0) throw new IOException("Cannot close pairing directory.");
    }

    private static bool Matches(CreatedRecord record, string candidate)
    {
        if (!IsCode(candidate)) return false;
        var actual = Convert.FromHexString(Verifier(Convert.FromHexString(record.CodeSalt), candidate));
        return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(record.CodeVerifierSha256), actual) &&
            CryptographicOperations.FixedTimeEquals(Convert.FromHexString(record.CodeReservationSha256),
                SHA256.HashData(Encoding.ASCII.GetBytes(candidate)));
    }

    private static string Verifier(byte[] salt, string code) =>
        Convert.ToHexString(SHA256.HashData([.. salt, .. Encoding.ASCII.GetBytes(code)]));
    private static string CreatedName(string requestId) => "pairing-" + requestId + ".created.json";
    private string MarkerName(string requestId, string stage) => Path.Combine(directory, "pairing-" + requestId + "." + stage + ".json");
    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(c => char.IsAsciiDigit(c) || c is >= 'A' and <= 'F');
    private static bool IsCode(string? value) => value is { Length: 6 } && value.All(char.IsAsciiDigit);
    private static bool IsRequestId(string? value) => value is { Length: 32 } && value.All(c => char.IsAsciiDigit(c) || c is >= 'A' and <= 'F');
    private static bool IsIdentifier(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength && !value.Any(char.IsControl);
    private static void ValidateIdentifier(string value, string name, int maximumLength)
    {
        if (!IsIdentifier(value, maximumLength))
            throw new ArgumentException("A bounded printable identifier is required.", name);
    }

    private sealed record Reservation(int Version, string RequestId);
    private sealed record CreatedRecord(int Version, string RequestId, string CsrSha256,
        string SpkiSha256, string CodeSalt, string CodeVerifierSha256, string CodeReservationSha256,
        DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, int MaximumAttempts, int Slot);
    private sealed record AttemptRecord(int Version, string RequestId, int Attempt, DateTimeOffset At);
    private sealed record TransitionRecord(int Version, string RequestId, DateTimeOffset At,
        string? TechnicianSubject, string? AuthenticationMethod, string? AssetId,
        string? CsrSha256, string? SpkiSha256, string? TechnicianCapability = null);
    private sealed record PairingGraph(CreatedRecord Created, TransitionRecord? Ready, TransitionRecord? Failed,
        TransitionRecord? Claimed, TransitionRecord? Approved, int Attempts, DateTimeOffset LastAttemptAt);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int fd);
    [DllImport("libc", EntryPoint = "close")]
    private static extern int Close(int fd);
}
