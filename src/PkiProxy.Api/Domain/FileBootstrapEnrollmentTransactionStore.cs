using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PkiProxy.Domain;

internal enum BootstrapTransactionResult
{
    Retained,
    AlreadyRetained,
    AssetBound,
    AlreadyBound,
    Claimed,
    AlreadyClaimed,
    Recorded,
    NotFound,
    Expired,
    BindingMismatch,
    InvalidState,
    Conflict
}

internal enum BootstrapTransactionState
{
    RetainedUnbound,
    AssetBound,
    SubmissionClaimed,
    Pending,
    Issued,
    Failed,
    Expired
}

internal sealed record BootstrapTransactionRetainResult(BootstrapTransactionResult Result, string? TransactionId);
internal sealed record BootstrapTransactionClaimResult(BootstrapTransactionResult Result,
    FileBootstrapEnrollmentTransactionStore.SubmissionClaim? Claim);
internal sealed record BootstrapTransactionLookup(BootstrapTransactionResult Result, BootstrapTransactionState? State,
    int? IssuerRequestId = null, string? CertificateSha256 = null, string? SerialHex = null,
    string? FailureReasonCode = null, DateTimeOffset? ExpiresAt = null,
    FileBootstrapEnrollmentTransactionStore.SubmissionClaim? PendingCompletion = null);
internal sealed record BootstrapIssuedResponse(byte[] CertificateDer, byte[] FullPkiResponseDer, string RequestId);
internal sealed record BootstrapSubmissionPreparation(BootstrapTransactionResult Result, BootstrapTransactionState? State,
    string? AssetId = null, CsrBinding? Binding = null, byte[]? CsrDer = null,
    BootstrapIssuedResponse? IssuedResponse = null);

// Linux-local source-only component. The caller must validate the PKCS#10 request
// before retention. Every lifecycle transition is a create-once durable marker.
// BindAsset is a persistence seam, not authentication or asset authorization:
// the caller must complete authenticated technician approval against its catalogue.
// All times must come from the trusted service clock, never the client.
internal sealed class FileBootstrapEnrollmentTransactionStore
{
    internal const int MaximumCsrBytes = 65_536;
    private const int MaximumJsonBytes = 16_384;
    private const int MaximumCertificateBytes = 65_536;
    private const int MaximumFullPkiResponseBytes = 786_432;
    private const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode FileModeOwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        MaxDepth = 4,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly string directory;

    internal FileBootstrapEnrollmentTransactionStore(string directory)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux local transaction store required.");
        if (!Path.IsPathFullyQualified(directory)) throw new ArgumentException("Absolute transaction directory required.");
        var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        if (!string.Equals(normalized, Path.TrimEndingDirectorySeparator(directory), StringComparison.Ordinal))
            throw new ArgumentException("Canonical transaction directory path required.");
        this.directory = normalized;
        CheckDirectory();
    }

    internal BootstrapTransactionRetainResult Retain(ReadOnlySpan<byte> validatedCsrDer, CsrBinding binding,
        DateTimeOffset now, TimeSpan lifetime)
        => Retain(validatedCsrDer, binding, now, lifetime,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));

    internal BootstrapTransactionRetainResult Retain(ReadOnlySpan<byte> validatedCsrDer, CsrBinding binding,
        DateTimeOffset now, TimeSpan lifetime, string transactionId)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (validatedCsrDer.IsEmpty || validatedCsrDer.Length > MaximumCsrBytes)
            throw new ArgumentOutOfRangeException(nameof(validatedCsrDer), "A bounded public PKCS#10 request is required.");
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(24))
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Transaction lifetime must be positive and at most 24 hours.");
        if (!IsTransactionId(transactionId))
            throw new ArgumentException("Exact bootstrap transaction identifier required.", nameof(transactionId));
        var snapshot = binding.Snapshot();
        CsrBinding parsed;
        try { parsed = CsrBinding.FromDer(validatedCsrDer); }
        catch (Exception error) when (error is ArgumentException or CryptographicException)
        { throw new ArgumentException("Validated request must be a public DER PKCS#10 request.", nameof(validatedCsrDer), error); }
        if (!snapshot.Matches(parsed)) throw new ArgumentException("CSR and SPKI bindings do not match retained request.", nameof(binding));

        var record = new RetainedRecord(1, transactionId,
            Convert.ToHexString(snapshot.CsrSha256), Convert.ToHexString(snapshot.SubjectPublicKeyInfoSha256),
            validatedCsrDer.Length, now, now.Add(lifetime));
        var bindingName = "bootstrap-csr-" + record.CsrSha256 + ".json";
        if (!CreateJson(bindingName, record))
        {
            var existing = ReadJson<RetainedRecord>(bindingName);
            ValidateRetained(existing, existing.TransactionId);
            var same = existing.CsrSha256 == record.CsrSha256 &&
                existing.SpkiSha256 == record.SpkiSha256 && existing.CsrLength == record.CsrLength &&
                existing.CreatedAt == record.CreatedAt && existing.ExpiresAt == record.ExpiresAt;
            if (same && Load(existing.TransactionId, snapshot).Result != BootstrapTransactionResult.Recorded)
                throw new IOException("Retained transaction is incomplete and requires reconciliation.");
            return new(same ? BootstrapTransactionResult.AlreadyRetained : BootstrapTransactionResult.Conflict,
                same ? existing.TransactionId : null);
        }

        CreateBytesRequired(CsrName(transactionId), validatedCsrDer);
        CreateJsonRequired(RetainedName(transactionId), record);
        return new(BootstrapTransactionResult.Retained, transactionId);
    }

    internal BootstrapTransactionResult BindAsset(string transactionId, CsrBinding binding,
        string authoritativeAssetId, DateTimeOffset now)
    {
        ValidateAsset(authoritativeAssetId);
        var loaded = Load(transactionId, binding);
        if (loaded.Result != BootstrapTransactionResult.Recorded) return loaded.Result;
        var retained = loaded.Record!;
        if (now < retained.CreatedAt || (loaded.Asset is not null && now < loaded.Asset.BoundAt))
            return BootstrapTransactionResult.InvalidState;
        if (now >= retained.ExpiresAt) return BootstrapTransactionResult.Expired;
        if (HasSubmissionState(transactionId)) return BootstrapTransactionResult.InvalidState;
        if (loaded.Asset is not null)
        {
            if (loaded.Asset.AssetId != authoritativeAssetId) return BootstrapTransactionResult.Conflict;
            // A concurrent creator may have linked its fsynced file but not yet
            // flushed the directory. Reconciliation must also be durable.
            SyncDirectory();
            return BootstrapTransactionResult.AlreadyBound;
        }

        var asset = new AssetRecord(1, transactionId, retained.CsrSha256, retained.SpkiSha256,
            authoritativeAssetId, now);
        if (CreateJson(AssetName(transactionId), asset)) return BootstrapTransactionResult.AssetBound;
        // Another caller published a complete marker. Re-read all durable inputs;
        // an exact replay reconciles the winner but never creates another binding.
        var existing = Load(transactionId, binding);
        if (existing.Result != BootstrapTransactionResult.Recorded || existing.Asset is null)
            throw new InvalidDataException("Asset binding is incomplete and requires reconciliation.");
        if (now < existing.Asset.BoundAt || HasSubmissionState(transactionId))
            return BootstrapTransactionResult.InvalidState;
        if (existing.Asset.AssetId != authoritativeAssetId) return BootstrapTransactionResult.Conflict;
        SyncDirectory();
        return BootstrapTransactionResult.AlreadyBound;
    }

    internal BootstrapTransactionClaimResult TryClaimSubmission(string transactionId, CsrBinding binding,
        string assetId, DateTimeOffset now)
    {
        ValidateAsset(assetId);
        var loaded = Load(transactionId, binding);
        if (loaded.Result != BootstrapTransactionResult.Recorded)
            return new(loaded.Result, null);
        if (now < loaded.Record!.CreatedAt)
            return new(BootstrapTransactionResult.InvalidState, null);
        if (now >= loaded.Record!.ExpiresAt)
            return new(BootstrapTransactionResult.Expired, null);
        if (loaded.Asset is null || now < loaded.Asset.BoundAt)
            return new(BootstrapTransactionResult.InvalidState, null);
        if (loaded.Asset.AssetId != assetId)
            return new(BootstrapTransactionResult.BindingMismatch, null);
        if (ExistsChecked(PendingName(transactionId)) || ExistsChecked(TerminalName(transactionId)))
            return new(BootstrapTransactionResult.InvalidState, null);
        var transition = new ClaimRecord(1, transactionId, loaded.Record.CsrSha256,
            loaded.Record.SpkiSha256, assetId, loaded.Asset.BoundAt, now);
        if (!CreateJson(ClaimedName(transactionId), transition))
        {
            var existing = ReadJson<ClaimRecord>(ClaimedName(transactionId));
            ValidateClaim(existing, loaded.Record, loaded.Asset);
            if (now < existing.ClaimedAt) return new(BootstrapTransactionResult.InvalidState, null);
            return new(BootstrapTransactionResult.AlreadyClaimed, null);
        }
        return new(BootstrapTransactionResult.Claimed,
            NewClaim(loaded.Record, loaded.Asset, loaded.CsrBytes!));
    }

    internal BootstrapTransactionLookup Lookup(string transactionId, CsrBinding binding,
        string? assetId, DateTimeOffset now)
    {
        if (assetId is not null) ValidateAsset(assetId);
        var loaded = Load(transactionId, binding);
        if (loaded.Result != BootstrapTransactionResult.Recorded)
            return new(loaded.Result, null);
        var retained = loaded.Record!;
        if (now < retained.CreatedAt || (loaded.Asset is not null && now < loaded.Asset.BoundAt))
            return new(BootstrapTransactionResult.InvalidState, null);
        if (loaded.Asset is null)
        {
            if (assetId is not null) return new(BootstrapTransactionResult.InvalidState, null);
            return now >= retained.ExpiresAt
                ? new(BootstrapTransactionResult.Expired, BootstrapTransactionState.Expired, ExpiresAt: retained.ExpiresAt)
                : new(BootstrapTransactionResult.Recorded, BootstrapTransactionState.RetainedUnbound, ExpiresAt: retained.ExpiresAt);
        }
        if (loaded.Asset.AssetId != assetId) return new(BootstrapTransactionResult.BindingMismatch, null);
        if (ExistsChecked(TerminalName(transactionId)))
        {
            if (!ExistsChecked(ClaimedName(transactionId)))
                throw new InvalidDataException("Terminal transaction has no submission claim.");
            var claim = ReadJson<ClaimRecord>(ClaimedName(transactionId));
            ValidateClaim(claim, retained, loaded.Asset);
            var terminal = ReadJson<TerminalRecord>(TerminalName(transactionId));
            ValidateTerminal(terminal, retained);
            if (terminal.RecordedAt < claim.ClaimedAt)
                throw new InvalidDataException("Terminal outcome predates submission claim.");
            if (now < terminal.RecordedAt) return new(BootstrapTransactionResult.InvalidState, null);
            if (ExistsChecked(PendingName(transactionId)))
            {
                var pending = ReadJson<PendingRecord>(PendingName(transactionId));
                ValidatePending(pending, retained);
                if (pending.RecordedAt < claim.ClaimedAt || terminal.RecordedAt < pending.RecordedAt)
                    throw new InvalidDataException("Invalid pending-to-terminal chronology.");
                if (terminal.Kind == "issued" && pending.IssuerRequestId != terminal.IssuerRequestId)
                    throw new InvalidDataException("Issued result conflicts with pending issuer request.");
            }
            if (terminal.Kind == "issued")
            {
                if (terminal.Version == 2) _ = ReadIssuedResponse(retained, terminal);
                return new(BootstrapTransactionResult.Recorded, BootstrapTransactionState.Issued,
                    terminal.IssuerRequestId, terminal.CertificateSha256, terminal.SerialHex, null, retained.ExpiresAt);
            }
            return new(BootstrapTransactionResult.Recorded, BootstrapTransactionState.Failed,
                FailureReasonCode: terminal.ReasonCode, ExpiresAt: retained.ExpiresAt);
        }
        if (ExistsChecked(PendingName(transactionId)))
        {
            if (!ExistsChecked(ClaimedName(transactionId)))
                throw new InvalidDataException("Pending transaction has no submission claim.");
            var claim = ReadJson<ClaimRecord>(ClaimedName(transactionId));
            ValidateClaim(claim, retained, loaded.Asset);
            var pending = ReadJson<PendingRecord>(PendingName(transactionId));
            ValidatePending(pending, retained);
            if (pending.RecordedAt < claim.ClaimedAt)
                throw new InvalidDataException("Pending outcome predates submission claim.");
            if (now < pending.RecordedAt) return new(BootstrapTransactionResult.InvalidState, null);
            return new(BootstrapTransactionResult.Recorded, BootstrapTransactionState.Pending,
                pending.IssuerRequestId, ExpiresAt: retained.ExpiresAt,
                PendingCompletion: NewClaim(retained, loaded.Asset, loaded.CsrBytes!));
        }
        if (ExistsChecked(ClaimedName(transactionId)))
        {
            var claim = ReadJson<ClaimRecord>(ClaimedName(transactionId));
            ValidateClaim(claim, retained, loaded.Asset);
            if (now < claim.ClaimedAt) return new(BootstrapTransactionResult.InvalidState, null);
            return new(BootstrapTransactionResult.Recorded, BootstrapTransactionState.SubmissionClaimed,
                ExpiresAt: retained.ExpiresAt);
        }
        if (now >= retained.ExpiresAt)
            return new(BootstrapTransactionResult.Expired, BootstrapTransactionState.Expired, ExpiresAt: retained.ExpiresAt);
        return new(BootstrapTransactionResult.Recorded, BootstrapTransactionState.AssetBound,
            ExpiresAt: retained.ExpiresAt);
    }

    // Recovery uses the immutable asset marker directly because an otherwise
    // valid binding is reported as expired after the anonymous lifetime. It
    // must not infer trust from pairing approval alone.
    internal bool HasDurableAssetBinding(string transactionId, CsrBinding binding, string assetId)
    {
        ValidateAsset(assetId);
        var loaded = Load(transactionId, binding);
        if (loaded.Result != BootstrapTransactionResult.Recorded) return false;
        return loaded.Asset?.AssetId == assetId;
    }

    // Internal status/issuance correlation uses the opaque 128-bit transaction
    // identifier. It never accepts the six-digit display aid or client facts.
    internal BootstrapSubmissionPreparation PrepareSubmission(string transactionId, DateTimeOffset now)
    {
        var loaded = LoadById(transactionId);
        if (loaded.Result != BootstrapTransactionResult.Recorded)
            return new(loaded.Result, null);
        var binding = Binding(loaded.Record!);
        var lookup = Lookup(transactionId, binding, loaded.Asset?.AssetId, now);
        BootstrapIssuedResponse? issued = null;
        if (lookup.State == BootstrapTransactionState.Issued)
        {
            var terminal = ReadJson<TerminalRecord>(TerminalName(transactionId));
            if (terminal.Version == 2) issued = ReadIssuedResponse(loaded.Record!, terminal);
        }
        return new(lookup.Result, lookup.State, loaded.Asset?.AssetId, binding,
            loaded.CsrBytes?.ToArray(), issued);
    }

    // Called only while the process-shared intake lock is held. It removes an
    // uncommitted or expired anonymous request, never a technician-bound,
    // claimed, pending, issued or failed transaction. Every existing pathname
    // is validated through the ordinary bounded reader before unlinking.
    internal void DeleteUntrusted(string transactionId, CsrBinding binding,
        DateTimeOffset now, bool requireExpiry)
    {
        if (!IsTransactionId(transactionId)) throw new ArgumentException("Exact transaction identifier required.");
        ArgumentNullException.ThrowIfNull(binding);
        var retainedName = RetainedName(transactionId);
        if (!ExistsChecked(retainedName)) return;
        var loaded = Load(transactionId, binding);
        if (loaded.Result != BootstrapTransactionResult.Recorded || loaded.Record is null || loaded.Asset is not null ||
            HasSubmissionState(transactionId) || (requireExpiry && now < loaded.Record.ExpiresAt))
            throw new InvalidDataException("Bootstrap transaction is not collectable.");

        var reservationName = "bootstrap-csr-" + loaded.Record.CsrSha256 + ".json";
        _ = ReadJson<RetainedRecord>(reservationName);
        _ = ReadBytes(CsrName(transactionId), MaximumCsrBytes);
        File.Delete(Path.Combine(directory, CsrName(transactionId)));
        File.Delete(Path.Combine(directory, retainedName));
        File.Delete(Path.Combine(directory, reservationName));
        SyncDirectory();
    }

    private LoadResult LoadById(string transactionId)
    {
        if (!IsTransactionId(transactionId)) return new(BootstrapTransactionResult.NotFound, null, null);
        if (!ExistsChecked(RetainedName(transactionId))) return new(BootstrapTransactionResult.NotFound, null, null);
        var retained = ReadJson<RetainedRecord>(RetainedName(transactionId));
        ValidateRetained(retained, transactionId);
        return Load(transactionId, Binding(retained));
    }

    private static CsrBinding Binding(RetainedRecord retained) => new(
        Convert.FromHexString(retained.CsrSha256), Convert.FromHexString(retained.SpkiSha256));

    private LoadResult Load(string transactionId, CsrBinding binding)
    {
        if (!IsTransactionId(transactionId)) return new(BootstrapTransactionResult.NotFound, null, null);
        ArgumentNullException.ThrowIfNull(binding);
        var retainedName = RetainedName(transactionId);
        if (!ExistsChecked(retainedName)) return new(BootstrapTransactionResult.NotFound, null, null);
        var record = ReadJson<RetainedRecord>(retainedName);
        ValidateRetained(record, transactionId);
        var reservation = ReadJson<RetainedRecord>("bootstrap-csr-" + record.CsrSha256 + ".json");
        ValidateRetained(reservation, transactionId);
        if (reservation != record) throw new InvalidDataException("Immutable transaction reservation changed.");
        var csr = ReadBytes(CsrName(transactionId), MaximumCsrBytes);
        if (csr.Length != record.CsrLength) throw new InvalidDataException("Retained CSR length changed.");
        CsrBinding parsed;
        try { parsed = CsrBinding.FromDer(csr); }
        catch (Exception error) when (error is ArgumentException or CryptographicException)
        { throw new InvalidDataException("Retained CSR is invalid.", error); }
        var expected = new CsrBinding(Convert.FromHexString(record.CsrSha256), Convert.FromHexString(record.SpkiSha256));
        if (!expected.Matches(parsed)) throw new InvalidDataException("Retained CSR binding changed.");
        if (!expected.Matches(binding))
            return new(BootstrapTransactionResult.BindingMismatch, null, null);
        AssetRecord? asset = null;
        if (ExistsChecked(AssetName(transactionId)))
        {
            asset = ReadJson<AssetRecord>(AssetName(transactionId));
            ValidateAssetRecord(asset, record);
            if (ExistsChecked(ClaimedName(transactionId)))
                ValidateClaim(ReadJson<ClaimRecord>(ClaimedName(transactionId)), record, asset);
        }
        else if (HasSubmissionState(transactionId))
            throw new InvalidDataException("Submission state has no durable asset binding.");
        return new(BootstrapTransactionResult.Recorded, record, csr, asset);
    }

    private bool HasSubmissionState(string transactionId) => ExistsChecked(ClaimedName(transactionId)) ||
        ExistsChecked(PendingName(transactionId)) || ExistsChecked(TerminalName(transactionId));

    private void RecordPending(RetainedRecord retained, AssetRecord asset, int issuerRequestId, DateTimeOffset now)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(issuerRequestId);
        var claim = CheckClaimedMutable(retained, asset);
        if (now < claim.ClaimedAt) throw new ArgumentOutOfRangeException(nameof(now), "Pending outcome cannot predate claim.");
        if (ExistsChecked(TerminalName(retained.TransactionId)))
            throw new InvalidOperationException("Transaction is terminal.");
        var record = new PendingRecord(1, retained.TransactionId, issuerRequestId, now);
        if (!CreateJson(PendingName(retained.TransactionId), record))
        {
            var existing = ReadJson<PendingRecord>(PendingName(retained.TransactionId));
            ValidatePending(existing, retained);
            if (existing.IssuerRequestId != issuerRequestId) throw new InvalidOperationException("Conflicting issuer request ID.");
            throw new InvalidOperationException("Pending outcome was already recorded.");
        }
    }

    private void RecordIssued(RetainedRecord retained, AssetRecord asset, int issuerRequestId, string certificateSha256,
        string serialHex, DateTimeOffset now)
    {
        if (issuerRequestId <= 0 || !IsHash(certificateSha256))
            throw new ArgumentException("Positive issuer request ID and exact certificate SHA256 required.");
        if (!IsSerial(serialHex)) throw new ArgumentException("Bounded hexadecimal certificate serial required.", nameof(serialHex));
        var claim = CheckClaimedMutable(retained, asset);
        if (now < claim.ClaimedAt) throw new ArgumentOutOfRangeException(nameof(now), "Issued outcome cannot predate claim.");
        if (ExistsChecked(TerminalName(retained.TransactionId))) throw new InvalidOperationException("Transaction is terminal.");
        if (ExistsChecked(PendingName(retained.TransactionId)))
        {
            var pending = ReadJson<PendingRecord>(PendingName(retained.TransactionId));
            ValidatePending(pending, retained);
            if (pending.IssuerRequestId != issuerRequestId) throw new InvalidOperationException("Issued result conflicts with pending request.");
            if (now < pending.RecordedAt) throw new ArgumentOutOfRangeException(nameof(now), "Issued outcome cannot predate pending state.");
        }
        var record = new TerminalRecord(1, retained.TransactionId, "issued", issuerRequestId,
            certificateSha256.ToUpperInvariant(), serialHex.ToUpperInvariant(), null, now);
        if (!CreateJson(TerminalName(retained.TransactionId), record))
            throw new InvalidOperationException("Terminal outcome was already recorded.");
    }

    private void RecordIssuedResponse(RetainedRecord retained, AssetRecord asset, int issuerRequestId,
        ReadOnlySpan<byte> certificateDer, ReadOnlySpan<byte> fullPkiResponseDer, DateTimeOffset now)
    {
        if (certificateDer.IsEmpty || certificateDer.Length > MaximumCertificateBytes ||
            fullPkiResponseDer.IsEmpty || fullPkiResponseDer.Length > MaximumFullPkiResponseBytes)
            throw new ArgumentException("Bounded public issuance response required.");
        using var certificate = X509CertificateLoader.LoadCertificate(certificateDer);
        var certificateHash = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        var serial = certificate.SerialNumber;
        var responseHash = Convert.ToHexString(SHA256.HashData(fullPkiResponseDer));
        var claim = CheckClaimedMutable(retained, asset);
        ArgumentOutOfRangeException.ThrowIfLessThan(now, claim.ClaimedAt);
        if (ExistsChecked(TerminalName(retained.TransactionId)))
            throw new InvalidOperationException("Transaction is terminal.");

        CreateBytesRequired(CertificateName(retained.TransactionId), certificateDer);
        CreateBytesRequired(FullResponseName(retained.TransactionId), fullPkiResponseDer);
        CreateJsonRequired(ReleaseName(retained.TransactionId), new ReleaseRecord(1,
            retained.TransactionId, issuerRequestId, certificateHash, certificateDer.Length,
            responseHash, fullPkiResponseDer.Length));
        if (ExistsChecked(PendingName(retained.TransactionId)))
        {
            var pending = ReadJson<PendingRecord>(PendingName(retained.TransactionId));
            ValidatePending(pending, retained);
            if (pending.IssuerRequestId != issuerRequestId)
                throw new InvalidOperationException("Issued result conflicts with pending request.");
            ArgumentOutOfRangeException.ThrowIfLessThan(now, pending.RecordedAt);
        }
        CreateJsonRequired(TerminalName(retained.TransactionId), new TerminalRecord(2,
            retained.TransactionId, "issued", issuerRequestId, certificateHash, serial, null, now));
    }

    private BootstrapIssuedResponse ReadIssuedResponse(RetainedRecord retained, TerminalRecord terminal)
    {
        var release = ReadJson<ReleaseRecord>(ReleaseName(retained.TransactionId));
        if (release.Version != 1 || release.TransactionId != retained.TransactionId ||
            release.IssuerRequestId != terminal.IssuerRequestId ||
            release.CertificateSha256 != terminal.CertificateSha256 ||
            !IsHash(release.FullPkiResponseSha256) ||
            release.CertificateLength is < 1 or > MaximumCertificateBytes ||
            release.FullPkiResponseLength is < 1 or > MaximumFullPkiResponseBytes)
            throw new InvalidDataException("Invalid durable bootstrap release record.");
        var certificate = ReadBytes(CertificateName(retained.TransactionId), MaximumCertificateBytes);
        var response = ReadBytes(FullResponseName(retained.TransactionId), MaximumFullPkiResponseBytes);
        if (certificate.Length != release.CertificateLength || response.Length != release.FullPkiResponseLength ||
            Convert.ToHexString(SHA256.HashData(certificate)) != release.CertificateSha256 ||
            Convert.ToHexString(SHA256.HashData(response)) != release.FullPkiResponseSha256)
            throw new InvalidDataException("Durable bootstrap release material changed.");
        using var leaf = X509CertificateLoader.LoadCertificate(certificate);
        if (leaf.SerialNumber != terminal.SerialHex)
            throw new InvalidDataException("Durable bootstrap certificate serial changed.");
        return new(certificate, response, release.IssuerRequestId.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private void RecordFailed(RetainedRecord retained, AssetRecord asset, string reasonCode, DateTimeOffset now)
    {
        ValidateReason(reasonCode);
        var claim = CheckClaimedMutable(retained, asset);
        if (now < claim.ClaimedAt) throw new ArgumentOutOfRangeException(nameof(now), "Failure cannot predate claim.");
        if (ExistsChecked(PendingName(retained.TransactionId)))
        {
            var pending = ReadJson<PendingRecord>(PendingName(retained.TransactionId));
            ValidatePending(pending, retained);
            if (now < pending.RecordedAt) throw new ArgumentOutOfRangeException(nameof(now), "Failure cannot predate pending state.");
        }
        var record = new TerminalRecord(1, retained.TransactionId, "failed", null, null, null, reasonCode, now);
        if (!CreateJson(TerminalName(retained.TransactionId), record))
            throw new InvalidOperationException("Terminal outcome was already recorded.");
    }

    private ClaimRecord CheckClaimedMutable(RetainedRecord retained, AssetRecord asset)
    {
        var loaded = Load(retained.TransactionId,
            new CsrBinding(Convert.FromHexString(retained.CsrSha256), Convert.FromHexString(retained.SpkiSha256)));
        if (loaded.Result != BootstrapTransactionResult.Recorded || loaded.Record != retained || loaded.Asset != asset)
            throw new InvalidDataException("Claimed transaction or asset binding changed.");
        if (!ExistsChecked(ClaimedName(retained.TransactionId))) throw new InvalidOperationException("Submission was not claimed.");
        var claim = ReadJson<ClaimRecord>(ClaimedName(retained.TransactionId));
        ValidateClaim(claim, retained, asset);
        return claim;
    }

    private static void ValidateRetained(RetainedRecord value, string expectedTransactionId)
    {
        if (value.Version != 1 || value.TransactionId != expectedTransactionId || !IsTransactionId(value.TransactionId) ||
            !IsHash(value.CsrSha256) || !IsHash(value.SpkiSha256) || value.CsrLength is < 1 or > MaximumCsrBytes ||
            value.ExpiresAt <= value.CreatedAt ||
            value.ExpiresAt - value.CreatedAt > TimeSpan.FromHours(24))
            throw new InvalidDataException("Invalid retained transaction record.");
    }

    private static void ValidateAssetRecord(AssetRecord value, RetainedRecord retained)
    {
        if (value.Version != 1 || value.TransactionId != retained.TransactionId || !IsAsset(value.AssetId) ||
            value.CsrSha256 != retained.CsrSha256 || value.SpkiSha256 != retained.SpkiSha256 ||
            value.BoundAt < retained.CreatedAt || value.BoundAt >= retained.ExpiresAt)
            throw new InvalidDataException("Invalid immutable asset binding record.");
    }

    private static void ValidateClaim(ClaimRecord value, RetainedRecord retained, AssetRecord asset)
    {
        if (value.Version != 1 || value.TransactionId != retained.TransactionId || value.AssetId != asset.AssetId ||
            value.CsrSha256 != retained.CsrSha256 || value.SpkiSha256 != retained.SpkiSha256 ||
            value.AssetBoundAt != asset.BoundAt || value.ClaimedAt < asset.BoundAt || value.ClaimedAt >= retained.ExpiresAt)
            throw new InvalidDataException("Invalid submission claim record.");
    }

    private static void ValidatePending(PendingRecord value, RetainedRecord retained)
    {
        if (value.Version != 1 || value.TransactionId != retained.TransactionId || value.IssuerRequestId <= 0 ||
            value.RecordedAt < retained.CreatedAt)
            throw new InvalidDataException("Invalid pending transaction record.");
    }

    private static void ValidateTerminal(TerminalRecord value, RetainedRecord retained)
    {
        var issued = value.Kind == "issued" && value.IssuerRequestId > 0 && IsHash(value.CertificateSha256) &&
            IsSerial(value.SerialHex) && value.ReasonCode is null;
        var failed = value.Kind == "failed" && value.IssuerRequestId is null && value.CertificateSha256 is null &&
            value.SerialHex is null && IsReason(value.ReasonCode);
        if ((value.Version is not 1 and not 2) || (value.Version == 2 && !issued) ||
            value.TransactionId != retained.TransactionId || (!issued && !failed) ||
            value.RecordedAt < retained.CreatedAt)
            throw new InvalidDataException("Invalid terminal transaction record.");
    }

    private bool ExistsChecked(string name)
    {
        CheckDirectory();
        var path = Path.Combine(directory, name);
        var info = new FileInfo(path);
        info.Refresh();
        if (info.LinkTarget is not null) throw new IOException("Symbolic-link transaction record rejected.");
        if (!info.Exists) return false;
        CheckFile(path, MaximumJsonBytes);
        return true;
    }

    private T ReadJson<T>(string name)
    {
        var bytes = ReadBytes(name, MaximumJsonBytes);
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("JSON record must be an object.");
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate JSON property.");
            return document.RootElement.Deserialize<T>(JsonOptions) ?? throw new InvalidDataException("Missing JSON record.");
        }
        catch (JsonException error) { throw new InvalidDataException("Invalid transaction JSON.", error); }
    }

    private byte[] ReadBytes(string name, int maximum)
    {
        CheckDirectory();
        var path = Path.Combine(directory, name);
        var info = CheckFile(path, maximum);
        using var stream = new FileStream(path, System.IO.FileMode.Open, FileAccess.Read, FileShare.Read);
        var bytes = new byte[(int)info.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("Transaction record changed while reading.");
        return bytes;
    }

    private static FileInfo CheckFile(string path, int maximum)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux local transaction store required.");
        var info = new FileInfo(path);
        info.Refresh();
        if (!info.Exists || info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            info.Length <= 0 || info.Length > maximum || File.GetUnixFileMode(path) != FileModeOwnerOnly ||
            !LinuxFileLinkGuard.IsSingleRegular(path))
            throw new IOException("Invalid private transaction record.");
        return info;
    }

    private bool CreateJson(string name, object value)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux local transaction store required.");
        CheckDirectory();
        var path = Path.Combine(directory, name);
        var stagingPath = Path.Combine(directory,
            ".bootstrap-write-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + ".tmp");
        try
        {
            using (var stream = Create(stagingPath))
            {
                JsonSerializer.Serialize(stream, value, JsonOptions);
                stream.Flush(flushToDisk: true);
            }
            if (!LinuxAtomicPublish.TryRenameNoReplace(stagingPath, path))
            {
                return false;
            }
            SyncDirectory();
            return true;
        }
        finally
        {
            if (File.Exists(stagingPath)) File.Delete(stagingPath);
        }
    }

    private void CreateJsonRequired(string name, object value)
    {
        if (!CreateJson(name, value)) throw new IOException("Transaction marker already exists and requires reconciliation.");
    }

    private void CreateBytesRequired(string name, ReadOnlySpan<byte> value)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux local transaction store required.");
        CheckDirectory();
        var path = Path.Combine(directory, name);
        var stagingPath = Path.Combine(directory,
            ".bootstrap-write-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + ".tmp");
        try
        {
            using (var stream = Create(stagingPath))
            {
                stream.Write(value);
                stream.Flush(flushToDisk: true);
            }
            if (!LinuxAtomicPublish.TryRenameNoReplace(stagingPath, path))
                throw new IOException("Cannot publish retained CSR.");
            SyncDirectory();
        }
        finally
        {
            if (File.Exists(stagingPath)) File.Delete(stagingPath);
        }
    }

    private static FileStream Create(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux local transaction store required.");
        return new(path, new FileStreamOptions
        {
            Mode = System.IO.FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.WriteThrough,
            UnixCreateMode = FileModeOwnerOnly
        });
    }

    private void CheckDirectory()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux local transaction store required.");
        var info = new DirectoryInfo(directory);
        info.Refresh();
        if (!info.Exists || info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            File.GetUnixFileMode(directory) != DirectoryMode)
            throw new IOException("Pre-provisioned owner-only transaction directory required.");
    }

    private void SyncDirectory()
    {
        var descriptor = Open(directory, 0x10000 | 0x80000);
        if (descriptor < 0) throw new IOException("Cannot open transaction directory for durability.");
        int closeResult;
        try { if (Fsync(descriptor) != 0) throw new IOException("Cannot flush transaction directory."); }
        finally { closeResult = Close(descriptor); }
        if (closeResult != 0) throw new IOException("Cannot close transaction directory.");
    }

    private static void ValidateAsset(string value)
    {
        if (!IsAsset(value)) throw new ArgumentException("Bounded authoritative asset ID required.", nameof(value));
    }

    private static void ValidateReason(string value)
    {
        if (!IsReason(value)) throw new ArgumentException("Bounded failure reason code required.", nameof(value));
    }

    private static bool IsAsset(string? value) => value is { Length: >= 1 and <= 256 } &&
        !char.IsWhiteSpace(value[0]) && !char.IsWhiteSpace(value[^1]) && value.All(c => !char.IsControl(c));
    private static bool IsReason(string? value) => value is { Length: >= 1 and <= 64 } &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or ':');
    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    private static bool IsSerial(string? value) => value is { Length: >= 2 and <= 128 } && value.Length % 2 == 0 && value.All(char.IsAsciiHexDigit);
    private static bool IsTransactionId(string? value) => value is { Length: 32 } && value.All(char.IsAsciiHexDigit);
    private SubmissionClaim NewClaim(RetainedRecord retained, AssetRecord asset, byte[] csr) => new(this, retained.TransactionId,
        asset.AssetId, asset.BoundAt, retained.CsrSha256, retained.SpkiSha256, retained.CsrLength,
        retained.CreatedAt, retained.ExpiresAt, csr);
    private static string RetainedName(string id) => "bootstrap-" + id + ".retained.json";
    private static string CsrName(string id) => "bootstrap-" + id + ".csr";
    private static string AssetName(string id) => "bootstrap-" + id + ".asset.json";
    private static string ClaimedName(string id) => "bootstrap-" + id + ".claimed.json";
    private static string PendingName(string id) => "bootstrap-" + id + ".pending.json";
    private static string TerminalName(string id) => "bootstrap-" + id + ".terminal.json";
    private static string CertificateName(string id) => "bootstrap-" + id + ".certificate.der";
    private static string FullResponseName(string id) => "bootstrap-" + id + ".full-response.der";
    private static string ReleaseName(string id) => "bootstrap-" + id + ".release.json";

    private sealed record RetainedRecord(int Version, string TransactionId,
        string CsrSha256, string SpkiSha256, int CsrLength, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);
    private sealed record AssetRecord(int Version, string TransactionId, string CsrSha256,
        string SpkiSha256, string AssetId, DateTimeOffset BoundAt);
    private sealed record ClaimRecord(int Version, string TransactionId, string CsrSha256,
        string SpkiSha256, string AssetId, DateTimeOffset AssetBoundAt, DateTimeOffset ClaimedAt);
    private sealed record PendingRecord(int Version, string TransactionId, int IssuerRequestId, DateTimeOffset RecordedAt);
    private sealed record TerminalRecord(int Version, string TransactionId, string Kind, int? IssuerRequestId,
        string? CertificateSha256, string? SerialHex, string? ReasonCode, DateTimeOffset RecordedAt);
    private sealed record ReleaseRecord(int Version, string TransactionId, int IssuerRequestId,
        string CertificateSha256, int CertificateLength, string FullPkiResponseSha256,
        int FullPkiResponseLength);
    private sealed record LoadResult(BootstrapTransactionResult Result, RetainedRecord? Record, byte[]? CsrBytes,
        AssetRecord? Asset = null);

    internal sealed class SubmissionClaim
    {
        private readonly FileBootstrapEnrollmentTransactionStore owner;
        private readonly RetainedRecord retained;
        private readonly AssetRecord asset;
        private readonly byte[] csr;
        internal SubmissionClaim(FileBootstrapEnrollmentTransactionStore owner, string transactionId,
            string assetId, DateTimeOffset assetBoundAt, string csrSha256, string spkiSha256, int csrLength,
            DateTimeOffset createdAt, DateTimeOffset expiresAt, byte[] csr)
        {
            this.owner = owner;
            retained = new RetainedRecord(1, transactionId, csrSha256, spkiSha256,
                csrLength, createdAt, expiresAt);
            asset = new AssetRecord(1, transactionId, csrSha256, spkiSha256, assetId, assetBoundAt);
            this.csr = csr.ToArray();
        }
        internal byte[] ExportValidatedCsr()
        {
            owner.CheckClaimedMutable(retained, asset);
            return csr.ToArray();
        }
        internal void RecordPending(int issuerRequestId, DateTimeOffset now) => owner.RecordPending(retained, asset, issuerRequestId, now);
        internal void RecordIssued(int issuerRequestId, string certificateSha256, string serialHex, DateTimeOffset now) =>
            owner.RecordIssued(retained, asset, issuerRequestId, certificateSha256, serialHex, now);
        internal void RecordIssuedResponse(int issuerRequestId, ReadOnlySpan<byte> certificateDer,
            ReadOnlySpan<byte> fullPkiResponseDer, DateTimeOffset now) =>
            owner.RecordIssuedResponse(retained, asset, issuerRequestId, certificateDer, fullPkiResponseDer, now);
        internal void RecordFailed(string reasonCode, DateTimeOffset now) => owner.RecordFailed(retained, asset, reasonCode, now);
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int descriptor);
    [DllImport("libc", EntryPoint = "close")]
    private static extern int Close(int descriptor);
}
