using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using PkiProxy.Protocol.Cmc;

namespace PkiProxy.Domain;

internal sealed record RecordedDomainCertificate(Guid DirectoryObjectId, string AssetId, string CertificateSha256);

// Linux, local durable filesystem only. A successful claim must precede SendAsync.
// Existing, partial, failed or uncertain attempts are NEVER automatically retried.
// Reconciliation is explicit; records must not be deleted to make a retry work.
internal sealed class EnrollmentSubmissionJournal
{
    private readonly string directory;
    private const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode RecordMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly JsonSerializerOptions Options = new()
    {
        RespectRequiredConstructorParameters = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 4
    };

    internal EnrollmentSubmissionJournal(string directory)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        if (!Path.IsPathFullyQualified(directory)) throw new ArgumentException("Absolute journal directory required.");
        this.directory = Path.GetFullPath(directory);
        CheckDirectory();
    }

    internal SubmissionClaim? TryBegin(AuthorizedDomainCmcEnrollment enrollment, DateTimeOffset now)
    {
        if (!Guid.TryParse(enrollment.DirectoryObjectId, out var objectId))
            throw new ArgumentException("Canonical directory object GUID required.");
        return TryBeginCore(objectId, enrollment.AssetId, enrollment.FactsSourceVersion,
            enrollment.ExportBinding(), null, now);
    }

    internal SubmissionClaim? TryBegin(AuthorizedDomainRenewal enrollment, DateTimeOffset now) =>
        TryBeginCore(enrollment.DirectoryObjectId, enrollment.AssetId, enrollment.FactsVersion,
            enrollment.ExportBinding(), enrollment.OldCertificateSha256, now);

    private SubmissionClaim? TryBeginCore(Guid objectId, string assetId, long factsVersion,
        CmcRequestBinding binding, string? oldCertificateSha256, DateTimeOffset now)
    {
        if (objectId == Guid.Empty) throw new ArgumentException("Nonempty directory object GUID required.");
        if (string.IsNullOrWhiteSpace(assetId) || assetId.Length > 1024 || assetId.Any(char.IsControl))
            throw new ArgumentException("Bounded authoritative asset ID required.");
        // CMC wrapping/signature changes must not permit the same CSR to be resent.
        var key = objectId.ToString("N") + "-" + Convert.ToHexString(binding.Csr.CsrSha256);
        var path = Path.Combine(directory, key + ".submitted.json");
        var record = new SubmittedRecord(2, objectId, assetId, Convert.ToHexString(binding.Csr.CsrSha256),
            Convert.ToHexString(binding.EnvelopeSha256), factsVersion, now,
            oldCertificateSha256 is null ? "initial" : "renewal", oldCertificateSha256);
        if (!Publish(path, record, receipt: false)) return null;
        return new SubmissionClaim(this, key, objectId, assetId);
    }

    // A receipt is evidence of broker issuance, not certificate trust or present
    // authorization. Version1 records lack asset binding and cannot grant renewal.
    internal RecordedDomainCertificate? FindValidatedBinding(Guid objectId, string certificateSha256)
    {
        if (objectId == Guid.Empty) throw new ArgumentException("Nonempty directory identifier required.");
        return FindValidatedBindingCore(objectId, certificateSha256);
    }

    // Certificate-authenticated callers have no trusted AD GUID yet. Resolve
    // only from a durable receipt, never from certificate subject/SAN assertions.
    // This lookup does NOT validate TLS possession, chain, CRL or current AD access.
    internal RecordedDomainCertificate? FindValidatedBinding(string certificateSha256) =>
        FindValidatedBindingCore(null, certificateSha256);

    private RecordedDomainCertificate? FindValidatedBindingCore(Guid? objectId, string certificateSha256)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        if (certificateSha256 is null || certificateSha256.Length != 64 || certificateSha256.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("Exact directory/certificate identifiers required.");
        CheckDirectory();
        RecordedDomainCertificate? match = null;
        var examined = 0;
        foreach (var path in System.IO.Directory.EnumerateFiles(directory,
            objectId.HasValue ? objectId.Value.ToString("N") + "-*.validated.json" : "*.validated.json"))
        {
            if (++examined > 4096) throw new IOException("Renewal receipt lookup requires journal maintenance.");
            var record = (ReceiptRecord?)InspectMarker(path, receipt: true);
            if (record is null) continue; // Strictly inspected v1 never grants renewal.
            var recordedObject = record.DirectoryObjectId;
            var recordedHash = record.CertificateSha256;
            if ((objectId.HasValue && recordedObject != objectId.Value) ||
                !Path.GetFileName(path).StartsWith(recordedObject.ToString("N") + "-", StringComparison.Ordinal))
                throw new IOException("Invalid issuance receipt binding.");
            if (!string.Equals(recordedHash, certificateSha256, StringComparison.OrdinalIgnoreCase)) continue;
            if (match is not null) throw new IOException("Ambiguous issuance receipt binding.");
            match = new(recordedObject, record.AssetId, recordedHash.ToUpperInvariant());
        }
        return match;
    }

    // Publication is one no-replace link, never a partially serialized final file.
    // A storage failure after publication leaves a conservative marker, not authority.
    private bool Publish(string path, object value, bool receipt)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        CheckDirectory();
        var staging = Path.Combine(directory, ".journal-" + Guid.NewGuid().ToString("N") + ".tmp");
        var created = false;
        try
        {
            using (var stream = new FileStream(staging, new FileStreamOptions {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
                Options = FileOptions.WriteThrough, UnixCreateMode = RecordMode }))
            {
                created = true;
                JsonSerializer.Serialize(stream, value, Options);
                stream.Flush(flushToDisk: true);
            }
            ValidateMarker(path, Inspect(staging, receipt));
            CheckDirectory();
            if (Link(staging, path) != 0)
            {
                if (Marshal.GetLastPInvokeError() != 17) // EEXIST alone is a publication loser.
                    throw new IOException("Cannot publish durable journal marker.");
                var winner = InspectMarker(path, receipt); // Incoherent winners are storage faults.
                if (winner is SubmittedRecord submitted && value is SubmittedRecord proposed &&
                    (submitted.AssetId != proposed.AssetId || submitted.RequestKind != proposed.RequestKind ||
                    !string.Equals(submitted.OldCertificateSha256, proposed.OldCertificateSha256, StringComparison.OrdinalIgnoreCase)))
                    throw new IOException("Submission winner disagrees with claim identity.");
                return false;
            }
            InspectMarker(path, receipt);
        }
        finally
        {
            if (created)
            {
                File.Delete(staging);
                SyncDirectory(); // Persist publication and staging cleanup before returning a claim.
            }
        }
        return true;
    }

    private object? InspectMarker(string path, bool receipt)
    {
        var record = Inspect(path, receipt);
        ValidateMarker(path, record);
        return record;
    }

    private void ValidateMarker(string path, object? record)
    {
        if (record is SubmittedRecord submitted)
        {
            var filename = submitted.DirectoryObjectId.ToString("N") + "-" + submitted.CsrSha256 + ".submitted.json";
            if (!string.Equals(Path.GetFileName(path), filename, StringComparison.Ordinal))
                throw new IOException("Submission filename disagrees with its binding.");
        }
        else if (record is ReceiptRecord receipt)
        {
            const string suffix = ".validated.json";
            if (!path.EndsWith(suffix, StringComparison.Ordinal))
                throw new IOException("Invalid issuance receipt filename.");
            var companion = (SubmittedRecord?)InspectMarker(path[..^suffix.Length] + ".submitted.json", receipt: false);
            if (companion is null || receipt.DirectoryObjectId != companion.DirectoryObjectId ||
                receipt.AssetId != companion.AssetId || receipt.ValidatedAt < companion.ClaimedAt)
                throw new IOException("Issuance receipt disagrees with its submitted companion.");
        }
    }

    private object? Inspect(string path, bool receipt)
    {
        var bytes = ReadStable(path);
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new IOException("Journal object required.");
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!names.Add(property.Name)) throw new IOException("Duplicate journal property.");
            if (!root.TryGetProperty("Version", out var version) || !version.TryGetInt32(out var number))
                throw new IOException("Journal version required.");
            // Legacy records are bounded, stable objects, but carry no usable authority.
            // Do not impose the v2 asset schema, migrate or repair these blockers.
            if (number == 1) return null;
            if (number != 2) throw new IOException("Unsupported journal version.");
            if (receipt)
            {
                var record = root.Deserialize<ReceiptRecord>(Options) ?? throw new IOException("Missing receipt.");
                if (record.DirectoryObjectId == Guid.Empty || !IsAsset(record.AssetId) ||
                    record.IssuerRequestId <= 0 || !IsHash(record.CertificateSha256) || !IsTime(record.ValidatedAt))
                    throw new IOException("Invalid issuance receipt schema.");
                return record;
            }
            var submitted = root.Deserialize<SubmittedRecord>(Options) ?? throw new IOException("Missing submission.");
            if (submitted.DirectoryObjectId == Guid.Empty || !IsAsset(submitted.AssetId) ||
                !IsHash(submitted.CsrSha256) || !IsHash(submitted.EnvelopeSha256) || submitted.FactsVersion <= 0 ||
                !IsTime(submitted.ClaimedAt) || submitted.RequestKind is not ("initial" or "renewal") ||
                (submitted.RequestKind == "initial") != (submitted.OldCertificateSha256 is null) ||
                (submitted.OldCertificateSha256 is not null && !IsHash(submitted.OldCertificateSha256)))
                throw new IOException("Invalid submission schema.");
            return submitted;
        }
        catch (JsonException error) { throw new IOException("Invalid journal JSON.", error); }
        catch (InvalidOperationException error) { throw new IOException("Invalid journal value.", error); }
    }

    private byte[] ReadStable(string path)
    {
        CheckDirectory();
        var before = CheckRecord(path);
        var bytes = ReadBytes(path, before.Length);
        VerifyUnchanged(path, before, bytes);
        return bytes;
    }

    private void VerifyUnchanged(string path, RecordSnapshot before, byte[] bytes)
    {
        CheckDirectory();
        if (CheckRecord(path) != before || !ReadBytes(path, before.Length).AsSpan().SequenceEqual(bytes) ||
            CheckRecord(path) != before)
            throw new IOException("Journal record changed during pathname verification.");
        CheckDirectory();
    }

    private static byte[] ReadBytes(string path, long length)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var bytes = new byte[(int)length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("Journal record changed during read.");
        return bytes;
    }

    private static RecordSnapshot CheckRecord(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null ||
            (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            info.Length is <= 0 or > 16384 || File.GetUnixFileMode(path) != RecordMode)
            throw new IOException("Bounded owner-only regular journal record required.");
        return new(info.Length, info.CreationTimeUtc, info.LastWriteTimeUtc);
    }

    private void CheckDirectory()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new DirectoryInfo(directory);
        if (!info.Exists || info.LinkTarget is not null ||
            (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != FileAttributes.Directory ||
            File.GetUnixFileMode(directory) != DirectoryMode)
            throw new IOException("Pre-provisioned owner-only regular journal directory required.");
    }

    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    private static bool IsAsset(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 1024 && !value.Any(char.IsControl);
    private static bool IsTime(DateTimeOffset value) => value > DateTimeOffset.MinValue && value < DateTimeOffset.MaxValue;
    private sealed record RecordSnapshot(long Length, DateTime CreatedAt, DateTime WrittenAt);
    private sealed record SubmittedRecord(int Version, Guid DirectoryObjectId, string AssetId, string CsrSha256,
        string EnvelopeSha256, long FactsVersion, DateTimeOffset ClaimedAt, string RequestKind, string? OldCertificateSha256);
    private sealed record ReceiptRecord(int Version, Guid DirectoryObjectId, string AssetId, int IssuerRequestId,
        string CertificateSha256, DateTimeOffset ValidatedAt);

    private void SyncDirectory()
    {
        CheckDirectory();
        var fd = Open(directory, 0x10000 | 0x80000); // O_RDONLY | O_DIRECTORY | O_CLOEXEC (Linux).
        if (fd < 0) throw new IOException("Cannot open durable journal directory.");
        int closeResult;
        try { if (Fsync(fd) != 0) throw new IOException("Cannot flush durable journal directory."); }
        finally { closeResult = Close(fd); }
        if (closeResult != 0) throw new IOException("Cannot close journal directory descriptor.");
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);
    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int Link(string existingPath, string newPath);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int fd);
    [DllImport("libc", EntryPoint = "close")]
    private static extern int Close(int fd);

    internal sealed class SubmissionClaim
    {
        private readonly EnrollmentSubmissionJournal owner;
        private readonly string key;
        private readonly Guid objectId;
        private readonly string assetId;
        private readonly SubmittedRecord submitted;
        internal SubmissionClaim(EnrollmentSubmissionJournal owner, string key, Guid objectId, string assetId)
        {
            this.owner = owner; this.key = key; this.objectId = objectId; this.assetId = assetId;
            submitted = (SubmittedRecord?)owner.InspectMarker(Path.Combine(owner.directory, key + ".submitted.json"), receipt: false)
                ?? throw new IOException("A v2 submitted claim is required.");
            if (submitted.DirectoryObjectId != objectId || submitted.AssetId != assetId)
                throw new IOException("Submission claim disagrees with its durable record.");
        }

        // Call only after validating the response and certificate. This audit marker
        // does not grant reuse or release; failure remains an uncertain outcome.
        internal void RecordValidatedResponse(string issuerRequestId, string certificateSha256, DateTimeOffset now)
        {
            if (!int.TryParse(issuerRequestId, out var id) || id <= 0 || !IsHash(certificateSha256))
                throw new ArgumentException("Bounded issuance metadata required.");
            var durable = (SubmittedRecord?)owner.InspectMarker(Path.Combine(owner.directory, key + ".submitted.json"), receipt: false);
            if (durable != submitted || !IsTime(now) || now < submitted.ClaimedAt)
                throw new IOException("Validated response disagrees with its durable submission claim.");
            if (!owner.Publish(Path.Combine(owner.directory, key + ".validated.json"),
                new ReceiptRecord(2, objectId, assetId, id, certificateSha256.ToUpperInvariant(), now), receipt: true))
                throw new IOException("Validated journal marker already exists; replacement refused.");
        }
    }
}
