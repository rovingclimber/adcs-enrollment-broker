using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PkiProxy.Domain;
using PkiProxy.Protocol.Cmc;

internal static class EnrollmentSubmissionJournalMarkerTests
{
    private const UnixFileMode PrivateDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly Guid ObjectId = Guid.Parse("081cdbd4-62a8-45d0-adc4-820c82f36621");
    private static readonly DateTimeOffset Now = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);
    private static readonly string Hash = new('A', 64);
    private static readonly string Key = ObjectId.ToString("N") + "-" + new string('0', 64);
    private static readonly bool[] MarkerKinds = [false, true];
    private static readonly string[] MismatchedWinners = [
        Mutate(Submitted(), "DirectoryObjectId", Guid.NewGuid()),
        Mutate(Submitted(), "CsrSha256", Hash), Mutate(Submitted(), "AssetId", "other-asset"),
        Mutate(Mutate(Submitted(), "RequestKind", "renewal"), "OldCertificateSha256", Hash) ];
    private static readonly string?[] InvalidCompanions = [ null, "{\"Version\":1}", "{",
        Mutate(Submitted(), "DirectoryObjectId", Guid.NewGuid()),
        Mutate(Submitted(), "CsrSha256", Hash), Mutate(Submitted(), "AssetId", "other-asset"),
        Mutate(Submitted(), "ClaimedAt", Now.AddTicks(1)), Mutate(Submitted(), "RequestKind", "renewal") ];
    private static readonly string[] IncoherentReceipts = [
        Mutate(Receipt(), "DirectoryObjectId", Guid.NewGuid()), Mutate(Receipt(), "AssetId", "other-asset"),
        Mutate(Receipt(), "ValidatedAt", Now.AddTicks(-1)) ];
    private static readonly string[] MismatchedKeys = [
        ObjectId.ToString("N").ToUpperInvariant() + "-" + new string('0', 64),
        ObjectId.ToString("N") + "-" + Hash, Key + ".reconciled" ];
    private static readonly string?[] ChangedClaims = [ null, "{\"Version\":1}", "{",
        Mutate(Submitted(), "DirectoryObjectId", Guid.NewGuid()), Mutate(Submitted(), "CsrSha256", Hash),
        Mutate(Submitted(), "AssetId", "other-asset"), Mutate(Submitted(), "EnvelopeSha256", Hash),
        Mutate(Submitted(), "FactsVersion", 2L), Mutate(Submitted(), "ClaimedAt", Now.AddTicks(-1)),
        Mutate(Mutate(Submitted(), "RequestKind", "renewal"), "OldCertificateSha256", Hash) ];
    private static readonly DateTimeOffset[] InvalidValidationTimes = [ Now.AddTicks(-1), DateTimeOffset.MinValue, DateTimeOffset.MaxValue ];
    private static int checks;

    // The subprocess branch only operates on a test-owned disposable directory.
    internal static bool Run(string[] args)
    {
        if (!OperatingSystem.IsLinux()) return false;
        return RunLinux(args);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static bool RunLinux(string[] args)
    {
        if (args.Length == 2 && args[0] == "--submission-journal-claim-fixture")
        {
            Environment.ExitCode = Begin(new EnrollmentSubmissionJournal(args[1])) is null ? 10 : 0;
            return true;
        }
        if (args.Length == 3 && args[0] == "--submission-journal-receipt-fixture")
        {
            var claim = Begin(new EnrollmentSubmissionJournal(args[1]), csrSeed: byte.Parse(args[2], CultureInfo.InvariantCulture));
            if (claim is null) throw new InvalidOperationException("Distinct fixture CSR required.");
            try { claim.RecordValidatedResponse("27", Hash, Now); }
            catch (IOException) { Environment.ExitCode = 11; }
            return true;
        }
        if (args.Length != 0) return false;
        WithScratch(path =>
        {
            var journal = new EnrollmentSubmissionJournal(path);
            var claims = new System.Collections.Concurrent.ConcurrentBag<EnrollmentSubmissionJournal.SubmissionClaim>();
            Parallel.For(0, 12, _ => { var candidate = Begin(new EnrollmentSubmissionJournal(path)); if (candidate is not null) claims.Add(candidate); });
            Check(claims.Count == 1, "one complete claim winner across journal instances");
            var claim = claims.Single();
            Check(Begin(journal) is null, "reopen refuses uncertain claim");
            claim.RecordValidatedResponse("27", Hash.ToLowerInvariant(), Now);
            var reopened = new EnrollmentSubmissionJournal(path);
            var found = reopened.FindValidatedBinding(Hash.ToLowerInvariant());
            Check(found == new RecordedDomainCertificate(ObjectId, "asset/marker-test", Hash), "v2 reopen preserves claim identity and uppercase hash");
            Check(reopened.FindValidatedBinding(ObjectId, Hash.ToLowerInvariant()) == found, "object lookup preserves case behavior");
            Reject(() => claim.RecordValidatedResponse("28", new string('B', 64), Now), "valid receipt winner cannot be overwritten");
            Check(reopened.FindValidatedBinding(Hash) == found && Begin(reopened) is null, "completed attempt stays closed");
            var files = System.IO.Directory.GetFiles(path);
            Check(files.Length == 3 && files.All(IsOwnerOnly), "only owner-only final records and index remain");
        });
        GraphChecks();
        WithScratch(path =>
        {
            var children = Enumerable.Range(0, 6).Select(_ => StartFixtureProcess("--submission-journal-claim-fixture", path)).ToArray();
            try
            {
                foreach (var child in children)
                    Check(child.WaitForExit(30000), "claim subprocess completes");
                Check(children.Count(p => p.ExitCode == 0) == 1 && children.Count(p => p.ExitCode == 10) == 5,
                    "link publication elects one cross-process winner");
                Check(System.IO.Directory.GetFiles(path).Length == 1, "cross-process loser staging is removed");
            }
            finally { foreach (var child in children) { if (!child.HasExited) child.Kill(entireProcessTree: true); child.Dispose(); } }
        });
        ReceiptIndexMigrationChecks();
        ReceiptIndexPublicationChecks();
        ReceiptIndexValidationChecks();
        WithScratch(path =>
        {
            var journal = new EnrollmentSubmissionJournal(path);
            foreach (var receipt in MarkerKinds)
            {
                var final = Path.Combine(path, Key + (receipt ? ".validated.json" : ".submitted.json"));
                var failure = new SerializationFailure(path, final);
                var failed = false;
                try { Invoke(journal, "Publish", final, failure, receipt); }
                catch (InvalidOperationException) { failed = true; }
                Check(failed && failure.Inspected, "serialization sees private staging before deliberately failing");
                Check(System.IO.Directory.GetFileSystemEntries(path).Length == 0, "serialization failure leaves neither partial final nor staging");
            }
        });
        foreach (var receipt in MarkerKinds)
        {
            var valid = receipt ? Receipt() : Submitted();
            var malformed = new List<string> { "", " ", "{", "null", "[]", "42", new(' ', 16385),
                valid.Insert(1, "\"Version\":2,"), Mutate(valid, "Extra", 1), Mutate(valid, "Version", 3),
                Mutate(valid, "Version", "2"), Mutate(valid, "Version", (string?)null),
                Mutate(valid, "DirectoryObjectId", Guid.Empty.ToString()), Mutate(valid, "AssetId", ""),
                Mutate(valid, "AssetId", (string?)null),
                Mutate(valid, "AssetId", new string('x', 1025)), Mutate(valid, "AssetId", "bad\nasset"),
                Mutate(valid, receipt ? "CertificateSha256" : "CsrSha256", "not-a-hash"),
                Mutate(valid, receipt ? "ValidatedAt" : "ClaimedAt", "invalid-time"),
                Mutate(valid, receipt ? "ValidatedAt" : "ClaimedAt", DateTimeOffset.MinValue.ToString("O")) };
            foreach (var name in JsonNode.Parse(valid)!.AsObject().Select(p => p.Key))
                malformed.Add(Remove(valid, name));
            if (receipt) malformed.Add(Mutate(valid, "IssuerRequestId", 0));
            else
            {
                malformed.Add(Mutate(valid, "FactsVersion", 0));
                malformed.Add(Mutate(valid, "FactsVersion", "1"));
                malformed.Add(Mutate(valid, "EnvelopeSha256", "bad"));
                malformed.Add(Mutate(valid, "RequestKind", "other"));
                malformed.Add(Mutate(valid, "OldCertificateSha256", "bad"));
                malformed.Add(Mutate(valid, "OldCertificateSha256", Hash));
                malformed.Add(Mutate(valid, "RequestKind", "renewal"));
            }
            foreach (var content in malformed)
                WithScratch(path =>
                {
                    var journal = new EnrollmentSubmissionJournal(path);
                    var claim = receipt ? Begin(journal) : null;
                    var final = Path.Combine(path, Key + (receipt ? ".validated.json" : ".submitted.json"));
                    Write(final, content);
                    if (receipt)
                    {
                        Reject(() => new EnrollmentSubmissionJournal(path).FindValidatedBinding(Hash), "corrupt receipt fails cold lookup");
                        Reject(() => claim!.RecordValidatedResponse("27", Hash, Now), "corrupt receipt winner fails publication");
                    }
                    else Reject(() => Begin(journal), "corrupt submitted winner is a storage fault");
                    Check(File.ReadAllText(final) == content, "corrupt winner is never repaired");
                    Check(System.IO.Directory.GetFiles(path, "*.tmp").Length == 0, "corrupt-winner loser staging is cleaned");
                });
            WithScratch(path =>
            {
                var journal = new EnrollmentSubmissionJournal(path);
                var final = Path.Combine(path, Key + (receipt ? ".validated.json" : ".submitted.json"));
                Write(final, valid);
                File.SetUnixFileMode(final, PrivateFile | UnixFileMode.GroupRead);
                Reject(() => Inspect(journal, final, receipt), "shared-mode record rejected");
                File.SetUnixFileMode(final, PrivateFile);
                var target = Path.Combine(path, "target");
                File.Move(final, target);
                File.CreateSymbolicLink(final, target);
                Reject(() => Inspect(journal, final, receipt), "symlink/reparse record rejected");
                File.Delete(final);
                File.CreateSymbolicLink(final, Path.Combine(path, "missing"));
                Reject(() => Inspect(journal, final, receipt), "dangling record symlink rejected");
                File.Delete(final);
                System.IO.Directory.CreateDirectory(final, PrivateDirectory);
                Reject(() => Inspect(journal, final, receipt), "directory record rejected");
            });
        }
        WithScratch(path =>
        {
            var journal = new EnrollmentSubmissionJournal(path);
            var submitted = Path.Combine(path, Key + ".submitted.json");
            var legacy = Remove(Remove(Remove(Mutate(Submitted(), "Version", 1), "AssetId"), "RequestKind"), "OldCertificateSha256");
            Write(submitted, legacy);
            Write(Path.Combine(path, Key + ".validated.json"), "{\"Version\":1,\"IssuerRequestId\":26,\"CertificateSha256\":\"" + Hash + "\"}");
            Check(Begin(journal) is null && File.ReadAllText(submitted) == legacy, "legacy submitted marker remains an unchanged blocker");
            Check(!File.Exists(IndexPath(path)) && journal.FindValidatedBinding(Hash) is null &&
                journal.FindValidatedBinding(ObjectId, Hash) is null,
                "strictly inspected legacy v1 receipt never grants renewal");
        });
        WithScratch(path =>
        {
            var journal = new EnrollmentSubmissionJournal(path);
            var file = Path.Combine(path, Key + ".validated.json");
            Write(file, Receipt());
            var before = Invoke(null, "CheckRecord", file)!;
            var bytes = File.ReadAllBytes(file);
            // Deterministically interleave replacement between the snapshot and
            // the production pathname re-read, without timing-dependent loops.
            var replacement = Path.Combine(path, "replacement");
            Write(replacement, Receipt().Replace("asset/marker-test", "asset/marker-best", StringComparison.Ordinal));
            File.SetLastWriteTimeUtc(replacement, File.GetLastWriteTimeUtc(file));
            File.Move(replacement, file, overwrite: true);
            Reject(() => Invoke(journal, "VerifyUnchanged", file, before, bytes), "same-length pathname swap rejected");
            before = Invoke(null, "CheckRecord", file)!;
            bytes = File.ReadAllBytes(file);
            File.AppendAllText(file, " ");
            Reject(() => Invoke(journal, "VerifyUnchanged", file, before, bytes), "in-place record growth rejected");
            File.SetUnixFileMode(path, PrivateDirectory | UnixFileMode.GroupExecute);
            Reject(() => journal.FindValidatedBinding(Hash), "directory mode rechecked after construction");
            Reject(() => _ = new EnrollmentSubmissionJournal(path), "shared-mode directory rejected");
            File.SetUnixFileMode(path, PrivateDirectory);
        });
        WithScratch(path =>
        {
            var target = Path.Combine(path, "target");
            System.IO.Directory.CreateDirectory(target, PrivateDirectory);
            var alias = Path.Combine(path, "alias");
            System.IO.Directory.CreateSymbolicLink(alias, target);
            Reject(() => _ = new EnrollmentSubmissionJournal(alias), "symlink/reparse journal directory rejected");
            File.Delete(alias);
        });
        Console.WriteLine($"Submission journal marker checks passed: {checks}");
        return false;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static void ReceiptIndexMigrationChecks()
    {
        WithScratch(path =>
        {
            for (var i = 0; i < 4097; i++)
                Write(Path.Combine(path, i.ToString(CultureInfo.InvariantCulture) + ".validated.json"), "{\"Version\":1}");
            var submittedPath = Path.Combine(path, Key + ".submitted.json");
            var receiptPath = Path.Combine(path, Key + ".validated.json");
            var legacyReceipt = Mutate(Receipt(), "CertificateSha256", Hash.ToLowerInvariant());
            Write(submittedPath, Submitted());
            Write(receiptPath, legacyReceipt);
            var journal = new EnrollmentSubmissionJournal(path);
            var binding = new RecordedDomainCertificate(ObjectId, "asset/marker-test", Hash);
            Check(journal.InspectHistoricalBinding(ObjectId, Hash.ToLowerInvariant()) == binding && !File.Exists(IndexPath(path)),
                "operator preflight finds legacy v2 binding without creating an index");
            Check(journal.FindValidatedBinding(Hash.ToLowerInvariant()) == binding &&
                journal.FindValidatedBinding(ObjectId, Hash) == binding, "v2 receipt migrates beyond the old global cap");
            Check(Begin(journal) is null && journal.FindValidatedBinding(Guid.NewGuid(), Hash) is null,
                "migration preserves the claim blocker and exact GUID check");
            Check(File.ReadAllText(receiptPath) == legacyReceipt && File.ReadAllText(submittedPath) == Submitted() &&
                File.ReadAllText(IndexPath(path)) == JsonSerializer.Serialize(Key + ".validated.json") && IsOwnerOnly(IndexPath(path)),
                "migration preserves source records and writes only the canonical private pointer");
            Write(Path.Combine(path, "0.validated.json"), "{");
            Check(journal.FindValidatedBinding(Hash) == binding, "warm lookup does not read unrelated corrupt receipts");
            var cold = new EnrollmentSubmissionJournal(path);
            Reject(() => cold.FindValidatedBinding(Hash), "cold migration refuses unrelated corrupt history");
            Reject(() => Begin(new EnrollmentSubmissionJournal(path), csrSeed: 1), "cold migration failure prevents a new claim");
            Check(System.IO.Directory.GetFiles(path, "*.submitted.json").Length == 1,
                "failed migration consumes no new submission");
        });
        WithScratch(path =>
        {
            var secondCsr = new string('1', 64);
            var secondKey = ObjectId.ToString("N") + "-" + secondCsr;
            Write(Path.Combine(path, Key + ".submitted.json"), Submitted());
            Write(Path.Combine(path, Key + ".validated.json"), Receipt());
            Write(Path.Combine(path, secondKey + ".submitted.json"), Mutate(Submitted(), "CsrSha256", secondCsr));
            Write(Path.Combine(path, secondKey + ".validated.json"), Mutate(Receipt(), "CertificateSha256", Hash.ToLowerInvariant()));
            var journal = new EnrollmentSubmissionJournal(path);
            Reject(() => journal.InspectHistoricalBinding(ObjectId, Hash), "operator preflight refuses ambiguous same-object history");
            Check(!File.Exists(IndexPath(path)), "ambiguous preflight leaves history untouched");
            Reject(() => journal.FindValidatedBinding(Hash), "two coherent legacy receipts for the same digest fail migration");
            Reject(() => new EnrollmentSubmissionJournal(path).FindValidatedBinding(ObjectId, Hash),
                "restarted migration still refuses a legacy duplicate after partial backfill");
        });
    }

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static void ReceiptIndexPublicationChecks()
    {
        WithScratch(path =>
        {
            var journal = new EnrollmentSubmissionJournal(path);
            var claim = Begin(journal)!;
            var index = IndexPath(path);
            Write(index, JsonSerializer.Serialize(Key + ".validated.json"));
            var reopened = new EnrollmentSubmissionJournal(path);
            Reject(() => reopened.FindValidatedBinding(Hash), "interrupted pointer-only publication grants no authority");
            var different = Begin(reopened, csrSeed: 1)!;
            Reject(() => different.RecordValidatedResponse("27", Hash.ToLowerInvariant(), Now),
                "interrupted reservation still blocks a different receipt key");
            claim.RecordValidatedResponse("27", Hash, Now);
            Check(reopened.FindValidatedBinding(Hash)?.DirectoryObjectId == ObjectId,
                "the same validated claim can finish a pointer-only reservation");
            Reject(() => claim.RecordValidatedResponse("27", Hash, Now), "a durable receipt never replays");
        });
        WithScratch(path =>
        {
            const string mode = "--submission-journal-receipt-fixture";
            using var first = StartFixtureProcess(mode, path, "0");
            using var second = StartFixtureProcess(mode, path, "1");
            try
            {
                Check(first.WaitForExit(30000) && second.WaitForExit(30000), "receipt subprocesses complete");
                Check(Math.Min(first.ExitCode, second.ExitCode) == 0 && Math.Max(first.ExitCode, second.ExitCode) == 11,
                    "exactly one receipt key reserves a digest across processes");
                Check(System.IO.Directory.GetFiles(path).Length == 4 &&
                    new EnrollmentSubmissionJournal(path).FindValidatedBinding(Hash)?.DirectoryObjectId == ObjectId,
                    "race preserves two claims, one receipt and one index without staging residue");
            }
            finally
            {
                if (!first.HasExited) first.Kill(entireProcessTree: true);
                if (!second.HasExited) second.Kill(entireProcessTree: true);
            }
        });
    }

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static void ReceiptIndexValidationChecks()
    {
        WithScratch(path =>
        {
            var journal = new EnrollmentSubmissionJournal(path);
            Begin(journal)!.RecordValidatedResponse("27", Hash, Now);
            var index = IndexPath(path);
            var receiptPath = Path.Combine(path, Key + ".validated.json");
            var submittedPath = Path.Combine(path, Key + ".submitted.json");
            File.Delete(index);
            Check(journal.FindValidatedBinding(Hash) is null, "warm lookup denies a missing index without scanning");
            Check(new EnrollmentSubmissionJournal(path).FindValidatedBinding(Hash) is not null, "cold migration can recreate a missing pointer from the exact v2 pair");
            var pointer = File.ReadAllText(index);
            foreach (var invalid in new[] { "{", "null", JsonSerializer.Serialize("../" + Key + ".validated.json"),
                JsonSerializer.Serialize(Key.ToUpperInvariant() + ".validated.json") })
            {
                Write(index, invalid);
                Reject(() => journal.FindValidatedBinding(Hash), "index rejects malformed or noncanonical targets");
            }
            Write(index, pointer);
            File.SetUnixFileMode(index, PrivateFile | UnixFileMode.GroupRead);
            Reject(() => journal.FindValidatedBinding(Hash), "index must be owner-only");
            File.SetUnixFileMode(index, PrivateFile);
            var otherHash = new string('B', 64);
            Begin(journal, csrSeed: 1)!.RecordValidatedResponse("28", otherHash, Now);
            Write(index, File.ReadAllText(IndexPath(path, otherHash)));
            Reject(() => journal.FindValidatedBinding(Hash), "index cannot redirect to a valid receipt for a different digest");
            Write(index, pointer);
            foreach (var invalid in new[] { "{", "{\"Version\":1}", Mutate(Receipt(), "CertificateSha256", new string('B', 64)) })
            {
                Write(receiptPath, invalid);
                Reject(() => journal.FindValidatedBinding(Hash), "index cannot grant with an invalid or mismatched receipt");
            }
            Write(receiptPath, Receipt());
            Write(submittedPath, Mutate(Submitted(), "AssetId", "other-asset"));
            Reject(() => journal.FindValidatedBinding(Hash), "index still requires the exact durable submitted companion");
            Write(submittedPath, Submitted());
            Check(journal.FindValidatedBinding(Hash) is not null, "matching valid journal graph still grants");
        });
    }

    private static string IndexPath(string path, string? hash = null) => Path.Combine(path, ".receipt-" + (hash ?? Hash) + ".json");

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static void GraphChecks()
    {
        foreach (var content in MismatchedWinners)
            WithScratch(path =>
            {
                var final = Path.Combine(path, Key + ".submitted.json");
                Write(final, content);
                Reject(() => Begin(new EnrollmentSubmissionJournal(path)), "schema-valid winner must match path and claim identity");
                Check(File.ReadAllText(final) == content && System.IO.Directory.GetFiles(path).Length == 1,
                    "mismatched winner remains unchanged with no staging residue");
            });
        WithScratch(path =>
        {
            var content = Mutate(Mutate(Mutate(Submitted(), "EnvelopeSha256", Hash), "FactsVersion", 2L),
                "ClaimedAt", Now.AddMinutes(-1));
            var final = Path.Combine(path, Key + ".submitted.json");
            Write(final, content);
            Check(Begin(new EnrollmentSubmissionJournal(path)) is null && File.ReadAllText(final) == content,
                "rewrapped CSR with changed facts and retry time remains a conservative blocker");
        });
        WithScratch(path =>
        {
            var journal = new EnrollmentSubmissionJournal(path);
            var claim = Begin(journal, Hash)!;
            Reject(() => Begin(journal, new string('B', 64)), "renewal winner cannot change predecessor certificate");
            Check(Begin(journal, Hash.ToLowerInvariant()) is null, "predecessor hash casing preserves duplicate blocker");
            claim.RecordValidatedResponse("28", new string('B', 64), Now.AddSeconds(1));
            Check(journal.FindValidatedBinding(ObjectId, new string('b', 64))?.AssetId == "asset/marker-test",
                "coherent renewal pair grants its recorded binding");
        });
        // Each bad graph must fail both lookup forms, even for an unrelated hash.
        foreach (var content in InvalidCompanions)
            WithScratch(path =>
            {
                if (content is not null) Write(Path.Combine(path, Key + ".submitted.json"), content);
                Write(Path.Combine(path, Key + ".validated.json"), Receipt());
                var journal = new EnrollmentSubmissionJournal(path);
                Reject(() => journal.FindValidatedBinding(Hash), "invalid companion cannot grant certificate-only authority");
                Reject(() => journal.FindValidatedBinding(ObjectId, Hash), "invalid companion cannot grant object authority");
                Reject(() => journal.FindValidatedBinding(new string('B', 64)), "unmatched certificate does not hide incoherent graph");
            });
        foreach (var content in IncoherentReceipts)
            WithScratch(path =>
            {
                var journal = new EnrollmentSubmissionJournal(path);
                var claim = Begin(journal)!;
                var final = Path.Combine(path, Key + ".validated.json");
                Write(final, content);
                Reject(() => new EnrollmentSubmissionJournal(path).FindValidatedBinding(Hash), "receipt identity and timeline must match companion");
                Reject(() => claim.RecordValidatedResponse("27", Hash, Now), "incoherent receipt winner is a storage fault");
                Check(File.ReadAllText(final) == content, "incoherent receipt winner is not overwritten");
            });
        foreach (var key in MismatchedKeys)
            WithScratch(path =>
            {
                Write(Path.Combine(path, key + ".submitted.json"), Submitted());
                Write(Path.Combine(path, key + ".validated.json"), Receipt());
                Reject(() => new EnrollmentSubmissionJournal(path).FindValidatedBinding(Hash),
                    "companion filename must exactly encode its object and CSR");
            });
        foreach (var content in ChangedClaims)
            WithScratch(path =>
            {
                var journal = new EnrollmentSubmissionJournal(path);
                var claim = Begin(journal)!;
                var submitted = Path.Combine(path, Key + ".submitted.json");
                if (content is null) File.Delete(submitted); else Write(submitted, content);
                Reject(() => claim.RecordValidatedResponse("27", Hash, Now), "claim rejects missing or changed durable snapshot");
                Check(!File.Exists(Path.Combine(path, Key + ".validated.json")) &&
                    System.IO.Directory.GetFiles(path, "*.tmp").Length == 0, "invalid claim never publishes a receipt or leaves staging");
            });
        WithScratch(path =>
        {
            var journal = new EnrollmentSubmissionJournal(path);
            var claim = Begin(journal)!;
            foreach (var timestamp in InvalidValidationTimes)
                Reject(() => claim.RecordValidatedResponse("27", Hash, timestamp), "validation time must be bounded and follow claim");
            Check(System.IO.Directory.GetFiles(path).Length == 1, "invalid times never publish a receipt");
            Reject(() => _ = new EnrollmentSubmissionJournal.SubmissionClaim(journal, Key, Guid.NewGuid(), "asset/marker-test"),
                "reconstructed claim must match durable object");
            Reject(() => _ = new EnrollmentSubmissionJournal.SubmissionClaim(journal, Key, ObjectId, "other-asset"),
                "reconstructed claim must match durable asset");
            new EnrollmentSubmissionJournal.SubmissionClaim(journal, Key, ObjectId, "asset/marker-test")
                .RecordValidatedResponse("27", Hash, Now);
            Check(journal.FindValidatedBinding(Hash) is not null, "reconstructed exact durable claim accepts equal timestamp");
        });
    }

    private static EnrollmentSubmissionJournal.SubmissionClaim? Begin(EnrollmentSubmissionJournal journal,
        string? oldCertificate = null, byte csrSeed = 0)
    {
        var csrHash = new byte[32];
        csrHash[0] = csrSeed;
        return (EnrollmentSubmissionJournal.SubmissionClaim?)Invoke(journal, "TryBeginCore", ObjectId, "asset/marker-test", 1L,
            new CmcRequestBinding(new byte[32], new CsrBinding(csrHash, new byte[32])), oldCertificate, Now);
    }

    private static string Submitted() => JsonSerializer.Serialize(new {
        Version = 2, DirectoryObjectId = ObjectId, AssetId = "asset/marker-test", CsrSha256 = new string('0', 64),
        EnvelopeSha256 = new string('0', 64), FactsVersion = 1L, ClaimedAt = Now, RequestKind = "initial", OldCertificateSha256 = (string?)null });
    private static string Receipt() => JsonSerializer.Serialize(new {
        Version = 2, DirectoryObjectId = ObjectId, AssetId = "asset/marker-test", IssuerRequestId = 27,
        CertificateSha256 = Hash, ValidatedAt = Now });
    private static string Mutate<T>(string json, string property, T value)
    { var node = JsonNode.Parse(json)!.AsObject(); node[property] = JsonSerializer.SerializeToNode(value); return node.ToJsonString(); }
    private static string Remove(string json, string property)
    { var node = JsonNode.Parse(json)!.AsObject(); node.Remove(property); return node.ToJsonString(); }
    private static void Write(string path, string content)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        File.WriteAllText(path, content, new UTF8Encoding(false));
        File.SetUnixFileMode(path, PrivateFile);
    }
    private static bool IsOwnerOnly(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        return File.GetUnixFileMode(path) == PrivateFile;
    }
    private static object? Invoke(object? target, string name, params object?[] args)
    {
        try { return typeof(EnrollmentSubmissionJournal).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)!.Invoke(target, args); }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        { ExceptionDispatchInfo.Capture(error.InnerException).Throw(); throw; }
    }
    private static void Inspect(EnrollmentSubmissionJournal journal, string path, bool receipt) => Invoke(journal, "Inspect", path, receipt);
    private static void Check(bool condition, string message)
    { if (!condition) throw new InvalidOperationException("Submission journal markers: " + message); checks++; }
    private static void Reject(Action action, string message)
    { try { action(); } catch (IOException) { checks++; return; } throw new InvalidOperationException("Submission journal markers accepted: " + message); }
    private static void WithScratch(Action<string> action)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var directory = System.IO.Directory.CreateTempSubdirectory("pkiproxy-marker-test-");
        File.SetUnixFileMode(directory.FullName, PrivateDirectory);
        try { action(directory.FullName); }
        finally { directory.Delete(recursive: true); }
    }
    private static Process StartFixtureProcess(params string[] args)
    {
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Test process path required.");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(typeof(EnrollmentSubmissionJournalMarkerTests).Assembly.Location);
        foreach (var argument in args) start.ArgumentList.Add(argument);
        return Process.Start(start) ?? throw new InvalidOperationException("Cannot start journal fixture process.");
    }
    private sealed class SerializationFailure(string directory, string final)
    {
        [System.Text.Json.Serialization.JsonIgnore]
        public bool Inspected { get; private set; }
        public string Value
        {
            get
            {
                if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
                var staging = System.IO.Directory.GetFiles(directory, "*.tmp");
                Inspected = staging.Length == 1 && File.GetUnixFileMode(staging[0]) == PrivateFile && !File.Exists(final);
                throw new InvalidOperationException("Deliberate test serialization failure.");
            }
        }
    }
}
