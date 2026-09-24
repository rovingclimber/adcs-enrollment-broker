using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;

internal static class FileBootstrapEnrollmentTransactionStoreTests
{
    private const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode FileModeOwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal static void Run()
    {
        if (!OperatingSystem.IsLinux())
        {
            Console.WriteLine("Bootstrap transaction store checks skipped: Linux filesystem semantics required.");
            return;
        }

        var checks = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException("Bootstrap transaction store: " + label);
            checks++;
        }
        void Throws<T>(Action action, string label) where T : Exception
        {
            try { action(); }
            catch (T) { checks++; return; }
            throw new InvalidOperationException("Bootstrap transaction store did not reject: " + label);
        }

        var now = DateTimeOffset.Parse("2026-09-14T12:00:00Z");
        var (csr, binding) = Request();
        using var main = Root();
        var store = new FileBootstrapEnrollmentTransactionStore(main.Path);
        var retained = store.Retain(csr, binding, now, TimeSpan.FromMinutes(20));
        Check(retained.Result == BootstrapTransactionResult.Retained && retained.TransactionId is not null,
            "retains a validated request with an independent transaction ID");
        var transactionId = retained.TransactionId!;
        Check(Directory.EnumerateFiles(main.Path).All(IsOwnerOnly),
            "every retained file is owner-only");
        Check(Directory.EnumerateFiles(main.Path, "*.csr").Single() is var csrPath &&
            File.ReadAllBytes(csrPath).SequenceEqual(csr), "exact public CSR bytes survive retention");
        Check(new FileBootstrapEnrollmentTransactionStore(main.Path)
            .Lookup(transactionId, binding, null, now).State == BootstrapTransactionState.RetainedUnbound,
            "retained unbound state survives restart without an asset assertion");
        Check(store.Retain(csr, binding, now, TimeSpan.FromMinutes(20)).Result ==
            BootstrapTransactionResult.AlreadyRetained, "the same immutable request is create-once");
        Check(store.Retain(csr, binding, now, TimeSpan.FromMinutes(21)).Result ==
            BootstrapTransactionResult.Conflict, "changed retention expiry cannot reuse a CSR binding");
        Check(Directory.EnumerateFiles(main.Path, "*.json").All(path =>
            !File.ReadAllText(path).Contains("asset", StringComparison.OrdinalIgnoreCase)),
            "retained and reservation records have no asset field or asset text");
        Check(!System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(csrPath!))
            .Contains("asset-physical-001", StringComparison.Ordinal), "retained CSR has no injected asset text");
        var beforeBinding = store.TryClaimSubmission(transactionId, binding, "asset-physical-001", now);
        Check(beforeBinding.Result == BootstrapTransactionResult.InvalidState && beforeBinding.Claim is null &&
            !Directory.EnumerateFiles(main.Path, "*.claimed.json").Any(), "claim before asset binding creates no claim");
        Check(store.BindAsset(transactionId, Different(binding), "asset-physical-001", now) ==
            BootstrapTransactionResult.BindingMismatch, "binding rejects wrong CSR");
        Check(store.BindAsset(transactionId, DifferentSpki(binding), "asset-physical-001", now) ==
            BootstrapTransactionResult.BindingMismatch, "binding rejects wrong SPKI");
        foreach (var badAsset in new[] { "", " asset", "asset ", "asset\ninvalid", new string('a', 257) })
            Throws<ArgumentException>(() => store.BindAsset(transactionId, binding, badAsset, now), "invalid bounded asset ID");
        Check(!Directory.EnumerateFiles(main.Path, "*.asset.json").Any(), "rejected bindings leave no asset marker");
        var bindContenders = Enumerable.Range(0, 12).Select(_ => Task.Run(() =>
            new FileBootstrapEnrollmentTransactionStore(main.Path)
                .BindAsset(transactionId, binding, "asset-physical-001", now.AddSeconds(30)))).ToArray();
        Task.WaitAll(bindContenders);
        Check(bindContenders.Count(task => task.Result == BootstrapTransactionResult.AssetBound) == 1 &&
            bindContenders.Count(task => task.Result == BootstrapTransactionResult.AlreadyBound) == 11,
            "same-asset concurrent bind has one creator and exact idempotent reconciliation");
        var assetPath = Directory.EnumerateFiles(main.Path, "*.asset.json").Single();
        var assetBytes = File.ReadAllBytes(assetPath);
        Check(IsOwnerOnly(assetPath), "asset marker is owner-only");
        Check(new FileBootstrapEnrollmentTransactionStore(main.Path)
            .Lookup(transactionId, binding, "asset-physical-001", now.AddSeconds(30)).State == BootstrapTransactionState.AssetBound,
            "exact asset binding survives reopen");
        Check(store.BindAsset(transactionId, binding, "asset-physical-001", now.AddSeconds(31)) ==
            BootstrapTransactionResult.AlreadyBound, "later exact replay reconciles the immutable original binding time");
        Check(store.BindAsset(transactionId, binding, "ASSET-physical-001", now.AddSeconds(31)) ==
            BootstrapTransactionResult.Conflict, "asset IDs are exact and case-sensitive");
        Check(store.TryClaimSubmission(transactionId, binding, "asset-other", now.AddSeconds(31)).Result ==
            BootstrapTransactionResult.BindingMismatch, "claim rejects a different asset");
        Check(store.TryClaimSubmission(transactionId, Different(binding), "asset-physical-001", now.AddSeconds(31)).Result ==
            BootstrapTransactionResult.BindingMismatch, "claim rejects a different CSR");
        Check(store.TryClaimSubmission(transactionId, DifferentSpki(binding), "asset-physical-001", now.AddSeconds(31)).Result ==
            BootstrapTransactionResult.BindingMismatch, "claim rejects a different SPKI");
        Check(File.ReadAllBytes(assetPath).SequenceEqual(assetBytes), "replays and conflicts never overwrite asset marker");
        Check(store.Lookup(transactionId, binding, null, now.AddSeconds(31)).Result ==
            BootstrapTransactionResult.BindingMismatch, "post-bind lookup requires the exact authoritative asset");

        using var bindRaceRoot = Root();
        var bindRaceStore = new FileBootstrapEnrollmentTransactionStore(bindRaceRoot.Path);
        var bindRaceRequest = Request();
        var bindRaceId = bindRaceStore.Retain(bindRaceRequest.Csr, bindRaceRequest.Binding, now,
            TimeSpan.FromMinutes(5)).TransactionId!;
        var differentBindContenders = Enumerable.Range(0, 12).Select(index => Task.Run(() =>
            (Asset: "asset-race-" + index, Result: new FileBootstrapEnrollmentTransactionStore(bindRaceRoot.Path)
                .BindAsset(bindRaceId, bindRaceRequest.Binding, "asset-race-" + index, now)))).ToArray();
        Task.WaitAll(differentBindContenders);
        Check(differentBindContenders.Count(task => task.Result.Result == BootstrapTransactionResult.AssetBound) == 1 &&
            differentBindContenders.Count(task => task.Result.Result == BootstrapTransactionResult.Conflict) == 11,
            "different-asset concurrent bind has one creator and eleven conflicts");
        var boundWinner = differentBindContenders.Single(task => task.Result.Result == BootstrapTransactionResult.AssetBound).Result.Asset;
        Check(new FileBootstrapEnrollmentTransactionStore(bindRaceRoot.Path)
            .TryClaimSubmission(bindRaceId, bindRaceRequest.Binding, boundWinner, now).Claim is not null,
            "the winning concurrent asset binding is durable and claimable");

        var contenders = Enumerable.Range(0, 12).Select(_ => Task.Run(() =>
            new FileBootstrapEnrollmentTransactionStore(main.Path)
                .TryClaimSubmission(transactionId, binding, "asset-physical-001", now.AddMinutes(1)))).ToArray();
        Task.WaitAll(contenders);
        Check(contenders.Count(task => task.Result.Result == BootstrapTransactionResult.Claimed) == 1,
            "concurrent callers have exactly one durable submission winner");
        Check(contenders.Where(task => task.Result.Result != BootstrapTransactionResult.Claimed)
            .All(task => task.Result.Result == BootstrapTransactionResult.AlreadyClaimed),
            "all submission losers receive no claim");
        var winner = contenders.Single(task => task.Result.Result == BootstrapTransactionResult.Claimed).Result.Claim!;
        Check(store.BindAsset(transactionId, binding, "asset-physical-001", now.AddMinutes(2)) ==
            BootstrapTransactionResult.InvalidState, "bind after claim is rejected even for the original asset");
        Check(store.BindAsset(transactionId, binding, "asset-other", now.AddMinutes(2)) ==
            BootstrapTransactionResult.InvalidState, "bind after claim never changes asset");
        Check(winner.ExportValidatedCsr().SequenceEqual(csr), "the winner receives the exact retained CSR");
        Check(new FileBootstrapEnrollmentTransactionStore(main.Path)
            .TryClaimSubmission(transactionId, binding, "asset-physical-001", now.AddMinutes(2)).Result ==
            BootstrapTransactionResult.AlreadyClaimed, "restart after an uncertain send never permits resubmission");
        Check(new FileBootstrapEnrollmentTransactionStore(main.Path)
            .Lookup(transactionId, binding, "asset-physical-001", now.AddHours(1)).State ==
            BootstrapTransactionState.SubmissionClaimed, "uncertain claim remains explicit after restart");

        winner.RecordPending(417, now.AddMinutes(2));
        var pending = new FileBootstrapEnrollmentTransactionStore(main.Path)
            .Lookup(transactionId, binding, "asset-physical-001", now.AddHours(1));
        Check(pending.State == BootstrapTransactionState.Pending && pending.IssuerRequestId == 417 &&
            pending.PendingCompletion is not null, "pending issuer request remains queryable and completable after intake expiry");
        Check(new FileBootstrapEnrollmentTransactionStore(main.Path)
            .Lookup(transactionId, Different(binding), "asset-physical-001", now.AddMinutes(3)).Result ==
            BootstrapTransactionResult.BindingMismatch, "transaction ID cannot bypass exact CSR binding");
        Check(new FileBootstrapEnrollmentTransactionStore(main.Path)
            .Lookup(transactionId, DifferentSpki(binding), "asset-physical-001", now.AddMinutes(3)).Result ==
            BootstrapTransactionResult.BindingMismatch, "transaction ID cannot bypass exact SPKI binding");
        Check(new FileBootstrapEnrollmentTransactionStore(main.Path)
            .Lookup(transactionId, binding, "asset-other", now.AddMinutes(3)).Result ==
            BootstrapTransactionResult.BindingMismatch, "transaction ID cannot bypass authoritative asset binding");
        Throws<InvalidOperationException>(() => pending.PendingCompletion!.RecordIssued(418,
            new string('A', 64), "10", now.AddMinutes(4)), "issued outcome with a different pending request ID");
        pending.PendingCompletion!.RecordIssued(417, new string('B', 64), "00FE", now.AddHours(1));
        var issued = new FileBootstrapEnrollmentTransactionStore(main.Path)
            .Lookup(transactionId, binding, "asset-physical-001", now.AddHours(2));
        Check(issued.State == BootstrapTransactionState.Issued && issued.IssuerRequestId == 417 &&
            issued.CertificateSha256 == new string('B', 64) && issued.SerialHex == "00FE",
            "issued receipt remains durable and bound after transaction expiry");
        var pendingPath = Directory.EnumerateFiles(main.Path, "*.pending.json").Single();
        File.WriteAllText(pendingPath, File.ReadAllText(pendingPath).Replace(
            "\"IssuerRequestId\":417", "\"IssuerRequestId\":418", StringComparison.Ordinal));
        File.SetUnixFileMode(pendingPath, FileModeOwnerOnly);
        Throws<InvalidDataException>(() => new FileBootstrapEnrollmentTransactionStore(main.Path)
            .Lookup(transactionId, binding, "asset-physical-001", now.AddHours(2)),
            "issued receipt conflicting with a simultaneously present pending request");
        Throws<InvalidOperationException>(() => pending.PendingCompletion.RecordFailed("issuer-error", now.AddMinutes(5)),
            "failure after issued terminal outcome");

        using var failedRoot = Root();
        var failedStore = new FileBootstrapEnrollmentTransactionStore(failedRoot.Path);
        var failedRequest = Request();
        var failedId = failedStore.Retain(failedRequest.Csr, failedRequest.Binding, now,
            TimeSpan.FromMinutes(10)).TransactionId!;
        Check(failedStore.BindAsset(failedId, failedRequest.Binding, "asset-002", now) ==
            BootstrapTransactionResult.AssetBound, "failed lifecycle binds asset first");
        var failedClaim = failedStore.TryClaimSubmission(failedId, failedRequest.Binding, "asset-002",
            now.AddMinutes(1)).Claim!;
        failedClaim.RecordFailed("transport-uncertain", now.AddMinutes(2));
        Check(new FileBootstrapEnrollmentTransactionStore(failedRoot.Path)
            .Lookup(failedId, failedRequest.Binding, "asset-002", now.AddMinutes(3)).State ==
            BootstrapTransactionState.Failed, "terminal failure survives restart");
        Throws<InvalidOperationException>(() => failedClaim.RecordIssued(1, new string('C', 64), "12", now.AddMinutes(3)),
            "issued outcome after terminal failure");

        using var terminalRaceRoot = Root();
        var terminalRaceStore = new FileBootstrapEnrollmentTransactionStore(terminalRaceRoot.Path);
        var terminalRaceRequest = Request();
        var terminalRaceId = terminalRaceStore.Retain(terminalRaceRequest.Csr, terminalRaceRequest.Binding, now, TimeSpan.FromMinutes(10)).TransactionId!;
        Check(terminalRaceStore.BindAsset(terminalRaceId, terminalRaceRequest.Binding, "asset-race", now) ==
            BootstrapTransactionResult.AssetBound, "terminal race binds asset first");
        var terminalRaceClaim = terminalRaceStore.TryClaimSubmission(terminalRaceId, terminalRaceRequest.Binding,
            "asset-race", now.AddMinutes(1)).Claim!;
        var terminalContenders = new[]
        {
            Task.Run(() => TryTerminal(() => terminalRaceClaim.RecordIssued(99, new string('D', 64), "22", now.AddMinutes(2)), "issued")),
            Task.Run(() => TryTerminal(() => terminalRaceClaim.RecordFailed("issuer-rejected", now.AddMinutes(2)), "failed"))
        };
        Task.WaitAll(terminalContenders);
        Check(terminalContenders.Count(task => task.Result != "lost") == 1,
            "concurrent issued and failed writers have one durable terminal winner");
        var terminalRaceLookup = new FileBootstrapEnrollmentTransactionStore(terminalRaceRoot.Path)
            .Lookup(terminalRaceId, terminalRaceRequest.Binding, "asset-race", now.AddMinutes(3));
        Check((terminalRaceLookup.State is BootstrapTransactionState.Issued or BootstrapTransactionState.Failed) &&
            Directory.EnumerateFiles(terminalRaceRoot.Path, "*.terminal.json").Count() == 1,
            "terminal race leaves exactly one valid outcome marker");

        using var expiryRoot = Root();
        var expiryStore = new FileBootstrapEnrollmentTransactionStore(expiryRoot.Path);
        var expiryRequest = Request();
        var expiryId = expiryStore.Retain(expiryRequest.Csr, expiryRequest.Binding, now,
            TimeSpan.FromMinutes(1)).TransactionId!;
        Check(expiryStore.BindAsset(expiryId, expiryRequest.Binding, "asset-003", now.AddMinutes(1)) ==
            BootstrapTransactionResult.Expired && !Directory.EnumerateFiles(expiryRoot.Path, "*.asset.json").Any(),
            "expiry boundary rejects asset binding without a marker");
        Check(expiryStore.TryClaimSubmission(expiryId, expiryRequest.Binding, "asset-003", now.AddMinutes(1)).Result ==
            BootstrapTransactionResult.Expired, "expiry boundary rejects submission");
        Check(expiryStore.Lookup(new string('0', 32), expiryRequest.Binding, "asset-003", now).Result ==
            BootstrapTransactionResult.NotFound, "unknown transaction is rejected");
        Check(expiryStore.Lookup(expiryId, expiryRequest.Binding, null, now.AddMinutes(1)).State ==
            BootstrapTransactionState.Expired, "expired retained transaction remains distinguishable");

        using var chronologyRoot = Root();
        var chronologyStore = new FileBootstrapEnrollmentTransactionStore(chronologyRoot.Path);
        var chronologyRequest = Request();
        var chronologyId = chronologyStore.Retain(chronologyRequest.Csr, chronologyRequest.Binding, now, TimeSpan.FromMinutes(5)).TransactionId!;
        Check(chronologyStore.BindAsset(chronologyId, chronologyRequest.Binding, "asset-time", now.AddTicks(-1)) ==
            BootstrapTransactionResult.InvalidState && !Directory.EnumerateFiles(chronologyRoot.Path, "*.asset.json").Any(),
            "binding cannot predate retention");
        Check(chronologyStore.BindAsset(chronologyId, chronologyRequest.Binding, "asset-time", now.AddSeconds(30)) ==
            BootstrapTransactionResult.AssetBound, "binding chronology fixture");
        Check(chronologyStore.BindAsset(chronologyId, chronologyRequest.Binding, "asset-time", now) ==
            BootstrapTransactionResult.InvalidState, "idempotent binding cannot predate durable binding time");
        Check(chronologyStore.TryClaimSubmission(chronologyId, chronologyRequest.Binding, "asset-time", now).Result ==
            BootstrapTransactionResult.InvalidState, "claim cannot predate asset binding");
        Check(chronologyStore.Lookup(chronologyId, chronologyRequest.Binding, "asset-time", now).Result ==
            BootstrapTransactionResult.InvalidState, "lookup cannot predate asset binding");
        Check(chronologyStore.Lookup(chronologyId, chronologyRequest.Binding, "asset-time", now.AddMinutes(5)).State ==
            BootstrapTransactionState.Expired, "expired asset-bound state is explicit");
        Check(chronologyStore.TryClaimSubmission(chronologyId, chronologyRequest.Binding, "asset-time", now.AddMinutes(5)).Result ==
            BootstrapTransactionResult.Expired, "bound transaction cannot claim at expiry");
        Check(chronologyStore.TryClaimSubmission(chronologyId, chronologyRequest.Binding, "asset-time",
            now.AddSeconds(-1)).Result == BootstrapTransactionResult.InvalidState, "backdated claim is rejected");
        var chronologyClaim = chronologyStore.TryClaimSubmission(chronologyId, chronologyRequest.Binding,
            "asset-time", now.AddMinutes(1)).Claim!;
        Throws<ArgumentOutOfRangeException>(() => chronologyClaim.RecordPending(8, now),
            "backdated pending transition");
        Throws<ArgumentOutOfRangeException>(() => chronologyClaim.RecordIssued(8, new string('E', 64), "12", now),
            "backdated issued transition");
        Throws<ArgumentOutOfRangeException>(() => chronologyClaim.RecordFailed("failure", now),
            "backdated failure transition");
        Check(chronologyStore.Lookup(chronologyId, chronologyRequest.Binding, "asset-time", now.AddSeconds(45)).Result ==
            BootstrapTransactionResult.InvalidState, "lookup cannot predate submission claim");

        var privateKey = PrivateKey();
        Throws<ArgumentException>(() => expiryStore.Retain(privateKey, expiryRequest.Binding, now,
            TimeSpan.FromMinutes(1)), "private-key material in place of a public CSR");
        Throws<ArgumentOutOfRangeException>(() => expiryStore.Retain(new byte[FileBootstrapEnrollmentTransactionStore.MaximumCsrBytes + 1],
            expiryRequest.Binding, now, TimeSpan.FromMinutes(1)), "oversized request");
        Throws<ArgumentException>(() => expiryStore.Retain(csr, Different(binding), now,
            TimeSpan.FromMinutes(1)), "retention rejects a mismatched CSR hash");
        Throws<ArgumentException>(() => expiryStore.Retain(csr, DifferentSpki(binding), now,
            TimeSpan.FromMinutes(1)), "retention rejects a mismatched SPKI hash");
        Throws<ArgumentOutOfRangeException>(() => expiryStore.Retain(csr, binding, now, TimeSpan.Zero), "zero lifetime");
        Throws<ArgumentOutOfRangeException>(() => expiryStore.Retain(csr, binding, now, TimeSpan.FromHours(25)), "excessive lifetime");

        using var incompleteRoot = Root();
        var incompleteStore = new FileBootstrapEnrollmentTransactionStore(incompleteRoot.Path);
        var incompleteRequest = Request();
        var incompleteId = incompleteStore.Retain(incompleteRequest.Csr, incompleteRequest.Binding, now,
            TimeSpan.FromMinutes(5)).TransactionId!;
        File.Delete(Directory.EnumerateFiles(incompleteRoot.Path, "*.csr").Single());
        Throws<IOException>(() => incompleteStore.BindAsset(incompleteId, incompleteRequest.Binding, "asset-incomplete", now),
            "binding requires the complete retained public request");
        Check(!Directory.EnumerateFiles(incompleteRoot.Path, "*.asset.json").Any(), "incomplete retention cannot leave an asset marker");

        using var malformedRoot = Root();
        var malformedStore = new FileBootstrapEnrollmentTransactionStore(malformedRoot.Path);
        var malformedRequest = Request();
        var malformedId = malformedStore.Retain(malformedRequest.Csr, malformedRequest.Binding, now,
            TimeSpan.FromMinutes(5)).TransactionId!;
        var retainedPath = Directory.EnumerateFiles(malformedRoot.Path, "*.retained.json").Single();
        var text = File.ReadAllText(retainedPath).Replace("\"Version\":1", "\"Version\":1,\"Version\":1", StringComparison.Ordinal);
        File.WriteAllText(retainedPath, text);
        File.SetUnixFileMode(retainedPath, FileModeOwnerOnly);
        Throws<InvalidDataException>(() => malformedStore.Lookup(malformedId, malformedRequest.Binding, "asset-005", now),
            "ambiguous duplicate-property JSON");

        using var immutableRoot = Root();
        var immutableStore = new FileBootstrapEnrollmentTransactionStore(immutableRoot.Path);
        var immutableRequest = Request();
        var immutableId = immutableStore.Retain(immutableRequest.Csr, immutableRequest.Binding, now,
            TimeSpan.FromMinutes(5)).TransactionId!;
        Check(immutableStore.BindAsset(immutableId, immutableRequest.Binding, "asset-original", now) ==
            BootstrapTransactionResult.AssetBound, "immutable asset fixture binds");
        var immutableClaim = immutableStore.TryClaimSubmission(immutableId, immutableRequest.Binding, "asset-original", now).Claim!;
        var immutableRecord = Directory.EnumerateFiles(immutableRoot.Path, "*.asset.json").Single();
        File.WriteAllText(immutableRecord, File.ReadAllText(immutableRecord).Replace(
            "asset-original", "asset-modified", StringComparison.Ordinal));
        File.SetUnixFileMode(immutableRecord, FileModeOwnerOnly);
        Throws<InvalidDataException>(() => immutableStore.Lookup(immutableId, immutableRequest.Binding, "asset-modified", now),
            "changed asset marker conflicts with durable submission claim");
        Throws<InvalidDataException>(() => immutableClaim.ExportValidatedCsr(), "cached claim revalidates asset before CSR export");
        Throws<InvalidDataException>(() => immutableClaim.RecordPending(10, now), "cached claim revalidates asset before pending");
        Throws<InvalidDataException>(() => immutableClaim.RecordIssued(10, new string('F', 64), "14", now),
            "cached claim revalidates asset before issued");
        Throws<InvalidDataException>(() => immutableClaim.RecordFailed("failure", now), "cached claim revalidates asset before failure");

        foreach (var corruption in new[] { "json", "duplicate", "csr-hash", "spki-hash", "backdated", "expired", "swapped", "symlink", "mode" })
        {
            using var corruptRoot = Root();
            var corruptStore = new FileBootstrapEnrollmentTransactionStore(corruptRoot.Path);
            var corruptRequest = Request();
            var corruptId = corruptStore.Retain(corruptRequest.Csr, corruptRequest.Binding, now,
                TimeSpan.FromMinutes(5)).TransactionId!;
            corruptStore.BindAsset(corruptId, corruptRequest.Binding, "asset-corruption", now.AddMinutes(1));
            var corruptPath = Directory.EnumerateFiles(corruptRoot.Path, "*.asset.json").Single();
            var originalText = File.ReadAllText(corruptPath);
            if (corruption == "symlink")
            {
                File.Delete(corruptPath);
                File.CreateSymbolicLink(corruptPath, assetPath);
            }
            else if (corruption == "mode") File.SetUnixFileMode(corruptPath, FileModeOwnerOnly | UnixFileMode.GroupRead);
            else
            {
                var corruptText = corruption switch
                {
                    "json" => "{",
                    "duplicate" => originalText.Replace("\"Version\":1", "\"Version\":1,\"Version\":1", StringComparison.Ordinal),
                    "csr-hash" => originalText.Replace(Convert.ToHexString(corruptRequest.Binding.CsrSha256), new string('0', 64), StringComparison.Ordinal),
                    "spki-hash" => originalText.Replace(Convert.ToHexString(corruptRequest.Binding.SubjectPublicKeyInfoSha256), new string('0', 64), StringComparison.Ordinal),
                    "backdated" => originalText.Replace("12:01:00", "11:59:59", StringComparison.Ordinal),
                    "expired" => originalText.Replace("12:01:00", "12:05:00", StringComparison.Ordinal),
                    "swapped" => System.Text.Encoding.UTF8.GetString(assetBytes),
                    _ => throw new InvalidOperationException("Unknown corruption fixture.")
                };
                File.WriteAllText(corruptPath, corruptText);
                File.SetUnixFileMode(corruptPath, FileModeOwnerOnly);
            }
            try
            {
                var operations = new Action[]
                {
                    () => new FileBootstrapEnrollmentTransactionStore(corruptRoot.Path)
                        .Lookup(corruptId, corruptRequest.Binding, "asset-corruption", now.AddMinutes(2)),
                    () => corruptStore.TryClaimSubmission(corruptId, corruptRequest.Binding, "asset-corruption", now.AddMinutes(2)),
                    () => corruptStore.BindAsset(corruptId, corruptRequest.Binding, "asset-corruption", now.AddMinutes(2))
                };
                foreach (var operation in operations)
                {
                    if (corruption is "symlink" or "mode") Throws<IOException>(operation, "asset marker filesystem rejection: " + corruption);
                    else Throws<InvalidDataException>(operation, "asset marker data rejection: " + corruption);
                }
                Check(!Directory.EnumerateFiles(corruptRoot.Path, "*.claimed.json").Any(), "corrupt asset cannot create claim: " + corruption);
            }
            finally
            {
                if (corruption == "symlink") File.Delete(corruptPath);
            }
        }

        foreach (var corruption in new[] { "missing-asset", "csr-bytes", "asset-time" })
        {
            using var changedRoot = Root();
            var changedStore = new FileBootstrapEnrollmentTransactionStore(changedRoot.Path);
            var changedRequest = Request();
            var changedId = changedStore.Retain(changedRequest.Csr, changedRequest.Binding, now,
                TimeSpan.FromMinutes(5)).TransactionId!;
            changedStore.BindAsset(changedId, changedRequest.Binding, "asset-cached", now);
            var changedClaim = changedStore.TryClaimSubmission(changedId, changedRequest.Binding, "asset-cached", now.AddMinutes(1)).Claim!;
            changedClaim.RecordPending(42, now.AddMinutes(2));
            var recoveredClaim = new FileBootstrapEnrollmentTransactionStore(changedRoot.Path)
                .Lookup(changedId, changedRequest.Binding, "asset-cached", now.AddMinutes(2)).PendingCompletion!;
            var changedAssetPath = Directory.EnumerateFiles(changedRoot.Path, "*.asset.json").Single();
            if (corruption == "missing-asset") File.Delete(changedAssetPath);
            else if (corruption == "csr-bytes")
                File.WriteAllBytes(Directory.EnumerateFiles(changedRoot.Path, "*.csr").Single(), Request().Csr);
            else
                File.WriteAllText(changedAssetPath, File.ReadAllText(changedAssetPath).Replace("12:00:00", "12:00:30", StringComparison.Ordinal));
            Throws<InvalidDataException>(() => changedStore.Lookup(changedId, changedRequest.Binding, "asset-cached", now.AddMinutes(3)),
                "pending lookup revalidates: " + corruption);
            Throws<InvalidDataException>(() => changedClaim.ExportValidatedCsr(), "original claim export revalidates: " + corruption);
            Throws<InvalidDataException>(() => recoveredClaim.RecordIssued(42, new string('F', 64), "16", now.AddMinutes(3)),
                "recovered pending claim revalidates: " + corruption);
            Throws<InvalidDataException>(() => recoveredClaim.RecordFailed("failure", now.AddMinutes(3)),
                "recovered pending failure revalidates: " + corruption);
        }

        using var modeRoot = Root();
        var modeStore = new FileBootstrapEnrollmentTransactionStore(modeRoot.Path);
        var modeRequest = Request();
        var modeId = modeStore.Retain(modeRequest.Csr, modeRequest.Binding, now,
            TimeSpan.FromMinutes(5)).TransactionId!;
        var modeFile = Directory.EnumerateFiles(modeRoot.Path, "*.retained.json").Single();
        File.SetUnixFileMode(modeFile, FileModeOwnerOnly | UnixFileMode.GroupRead);
        Throws<IOException>(() => modeStore.Lookup(modeId, modeRequest.Binding, "asset-006", now),
            "group-readable record");
        File.SetUnixFileMode(modeFile, FileModeOwnerOnly);

        File.WriteAllBytes(modeFile, new byte[20_000]);
        File.SetUnixFileMode(modeFile, FileModeOwnerOnly);
        Throws<IOException>(() => modeStore.Lookup(modeId, modeRequest.Binding, "asset-006", now),
            "oversized JSON record");

        using var badRoot = Root();
        File.SetUnixFileMode(badRoot.Path, DirectoryMode | UnixFileMode.GroupRead);
        Throws<IOException>(() => { _ = new FileBootstrapEnrollmentTransactionStore(badRoot.Path); },
            "non-owner-only root directory");
        File.SetUnixFileMode(badRoot.Path, DirectoryMode);

        using var recordLinkRoot = Root();
        var recordLinkStore = new FileBootstrapEnrollmentTransactionStore(recordLinkRoot.Path);
        var recordLinkRequest = Request();
        var recordLinkId = recordLinkStore.Retain(recordLinkRequest.Csr, recordLinkRequest.Binding, now, TimeSpan.FromMinutes(5)).TransactionId!;
        var linkedRecord = Directory.EnumerateFiles(recordLinkRoot.Path, "*.retained.json").Single();
        var reservationRecord = Directory.EnumerateFiles(recordLinkRoot.Path, "bootstrap-csr-*.json").Single();
        File.Delete(linkedRecord);
        File.CreateSymbolicLink(linkedRecord, reservationRecord);
        try
        {
            Throws<IOException>(() => recordLinkStore.Lookup(recordLinkId, recordLinkRequest.Binding, "asset-007", now),
                "symlink transaction record");
        }
        finally { File.Delete(linkedRecord); }

        using var linkTarget = Root();
        var linkPath = linkTarget.Path + "-link";
        Directory.CreateSymbolicLink(linkPath, linkTarget.Path);
        try { Throws<IOException>(() => { _ = new FileBootstrapEnrollmentTransactionStore(linkPath); }, "symlink root"); }
        finally { Directory.Delete(linkPath); }

        Console.WriteLine($"Bootstrap enrollment transaction store checks passed: {checks}.");
    }

    private static (byte[] Csr, CsrBinding Binding) Request()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=bootstrap-transaction-test", key, HashAlgorithmName.SHA256);
        var csr = request.CreateSigningRequest();
        return (csr, CsrBinding.FromDer(csr));
    }

    private static byte[] PrivateKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return key.ExportPkcs8PrivateKey();
    }

    private static string TryTerminal(Action transition, string winner)
    {
        try { transition(); return winner; }
        catch (InvalidOperationException) { return "lost"; }
    }

    private static CsrBinding Different(CsrBinding binding) =>
        new(binding.CsrSha256.Select((value, index) => index == 0 ? (byte)(value ^ 1) : value).ToArray(),
            binding.SubjectPublicKeyInfoSha256.ToArray());

    private static CsrBinding DifferentSpki(CsrBinding binding) =>
        new(binding.CsrSha256.ToArray(),
            binding.SubjectPublicKeyInfoSha256.Select((value, index) => index == 0 ? (byte)(value ^ 1) : value).ToArray());

    private static ScratchRoot Root()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var directory = Directory.CreateTempSubdirectory("bootstrap-enrollment-transaction-");
        File.SetUnixFileMode(directory.FullName, DirectoryMode);
        return new ScratchRoot(directory.FullName);
    }

    private static bool IsOwnerOnly(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        return File.GetUnixFileMode(path) == FileModeOwnerOnly;
    }

    private sealed class ScratchRoot(string path) : IDisposable
    {
        internal string Path { get; } = path;
        public void Dispose()
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
            File.SetUnixFileMode(Path, DirectoryMode);
            foreach (var file in Directory.EnumerateFiles(Path)) File.SetUnixFileMode(file, FileModeOwnerOnly);
            Directory.Delete(Path, recursive: true);
        }
    }
}
