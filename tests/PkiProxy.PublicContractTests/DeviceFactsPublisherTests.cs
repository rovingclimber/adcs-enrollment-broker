using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using PkiProxy.Authentication;
using PkiProxy.Domain;

internal static class DeviceFactsPublisherTests
{
    private const string HistoryName = ".facts-history";
    private const string BundleStagingName = ".bundle-staging";
    private const string OutcomeStagingName = ".outcome-staging";
    private const string IntentName = "intent.json";
    private const string CommittedName = "committed.json";
    private const string AbortedName = "aborted.json";
    private const string BeforeName = "before.json";
    private const string AfterName = "after.json";
    private const string Asset = "CLIENT-001.example.test";
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectory = PrivateFile | UnixFileMode.UserExecute;

    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Publisher tests require Linux.");
        var root = Path.Combine(Path.GetTempPath(), "facts-publish-test-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var source = File.ReadAllBytes("lab/device-facts/devices.client001-engineering-v3.json");
        var sourceHash = Hash(source);
        var draft = DeviceFactsEditor.PrepareUseCase(source, sourceHash, Asset, "lab-validation");
        var next = DeviceFactsEditor.PrepareUseCase(draft, Hash(draft), Asset, "engineering");
        var checks = 0;
        string Target(string name)
        {
            var directory = Path.Combine(root, name);
            System.IO.Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var file = Path.Combine(directory, "devices.json"); File.WriteAllBytes(file, source);
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            return file;
        }
        void Assert(bool condition, string message)
        { if (!condition) throw new InvalidOperationException(message); checks++; }
        void Reject(Action action)
        {
            try { action(); }
            catch (Exception e) when (e is InvalidDataException or IOException or OverflowException) { checks++; return; }
            throw new InvalidOperationException("Unsafe facts publication accepted.");
        }
        try
        {
            var target = Target("success");
            var reader = new JsonFileDeviceFactsSource(target);
            var beforeFacts = await reader.FindByDnsHostNameAsync(Asset, CancellationToken.None);
            Assert(beforeFacts is { UseCase: "engineering", SourceVersion: 3 }, "Initial broker-reader facts mismatch.");
            var receipt = DeviceFactsPublisher.Publish(target, draft, sourceHash, Hash(draft),
                operatorIdentity: "avery@example.com",
                operatorCapability: TechnicianCapabilities.FactsWrite);
            var afterFacts = await reader.FindByDnsHostNameAsync(Asset, CancellationToken.None);
            Assert(afterFacts is { UseCase: "lab-validation", SourceVersion: 4 }, "Existing broker reader missed atomic replacement.");
            Assert(File.ReadAllBytes(target).AsSpan().SequenceEqual(draft), "Draft bytes not published exactly.");
            Assert(receipt.Revision == 4 && receipt.PreviousSha256 == sourceHash && receipt.PublishedSha256 == Hash(draft), "Receipt mismatch.");
            Assert(File.ReadAllBytes(Path.Combine(receipt.RecoveryDirectory, BeforeName)).AsSpan().SequenceEqual(source), "Backup mismatch.");
            Assert(File.ReadAllBytes(Path.Combine(receipt.RecoveryDirectory, AfterName)).AsSpan().SequenceEqual(draft), "Reviewed draft not retained.");
            Assert(File.Exists(Path.Combine(receipt.RecoveryDirectory, CommittedName)), "Commit record missing.");
            Assert(JsonNode.Parse(File.ReadAllText(Path.Combine(receipt.RecoveryDirectory, IntentName)))!["OperatorIdentity"]!.GetValue<string>() == "avery@example.com",
                "Authenticated operator missing from durable intent.");
            Assert(JsonNode.Parse(File.ReadAllText(Path.Combine(receipt.RecoveryDirectory, CommittedName)))!["OperatorIdentity"]!.GetValue<string>() == "avery@example.com",
                "Authenticated operator missing from commit audit.");
            Assert(File.GetUnixFileMode(target) == (UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead), "Facts read permissions changed.");
            Assert(File.GetUnixFileMode(Path.Combine(receipt.RecoveryDirectory, BeforeName)) == PrivateFile, "Backup not private.");
            Reject(() => DeviceFactsPublisher.Publish(target, draft, sourceHash, Hash(draft)));
            Assert(System.IO.Directory.GetDirectories(History(target)).Length == 1, "Stale retry created history.");

            var fresh = Target("refused");
            Reject(() => DeviceFactsPublisher.Publish(fresh, draft, new string('0', 64), Hash(draft)));
            Reject(() => DeviceFactsPublisher.Publish(fresh, draft, sourceHash, new string('0', 64)));
            try
            {
                _ = DeviceFactsPublisher.Publish(fresh, draft, sourceHash, Hash(draft), operatorIdentity: "not an identity");
                throw new InvalidOperationException("Invalid operator identity accepted.");
            }
            catch (ArgumentException) { checks++; }
            try
            {
                _ = DeviceFactsPublisher.Publish(fresh, draft, sourceHash, Hash(draft),
                    operatorIdentity: "avery@example.com", operatorCapability: "bootstrap-approve");
                throw new InvalidOperationException("Wrong operator capability accepted.");
            }
            catch (ArgumentException) { checks++; }
            var badRevision = JsonNode.Parse(draft)!; badRevision["revision"] = 9;
            var bad = Encoding.UTF8.GetBytes(badRevision.ToJsonString());
            Reject(() => DeviceFactsPublisher.Publish(fresh, bad, sourceHash, Hash(bad)));
            var changedCatalogue = JsonNode.Parse(draft)!; changedCatalogue["useCases"]![0]!["label"] = "Different";
            bad = Encoding.UTF8.GetBytes(changedCatalogue.ToJsonString());
            Reject(() => DeviceFactsPublisher.Publish(fresh, bad, sourceHash, Hash(bad)));
            Assert(File.ReadAllBytes(fresh).AsSpan().SequenceEqual(source), "Rejected draft changed source.");
            Assert(!System.IO.Directory.Exists(History(fresh)), "Rejected input created publication history.");
            Assert(DeviceFactsCommand.Run(["--facts-publish", fresh, fresh, sourceHash, sourceHash]) == 1,
                "Invalid publication should return a controlled CLI failure.");
            Assert(DeviceFactsCommand.Run(["--facts-publish"]) == 64, "Publisher usage error not reported.");
            Assert(DeviceFactsCommand.Run(["--facts-reconcile", "relative.json"]) == 64,
                "Reconciliation must require an absolute target.");

            var interrupted = Target("before-rename");
            Reject(() => DeviceFactsPublisher.Publish(interrupted, draft, sourceHash, Hash(draft), stage =>
            { if (stage == "before-rename") throw new IOException("Injected interruption."); }));
            Assert(File.ReadAllBytes(interrupted).AsSpan().SequenceEqual(source), "Pre-rename interruption changed authority.");
            var recovery = System.IO.Directory.GetDirectories(History(interrupted)).Single();
            Assert(File.Exists(Path.Combine(recovery, IntentName)) && !File.Exists(Path.Combine(recovery, CommittedName)), "Interrupted transaction misreported.");
            Reject(() => DeviceFactsPublisher.Publish(interrupted, draft, sourceHash, Hash(draft)));
            WritePrivate(Path.Combine(recovery, OutcomeStagingName), "partial abort");
            Assert(DeviceFactsPublisher.Reconcile(interrupted).RecoveredAborted == 1 &&
                File.Exists(Path.Combine(recovery, AbortedName)) && !File.Exists(Path.Combine(recovery, OutcomeStagingName)),
                "Interrupted abort marker was not recovered.");
            var pending = System.IO.Directory.GetFiles(Path.GetDirectoryName(interrupted)!, ".facts-*.pending").Single();
            Assert(File.ReadAllBytes(pending).AsSpan().SequenceEqual(draft), "Recovery discarded retained pending evidence.");

            var uncertain = Target("after-rename");
            Reject(() => DeviceFactsPublisher.Publish(uncertain, draft, sourceHash, Hash(draft), stage =>
            { if (stage == "after-rename") throw new IOException("Injected response loss."); }));
            Assert(File.ReadAllBytes(uncertain).AsSpan().SequenceEqual(draft), "Post-rename data incomplete.");
            Reject(() => DeviceFactsPublisher.Publish(uncertain, next, Hash(draft), Hash(next)));
            Assert(System.IO.Directory.GetDirectories(History(uncertain)).Length == 1, "Uncertain retry duplicated transaction.");
            Assert(DeviceFactsPublisher.Reconcile(uncertain).RecoveredCommitted == 1, "Post-rename interruption not committed.");
            Assert(DeviceFactsPublisher.Publish(uncertain, next, Hash(draft), Hash(next)).Revision == 5,
                "Valid next revision was refused after reconciliation.");

            CheckBundleStaging(Target("bundle-staging"), source, draft, Assert, Reject);
            CheckPublishedBundle(Target("bundle-published"), source, draft, Assert, Reject);
            CheckOutcomeStaging(Target("outcome-staging"), source, draft, next, Assert, Reject);
            CheckLegacyOrphan(Target("legacy-orphan"), source, draft, Assert, Reject);
            CheckQuotas(Target("quotas"), source, draft, next, Assert);
            CheckPendingQuota(Target("pending-quota"), source, draft, Assert, Reject);

            var external = Target("out-of-band");
            Reject(() => DeviceFactsPublisher.Publish(external, draft, sourceHash, Hash(draft), stage =>
            {
                if (stage != "before-rename") return;
                if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
                File.SetUnixFileMode(external, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.WriteAllText(external, "out-of-band change");
            }));
            Reject(() => DeviceFactsPublisher.Reconcile(external));
            Assert(File.ReadAllText(external) == "out-of-band change", "Publisher overwrote detected external edit.");

            var linked = Path.Combine(Path.GetDirectoryName(fresh)!, "linked.json");
            File.CreateSymbolicLink(linked, fresh);
            Reject(() => DeviceFactsPublisher.Publish(linked, draft, sourceHash, Hash(draft)));
            File.SetUnixFileMode(fresh, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite);
            Reject(() => DeviceFactsPublisher.Publish(fresh, draft, sourceHash, Hash(draft)));

            // A separate Linux flock process holds the same advisory lock. cat
            // remains alive until stdin closes; one echoed line confirms acquisition.
            var start = new ProcessStartInfo("flock") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add(target + ".publish.lock"); start.ArgumentList.Add("cat");
            using var holder = Process.Start(start)!;
            try
            {
                await holder.StandardInput.WriteLineAsync("locked"); await holder.StandardInput.FlushAsync();
                Assert(await holder.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)) == "locked", "External lock not acquired.");
                Reject(() => DeviceFactsPublisher.Publish(target, next, Hash(draft), Hash(next)));
                Assert(File.ReadAllBytes(target).AsSpan().SequenceEqual(draft), "Concurrent publisher changed target.");
            }
            finally { holder.StandardInput.Close(); await holder.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
            var nextReceipt = DeviceFactsPublisher.Publish(target, next, Hash(draft), Hash(next));
            Assert(nextReceipt.Revision == 5 && File.ReadAllBytes(target).AsSpan().SequenceEqual(next), "Publish after lock release failed.");
            Console.WriteLine($"Atomic facts publication checks passed: {checks} (disposable Linux data only).");
        }
        finally { System.IO.Directory.Delete(root, recursive: true); } // Unique test-owned directory only.
    }

    [SupportedOSPlatform("linux")]
    private static void CheckBundleStaging(string target, byte[] source, byte[] draft,
        Action<bool, string> assert, Action<Action> reject)
    {
        var second = Path.Combine(Path.GetDirectoryName(target)!, "second.json");
        File.WriteAllBytes(second, source);
        reject(() => DeviceFactsPublisher.Publish(target, draft, Hash(source), Hash(draft), stage =>
        {
            if (stage != "bundle-staging") return;
            reject(() => DeviceFactsPublisher.Reconcile(second));
            throw new IOException("Injected interruption during bundle write.");
        }));
        var staging = Path.Combine(History(target), BundleStagingName);
        assert(System.IO.Directory.GetFileSystemEntries(History(target)).SequenceEqual([staging]) &&
            System.IO.Directory.GetFileSystemEntries(staging).SequenceEqual([Path.Combine(staging, BeforeName)]),
            "Partial bundle leaked into the recognized recovery namespace.");
        reject(() => DeviceFactsPublisher.Publish(target, draft, Hash(source), Hash(draft)));

        var linked = Path.Combine(staging, AfterName);
        File.CreateSymbolicLink(linked, second);
        reject(() => DeviceFactsPublisher.Reconcile(target));
        assert(File.ReadAllBytes(second).AsSpan().SequenceEqual(source) &&
            new FileInfo(linked).LinkTarget == second && File.Exists(Path.Combine(staging, BeforeName)),
            "Unsafe staging was followed or partially discarded.");
        File.Delete(linked); // Remove the synthetic corruption for the successful recovery case.

        assert(DeviceFactsCommand.Run(["--facts-reconcile", target]) == 0 &&
            !System.IO.Directory.Exists(staging), "Private unpublished scratch survived restart.");
        assert(File.ReadAllBytes(target).AsSpan().SequenceEqual(source), "Staging recovery changed active facts.");
        assert(DeviceFactsPublisher.Publish(target, draft, Hash(source), Hash(draft)).Revision == 4,
            "Clean retry after unpublished scratch recovery failed.");
    }

    private static void CheckPublishedBundle(string target, byte[] source, byte[] draft,
        Action<bool, string> assert, Action<Action> reject)
    {
        reject(() => Interrupt(target, source, draft, "bundle-published"));
        var recovery = System.IO.Directory.GetDirectories(History(target)).Single();
        assert(System.IO.Directory.GetFiles(recovery).Length == 3 &&
            File.ReadAllBytes(target).AsSpan().SequenceEqual(source) &&
            !System.IO.Directory.EnumerateFiles(Path.GetDirectoryName(target)!, ".facts-*.pending").Any(),
            "Published bundle was incomplete or had already changed the target.");
        assert(DeviceFactsPublisher.Reconcile(target).RecoveredAborted == 1 &&
            File.Exists(Path.Combine(recovery, AbortedName)), "Published intent was not reconciled before target write.");
    }

    [SupportedOSPlatform("linux")]
    private static void CheckOutcomeStaging(string target, byte[] source, byte[] draft, byte[] next,
        Action<bool, string> assert, Action<Action> reject)
    {
        reject(() => Interrupt(target, source, draft, "outcome-staged"));
        var recovery = System.IO.Directory.GetDirectories(History(target)).Single();
        var committedPath = Path.Combine(recovery, CommittedName);
        var staging = Path.Combine(recovery, OutcomeStagingName);
        assert(File.Exists(staging) && !File.Exists(committedPath), "Outcome appeared before atomic publication.");
        WritePrivate(staging, "{"); // Simulate a torn write before the staging file was flushed.
        assert(DeviceFactsPublisher.Reconcile(target).RecoveredCommitted == 1 &&
            File.Exists(committedPath) && !File.Exists(staging), "Torn outcome staging blocked recovery.");
        var committed = File.ReadAllText(committedPath);
        assert(JsonNode.Parse(committed)!["Recovered"]!.GetValue<bool>() &&
            JsonNode.Parse(committed)!["OperatorIdentity"]!.GetValue<string>() == "avery@example.com",
            "Recovered outcome lost audit attribution.");
        assert(DeviceFactsPublisher.Reconcile(target).Committed == 1, "Recovered marker was not idempotent.");

        var unexpectedPath = Path.Combine(recovery, "unexpected.json");
        WritePrivate(unexpectedPath, "{}");
        reject(() => DeviceFactsPublisher.Reconcile(target));
        reject(() => DeviceFactsPublisher.Publish(target, next, Hash(draft), Hash(next)));
        assert(File.ReadAllText(unexpectedPath) == "{}", "Unrecognized recovery evidence was removed.");
        File.Delete(unexpectedPath);

        var abortedPath = Path.Combine(recovery, AbortedName);
        WritePrivate(abortedPath, "{}");
        reject(() => DeviceFactsPublisher.Reconcile(target));
        assert(File.Exists(abortedPath) && File.ReadAllText(committedPath) == committed,
            "Conflicting terminal evidence was modified.");
        File.Delete(abortedPath); // Remove the synthetic conflict before testing tamper.

        var tampered = JsonNode.Parse(committed)!;
        tampered["PublishedSha256"] = Hash(source);
        WritePrivate(committedPath, tampered.ToJsonString());
        reject(() => DeviceFactsPublisher.Reconcile(target));
        reject(() => DeviceFactsPublisher.Publish(target, next, Hash(draft), Hash(next)));
        assert(File.ReadAllBytes(target).AsSpan().SequenceEqual(draft) &&
            System.IO.Directory.GetDirectories(History(target)).Length == 1,
            "Tampered terminal evidence allowed a new write.");
    }

    [SupportedOSPlatform("linux")]
    private static void CheckLegacyOrphan(string target, byte[] source, byte[] draft,
        Action<bool, string> assert, Action<Action> reject)
    {
        var orphan = Path.Combine(History(target), Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(History(target), PrivateDirectory);
        System.IO.Directory.CreateDirectory(orphan, PrivateDirectory);
        var before = Path.Combine(orphan, BeforeName);
        WritePrivate(before, Encoding.UTF8.GetString(source));
        reject(() => DeviceFactsPublisher.Reconcile(target));
        assert(DeviceFactsCommand.Run(["--facts-reconcile", target]) == 1,
            "Operator reconciliation must refuse legacy ambiguous history.");
        reject(() => DeviceFactsPublisher.Publish(target, draft, Hash(source), Hash(draft)));
        assert(File.ReadAllBytes(before).AsSpan().SequenceEqual(source) &&
            System.IO.Directory.GetDirectories(History(target)).Single() == orphan,
            "Legacy incomplete recovery evidence was discarded.");
    }

    [SupportedOSPlatform("linux")]
    private static void CheckQuotas(string target, byte[] source, byte[] draft, byte[] next, Action<bool, string> assert)
    {
        var paddedSource = PadJson(source, 110_000);
        WritePrivate(target, Encoding.UTF8.GetString(paddedSource));
        ExpectRefusal(() => DeviceFactsPublisher.Publish(target, draft, Hash(paddedSource), Hash(draft), (10_000, 1)),
            "Facts history byte limit reached");
        assert(!System.IO.Directory.Exists(History(target)) && File.ReadAllBytes(target).AsSpan().SequenceEqual(paddedSource),
            "Prospective byte refusal created history or changed facts.");

        var receipt = DeviceFactsPublisher.Publish(target, draft, Hash(paddedSource), Hash(draft), (1, 1_000_000));
        var files = System.IO.Directory.GetFiles(receipt.RecoveryDirectory);
        var priorHashes = files.Select(path => Hash(File.ReadAllBytes(path))).ToArray();
        ExpectRefusal(() => DeviceFactsPublisher.Publish(target, next, Hash(draft), Hash(next), (1, 1_000_000)),
            "Facts history transaction limit reached");
        ExpectRefusal(() => DeviceFactsPublisher.Publish(target, next, Hash(draft), Hash(next), (10_000, 100_000)),
            "Facts history byte limit reached");
        assert(DeviceFactsPublisher.Reconcile(target).Committed == 1, "Over-budget history did not remain readable.");
        assert(File.ReadAllBytes(target).AsSpan().SequenceEqual(draft) &&
            System.IO.Directory.GetFileSystemEntries(History(target)).Single() == receipt.RecoveryDirectory &&
            System.IO.Directory.GetFiles(receipt.RecoveryDirectory).Length == files.Length &&
            files.Select(path => Hash(File.ReadAllBytes(path))).SequenceEqual(priorHashes),
            "Quota refusal or reconciliation mutated completed evidence or active facts.");
    }

    private static void CheckPendingQuota(string target, byte[] source, byte[] draft,
        Action<bool, string> assert, Action<Action> reject)
    {
        var paddedDraft = PadJson(draft, 110_000);
        reject(() => Interrupt(target, source, paddedDraft, "before-rename"));
        assert(DeviceFactsPublisher.Reconcile(target).RecoveredAborted == 1, "Expected retained pending evidence.");
        var pending = System.IO.Directory.GetFiles(Path.GetDirectoryName(target)!, ".facts-*.pending").Single();
        // The snapshots plus prospective bundle fit this budget. The retained pending copy does not.
        ExpectRefusal(() => DeviceFactsPublisher.Publish(target, draft, Hash(source), Hash(draft), (10_000, 220_000)),
            "Facts history byte limit reached");
        assert(File.ReadAllBytes(pending).AsSpan().SequenceEqual(paddedDraft) &&
            File.ReadAllBytes(target).AsSpan().SequenceEqual(source) &&
            System.IO.Directory.GetFileSystemEntries(History(target)).Length == 1,
            "Pending quota refusal changed facts or retained evidence.");
    }

    private static void Interrupt(string target, byte[] source, byte[] draft, string interruption) =>
        DeviceFactsPublisher.Publish(target, draft, Hash(source), Hash(draft), stage =>
        {
            if (stage == interruption) throw new IOException("Injected publication interruption.");
        }, "avery@example.com", TechnicianCapabilities.FactsWrite);

    private static byte[] PadJson(byte[] bytes, int size)
    {
        var padded = new byte[size];
        bytes.CopyTo(padded, 0);
        padded.AsSpan(bytes.Length).Fill((byte)' ');
        return padded;
    }

    private static void ExpectRefusal(Action action, string reason)
    {
        try { action(); }
        catch (IOException error) when (error.Message.StartsWith(reason, StringComparison.Ordinal)) { return; }
        throw new InvalidOperationException("Expected facts publication refusal: " + reason);
    }

    [SupportedOSPlatform("linux")]
    private static void WritePrivate(string path, string content)
    {
        File.WriteAllText(path, content);
        File.SetUnixFileMode(path, PrivateFile);
    }

    private static string History(string target) => Path.Combine(Path.GetDirectoryName(target)!, HistoryName);
    private static string Hash(byte[] data) => Convert.ToHexString(SHA256.HashData(data));
}
