using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using PkiProxy.Authentication;
using PkiProxy.Domain;

internal static class DeviceFactsPublisherTests
{
    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Publisher tests require Linux.");
        var root = Path.Combine(Path.GetTempPath(), "facts-publish-test-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var source = File.ReadAllBytes("lab/device-facts/devices.client001-engineering-v3.json");
        var sourceHash = Hash(source);
        var draft = DeviceFactsEditor.PrepareUseCase(source, sourceHash, "CLIENT-001.example.test", "lab-validation");
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
            var beforeFacts = await reader.FindByDnsHostNameAsync("CLIENT-001.example.test", CancellationToken.None);
            Assert(beforeFacts is { UseCase: "engineering", SourceVersion: 3 }, "Initial broker-reader facts mismatch.");
            var receipt = DeviceFactsPublisher.Publish(target, draft, sourceHash, Hash(draft),
                operatorIdentity: "avery@example.com",
                operatorCapability: TechnicianCapabilities.FactsWrite);
            var afterFacts = await reader.FindByDnsHostNameAsync("CLIENT-001.example.test", CancellationToken.None);
            Assert(afterFacts is { UseCase: "lab-validation", SourceVersion: 4 }, "Existing broker reader missed atomic replacement.");
            Assert(File.ReadAllBytes(target).AsSpan().SequenceEqual(draft), "Draft bytes not published exactly.");
            Assert(receipt.Revision == 4 && receipt.PreviousSha256 == sourceHash && receipt.PublishedSha256 == Hash(draft), "Receipt mismatch.");
            Assert(File.ReadAllBytes(Path.Combine(receipt.RecoveryDirectory, "before.json")).AsSpan().SequenceEqual(source), "Backup mismatch.");
            Assert(File.ReadAllBytes(Path.Combine(receipt.RecoveryDirectory, "after.json")).AsSpan().SequenceEqual(draft), "Reviewed draft not retained.");
            Assert(File.Exists(Path.Combine(receipt.RecoveryDirectory, "committed.json")), "Commit record missing.");
            Assert(JsonNode.Parse(File.ReadAllText(Path.Combine(receipt.RecoveryDirectory, "intent.json")))!["OperatorIdentity"]!.GetValue<string>() == "avery@example.com",
                "Authenticated operator missing from durable intent.");
            Assert(JsonNode.Parse(File.ReadAllText(Path.Combine(receipt.RecoveryDirectory, "committed.json")))!["OperatorIdentity"]!.GetValue<string>() == "avery@example.com",
                "Authenticated operator missing from commit audit.");
            Assert(File.GetUnixFileMode(target) == (UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead), "Facts read permissions changed.");
            Assert(File.GetUnixFileMode(Path.Combine(receipt.RecoveryDirectory, "before.json")) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "Backup not private.");
            Reject(() => DeviceFactsPublisher.Publish(target, draft, sourceHash, Hash(draft)));
            Assert(System.IO.Directory.GetDirectories(Path.Combine(Path.GetDirectoryName(target)!, ".facts-history")).Length == 1, "Stale retry created history.");

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
            Assert(!System.IO.Directory.Exists(Path.Combine(Path.GetDirectoryName(fresh)!, ".facts-history")), "Rejected input created publication history.");
            Assert(DeviceFactsCommand.Run(["--facts-publish", fresh, fresh, sourceHash, sourceHash]) == 1,
                "Invalid publication should return a controlled CLI failure.");
            Assert(DeviceFactsCommand.Run(["--facts-publish"]) == 64, "Publisher usage error not reported.");

            var interrupted = Target("before-rename");
            Reject(() => DeviceFactsPublisher.Publish(interrupted, draft, sourceHash, Hash(draft), stage =>
            { if (stage == "before-rename") throw new IOException("Injected interruption."); }));
            Assert(File.ReadAllBytes(interrupted).AsSpan().SequenceEqual(source), "Pre-rename interruption changed authority.");
            var recovery = System.IO.Directory.GetDirectories(Path.Combine(Path.GetDirectoryName(interrupted)!, ".facts-history")).Single();
            Assert(File.Exists(Path.Combine(recovery, "intent.json")) && !File.Exists(Path.Combine(recovery, "committed.json")), "Interrupted transaction misreported.");

            var uncertain = Target("after-rename");
            Reject(() => DeviceFactsPublisher.Publish(uncertain, draft, sourceHash, Hash(draft), stage =>
            { if (stage == "after-rename") throw new IOException("Injected response loss."); }));
            Assert(File.ReadAllBytes(uncertain).AsSpan().SequenceEqual(draft), "Post-rename data incomplete.");
            Reject(() => DeviceFactsPublisher.Publish(uncertain, draft, sourceHash, Hash(draft)));
            Assert(System.IO.Directory.GetDirectories(Path.Combine(Path.GetDirectoryName(uncertain)!, ".facts-history")).Length == 1, "Uncertain retry duplicated transaction.");

            var external = Target("out-of-band");
            Reject(() => DeviceFactsPublisher.Publish(external, draft, sourceHash, Hash(draft), stage =>
            {
                if (stage != "before-rename") return;
                if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
                File.SetUnixFileMode(external, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.WriteAllText(external, "out-of-band change");
            }));
            Assert(File.ReadAllText(external) == "out-of-band change", "Publisher overwrote detected external edit.");

            var linked = Path.Combine(Path.GetDirectoryName(fresh)!, "linked.json");
            File.CreateSymbolicLink(linked, fresh);
            Reject(() => DeviceFactsPublisher.Publish(linked, draft, sourceHash, Hash(draft)));
            File.SetUnixFileMode(fresh, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite);
            Reject(() => DeviceFactsPublisher.Publish(fresh, draft, sourceHash, Hash(draft)));

            // A separate Linux flock process holds the same advisory lock. cat
            // remains alive until stdin closes; one echoed line confirms acquisition.
            var next = DeviceFactsEditor.PrepareUseCase(draft, Hash(draft), "CLIENT-001.example.test", "engineering");
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
    private static string Hash(byte[] data) => Convert.ToHexString(SHA256.HashData(data));
}
