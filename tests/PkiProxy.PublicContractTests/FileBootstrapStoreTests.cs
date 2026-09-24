using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using PkiProxy.Domain;

internal static class FileBootstrapStoreTests
{
    internal static int ConsumeFixture(string[] args)
    {
        if (args.Length != 5 || !OperatingSystem.IsLinux()) throw new ArgumentException("Fixture arguments required.");
        var path = Path.GetFullPath(args[1]);
        if (Path.GetDirectoryName(path) != Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar) ||
            !Path.GetFileName(path).StartsWith("bootstrap-store-test-", StringComparison.Ordinal))
            throw new ArgumentException("Disposable fixture directory required.");
        var binding = new CsrBinding(Convert.FromHexString(args[2]), Convert.FromHexString(args[3]));
        var now = DateTimeOffset.ParseExact(args[4], "O", CultureInfo.InvariantCulture);
        var result = new FileBootstrapAttestationStore(path).Consume(binding, now);
        return result.Result == BootstrapStoreResult.Consumed ? 0 : result.Result == BootstrapStoreResult.InvalidState ? 3 : 4;
    }

    private static async Task<int> ConsumeInChildAsync(string directory, CsrBinding binding, DateTimeOffset now)
    {
        var start = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { typeof(FileBootstrapStoreTests).Assembly.Location, "--bootstrap-consume-fixture", directory,
            Convert.ToHexString(binding.CsrSha256), Convert.ToHexString(binding.SubjectPublicKeyInfoSha256), now.ToString("O", CultureInfo.InvariantCulture) })
            start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Fixture child failed.");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await process.WaitForExitAsync(timeout.Token);
            return process.ExitCode;
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            await Task.WhenAll(output, error);
        }
    }

    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux()) return;
        var scratch = Directory.CreateTempSubdirectory("bootstrap-store-test-");
        File.SetUnixFileMode(scratch.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var now = DateTimeOffset.UtcNow;
        var checks = 0;
        void Check(bool result, string label)
        { if (!result) throw new InvalidOperationException("Durable bootstrap: " + label); checks++; }
        CsrBinding Binding() => new(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
        FileBootstrapAttestationStore Reopen() => new(scratch.FullName);
        try
        {
            MarkerIoChecks(Check);
            var binding = Binding();
            var store = Reopen();
            Check(store.Record(binding, now, TimeSpan.FromMinutes(15)) == BootstrapStoreResult.Recorded, "record");
            Check(Reopen().Record(binding, now, TimeSpan.FromMinutes(15)) == BootstrapStoreResult.AlreadyExists, "no overwrite after restart");
            Check(Reopen().GetAttestedAsset(binding, now).Result == BootstrapStoreResult.InvalidState, "pending cannot issue");
            Check(Reopen().Attest(binding, "asset-test", now.AddMinutes(1)) == BootstrapStoreResult.Attested, "approve after restart");
            Check(Reopen().GetAttestedAsset(binding, now.AddMinutes(2)).AuthoritativeAssetId == "asset-test", "approval survives reopen");
            Check(Reopen().Attest(binding, "different-asset", now.AddMinutes(2)) == BootstrapStoreResult.InvalidState, "cannot swap attested asset");
            var swapped = new CsrBinding(binding.CsrSha256.ToArray(), RandomNumberGenerator.GetBytes(32));
            Check(Reopen().GetAttestedAsset(swapped, now.AddMinutes(2)).Result == BootstrapStoreResult.BindingMismatch, "SPKI swap denied");
            Check(Reopen().GetAttestedAsset(Binding(), now).Result == BootstrapStoreResult.NotFound, "CSR swap denied");
            var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() => Reopen().Consume(binding, now.AddMinutes(3)))));
            Check(results.Count(r => r.Result == BootstrapStoreResult.Consumed) == 1, "one concurrent consumer");
            Check(results.Where(r => r.Result != BootstrapStoreResult.Consumed).All(r => r.AuthoritativeAssetId is null), "losers receive no asset grant");
            Check(Reopen().Consume(binding, now.AddMinutes(4)).Result == BootstrapStoreResult.InvalidState, "consumption survives reopen");
            Check(Reopen().Attest(binding, "asset-test", now.AddMinutes(4)) == BootstrapStoreResult.InvalidState, "consumed cannot reattest");
            var crossProcess = Binding();
            store.Record(crossProcess, now, TimeSpan.FromMinutes(10));
            store.Attest(crossProcess, "asset-test", now);
            var exits = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => ConsumeInChildAsync(scratch.FullName, crossProcess, now)));
            Check(exits.Count(code => code == 0) == 1 && exits.Count(code => code == 3) == 3, "one consumer across four fresh processes");
            Check(Reopen().GetAttestedAsset(crossProcess, now).Result == BootstrapStoreResult.InvalidState, "child consumption persists after child exit");
            var expired = Binding();
            store.Record(expired, now, TimeSpan.FromMinutes(1));
            Check(Reopen().Attest(expired, "asset-test", now.AddMinutes(1)) == BootstrapStoreResult.Expired, "expiry boundary");
            var partial = Binding();
            store.Record(partial, now, TimeSpan.FromMinutes(10));
            store.Attest(partial, "asset-test", now);
            var marker = Path.Combine(scratch.FullName, Convert.ToHexString(partial.CsrSha256) + ".consumed.json");
            File.WriteAllText(marker, "{"); File.SetUnixFileMode(marker, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            try { Reopen().Consume(partial, now); throw new InvalidOperationException("Corrupt consumed marker accepted"); }
            catch (InvalidDataException) { checks++; }
            var corrupt = Binding(); store.Record(corrupt, now, TimeSpan.FromMinutes(10));
            var pending = Path.Combine(scratch.FullName, Convert.ToHexString(corrupt.CsrSha256) + ".pending.json");
            File.WriteAllText(pending, "{");
            try { Reopen().Attest(corrupt, "asset-test", now); throw new InvalidOperationException("Corrupt record accepted"); }
            catch (InvalidDataException) { checks++; }
            try { Reopen().Record(corrupt, now, TimeSpan.FromMinutes(10)); throw new InvalidOperationException("Corrupt publication winner accepted"); }
            catch (InvalidDataException) { checks++; }
            Check(File.ReadAllText(pending) == "{", "corrupt record never auto-repaired");
            try { store.Record(Binding(), now, TimeSpan.FromDays(2)); throw new InvalidOperationException("Unbounded lifetime"); }
            catch (ArgumentOutOfRangeException) { checks++; }
            var mutable = Binding(); var original = mutable.Snapshot();
            var memory = new InMemoryBootstrapAttestationStore(); memory.Record(mutable, now, TimeSpan.FromMinutes(5));
            mutable.SubjectPublicKeyInfoSha256[0] ^= 1;
            Check(memory.Attest(original, "asset-test", now) == BootstrapStoreResult.Attested, "in-memory store owns binding snapshot");
            using var deviceKey = RSA.Create(2048);
            var csr = new CertificateRequest("CN=CLIENT-CLAIM", deviceKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();
            var realBinding = CsrBinding.FromDer(csr);
            store.Record(realBinding, now, TimeSpan.FromMinutes(10)); store.Attest(realBinding, "asset-test", now);
            var facts = new AuthoritativeDeviceFacts("asset-test", "CN=AUTHORITATIVE-DEVICE", "workstation",
                "engineering", "lab", "workgroup", 7);
            var claims = new CertificateClaimPolicy("urn:example:pki-broker:lab:fact:v1:profile:broker-pilot",
                "urn:example:pki-broker:lab:fact:v1:");
            var missingFacts = new BootstrapEnrollmentAuthorizer(Reopen(), new TestFactsSource(facts with { AssetId = "different" }), claims, IncomingCsrPolicy.NoClientExtensions);
            Check((await missingFacts.AuthorizeAsync(csr, now, default)).Result == BootstrapEnrollmentAuthorizationResult.UnknownAuthoritativeAsset,
                "unknown authoritative asset cannot authorize");
            Check(Reopen().GetAttestedAsset(realBinding, now).Result == BootstrapStoreResult.Attested, "failed facts lookup does not consume");
            var authorizer = new BootstrapEnrollmentAuthorizer(Reopen(), new TestFactsSource(facts), claims, IncomingCsrPolicy.NoClientExtensions);
            var authorized = await authorizer.AuthorizeAsync(csr, now, default);
            Check(authorized.Result == BootstrapEnrollmentAuthorizationResult.Authorized &&
                authorized.ControlledIdentity?.SubjectDistinguishedName == "CN=AUTHORITATIVE-DEVICE" &&
                authorized.ControlledIdentity.SubjectAlternativeNameUris.Any(uri => uri.AbsoluteUri.EndsWith(":use-case:engineering", StringComparison.Ordinal)),
                "durable approval composes authoritative identity, not CSR subject");
            Check((await new BootstrapEnrollmentAuthorizer(Reopen(), new TestFactsSource(facts), claims, IncomingCsrPolicy.NoClientExtensions)
                .AuthorizeAsync(csr, now, default)).Result == BootstrapEnrollmentAuthorizationResult.AttestationUnavailable, "authorization replay denied after reopen");
            Check(Directory.EnumerateFiles(scratch.FullName).All(p => File.GetUnixFileMode(p) ==
                (UnixFileMode.UserRead | UnixFileMode.UserWrite)), "owner-only files");
        }
        finally { scratch.Delete(recursive: true); } // Unique test-owned directory only.
        Console.WriteLine($"Durable bootstrap record checks passed: {checks}.");
    }

    private static void MarkerIoChecks(Action<bool, string> check)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        // Every fault has an independent directory; retained corrupt markers must
        // not accidentally become the precondition of a later case.
        void WithStore(Action<string, FileBootstrapAttestationStore> action)
        {
            var root = Directory.CreateTempSubdirectory("attestation-marker-io-");
            File.SetUnixFileMode(root.FullName,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                action(root.FullName, new FileBootstrapAttestationStore(root.FullName));
            }
            finally { ReadProbe.DuringRead = null; root.Delete(recursive: true); }
        }

        void Reject(Action action, string label)
        {
            try { action(); }
            catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException)
            { check(true, label); return; }
            check(false, label);
        }

        WithStore((root, store) =>
        {
            var path = Path.Combine(root, "marker.json");
            var value = new WriteProbe { DuringWrite = () =>
            {
                check(!File.Exists(path), "final name is absent throughout serialization");
                check(Directory.EnumerateFiles(root).All(IsOwnerOnly), "staging is owner-only");
            } };
            check(InvokeCreate(store, "marker.json", value), "complete marker published");
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            check(document.RootElement.GetProperty("Value").GetString() == "complete",
                "final marker contains complete JSON");
            check(Directory.EnumerateFiles(root).Count() == 1, "successful publication removes staging");
        });
        WithStore((root, store) =>
        {
            Reject(() => InvokeCreate(store, "marker.json", new WriteProbe
                { DuringWrite = () => throw new IOException("synthetic write failure") }),
                "serialization failure propagates");
            check(!Directory.EnumerateFiles(root).Any(), "serialization failure leaves no partial final or staging file");
        });
        WithStore((root, store) =>
        {
            var contenders = Enumerable.Range(0, 12).Select(i => Task.Run(() =>
                InvokeCreate(store, "marker.json", new IoRecord(i.ToString())))).ToArray();
            Task.WaitAll(contenders);
            check(contenders.Count(task => task.Result) == 1, "atomic publication has exactly one winner");
            var winner = InvokeRead<IoRecord>(store, "marker.json");
            check(!InvokeCreate(store, "marker.json", new IoRecord("replacement")) &&
                InvokeRead<IoRecord>(store, "marker.json") == winner, "EEXIST preserves and reads the winner");
            check(Directory.EnumerateFiles(root).Count() == 1 && Directory.EnumerateFiles(root).All(IsOwnerOnly),
                "concurrent publication retains one owner-only final file");
        });

        foreach (var json in new[] { "", new string(' ', 4097), "[]", "null", "{", "{\"Value\":\"a\",\"Value\":\"b\"}",
                     "{\"Value\":\"a\",\"Extra\":true}", "{}" })
        {
            WithStore((root, store) =>
            {
                WritePrivate(Path.Combine(root, "marker.json"), json);
                Reject(() => InvokeRead<IoRecord>(store, "marker.json"), "strict generic reader rejects malformed or unbounded JSON");
                Reject(() => InvokeCreate(store, "marker.json", new IoRecord("safe")), "collision cannot hide corrupt winner");
            });
        }
        WithStore((root, store) =>
        {
            var path = Path.Combine(root, "marker.json");
            WritePrivate(path, "{\"Value\":\"a\"}");
            foreach (var mode in new[] { UnixFileMode.UserRead, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead,
                         UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute })
            {
                File.SetUnixFileMode(path, mode);
                Reject(() => InvokeRead<IoRecord>(store, "marker.json"), "reader requires exact mode 0600");
            }
        });
        foreach (var dangling in new[] { false, true })
        {
            WithStore((root, store) =>
            {
                var target = Path.Combine(root, "target.json");
                if (!dangling) WritePrivate(target, "{\"Value\":\"a\"}");
                var path = Path.Combine(root, "marker.json");
                File.CreateSymbolicLink(path, target);
                check(File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint), "Linux symlink exposes reparse attribute");
                Reject(() => InvokeRead<IoRecord>(store, "marker.json"), "reader rejects symlink including dangling target");
                Reject(() => InvokeCreate(store, "marker.json", new IoRecord("safe")), "publication loser rejects symlink");
            });
        }
        WithStore((root, store) =>
        {
            Directory.CreateDirectory(Path.Combine(root, "marker.json"));
            Reject(() => InvokeRead<IoRecord>(store, "marker.json"), "directory cannot be a regular marker");
        });
        foreach (var replacement in new[] { "{\"Value\":\"b\"}", "{\"Value\":\"longer\"}" })
        foreach (var replacePath in new[] { false, true })
        {
            WithStore((root, store) =>
            {
                var path = Path.Combine(root, "marker.json");
                WritePrivate(path, "{\"Value\":\"a\"}");
                var timestamp = File.GetLastWriteTimeUtc(path);
                var changed = false;
                ReadProbe.DuringRead = () =>
                {
                    if (!replacePath)
                    {
                        WritePrivate(path, replacement);
                        File.SetLastWriteTimeUtc(path, timestamp);
                    }
                    else
                    {
                        var swap = Path.Combine(root, "swap.json");
                        WritePrivate(swap, replacement);
                        File.SetLastWriteTimeUtc(swap, timestamp);
                        File.Move(swap, path, overwrite: true);
                    }
                    changed = true;
                };
                Reject(() => InvokeRead<ReadProbe>(store, "marker.json"),
                    "reader rejects changed/swapped marker even with preserved write time");
                check(changed, "fault injection changed the file during deserialization");
            });
        }

        foreach (var mode in new[] { UnixFileMode.UserRead | UnixFileMode.UserWrite,
                     UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead })
        {
            WithStore((root, store) =>
            {
                File.SetUnixFileMode(root, mode);
                try
                {
                    Reject(() => _ = new FileBootstrapAttestationStore(root), "constructor requires exact directory mode 0700");
                    Reject(() => InvokeCreate(store, "marker.json", new IoRecord("a")), "writer rechecks directory mode");
                    Reject(() => InvokeRead<IoRecord>(store, "marker.json"), "reader rechecks directory mode");
                }
                finally { File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
            });
        }
        WithStore((root, store) =>
        {
            var alias = Path.Combine(root, "alias");
            Directory.CreateSymbolicLink(alias, root);
            try { Reject(() => _ = new FileBootstrapAttestationStore(alias), "symlink store directory rejected"); }
            finally { Directory.Delete(alias); }
            Reject(() => _ = new FileBootstrapAttestationStore(Path.Combine(root, "absent")), "directory must be pre-provisioned");
        });

        // Exercise every actual constructor field, including nullable fields:
        // omitted authority/state must not silently deserialize to defaults.
        foreach (var missing in new[] { "Version", "CsrSha256", "SpkiSha256", "CreatedAt", "ExpiresAt", "AssetId", "TransitionAt" })
        {
            WithStore((root, store) =>
            {
                var now = DateTimeOffset.UtcNow;
                var binding = new CsrBinding(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
                store.Record(binding, now, TimeSpan.FromMinutes(10));
                var path = Path.Combine(root, Convert.ToHexString(binding.CsrSha256) + ".pending.json");
                var fields = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(File.ReadAllText(path))!;
                fields.Remove(missing);
                WritePrivate(path, JsonSerializer.Serialize(fields));
                Reject(() => store.Attest(binding, "asset-test", now), "missing Entry field rejected by same store: " + missing);
                Reject(() => new FileBootstrapAttestationStore(root).Record(binding, now, TimeSpan.FromMinutes(10)),
                    "missing Entry field rejected in reopened publication winner: " + missing);
            });
        }
        foreach (var stage in new[] { "pending", "attested", "consumed" })
        {
            WithStore((root, store) =>
            {
                var now = DateTimeOffset.UtcNow;
                var binding = new CsrBinding(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
                store.Record(binding, now, TimeSpan.FromMinutes(10));
                store.Attest(binding, "asset-test", now);
                var path = Path.Combine(root, Convert.ToHexString(binding.CsrSha256) + "." + stage + ".json");
                WritePrivate(path, "{}");
                Reject(() => store.GetAttestedAsset(binding, now), "same store rechecks " + stage);
                Reject(() => new FileBootstrapAttestationStore(root).GetAttestedAsset(binding, now), "reopened store rechecks " + stage);
                Reject(() => store.Attest(binding, "asset-test", now), "attestation rejects corrupt " + stage);
                check(!Directory.EnumerateFiles(root, "*.tmp").Any(), "corrupt winner leaves no staging files");
            });
        }
        foreach (var dangling in new[] { false, true })
        {
            WithStore((root, store) =>
            {
                var now = DateTimeOffset.UtcNow;
                var binding = new CsrBinding(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
                store.Record(binding, now, TimeSpan.FromMinutes(10));
                var target = Path.Combine(root, "target.json");
                if (!dangling) WritePrivate(target, "{}");
                File.CreateSymbolicLink(Path.Combine(root, Convert.ToHexString(binding.CsrSha256) + ".consumed.json"), target);
                Reject(() => store.Attest(binding, "asset-test", now), "consumed existence inspection rejects symlink");
                Reject(() => new FileBootstrapAttestationStore(root).GetAttestedAsset(binding, now),
                    "reopened consumed existence inspection rejects symlink");
            });
        }
    }

    private static void WritePrivate(string path, string value)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.ReadWrite | FileShare.Delete,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
        });
        using var writer = new StreamWriter(stream);
        writer.Write(value);
    }

    private static bool InvokeCreate<T>(FileBootstrapAttestationStore store, string name, T value) =>
        (bool)InvokeGeneric(store, "Create", typeof(T), [name, value!])!;

    private static T InvokeRead<T>(FileBootstrapAttestationStore store, string name) =>
        (T)InvokeGeneric(store, "ReadJson", typeof(T), [name])!;

    private static object? InvokeGeneric(FileBootstrapAttestationStore store, string method, Type type, object[] args)
    {
        try
        {
            return typeof(FileBootstrapAttestationStore).GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!
                .MakeGenericMethod(type).Invoke(store, args);
        }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
            throw;
        }
    }

    private sealed record IoRecord(string Value);
    private sealed class WriteProbe
    {
        internal Action DuringWrite { get; init; } = () => { };
        public string Value { get { DuringWrite(); return "complete"; } }
    }
    private sealed class ReadProbe
    {
        internal static Action? DuringRead { get; set; }
        public string Value { get; }
        public ReadProbe(string value) { Value = value; DuringRead?.Invoke(); }
    }

    private static bool IsOwnerOnly(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        return File.GetUnixFileMode(path) == (UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
