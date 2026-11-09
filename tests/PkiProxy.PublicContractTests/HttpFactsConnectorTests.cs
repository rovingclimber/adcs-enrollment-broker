using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PkiProxy.Domain;

internal static class HttpFactsConnectorTests
{
    internal static async Task RunAsync()
    {
        var checks = 0;
        void Check(bool condition, string label)
        { if (!condition) throw new InvalidOperationException("HTTP facts connector: " + label); checks++; }

        var exampleRoot = Directory.Exists("public/examples") ? "public/examples" : "examples";
        var entra = HttpFactsConnector.ParseProfile(await File.ReadAllBytesAsync(
            Path.Combine(exampleRoot, "facts-connector.entra-device.json")), validateFiles: false);
        var serviceNow = HttpFactsConnector.ParseProfile(await File.ReadAllBytesAsync(
            Path.Combine(exampleRoot, "facts-connector.servicenow-cmdb.json")), validateFiles: false);
        Check(entra.Mode == FactsConnectorMode.Live && entra.Authentication.Type == "bearer" &&
            serviceNow.Mode == FactsConnectorMode.Snapshot && serviceNow.Authentication.Type == "bearer-mtls" &&
            serviceNow.IdentityPrefix == "asset_tag=", "committed provider profiles satisfy the strict schema");
        Reject(() => HttpFactsConnector.ParseProfile(Encoding.UTF8.GetBytes("""
            {"Version":1,"Version":1}
            """), validateFiles: false), "duplicate profile properties rejected"); checks++;

        var handler = new DelegateHandler(request =>
        {
            Check(request.Method == HttpMethod.Get, "configured method used");
            Check(request.RequestUri!.Scheme == "https" && request.RequestUri.Host == "inventory.example.net" &&
                request.RequestUri.AbsolutePath == "/v1/devices/client%2F001" &&
                request.RequestUri.Query.Contains("%24select=", StringComparison.Ordinal),
                "path identity and fixed query are context encoded");
            return Json("""
                {"record":{"host":"client-001.example.test","asset":"client/001","class":"workstation","purpose":"engineering","site":"office","realm":"example.test"}}
                """);
        });
        using (var connector = HttpFactsConnector.CreateForTests(Profile(FactsConnectorMode.Live,
                   FactsIdentityField.AssetId, FactsIdentityPlacement.PathSegment), handler))
        {
            var facts = await connector.FetchAsync("client/001", 7, default);
            Check(facts is { AssetId: "client/001", DeviceClass: "workstation", UseCase: "engineering",
                Location: "office", ManagementDomain: "example.test", SourceVersion: 7 },
                "bounded JSON Pointer mapping returns typed facts");
        }

        var queryHandler = new DelegateHandler(request =>
        {
            Check(request.RequestUri!.Query == "?device=CLIENT-001.example.test", "query identity is escaped separately");
            return Json("""
                {"record":{"host":"CLIENT-001.example.test","asset":"asset-1","class":"workstation","purpose":"engineering","site":"office","realm":"example.test"}}
                """);
        });
        using (var connector = HttpFactsConnector.CreateForTests(Profile(FactsConnectorMode.Live,
                   FactsIdentityField.Hostname, FactsIdentityPlacement.Query, "/lookup", "device", null), queryHandler))
            Check((await connector.FetchAsync("CLIENT-001.example.test", 1, default))?.AssetId == "asset-1",
                "query placement resolves an exact record");

        await RejectAsync(async () =>
        {
            using var connector = HttpFactsConnector.CreateForTests(Profile(FactsConnectorMode.Live,
                FactsIdentityField.AssetId, FactsIdentityPlacement.PathSegment), new DelegateHandler(_ => Json("""
                    {"record":{"host":"client-001.example.test","asset":"wrong","class":"workstation","purpose":"engineering","site":"office","realm":"example.test"}}
                    """)));
            _ = await connector.FetchAsync("asset-1", 1, default);
        }, "identity disagreement rejected"); checks++;

        await RejectAsync(async () =>
        {
            var p = Profile(FactsConnectorMode.Live, FactsIdentityField.AssetId, FactsIdentityPlacement.PathSegment) with
            { Response = new("/record", "exactly-one", Mappings()) };
            using var connector = HttpFactsConnector.CreateForTests(p, new DelegateHandler(_ => Json("""
                {"record":[{"host":"a.example.test"},{"host":"b.example.test"}]}
                """)));
            _ = await connector.FetchAsync("asset-1", 1, default);
        }, "ambiguous response rejected"); checks++;

        var directoryId = Guid.NewGuid();
        var catalogue = JsonNode.Parse(await File.ReadAllBytesAsync("lab/device-facts/devices.example.json"))!;
        catalogue["devices"]![0]!["directoryObjectId"] = directoryId.ToString("D");
        var current = Encoding.UTF8.GetBytes(catalogue.ToJsonString());
        var hash = Convert.ToHexString(SHA256.HashData(current));
        var snapshotHandler = new DelegateHandler(request =>
        {
            var asset = Uri.UnescapeDataString(request.RequestUri!.Segments[^1]);
            var host = asset == "asset-physical-001" ? "CLIENT-PHYSICAL-001.example.test" : "CLIENT-001.example.test";
            var body = $$$"""
                {"record":{"host":"{{{host}}}","asset":"{{{asset}}}","class":"managed-workstation","purpose":"engineering","site":"connector-site","realm":"example.test"}}
                """;
            return Json(body);
        });
        using (var connector = HttpFactsConnector.CreateForTests(Profile(FactsConnectorMode.Snapshot,
                   FactsIdentityField.AssetId, FactsIdentityPlacement.PathSegment), snapshotHandler))
        {
            var draft = await connector.PrepareSnapshotAsync(current, hash, default);
            var one = JsonFileDeviceFactsSource.Parse(draft, "CLIENT-PHYSICAL-001.example.test");
            var two = JsonFileDeviceFactsSource.Parse(draft, "CLIENT-001.example.test");
            Check(one is { SourceVersion: 2, Location: "connector-site", UseCase: "engineering" } &&
                one.DirectoryObjectId == directoryId &&
                two is { SourceVersion: 2, Location: "connector-site", DirectoryObjectId: null },
                "full refresh preserves local directory bindings and updates mutable facts");
        }

        var calls = 0;
        using (var connector = HttpFactsConnector.CreateForTests(Profile(FactsConnectorMode.Snapshot,
                   FactsIdentityField.AssetId, FactsIdentityPlacement.PathSegment), new DelegateHandler(request =>
                   {
                       calls++;
                       return calls == 1 ? snapshotHandler.Send(request) : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
                   })))
        {
            await RejectAsync(async () => _ = await connector.PrepareSnapshotAsync(current, hash, default),
                "one upstream failure rejects the complete snapshot"); checks++;
            Check(JsonFileDeviceFactsSource.Parse(current, "CLIENT-PHYSICAL-001.example.test")!.SourceVersion == 1,
                "failed refresh leaves source bytes untouched");
        }

        var cacheDirectory = Directory.CreateTempSubdirectory("http-facts-cache-");
        try
        {
            var cachePath = Path.Combine(cacheDirectory.FullName, "devices.json");
            const string hostname = "CLIENT-PHYSICAL-001.example.test";
            const string assetId = "asset-physical-001";
            await File.WriteAllBytesAsync(cachePath, current);
            var byAsset = Profile(FactsConnectorMode.Live, FactsIdentityField.AssetId,
                FactsIdentityPlacement.PathSegment) with { MaximumCacheAgeSeconds = 60 };
            var byHost = byAsset with { IdentityField = FactsIdentityField.Hostname };
            using (var source = new LiveHttpDeviceFactsSource(HttpFactsConnector.CreateForTests(byHost,
                       new DelegateHandler(_ => Record(hostname, "wrong-asset"))), new(cachePath), cachePath, true))
            {
                await RejectAsync(async () => _ = await source.FindByDnsHostNameAsync(hostname, default),
                    "correct live hostname with changed immutable asset is rejected without cache fallback"); checks++;
            }
            using (var source = new LiveHttpDeviceFactsSource(HttpFactsConnector.CreateForTests(byAsset,
                       new DelegateHandler(_ => Record("wrong.example.test", assetId))), new(cachePath), cachePath, true))
            {
                await RejectAsync(async () => _ = await source.FindByAssetIdAsync(assetId, default),
                    "correct live asset with changed immutable hostname is rejected without cache fallback"); checks++;
            }
            using (var source = new LiveHttpDeviceFactsSource(HttpFactsConnector.CreateForTests(byHost,
                       new DelegateHandler(_ => Record(hostname.ToLowerInvariant(), assetId))), new(cachePath), cachePath, false))
                Check(await source.FindByDnsHostNameAsync(hostname, default) is { AssetId: assetId } liveFacts &&
                    liveFacts.DirectoryObjectId == directoryId,
                    "live facts retain the local object binding with DNS case differences");

            var unavailable = new DelegateHandler(_ =>
                throw new HttpRequestException(HttpRequestError.ConnectionError, "upstream unavailable"));
            using var liveConnector = HttpFactsConnector.CreateForTests(byAsset, unavailable);
            using var initial = new LiveHttpDeviceFactsSource(liveConnector, new(cachePath), cachePath,
                allowCacheFallback: false, ownsConnector: false);
            await RejectAsync(async () => _ = await initial.FindByDnsHostNameAsync(hostname, default),
                "initial enrollment does not hide an upstream outage"); checks++;
            using var renewal = new LiveHttpDeviceFactsSource(liveConnector, new(cachePath), cachePath,
                allowCacheFallback: true, ownsConnector: false);
            Check((await renewal.FindByDnsHostNameAsync(hostname, default))?.AssetId ==
                assetId, "renewal can use a fresh accepted cache after transient connection failure");
            using var unauthorizedConnector = HttpFactsConnector.CreateForTests(byAsset,
                new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized)));
            using var unauthorizedRenewal = new LiveHttpDeviceFactsSource(unauthorizedConnector, new(cachePath), cachePath,
                allowCacheFallback: true, ownsConnector: false);
            await RejectAsync(async () => _ = await unauthorizedRenewal.FindByDnsHostNameAsync(
                hostname, default), "authentication failure cannot use cached facts"); checks++;
            foreach (var failure in new[] { HttpRequestError.SecureConnectionError, HttpRequestError.InvalidResponse })
            {
                using var failed = new LiveHttpDeviceFactsSource(HttpFactsConnector.CreateForTests(byAsset,
                    new DelegateHandler(_ => throw new HttpRequestException(failure, "synthetic transport failure"))),
                    new(cachePath), cachePath, true);
                await RejectAsync(async () => _ = await failed.FindByDnsHostNameAsync(hostname, default),
                    failure + " cannot authorize renewal from cached facts"); checks++;
            }

            using (var stalled = new LiveHttpDeviceFactsSource(HttpFactsConnector.CreateForTests(
                       byAsset with { TimeoutSeconds = 1 }, new DelegateHandler(_ => StalledJson())),
                       new(cachePath), cachePath, true))
            using (var watchdog = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
                Check((await stalled.FindByDnsHostNameAsync(hostname, watchdog.Token))?.AssetId == assetId,
                    "a stalled body hits the connector deadline and renewal uses fresh cached facts");

            File.SetLastWriteTimeUtc(cachePath, DateTime.UtcNow.AddMinutes(-2));
            try
            {
                _ = await renewal.FindByDnsHostNameAsync(hostname, default);
                throw new InvalidOperationException("Expired renewal cache accepted");
            }
            catch (InvalidOperationException error) when (error.InnerException is HttpRequestException) { checks++; }

            var refreshed = JsonNode.Parse(current)!.AsObject();
            refreshed["revision"] = 2;
            var updated = refreshed["devices"]!.AsArray().Single(device => device!["assetId"]!.GetValue<string>() == assetId)!;
            updated["location"] = "new-location";
            using (var replacement = new LiveHttpDeviceFactsSource(HttpFactsConnector.CreateForTests(byAsset,
                       new DelegateHandler(_ => PublishWhileInFlight(refreshed))), new(cachePath), cachePath, true))
                Check(await replacement.FindByDnsHostNameAsync(hostname, default) is
                    { SourceVersion: 2, Location: "new-location" },
                    "a replacement during an outage is read and validated as one fresh revision");

            refreshed["revision"] = 3;
            var replacedBinding = refreshed.DeepClone().AsObject();
            replacedBinding["devices"]![0]!["directoryObjectId"] = Guid.NewGuid().ToString("D");
            using (var replacement = new LiveHttpDeviceFactsSource(HttpFactsConnector.CreateForTests(byAsset,
                       new DelegateHandler(_ => PublishWhileInFlight(replacedBinding))), new(cachePath), cachePath, true))
            {
                try
                {
                    _ = await replacement.FindByDnsHostNameAsync(hostname, default);
                    throw new InvalidOperationException("Replacement directory binding remained eligible for fallback");
                }
                catch (InvalidOperationException error) when (error.InnerException is HttpRequestException) { checks++; }
            }
            refreshed["devices"]!.AsArray().Remove(updated);
            using (var replacement = new LiveHttpDeviceFactsSource(HttpFactsConnector.CreateForTests(byAsset,
                       new DelegateHandler(_ => PublishWhileInFlight(refreshed))), new(cachePath), cachePath, true))
            {
                try
                {
                    _ = await replacement.FindByDnsHostNameAsync(hostname, default);
                    throw new InvalidOperationException("Removed asset remained eligible for renewal");
                }
                catch (InvalidOperationException error) when (error.InnerException is HttpRequestException) { checks++; }
            }

            HttpResponseMessage PublishWhileInFlight(JsonObject snapshot)
            {
                var replacementPath = cachePath + ".new";
                File.WriteAllText(replacementPath, snapshot.ToJsonString());
                File.Move(replacementPath, cachePath, overwrite: true);
                return new(HttpStatusCode.ServiceUnavailable);
            }

            var rootPath = Path.Combine(cacheDirectory.FullName, "connector-trust.pem");
            Check(CustomTrustAcceptsPurpose(byAsset, rootPath, "1.3.6.1.5.5.7.3.1") &&
                !CustomTrustAcceptsPurpose(byAsset, rootPath, "1.3.6.1.5.5.7.3.2"),
                "custom trust accepts serverAuth and refuses a clientAuth-only certificate");
        }
        finally { cacheDirectory.Delete(recursive: true); }

        if (OperatingSystem.IsLinux())
            await CheckSnapshotRevalidationAsync(current, hash, snapshotHandler.Send, Check);
        else
            Console.WriteLine("Snapshot revalidation checks skipped: Linux publication store required.");

        Reject(() => HttpFactsConnector.CreateForTests(Profile(FactsConnectorMode.Live,
            FactsIdentityField.AssetId, FactsIdentityPlacement.PathSegment) with { BaseUri = "http://inventory.example.net/" },
            new DelegateHandler(_ => Json("{}"))), "cleartext origin rejected"); checks++;
        Reject(() => HttpFactsConnector.CreateForTests(Profile(FactsConnectorMode.Live,
            FactsIdentityField.AssetId, FactsIdentityPlacement.PathSegment) with { Path = "/devices/{identity}?next={identity}" },
            new DelegateHandler(_ => Json("{}"))), "raw query interpolation rejected"); checks++;
        Reject(() => HttpFactsConnector.CreateForTests(Profile(FactsConnectorMode.Live,
            FactsIdentityField.AssetId, FactsIdentityPlacement.PathSegment) with
            { Headers = new() { ["Authorization"] = "embedded-secret" } },
            new DelegateHandler(_ => Json("{}"))), "inline authorization header rejected"); checks++;

        Console.WriteLine($"HTTP facts connector checks passed: {checks}.");
    }

    [SupportedOSPlatform("linux")]
    private static async Task CheckSnapshotRevalidationAsync(byte[] current, string sourceHash,
        Func<HttpRequestMessage, HttpResponseMessage> changedRecord,
        Action<bool, string> check)
    {
        var directory = Directory.CreateTempSubdirectory("http-facts-revalidate-");
        try
        {
            const string hostname = "CLIENT-PHYSICAL-001.example.test";
            var path = Path.Combine(directory.FullName, "devices.json");
            await File.WriteAllBytesAsync(path, current);
            var mode = File.GetUnixFileMode(path);
            var oldWriteTime = DateTime.UtcNow.AddMinutes(-10);
            File.SetLastWriteTimeUtc(path, oldWriteTime);
            var originalWriteTime = File.GetLastWriteTimeUtc(path);

            var profile = Profile(FactsConnectorMode.Snapshot, FactsIdentityField.AssetId,
                FactsIdentityPlacement.PathSegment) with { MaximumCacheAgeSeconds = 60 };
            using var renewal = new LiveHttpDeviceFactsSource(HttpFactsConnector.CreateForTests(
                profile with { Mode = FactsConnectorMode.Live },
                new DelegateHandler(_ => new(HttpStatusCode.ServiceUnavailable))), new(path), path, true);
            try
            {
                _ = await renewal.FindByDnsHostNameAsync(hostname, default);
                throw new InvalidOperationException("Expired cache accepted before revalidation.");
            }
            catch (InvalidOperationException error) when (error.InnerException is HttpRequestException) { }

            var catalogue = JsonNode.Parse(current)!.AsObject();
            var devices = catalogue["devices"]!.AsArray();
            HttpResponseMessage UnchangedRecord(HttpRequestMessage request)
            {
                var asset = Uri.UnescapeDataString(request.RequestUri!.Segments[^1]);
                var device = devices.Single(device => device!["assetId"]!.GetValue<string>() == asset)!;
                return Json(JsonSerializer.Serialize(new { record = new
                {
                    host = device["hostname"], asset, @class = device["deviceClass"],
                    purpose = device["useCase"], site = device["location"], realm = device["managementDomain"]
                } }));
            }

            using var connector = HttpFactsConnector.CreateForTests(profile, new DelegateHandler(UnchangedRecord));
            var result = await HttpFactsConnectorCommand.RefreshAsync(path, connector, default);
            var afterRefresh = await File.ReadAllBytesAsync(path);
            check(result.SourceHash == sourceHash && result.Publication is null &&
                current.SequenceEqual(afterRefresh) &&
                File.GetUnixFileMode(path) == mode && File.GetLastWriteTimeUtc(path) > originalWriteTime &&
                !Directory.Exists(Path.Combine(directory.FullName, ".facts-history")),
                "unchanged full refresh updates freshness without rewriting the snapshot or creating history");
            check(await renewal.FindByDnsHostNameAsync(hostname, default) is { SourceVersion: 1, Location: "office" },
                "a transient 503 can use the successfully revalidated revision");

            var replacement = catalogue.DeepClone();
            replacement["revision"] = 2;
            replacement["devices"]![0]!["location"] = "replacement-site";
            var replacementBytes = Encoding.UTF8.GetBytes(replacement.ToJsonString());
            var replacementHash = Convert.ToHexString(SHA256.HashData(replacementBytes));
            FactsPublication? publication = null;
            DateTime replacementWriteTime = default;
            using var racingConnector = HttpFactsConnector.CreateForTests(profile, new DelegateHandler(request =>
            {
                if (publication is null)
                {
                    publication = DeviceFactsPublisher.Publish(path, replacementBytes, sourceHash, replacementHash);
                    File.SetLastWriteTimeUtc(path, oldWriteTime);
                    replacementWriteTime = File.GetLastWriteTimeUtc(path);
                }
                return UnchangedRecord(request);
            }));
            try
            {
                _ = await HttpFactsConnectorCommand.RefreshAsync(path, racingConnector, default);
                throw new InvalidOperationException("Snapshot revalidation accepted a replaced source.");
            }
            catch (InvalidDataException error) when (
                error.Message == "Source changed during connector refresh; revalidation refused.") { }
            var afterRace = await File.ReadAllBytesAsync(path);
            check(publication is { Revision: 2 } &&
                replacementBytes.SequenceEqual(afterRace) &&
                File.GetLastWriteTimeUtc(path) == replacementWriteTime,
                "racing publication keeps its bytes and timestamp when stale revalidation is refused");

            using var changedConnector = HttpFactsConnector.CreateForTests(profile, new DelegateHandler(changedRecord));
            var changed = await HttpFactsConnectorCommand.RefreshAsync(path, changedConnector, default);
            check(changed.SourceHash == replacementHash && changed.Publication is { Revision: 3 } receipt &&
                File.Exists(Path.Combine(receipt.RecoveryDirectory, "committed.json")) &&
                JsonFileDeviceFactsSource.Parse(await File.ReadAllBytesAsync(path), hostname) is
                    { SourceVersion: 3, Location: "connector-site" },
                "changed refresh still publishes a new revision and commits its history");
        }
        finally { directory.Delete(recursive: true); }
    }

    private static HttpFactsConnectorProfile Profile(FactsConnectorMode mode, FactsIdentityField field,
        FactsIdentityPlacement placement, string path = "/v1/devices/{identity}", string? name = null,
        Dictionary<string, string>? query = null) => new(1, mode, "https://inventory.example.net/", "GET", path,
        field, placement, name, null, null, query ?? (placement == FactsIdentityPlacement.PathSegment
            ? new() { ["$select"] = "host,asset,class,purpose,site,realm" } : null), null,
        new("none"), new("/record", "exactly-one", Mappings()));

    private static Dictionary<string, string> Mappings() => new(StringComparer.Ordinal)
    {
        ["hostname"] = "/host", ["assetId"] = "/asset", ["deviceClass"] = "/class",
        ["useCase"] = "/purpose", ["location"] = "/site", ["managementDomain"] = "/realm"
    };

    private static HttpResponseMessage Json(string value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(value, Encoding.UTF8, "application/json")
    };

    private static HttpResponseMessage Record(string host, string asset) => Json(JsonSerializer.Serialize(
        new { record = new { host, asset, @class = "workstation", purpose = "engineering", site = "office", realm = "example.test" } }));

    private static HttpResponseMessage StalledJson()
    {
        var content = new StreamContent(new StalledBody());
        content.Headers.ContentType = new("application/json");
        return new(HttpStatusCode.OK) { Content = content };
    }

    private static bool CustomTrustAcceptsPurpose(HttpFactsConnectorProfile profile, string path, string purpose)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Connector TLS test", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(purpose) }, false));
        var now = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(now.AddMinutes(-1), now.AddMinutes(5));
        File.WriteAllText(path, certificate.ExportCertificatePem());
        using var handler = HttpFactsConnector.BuildHandler(profile with { TrustRootFile = path });
        using var chain = new X509Chain();
        chain.ChainPolicy = handler.SslOptions.CertificateChainPolicy!;
        using var root = chain.ChainPolicy.CustomTrustStore[0];
        return chain.Build(certificate);
    }

    private sealed class StalledBody : MemoryStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }
    }

    private static async Task RejectAsync(Func<Task> action, string label)
    {
        try { await action(); throw new InvalidOperationException("Accepted: " + label); }
        catch (Exception error) when (error is InvalidDataException or HttpRequestException) { }
    }

    private static void Reject(Action action, string label)
    {
        try { action(); throw new InvalidOperationException("Accepted: " + label); }
        catch (InvalidDataException) { }
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> send) : HttpMessageHandler
    {
        internal HttpResponseMessage Send(HttpRequestMessage request) => send(request);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(send(request));
    }
}
