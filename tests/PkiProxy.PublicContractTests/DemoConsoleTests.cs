using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using PkiProxy.DemoConsole;

internal static class DemoConsoleTests
{
    internal static void Run()
    {
        var directory = Path.Combine(Path.GetTempPath(), "demo-console-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "session.json");
        try
        {
            var checks = 0;
            void Accept(string json, string label)
            {
                File.WriteAllText(path, json);
                using var snapshot = DemoConsoleHost.LoadSession(path);
                if (snapshot.RootElement.GetProperty("version").GetInt32() != 1)
                    throw new InvalidOperationException("Demo console: " + label);
                checks++;
            }
            void Reject(string json, string label)
            {
                File.WriteAllText(path, json);
                try { using var _ = DemoConsoleHost.LoadSession(path); }
                catch (InvalidDataException) { checks++; return; }
                throw new InvalidOperationException("Demo console accepted " + label);
            }

            const string valid = """
            {"version":1,"sessionId":"demo-1","title":"Example","updatedUtc":"1970-01-01T00:00:00Z",
             "device":{"hostname":"client.example.test","assetId":"asset-1","macAddress":"02:00:00:00:00:01"},
             "scenarios":[
              {"id":"native","label":"Native","summary":"Direct enrollment.","stages":[{"id":"ca","label":"CA","status":"pending"}],
               "events":[{"id":"n1","atUtc":"1970-01-01T00:00:01Z","source":"AD CS","stage":"ca","status":"success","title":"Issued","detail":"One certificate issued.","fields":{"request ID":"1"}}]},
              {"id":"broker","label":"Broker","summary":"Broker enrollment.","stages":[{"id":"facts","label":"Facts","status":"pending"}],
               "events":[{"id":"b1","atUtc":"1970-01-01T00:00:02Z","source":"Broker","stage":"facts","status":"active","title":"Resolved","detail":"Facts resolved."}]}
             ]}
            """;
            Accept(valid, "valid fixture did not load");
            var webRoot = Path.Combine(Environment.CurrentDirectory, "src", "PkiProxy.Api", "DemoConsole", "Web");
            var index = File.ReadAllText(Path.Combine(webRoot, "index.html"));
            var script = File.ReadAllText(Path.Combine(webRoot, "console.js"));
            if (!index.Contains("Connecting to collector feed", StringComparison.Ordinal) ||
                !index.Contains("LIVE SOURCE HEALTH", StringComparison.Ordinal) ||
                !index.Contains("Live component feed", StringComparison.Ordinal) ||
                !index.Contains("LATEST NETWORK AUTHORIZATION", StringComparison.Ordinal) ||
                !index.Contains("CORRELATED LIVE LOG", StringComparison.Ordinal) ||
                !index.Contains("Evidence timeline", StringComparison.Ordinal) ||
                !script.Contains("Live feed connected", StringComparison.Ordinal) ||
                !script.Contains("renderLiveBoard", StringComparison.Ordinal) ||
                !script.Contains("$('story-view').hidden = live", StringComparison.Ordinal) ||
                !script.Contains("$('controls').hidden = live", StringComparison.Ordinal) ||
                !script.Contains("new EventSource('/api/events')", StringComparison.Ordinal))
                throw new InvalidOperationException("Demo console evidence provenance is ambiguous.");
            checks++;
            const string live = """
            {"version":1,"mode":"live","sessionId":"live-1","title":"Live","updatedUtc":"1970-01-01T00:00:00Z",
             "sources":[{"id":"ad","label":"Active Directory","status":"waiting","observedUtc":"1970-01-01T00:00:00Z","detail":"Waiting."}],
             "device":{"hostname":"client.example.test","assetId":"asset-1","macAddress":"02:00:00:00:00:01"},
             "scenarios":[
              {"id":"native","label":"Native","summary":"Direct enrollment.","stages":[{"id":"ca","label":"CA","status":"pending"}],"events":[]},
              {"id":"broker","label":"Broker","summary":"Broker enrollment.","stages":[{"id":"facts","label":"Facts","status":"pending"}],"events":[]}
             ]}
            """;
            Accept(live, "live session with waiting sources did not load");
            Reject(live.Replace("\"status\":\"waiting\"", "\"status\":\"imaginary\"", StringComparison.Ordinal), "unknown source status");
            Reject(valid.Replace("\"status\":\"success\"", "\"status\":\"unknown\"", StringComparison.Ordinal), "unknown status");
            Reject(valid.Replace("\"stage\":\"ca\"", "\"stage\":\"missing\"", StringComparison.Ordinal), "undeclared stage");
            Reject(valid.Replace("\"id\":\"broker\"", "\"id\":\"native\"", StringComparison.Ordinal), "duplicate scenario ID");
            Reject(valid.Replace("1970-01-01T00:00:00Z", "1970-01-01T01:00:00+01:00", StringComparison.Ordinal), "non-UTC timestamp");
            Reject(valid.Replace("\"request ID\":\"1\"", "\"request ID\":{}", StringComparison.Ordinal), "non-string approved event field");
            var oversizedFields = string.Join(',', Enumerable.Range(1, 33).Select(i => $"\"extension{i}\":{{}}"));
            Reject(valid.Replace("\"request ID\":\"1\"", oversizedFields, StringComparison.Ordinal), "oversized event fields with extensions");
            if (!DemoConsoleHost.TryParseOptions(["--demo-console", Path.GetFullPath(path)], out var local) ||
                !System.Net.IPAddress.IsLoopback(local.ListenAddress) || local.Port != 0 ||
                !System.Net.IPAddress.IsLoopback(local.TrustedPeer) || local.CertificatePath is not null)
                throw new InvalidOperationException("Demo console loopback options were not preserved.");
            checks++;
            var deployedArgs = new[] { "--demo-console", Path.GetFullPath(path),
                "--listen-address", "0.0.0.0", "--listen-port", "8444",
                "--trusted-proxy-address", "198.51.100.10",
                "--https-certificate", Path.GetFullPath(Path.Combine(directory, "tls.crt")),
                "--https-key", Path.GetFullPath(Path.Combine(directory, "tls.key")) };
            if (!DemoConsoleHost.TryParseOptions(deployedArgs, out var deployed) || deployed.Port != 8444 ||
                deployed.TrustedPeer.ToString() != "198.51.100.10" || deployed.CertificatePath is null || deployed.KeyPath is null)
                throw new InvalidOperationException("Demo console reverse-proxy options did not load.");
            checks++;
            using (var key = RSA.Create(2048))
            {
                var request = new CertificateRequest("CN=demo.example.test", key,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),
                    DateTimeOffset.UtcNow.AddDays(1));
                File.WriteAllText(deployed.CertificatePath, created.ExportCertificatePem());
                File.WriteAllText(deployed.KeyPath, key.ExportPkcs8PrivateKeyPem());
                using var loaded = DemoConsoleHost.LoadServerCertificate(deployed);
                if (loaded is null || !loaded.HasPrivateKey)
                    throw new InvalidOperationException("Demo console did not bind the PEM certificate and key.");
                checks++;
            }
            foreach (var rejected in new[] {
                deployedArgs.Select(value => value == "198.51.100.10" ? "0.0.0.0" : value).ToArray(),
                deployedArgs.Select(value => value == "8444" ? "0" : value).ToArray(),
                deployedArgs[..^2],
                deployedArgs.Concat(["--listen-port", "9444"]).ToArray()
            })
            {
                if (DemoConsoleHost.TryParseOptions(rejected, out _))
                    throw new InvalidOperationException("Demo console accepted unsafe reverse-proxy options.");
                checks++;
            }
            Console.WriteLine($"Demo console checks passed: {checks}.");
            var streaming = live.Replace("\"events\":[]},", """
                "events":[{"id":"n1","atUtc":"1970-01-01T00:00:01Z","source":"AD CS","stage":"ca","status":"success","title":"Issued","detail":"One certificate issued.","fields":{"request ID":"1"}}]},
                """, StringComparison.Ordinal);
            RunLiveStreamContractsAsync(local, streaming).GetAwaiter().GetResult();
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static async Task RunLiveStreamContractsAsync(DemoConsoleHost.DemoConsoleOptions options, string live)
    {
        var path = options.SessionPath;
        var extended = live.Replace("\"version\":1", "\"rawRoot\":\"root-sentinel\",\"version\":1", StringComparison.Ordinal)
            .Replace("\"hostname\":", "\"rawDevice\":{\"trace\":\"device-sentinel\"},\"hostname\":", StringComparison.Ordinal)
            .Replace("\"request ID\":\"1\"", "\"request ID\":\"1\",\"rawScalar\":\"scalar-sentinel\",\"rawField\":{\"trace\":\"field-sentinel\"}", StringComparison.Ordinal);
        File.WriteAllText(path, extended);
        var clock = new RefreshClock();
        await using var app = DemoConsoleHost.BuildApplication(options, serverCertificate: null, clock);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var cancellation = deadline.Token;
        await app.StartAsync(cancellation);
        var listener = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false, MaxResponseDrainSize = 0 })
        {
            BaseAddress = new Uri(listener)
        };
        var active = new List<HttpResponseMessage>();
        try
        {
            for (var index = 0; index < 8; index++)
            {
                var stream = await OpenEventsAsync(client, cancellation);
                active.Add(stream);
                if (stream.StatusCode != HttpStatusCode.OK || !HasNoStore(stream) ||
                    stream.Content.Headers.ContentType?.MediaType != "text/event-stream")
                    throw new InvalidOperationException("Demo console did not admit all eight streams.");
            }
            using var reader = new StreamReader(await active[0].Content.ReadAsStreamAsync(cancellation));
            var initialEnvelope = await ReadEventEnvelopeAsync(reader, cancellation);
            AssertRevision(initialEnvelope, live);
            await AssertSessionRevisionAsync(client, initialEnvelope, cancellation);
            using (var excess = await OpenEventsAsync(client, cancellation))
            {
                if (excess.StatusCode != HttpStatusCode.ServiceUnavailable || !HasNoStore(excess) ||
                    excess.Headers.RetryAfter?.Delta != TimeSpan.FromSeconds(1))
                    throw new InvalidOperationException("Demo console did not promptly reject an excess stream.");
            }

            // Removing only ignored values must preserve both the content hash and the stream revision.
            ReplaceSession(path, live);
            clock.AdvanceRefresh();
            await AssertSessionRevisionAsync(client, initialEnvelope, cancellation);
            if (await reader.ReadLineAsync(cancellation) != ": keepalive")
                throw new InvalidOperationException("Demo console changed its revision when only extensions changed.");

            var replacement = live.Replace("\"title\":\"Live\"", "\"title\":\"Updated\"", StringComparison.Ordinal);
            ReplaceSession(path, replacement);
            await AssertSessionRevisionAsync(client, initialEnvelope, cancellation);

            active[^1].Dispose();
            active.RemoveAt(active.Count - 1);
            var reused = await WaitForStreamSlotAsync(client, cancellation);
            active.Add(reused);
            using (var reusedReader = new StreamReader(await reused.Content.ReadAsStreamAsync(cancellation), leaveOpen: true))
            {
                if (await ReadEventEnvelopeAsync(reusedReader, cancellation) != initialEnvelope)
                    throw new InvalidOperationException("Demo console did not share the cached revision with a new stream.");
            }

            clock.AdvanceRefresh();
            var updatedEnvelope = await ReadEventEnvelopeAsync(reader, cancellation);
            AssertRevision(updatedEnvelope, replacement);
            var duplicateKnown = replacement.Replace("\"version\":1", "\"version\":1,\"\\u0076ersion\":1", StringComparison.Ordinal);
            ReplaceSession(path, duplicateKnown);
            await AssertSessionRevisionAsync(client, updatedEnvelope, cancellation);
            await AssertRejectedRefreshAsync(client, reader, clock, cancellation);

            ReplaceSession(path, live);
            // The failed refresh is also shared for the rest of the interval.
            for (var index = 0; index <= 8; index++)
            {
                using var invalid = await OpenEventsAsync(client, cancellation);
                AssertUnavailable(invalid);
            }
            clock.AdvanceRefresh();
            await AssertSessionRevisionAsync(client, initialEnvelope, cancellation);

            using var recovered = await WaitForStreamSlotAsync(client, cancellation);
            using var recoveredReader = new StreamReader(await recovered.Content.ReadAsStreamAsync(cancellation));
            if (await ReadEventEnvelopeAsync(recoveredReader, cancellation) != initialEnvelope)
                throw new InvalidOperationException("Demo console did not publish the recovered revision.");
            var duplicateIgnored = extended.Replace("\"trace\":\"field-sentinel\"", "\"trace\":\"field-sentinel\",\"trace\":\"second-sentinel\"", StringComparison.Ordinal);
            ReplaceSession(path, duplicateIgnored);
            await AssertRejectedRefreshAsync(client, recoveredReader, clock, cancellation);
            await AssertPublishedFixturesAsync(client, path, clock, cancellation);
            Console.WriteLine("Demo console loopback stream checks passed (projection, capacity, reuse, shared revisions, duplicate refusal and recovery).");
        }
        finally
        {
            foreach (var stream in active) stream.Dispose();
            await app.StopAsync();
        }
    }

    private static async Task AssertPublishedFixturesAsync(HttpClient client, string path,
        RefreshClock clock, CancellationToken cancellation)
    {
        foreach (var name in new[] { "session.live-template.json", "session.physical-template.json", "session.example.json", "session.physical-replay.json" })
        {
            var fixture = Path.Combine(Environment.CurrentDirectory, "lab", "demo-console", name);
            if (!File.Exists(fixture)) continue;
            var expected = await File.ReadAllTextAsync(fixture, cancellation);
            ReplaceSession(path, expected);
            clock.AdvanceRefresh();
            AssertRevision(await ReadSessionEnvelopeAsync(client, cancellation), expected);
        }
    }

    private static async Task AssertRejectedRefreshAsync(HttpClient client, StreamReader reader,
        RefreshClock clock, CancellationToken cancellation)
    {
        clock.AdvanceRefresh();
        using (var invalid = await client.GetAsync("/api/session", cancellation))
            AssertUnavailable(invalid);
        string? line;
        while ((line = await reader.ReadLineAsync(cancellation)) is not null)
        {
            if (line.Length > 0 && line != ": keepalive")
                throw new InvalidOperationException("Demo console streamed session data after an invalid replacement.");
        }
        using var invalidStream = await OpenEventsAsync(client, cancellation);
        AssertUnavailable(invalidStream);
    }

    private static Task<HttpResponseMessage> OpenEventsAsync(HttpClient client, CancellationToken cancellation) =>
        client.GetAsync("/api/events", HttpCompletionOption.ResponseHeadersRead, cancellation);

    private static async Task<HttpResponseMessage> WaitForStreamSlotAsync(HttpClient client, CancellationToken cancellation)
    {
        while (true)
        {
            var stream = await OpenEventsAsync(client, cancellation);
            if (stream.StatusCode == HttpStatusCode.OK) return stream;
            using (stream)
            {
                if (stream.StatusCode != HttpStatusCode.ServiceUnavailable)
                    throw new InvalidOperationException("Demo console returned an unexpected response during stream slot reuse.");
            }
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellation);
        }
    }

    private static async Task<string> ReadSessionEnvelopeAsync(HttpClient client, CancellationToken cancellation)
    {
        using var response = await client.GetAsync("/api/session", cancellation);
        if (response.StatusCode != HttpStatusCode.OK || !HasNoStore(response) ||
            response.Content.Headers.ContentType?.MediaType != "application/json")
            throw new InvalidOperationException("Demo console session endpoint returned an unexpected response.");
        return await response.Content.ReadAsStringAsync(cancellation);
    }

    private static async Task AssertSessionRevisionAsync(HttpClient client, string expected,
        CancellationToken cancellation)
    {
        if (await ReadSessionEnvelopeAsync(client, cancellation) != expected)
            throw new InvalidOperationException("Demo console HTTP and SSE revisions differed.");
    }

    private static async Task<string> ReadEventEnvelopeAsync(StreamReader reader, CancellationToken cancellation)
    {
        string? line;
        do { line = await reader.ReadLineAsync(cancellation); }
        while (line is ": keepalive" or "");
        if (line != "event: session" ||
            await reader.ReadLineAsync(cancellation) is not { } data || !data.StartsWith("data: ", StringComparison.Ordinal) ||
            await reader.ReadLineAsync(cancellation) != "")
            throw new InvalidOperationException("Demo console returned an unexpected event frame.");
        return data[6..];
    }

    private static void AssertRevision(string envelope, string expected)
    {
        using var document = JsonDocument.Parse(envelope);
        using var expectedSession = JsonDocument.Parse(expected);
        var root = document.RootElement;
        var session = root.GetProperty("session");
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(session.GetRawText())));
        if (root.GetProperty("sha256").GetString() != hash || !JsonElement.DeepEquals(session, expectedSession.RootElement))
            throw new InvalidOperationException("Demo console returned an unexpected session revision.");
    }

    private static void AssertUnavailable(HttpResponseMessage response)
    {
        if (response.StatusCode != HttpStatusCode.Conflict || !HasNoStore(response) ||
            response.Content.Headers.ContentType?.MediaType != "application/json")
            throw new InvalidOperationException("Demo console did not reject the invalid cached session.");
    }

    private static bool HasNoStore(HttpResponseMessage response) => response.Headers.CacheControl?.NoStore == true;

    private static void ReplaceSession(string path, string session)
    {
        var temporaryPath = path + ".next";
        File.WriteAllText(temporaryPath, session);
        File.Move(temporaryPath, path, overwrite: true);
    }

    private sealed class RefreshClock : TimeProvider
    {
        private long timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref timestamp);
        internal void AdvanceRefresh() => Interlocked.Add(ref timestamp, TimeSpan.TicksPerSecond);
    }
}
