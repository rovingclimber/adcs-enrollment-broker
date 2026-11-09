using System.Buffers;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace PkiProxy.DemoConsole;

// Read-only presentation surface. Collectors write the bounded session file;
// this process has no credentials and performs no infrastructure actions.
internal static class DemoConsoleHost
{
    private const int MaximumSessionBytes = 1048576;
    private const int MaximumEventStreams = 8;
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(1);
    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowDuplicateProperties = false,
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 12
    };
    private static readonly JsonElement PresentationSchema = LoadPresentationSchema();
    private static readonly JsonElement EventFieldsSchema = PresentationSchema.GetProperty("scenarios")[0]
        .GetProperty("events")[0].GetProperty("fields");

    internal static async Task<int> RunAsync(string[] args)
    {
        if (!TryParseOptions(args, out var configuration))
        {
            await Console.Error.WriteLineAsync("Usage: --demo-console ABSOLUTE_SESSION_JSON [--listen-address IP --listen-port PORT --trusted-proxy-address IP --https-certificate ABSOLUTE_PEM --https-key ABSOLUTE_PEM]");
            return 64;
        }

        using var serverCertificate = LoadServerCertificate(configuration);
        await using var app = BuildApplication(configuration, serverCertificate);
        await app.StartAsync();
        var listener = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        Console.WriteLine("Enrollment demo console (read-only): " + listener);
        await app.WaitForShutdownAsync();
        return 0;
    }

    internal static WebApplication BuildApplication(DemoConsoleOptions configuration,
        X509Certificate2? serverCertificate, TimeProvider? clock = null)
    {
        var sessions = new SessionCache(configuration.SessionPath, clock ?? TimeProvider.System);
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
        builder.Services.AddSingleton(_ => new SemaphoreSlim(MaximumEventStreams, MaximumEventStreams));
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(configuration.ListenAddress, configuration.Port, listener =>
            {
                if (configuration.CertificatePath is not null)
                    listener.UseHttps(serverCertificate!);
            });
            kestrel.Limits.MaxRequestBodySize = 0;
            kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
        });
        var app = builder.Build();
        var streamSlots = app.Services.GetRequiredService<SemaphoreSlim>();
        app.Use(async (context, next) =>
        {
            if (context.Connection.RemoteIpAddress is not { } peer ||
                !configuration.TrustedPeer.Equals(peer.MapToIPv4()) ||
                (context.Request.Method != "GET" && context.Request.Method != "HEAD"))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers.ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
            try { await next(context); }
            catch (Exception error) when (error is InvalidDataException or IOException or JsonException)
            {
                if (context.Response.HasStarted) return;
                context.Response.StatusCode = StatusCodes.Status409Conflict;
                await context.Response.WriteAsJsonAsync(new { error = "The demo session is unavailable or invalid." });
            }
        });
        app.MapGet("/", () => Results.Content(Asset("index.html"), "text/html", Encoding.UTF8));
        app.MapGet("/console.css", () => Results.Content(Asset("console.css"), "text/css", Encoding.UTF8));
        app.MapGet("/console.js", () => Results.Content(Asset("console.js"), "text/javascript", Encoding.UTF8));
        app.MapGet("/api/session", () => Results.Bytes(sessions.Get().Envelope, "application/json; charset=utf-8"));
        app.MapGet("/api/events", context => HandleEventsAsync(context, sessions, streamSlots));
        return app;
    }

    private static async Task HandleEventsAsync(HttpContext context, SessionCache sessions, SemaphoreSlim streamSlots)
    {
        // Admission never waits. The stream observes request cancellation.
        if (!await streamSlots.WaitAsync(0, CancellationToken.None))
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.RetryAfter = "1";
            return;
        }
        try { await StreamEventsAsync(context, sessions); }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            // A disconnected viewer no longer needs the stream slot.
        }
        finally { streamSlots.Release(); }
    }

    private static async Task StreamEventsAsync(HttpContext context, SessionCache sessions)
    {
        context.Response.ContentType = "text/event-stream";
        context.Response.Headers["X-Accel-Buffering"] = "no";
        var body = context.Response.BodyWriter;
        var cancellation = context.RequestAborted;
        string? previousHash = null;
        while (!cancellation.IsCancellationRequested)
        {
            var snapshot = sessions.Get();
            if (StringComparer.Ordinal.Equals(snapshot.Hash, previousHash))
            {
                body.Write(": keepalive\n\n"u8);
            }
            else
            {
                body.Write("event: session\ndata: "u8);
                body.Write(snapshot.Envelope.AsSpan());
                body.Write("\n\n"u8);
                previousHash = snapshot.Hash;
            }
            var flushed = await body.FlushAsync(cancellation);
            if (flushed.IsCanceled || flushed.IsCompleted) return;
            await Task.Delay(RefreshInterval, cancellation);
        }
    }

    internal static bool TryParseOptions(string[] args, out DemoConsoleOptions parsed)
    {
        parsed = null!;
        if (args.Length == 2 && args[0] == "--demo-console" && Path.IsPathFullyQualified(args[1]))
        {
            parsed = new(Path.GetFullPath(args[1]), IPAddress.Loopback, 0,
                IPAddress.Loopback, null, null);
            return true;
        }
        if (args.Length != 12 || args[0] != "--demo-console" || !Path.IsPathFullyQualified(args[1])) return false;
        var named = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 2; index < args.Length; index += 2)
        {
            if (!named.TryAdd(args[index], args[index + 1])) return false;
        }
        if (named.Count != 5 ||
            !named.TryGetValue("--listen-address", out var listenText) ||
            !named.TryGetValue("--listen-port", out var portText) ||
            !named.TryGetValue("--trusted-proxy-address", out var proxyText) ||
            !named.TryGetValue("--https-certificate", out var certificatePath) ||
            !named.TryGetValue("--https-key", out var keyPath) ||
            !IPAddress.TryParse(listenText, out var listenAddress) || listenAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            !int.TryParse(portText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var port) || port is < 1024 or > 65535 ||
            !IPAddress.TryParse(proxyText, out var trustedProxy) || trustedProxy.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            IPAddress.IsLoopback(trustedProxy) || trustedProxy.Equals(IPAddress.Any) || trustedProxy.Equals(IPAddress.Broadcast) ||
            !Path.IsPathFullyQualified(certificatePath) || !Path.IsPathFullyQualified(keyPath)) return false;
        parsed = new(Path.GetFullPath(args[1]), listenAddress, port, trustedProxy,
            Path.GetFullPath(certificatePath), Path.GetFullPath(keyPath));
        return true;
    }

    internal static X509Certificate2? LoadServerCertificate(DemoConsoleOptions configuration)
    {
        if (configuration.CertificatePath is null) return null;
        var certificate = X509Certificate2.CreateFromPemFile(configuration.CertificatePath,
            configuration.KeyPath!);
        if (!certificate.HasPrivateKey)
        {
            certificate.Dispose();
            throw new InvalidDataException("Demo HTTPS certificate has no private key.");
        }
        return certificate;
    }

    internal static JsonDocument LoadSession(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new InvalidDataException("Absolute demo session path required.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length is <= 0 or > MaximumSessionBytes) throw new InvalidDataException("Unsupported demo session size.");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("Demo session changed during read.");
        var document = JsonDocument.Parse(bytes, DocumentOptions);
        try { Validate(document.RootElement); }
        catch { document.Dispose(); throw; }
        return document;
    }

    private static void Validate(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object || RequiredInt(root, "version") != 1)
            throw new InvalidDataException("Demo session version 1 required.");
        RequiredText(root, "sessionId", 128);
        RequiredText(root, "title", 160);
        RequiredText(root, "updatedUtc", 40, requireUtcTimestamp: true);
        if (root.TryGetProperty("mode", out var mode) &&
            (mode.ValueKind != JsonValueKind.String || mode.GetString() is not ("live" or "replay")))
            throw new InvalidDataException("Unsupported demo mode.");
        var live = root.TryGetProperty("mode", out mode) && mode.GetString() == "live";
        if (root.TryGetProperty("sources", out var sources))
        {
            if (sources.ValueKind != JsonValueKind.Array || sources.GetArrayLength() is < 1 or > 16)
                throw new InvalidDataException("Invalid source list.");
            var sourceIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var source in sources.EnumerateArray())
            {
                if (source.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Source objects required.");
                var sourceId = RequiredText(source, "id", 64);
                if (!sourceIds.Add(sourceId)) throw new InvalidDataException("Source IDs must be unique.");
                RequiredText(source, "label", 80);
                var sourceStatus = RequiredText(source, "status", 16);
                if (sourceStatus is not ("connected" or "waiting" or "stale" or "offline"))
                    throw new InvalidDataException("Unsupported source status.");
                RequiredText(source, "observedUtc", 40, requireUtcTimestamp: true);
                if (source.TryGetProperty("detail", out var detail) &&
                    (detail.ValueKind != JsonValueKind.String || !IsText(detail.GetString(), 300)))
                    throw new InvalidDataException("Invalid source detail.");
            }
        }
        var device = RequiredObject(root, "device");
        RequiredText(device, "hostname", 253);
        RequiredText(device, "assetId", 256);
        RequiredText(device, "macAddress", 32);
        var scenarios = RequiredArray(root, "scenarios", 2, 4);
        var scenarioIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var scenario in scenarios.EnumerateArray())
        {
            if (scenario.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Scenario objects required.");
            var scenarioId = RequiredText(scenario, "id", 64);
            if (!scenarioIds.Add(scenarioId)) throw new InvalidDataException("Scenario IDs must be unique.");
            RequiredText(scenario, "label", 100);
            RequiredText(scenario, "summary", 500);
            var stages = RequiredArray(scenario, "stages", 1, 16);
            var stageIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var stage in stages.EnumerateArray())
            {
                if (stage.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Stage objects required.");
                var id = RequiredText(stage, "id", 64);
                if (!stageIds.Add(id)) throw new InvalidDataException("Stage IDs must be unique within a scenario.");
                RequiredText(stage, "label", 100);
                RequiredStatus(stage);
            }
            var events = RequiredArray(scenario, "events", live ? 0 : 1, 256);
            var eventIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in events.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Event objects required.");
                var id = RequiredText(item, "id", 96);
                if (!eventIds.Add(id)) throw new InvalidDataException("Event IDs must be unique within a scenario.");
                RequiredText(item, "atUtc", 40, requireUtcTimestamp: true);
                RequiredText(item, "source", 80);
                RequiredText(item, "stage", 64);
                if (!stageIds.Contains(item.GetProperty("stage").GetString()!)) throw new InvalidDataException("Event stage is not declared.");
                RequiredText(item, "title", 160);
                RequiredText(item, "detail", 2000);
                RequiredStatus(item);
                ValidateEventFields(item);
            }
        }
    }

    private static void ValidateEventFields(JsonElement item)
    {
        if (!item.TryGetProperty("fields", out var fields)) return;
        if (fields.ValueKind != JsonValueKind.Object || fields.GetPropertyCount() > 32)
            throw new InvalidDataException("Event fields must be a bounded object.");
        if (fields.EnumerateObject().Any(field => EventFieldsSchema.TryGetProperty(field.Name, out _) &&
                (field.Name.Length is 0 or > 80 || field.Value.ValueKind != JsonValueKind.String ||
                    !IsText(field.Value.GetString(), 500))))
            throw new InvalidDataException("Event field strings are invalid.");
    }

    private static void RequiredStatus(JsonElement element)
    {
        var status = RequiredText(element, "status", 16);
        if (status is not ("pending" or "active" or "success" or "warning" or "denied"))
            throw new InvalidDataException("Unsupported demo status.");
    }

    private static int RequiredInt(JsonElement element, string name) =>
        element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.Number &&
        property.TryGetInt32(out var value)
            ? value : throw new InvalidDataException("Missing integer: " + name);

    private static JsonElement RequiredObject(JsonElement element, string name) =>
        element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.Object
            ? property : throw new InvalidDataException("Missing object: " + name);

    private static JsonElement RequiredArray(JsonElement element, string name, int minimum, int maximum)
    {
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Missing array: " + name);
        var count = property.GetArrayLength();
        if (count < minimum || count > maximum) throw new InvalidDataException("Invalid array length: " + name);
        return property;
    }

    private static string RequiredText(JsonElement element, string name, int maximum, bool requireUtcTimestamp = false)
    {
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String ||
            !IsText(property.GetString(), maximum)) throw new InvalidDataException("Invalid text: " + name);
        var value = property.GetString()!;
        if (requireUtcTimestamp && (!DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var parsed) || parsed.Offset != TimeSpan.Zero))
            throw new InvalidDataException("UTC timestamp required: " + name);
        return value;
    }

    private static bool IsText(string? value, int maximum) => value is { Length: > 0 } && value.Length <= maximum &&
        !value.Any(character => char.IsControl(character) && character is not '\t');

    private static JsonElement LoadPresentationSchema()
    {
        using var schema = JsonDocument.Parse(Asset("PresentationSchema.json"), DocumentOptions);
        return schema.RootElement.Clone();
    }

    private sealed record SessionEnvelope(string Hash, byte[] Envelope);

    private sealed class SessionCache(string path, TimeProvider clock)
    {
        private readonly object sync = new();
        private SessionEnvelope? current = ReadEnvelope(path); // Validate before listening.
        private long refreshedAt = clock.GetTimestamp();

        internal SessionEnvelope Get()
        {
            lock (sync)
            {
                if (clock.GetElapsedTime(refreshedAt) >= RefreshInterval)
                {
                    try { current = ReadEnvelope(path); }
                    catch (Exception error) when (error is InvalidDataException or IOException or JsonException or UnauthorizedAccessException)
                    {
                        current = null;
                    }
                    refreshedAt = clock.GetTimestamp();
                }
                return current ?? throw new InvalidDataException("The demo session is unavailable or invalid.");
            }
        }

        private static SessionEnvelope ReadEnvelope(string path)
        {
            using var snapshot = LoadSession(path);
            var projected = new ArrayBufferWriter<byte>();
            using (var writer = new Utf8JsonWriter(projected))
                WriteProjected(writer, snapshot.RootElement, PresentationSchema);

            var hash = Convert.ToHexString(SHA256.HashData(projected.WrittenSpan));
            var envelope = new ArrayBufferWriter<byte>();
            using (var writer = new Utf8JsonWriter(envelope))
            {
                writer.WriteStartObject();
                writer.WriteString("sha256", hash);
                writer.WritePropertyName("session");
                writer.WriteRawValue(projected.WrittenSpan, skipInputValidation: true);
                writer.WriteEndObject();
            }
            return new(hash, envelope.WrittenSpan.ToArray());
        }

        private static void WriteProjected(Utf8JsonWriter writer, JsonElement value, JsonElement schema)
        {
            switch (schema.ValueKind, value.ValueKind)
            {
                case (JsonValueKind.Object, JsonValueKind.Object):
                    writer.WriteStartObject();
                    foreach (var property in value.EnumerateObject())
                    {
                        if (!schema.TryGetProperty(property.Name, out var propertySchema)) continue;
                        writer.WritePropertyName(property.Name);
                        WriteProjected(writer, property.Value, propertySchema);
                    }
                    writer.WriteEndObject();
                    break;
                case (JsonValueKind.Array, JsonValueKind.Array):
                    writer.WriteStartArray();
                    foreach (var item in value.EnumerateArray())
                        WriteProjected(writer, item, schema[0]);
                    writer.WriteEndArray();
                    break;
                case (JsonValueKind.Null, JsonValueKind.String or JsonValueKind.Number or
                    JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null):
                    value.WriteTo(writer);
                    break;
                default:
                    throw new InvalidDataException("Invalid presentation value.");
            }
        }
    }

    internal sealed record DemoConsoleOptions(string SessionPath, IPAddress ListenAddress, int Port,
        IPAddress TrustedPeer, string? CertificatePath, string? KeyPath);

    private static string Asset(string name)
    {
        using var stream = typeof(DemoConsoleHost).Assembly.GetManifestResourceStream("DemoConsole." + name)
            ?? throw new InvalidOperationException("Missing demo-console asset.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
