using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using PkiProxy.Domain;

namespace PkiProxy.FactsWorkbench;

// Local operator editor. Publishing requires explicit Linux-only opt-in.
internal static class FactsWorkbenchHost
{
    internal static async Task<int> RunAsync(string[] args)
    {
        var localPublish = args.Length == 3 && args[2] == "--enable-publish";
        var hostedPublish = args.Length == 5 && args[2] == "--enable-publish" && args[3] == "--hosted-config";
        var publishEnabled = localPublish || hostedPublish;
        if ((args.Length != 2 && !localPublish && !hostedPublish) || !Path.IsPathFullyQualified(args[1]) ||
            (publishEnabled && !OperatingSystem.IsLinux()) || (hostedPublish && !Path.IsPathFullyQualified(args[4])))
        {
            Console.Error.WriteLine("Usage: --facts-workbench ABSOLUTE_SOURCE_JSON [--enable-publish [--hosted-config ABSOLUTE_JSON] (Linux only)]");
            return 64;
        }
        var path = args[1];
        _ = ReadSource(path); // Fail before listening if source is unavailable or invalid.
        using var hosted = hostedPublish ? FactsWorkbenchHostedAccess.Load(args[4]) : null;
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
        builder.WebHost.ConfigureKestrel(options =>
        {
            if (hosted is null) options.Listen(IPAddress.Loopback, 0);
            else options.Listen(hosted.ListenAddress, hosted.Value.HttpsPort,
                listener => listener.UseHttps(hosted.Certificate));
            options.Limits.MaxRequestBodySize = 1048576;
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
        });
        var app = builder.Build();
        var publicationBlocked = false;
        using var publicationGate = new SemaphoreSlim(1, 1);
        string? origin = hosted?.ExternalOrigin.AbsoluteUri.TrimEnd('/');
        app.Use(async (context, next) =>
        {
            var request = context.Request;
            var actualOrigin = request.Scheme + "://" + request.Host.Value;
            var actor = hosted?.Authenticate(context);
            if (origin is null || actualOrigin != origin ||
                (hosted is null ? context.Connection.RemoteIpAddress is not { } peer || !IPAddress.IsLoopback(peer) : actor is null))
            { context.Response.StatusCode = 403; return; }
            if (actor is not null) context.Items["facts-workbench-actor"] = actor;
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers.ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
            if (request.Path.StartsWithSegments("/api") &&
                (request.Headers["X-Workbench-Token"].Count != 1 || request.Headers["X-Workbench-Token"].ToString() != token ||
                 (request.Method != "GET" && request.Headers.Origin.ToString() != origin)))
            { context.Response.StatusCode = 403; return; }
            try { await next(context); }
            catch (Exception e) when (e is InvalidDataException or JsonException or OverflowException)
            { context.Response.StatusCode = 400; await context.Response.WriteAsJsonAsync(new { error = e is JsonException ? "Invalid JSON." : e.Message }); }
            catch (IOException)
            { context.Response.StatusCode = 409; await context.Response.WriteAsJsonAsync(new { error = "Source unavailable or changed. Reload the snapshot." }); }
        });
        app.MapGet("/", () => Results.Content(Asset("index.html").Replace("__WORKBENCH_TOKEN__", token, StringComparison.Ordinal), "text/html", Encoding.UTF8));
        app.MapGet("/workbench.css", () => Results.Content(Asset("workbench.css"), "text/css", Encoding.UTF8));
        app.MapGet("/publication.css", () => Results.Content(Asset("publication.css"), "text/css", Encoding.UTF8));
        app.MapGet("/workbench.js", () => Results.Content(Asset("workbench.js"), "text/javascript", Encoding.UTF8));
        app.MapGet("/api/snapshot", () =>
        {
            var bytes = ReadSource(path);
            using var document = JsonDocument.Parse(WithoutBom(bytes));
            return Results.Json(new { sha256 = Convert.ToHexString(SHA256.HashData(bytes)), document = document.RootElement.Clone(), publishEnabled, publicationBlocked });
        });
        app.MapPost("/api/publish", async (HttpContext context, CancellationToken cancellationToken) =>
        {
            var request = context.Request;
            if (!publishEnabled) return Results.StatusCode(403);
            if (request.ContentType is not "application/json" || request.Headers.IfMatch.Count != 1 ||
                request.Headers["X-Draft-SHA256"].Count != 1)
                return Results.BadRequest(new { error = "Reviewed JSON and both hashes are required." });
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int count;
            while ((count = await request.Body.ReadAsync(chunk, cancellationToken)) > 0)
            {
                if (buffer.Length + count > 1048576) return Results.StatusCode(413);
                buffer.Write(chunk, 0, count);
            }
            if (!await publicationGate.WaitAsync(0, cancellationToken))
                return Results.Conflict(new { error = "Another publication is in progress. Reload before retrying." });
            try
            {
                if (publicationBlocked) return Results.Conflict(new { error = "Publication paused. Operator reconciliation and restart required." });
                try
                {
                    // Finish the durable transaction even if the browser disconnects.
                    var receipt = DeviceFactsPublisher.Publish(path, buffer.ToArray(), request.Headers.IfMatch.ToString(),
                        request.Headers["X-Draft-SHA256"].ToString(), operatorIdentity:
                        context.Items.TryGetValue("facts-workbench-actor", out var actor) ? actor as string : null);
                    return Results.Json(new { receipt.Transaction, receipt.Revision, receipt.PublishedSha256 });
                }
                catch (Exception e) when (e is InvalidDataException or IOException or UnauthorizedAccessException or OverflowException)
                {
                    // Even a late filesystem failure can follow a successful rename.
                    publicationBlocked = true;
                    return Results.Conflict(new { error = "Publication did not complete cleanly. Do not retry: inspect the facts file and recovery history, then restart the workbench." });
                }
            }
            finally { publicationGate.Release(); }
        });
        app.MapPost("/api/draft", async (HttpRequest request, CancellationToken cancellationToken) =>
        {
            if (request.ContentType is not "application/json" || request.Headers.IfMatch.Count != 1)
                return Results.BadRequest(new { error = "JSON and the snapshot hash are required." });
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int count;
            while ((count = await request.Body.ReadAsync(chunk, cancellationToken)) > 0)
            {
                if (buffer.Length + count > 1048576) return Results.StatusCode(413);
                buffer.Write(chunk, 0, count);
            }
            var output = DeviceFactsEditor.PrepareDocument(ReadSource(path), request.Headers.IfMatch.ToString(), buffer.ToArray());
            return Results.File(output, "application/json", "device-facts.draft.json");
        });
        await app.StartAsync();
        var listener = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        origin ??= listener;
        Console.WriteLine("Device facts workbench (" + (hosted is not null ? "authenticated hosted publication" :
            publishEnabled ? "publication enabled" : "drafts only") + "): " + origin);
        await app.WaitForShutdownAsync();
        await app.DisposeAsync();
        return 0;
    }

    private static byte[] ReadSource(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length is 0 or > 1048576) throw new InvalidDataException("Unsupported facts file size.");
        var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("Source changed during read.");
        _ = JsonFileDeviceFactsSource.Parse(bytes, null);
        return bytes;
    }
    private static ReadOnlyMemory<byte> WithoutBom(byte[] bytes) =>
        bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }) ? bytes.AsMemory(3) : bytes;
    private static string Asset(string name)
    {
        using var stream = typeof(FactsWorkbenchHost).Assembly.GetManifestResourceStream("FactsWorkbench." + name)
            ?? throw new InvalidOperationException("Missing workbench asset.");
        using var reader = new StreamReader(stream); return reader.ReadToEnd();
    }
}
