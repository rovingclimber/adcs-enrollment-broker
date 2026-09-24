using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using PkiProxy.Domain;

internal static class FactsWorkbenchPublicationTests
{
    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var api = Path.GetFullPath("src/PkiProxy.Api/bin/Release/net10.0/PkiProxy.Api.dll");
        var source = File.ReadAllBytes("lab/device-facts/devices.client001-engineering-v3.json");
        var sourceHash = Convert.ToHexString(SHA256.HashData(source));
        var scratch = Directory.CreateTempSubdirectory("facts-http-");
        File.SetUnixFileMode(scratch.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var checks = 0;
        void Assert(bool condition) { if (!condition) throw new InvalidOperationException("Workbench publication HTTP check failed."); checks++; }
        try
        {
            foreach (var enabled in new[] { false, true })
            {
                var path = Path.Combine(scratch.FullName, enabled ? "enabled.json" : "draft.json");
                File.WriteAllBytes(path, source);
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                var start = new ProcessStartInfo("dotnet") { WorkingDirectory = scratch.FullName,
                    RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
                start.ArgumentList.Add(api); start.ArgumentList.Add("--facts-workbench"); start.ArgumentList.Add(path);
                if (enabled) start.ArgumentList.Add("--enable-publish");
                using var process = Process.Start(start)!;
                var errors = process.StandardError.ReadToEndAsync();
                Task<string>? remaining = null;
                try
                {
                    string? origin = null;
                    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                    while (origin is null)
                    {
                        var line = await process.StandardOutput.ReadLineAsync(deadline.Token)
                            ?? throw new InvalidOperationException("Workbench exited before ready.");
                        if (line.StartsWith("Device facts workbench (", StringComparison.Ordinal))
                            origin = line[(line.IndexOf(": http", StringComparison.Ordinal) + 2)..];
                    }
                    remaining = process.StandardOutput.ReadToEndAsync();
                    using var client = new HttpClient { BaseAddress = new Uri(origin), Timeout = TimeSpan.FromSeconds(10) };
                    var html = await client.GetStringAsync("/");
                    Assert((await client.GetStringAsync("/publication.css")).Contains("#publish-diff", StringComparison.Ordinal));
                    Assert((await client.GetStringAsync("/workbench.js")).Contains("/api/publish", StringComparison.Ordinal));
                    var token = Regex.Match(html, "name=\"workbench-token\" content=\"([A-F0-9]+)\"", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)).Groups[1].Value;
                    Assert(token.Length == 64);
                    async Task<HttpResponseMessage> Send(string route, byte[] bytes, string hash, bool auth = true, string? requestOrigin = null)
                    {
                        using var request = new HttpRequestMessage(HttpMethod.Post, route);
                        request.Content = new ByteArrayContent(bytes);
                        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                        request.Headers.TryAddWithoutValidation("If-Match", hash);
                        request.Headers.Add("X-Draft-SHA256", Convert.ToHexString(SHA256.HashData(bytes)));
                        request.Headers.Add("Origin", requestOrigin ?? origin);
                        if (auth) request.Headers.Add("X-Workbench-Token", token);
                        return await client.SendAsync(request);
                    }
                    var proposal = JsonNode.Parse(source)!;
                    proposal["devices"]![1]!["useCase"] = "lab-validation";
                    using var validated = await Send("/api/draft", Encoding.UTF8.GetBytes(proposal.ToJsonString()), sourceHash);
                    Assert(validated.StatusCode == HttpStatusCode.OK);
                    var draft = await validated.Content.ReadAsByteArrayAsync();
                    Assert(File.ReadAllBytes(path).AsSpan().SequenceEqual(source));
                    using var missing = await Send("/api/publish", draft, sourceHash, auth: false);
                    Assert(missing.StatusCode == HttpStatusCode.Forbidden);
                    using var cross = await Send("/api/publish", draft, sourceHash, requestOrigin: "https://untrusted.invalid");
                    Assert(cross.StatusCode == HttpStatusCode.Forbidden);
                    using var publication = await Send("/api/publish", draft, sourceHash);
                    Assert(publication.StatusCode == (enabled ? HttpStatusCode.OK : HttpStatusCode.Forbidden));
                    Assert(File.ReadAllBytes(path).AsSpan().SequenceEqual(enabled ? draft : source));
                    if (!enabled) continue;
                    var receipt = JsonNode.Parse(await publication.Content.ReadAsStringAsync())!;
                    Assert(receipt["revision"]!.GetValue<long>() == 4);
                    var reader = new JsonFileDeviceFactsSource(path);
                    Assert((await reader.FindByDnsHostNameAsync("CLIENT-001.example.test", CancellationToken.None)) is { SourceVersion: 4, UseCase: "lab-validation" });
                    using var replay = await Send("/api/publish", draft, sourceHash);
                    Assert(replay.StatusCode == HttpStatusCode.Conflict);
                    using var snapshotRequest = new HttpRequestMessage(HttpMethod.Get, "/api/snapshot");
                    snapshotRequest.Headers.Add("X-Workbench-Token", token);
                    using var snapshot = await client.SendAsync(snapshotRequest);
                    Assert(JsonNode.Parse(await snapshot.Content.ReadAsStringAsync())!["publicationBlocked"]!.GetValue<bool>());
                    Assert(File.ReadAllBytes(path).AsSpan().SequenceEqual(draft));
                }
                finally
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync();
                    if (remaining is not null) await remaining;
                    await errors;
                }
            }
            Console.WriteLine($"Workbench publication HTTP checks passed: {checks} (disposable Linux data only).");
        }
        finally { scratch.Delete(recursive: true); }
    }
}
