using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;

internal static class DisabledHostSmoke
{
    // Explicit opt-in: run in a network-none test container with no credentials mounted.
    internal static async Task RunAsync()
    {
        var api = Path.GetFullPath("src/PkiProxy.Api/bin/Release/net10.0/PkiProxy.Api.dll");
        var envelope = await File.ReadAllTextAsync("smoke/valid-envelope.xml");
        var scratch = Directory.CreateTempSubdirectory("disabled-host-smoke-");
        try
        {
            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = scratch.FullName,
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true
            };
            foreach (var key in start.Environment.Keys.Where(key =>
                key.StartsWith("Broker", StringComparison.OrdinalIgnoreCase) ||
                key.StartsWith("ASPNETCORE_", StringComparison.OrdinalIgnoreCase) ||
                key.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase)).ToArray())
                start.Environment.Remove(key);
            start.ArgumentList.Add(api);
            start.ArgumentList.Add("--urls");
            start.ArgumentList.Add("http://127.0.0.1:18089");
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Test host did not start.");
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            try
            {
                using var client = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:18089"), Timeout = TimeSpan.FromSeconds(2) };
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                while (true)
                {
                    if (process.HasExited) throw new InvalidOperationException("Disabled test host exited early.");
                    try
                    {
                        using var health = await client.GetAsync("/healthz", deadline.Token);
                        if (health.StatusCode != HttpStatusCode.OK) throw new InvalidOperationException("Liveness not OK.");
                        using var body = JsonDocument.Parse(await health.Content.ReadAsStringAsync(deadline.Token));
                        if (body.RootElement.EnumerateObject().Count() != 1 ||
                            body.RootElement.GetProperty("status").GetString() != "healthy")
                            throw new InvalidOperationException("Liveness response leaked capability detail.");
                        break;
                    }
                    catch (HttpRequestException) { await Task.Delay(100, deadline.Token); }
                }
                using var readiness = await client.GetAsync("/readyz", deadline.Token);
                if (readiness.StatusCode != HttpStatusCode.ServiceUnavailable ||
                    await readiness.Content.ReadAsStringAsync(deadline.Token) != "Unhealthy")
                    throw new InvalidOperationException("Disabled host reported ready.");
                using var content = new StringContent(envelope, Encoding.UTF8, "application/soap+xml");
                using var protocol = await client.PostAsync("/cep/kerberos/service.svc/CEP", content, deadline.Token);
                if (protocol.StatusCode != HttpStatusCode.NotImplemented ||
                    !(await protocol.Content.ReadAsStringAsync(deadline.Token)).Contains("ProtocolImplementationPending", StringComparison.Ordinal))
                    throw new InvalidOperationException("Disabled host protocol not fail-closed.");
                Console.WriteLine("Actual disabled-host HTTP smoke passed: liveness200, readiness503, CEP501.");
            }
            finally
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
                await Task.WhenAll(output, error);
            }
        }
        finally { scratch.Delete(recursive: true); } // Unique test-owned directory only.
    }
}
