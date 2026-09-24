using Microsoft.Extensions.Diagnostics.HealthChecks;
using PkiProxy.Domain;

internal static class BrokerReadinessTests
{
    internal static async Task RunAsync()
    {
        var context = new HealthCheckContext();
        var count = 0;
        void Check(bool value) { if (!value) throw new InvalidOperationException("Readiness contract failed."); count++; }
        using var disabled = new BrokerReadinessCheck(null);
        Check((await disabled.CheckHealthAsync(context)).Status == HealthStatus.Unhealthy);
        await disabled.StartAsync(default);
        Check((await disabled.CheckHealthAsync(context)).Status == HealthStatus.Unhealthy);
        var good = true;
        var signerCalls = 0;
        using var changing = new BrokerReadinessCheck(_ => { Interlocked.Increment(ref signerCalls); return Task.FromResult(good); }, TimeSpan.FromHours(1));
        Check((await changing.CheckHealthAsync(context)).Status == HealthStatus.Unhealthy && signerCalls == 0);
        await changing.StartAsync(default);
        Check((await changing.CheckHealthAsync(context)).Status == HealthStatus.Healthy && signerCalls == 1);
        var concurrent = await Task.WhenAll(Enumerable.Range(0, 128)
            .Select(_ => changing.CheckHealthAsync(context)));
        Check(concurrent.All(result => result.Status == HealthStatus.Healthy) && signerCalls == 1);
        good = false;
        Check((await changing.CheckHealthAsync(context)).Status == HealthStatus.Healthy && signerCalls == 1);
        await changing.RefreshAsync();
        Check((await changing.CheckHealthAsync(context)).Status == HealthStatus.Unhealthy && signerCalls == 2);
        good = true;
        await changing.RefreshAsync();
        Check((await changing.CheckHealthAsync(context)).Status == HealthStatus.Healthy && signerCalls == 3);
        using var malformed = new BrokerReadinessCheck(_ => throw new InvalidDataException("private-marker-path"));
        await malformed.StartAsync(default);
        var fault = await malformed.CheckHealthAsync(context);
        Check(fault.Status == HealthStatus.Unhealthy && fault.Exception is null && fault.Description is null);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var busy = new BrokerReadinessCheck(_ => release.Task);
        var first = busy.RefreshAsync();
        Check((await busy.CheckHealthAsync(context)).Status == HealthStatus.Unhealthy);
        await busy.RefreshAsync();
        release.SetResult(true);
        await first;
        Check((await busy.CheckHealthAsync(context)).Status == HealthStatus.Healthy);
        await changing.StopAsync(default);
        await malformed.StopAsync(default);
        await busy.StopAsync(default);
        Console.WriteLine($"Cached non-signing readiness checks passed: {count}.");
    }
}
