using System.Security.Cryptography;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace PkiProxy.Domain;

internal sealed class BrokerReadinessCheck(Func<CancellationToken, Task<bool>>? probe, TimeSpan refreshInterval) :
    IHealthCheck, IHostedService, IDisposable
{
    private readonly SemaphoreSlim slot = new(1, 1);
    private readonly CancellationTokenSource stopped = new();
    private Task? refreshLoop;
    private int cachedHealthy;

    internal BrokerReadinessCheck(Func<CancellationToken, Task<bool>>? probe) : this(probe, TimeSpan.FromMinutes(1)) { }

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Volatile.Read(ref cachedHealthy) == 1
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy());
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await RefreshAsync(cancellationToken);
        if (probe is not null) refreshLoop = RefreshLoopAsync(stopped.Token);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        stopped.Cancel();
        if (refreshLoop is not null)
            try { await refreshLoop.WaitAsync(cancellationToken); }
            catch (OperationCanceledException) when (stopped.IsCancellationRequested || cancellationToken.IsCancellationRequested) { }
    }

    internal async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        if (probe is null)
        {
            Volatile.Write(ref cachedHealthy, 0);
            return;
        }
        if (!await slot.WaitAsync(0, cancellationToken)) return;
        try
        {
            Volatile.Write(ref cachedHealthy, await probe(cancellationToken) ? 1 : 0);
        }
        catch (Exception error) when (error is InvalidDataException or IOException or CryptographicException or
            UnauthorizedAccessException or InvalidOperationException or ArgumentException or OperationCanceledException)
        {
            // No exception contents, filesystem paths, certificate identities or facts in health output/logs.
            Volatile.Write(ref cachedHealthy, 0);
        }
        finally { slot.Release(); }
    }

    private async Task RefreshLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(refreshInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
                await RefreshAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }

    public void Dispose() { stopped.Cancel(); stopped.Dispose(); slot.Dispose(); }
}
