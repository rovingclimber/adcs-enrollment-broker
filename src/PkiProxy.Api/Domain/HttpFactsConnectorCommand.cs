using System.Security.Cryptography;
using System.Text.Json;

namespace PkiProxy.Domain;

internal static class HttpFactsConnectorCommand
{
    internal static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken = default)
    {
        if (args.Length != 3 || args[0] != "--facts-connector-sync")
        {
            await Console.Error.WriteLineAsync("Usage: --facts-connector-sync ABSOLUTE_PROFILE_JSON ABSOLUTE_FACTS_JSON");
            return 64;
        }
        try
        {
            var target = Path.GetFullPath(args[2]);
            using var connector = HttpFactsConnector.Load(args[1]);
            var (sourceHash, publication) = await RefreshAsync(target, connector, cancellationToken);
            if (publication is null)
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    status = "connector-snapshot-unchanged",
                    connectorMode = connector.Profile.Mode.ToString().ToLowerInvariant(),
                    sourceSha256 = sourceHash
                }));
                return 0;
            }
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                status = "connector-snapshot-published",
                connectorMode = connector.Profile.Mode.ToString().ToLowerInvariant(),
                publication
            }));
            return 0;
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or
            ArgumentException or InvalidOperationException or HttpRequestException or OperationCanceledException or
            PlatformNotSupportedException or CryptographicException)
        {
            await Console.Error.WriteLineAsync("Connector sync refused: " + error.Message);
            return 1;
        }
    }

    internal static async Task<(string SourceHash, FactsPublication? Publication)> RefreshAsync(string target,
        HttpFactsConnector connector, CancellationToken cancellationToken)
    {
        var current = DeviceFactsPublisher.Read(target);
        var sourceHash = Convert.ToHexString(SHA256.HashData(current));
        var draft = await connector.PrepareSnapshotAsync(current, sourceHash, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (draft.AsSpan().SequenceEqual(current))
        {
            DeviceFactsPublisher.Revalidate(target, sourceHash, cancellationToken);
            return (sourceHash, null);
        }
        var draftHash = Convert.ToHexString(SHA256.HashData(draft));
        return (sourceHash, DeviceFactsPublisher.Publish(target, draft, sourceHash, draftHash));
    }
}
