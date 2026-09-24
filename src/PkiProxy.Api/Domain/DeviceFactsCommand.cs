using System.Security.Cryptography;
using System.Text.Json;

namespace PkiProxy.Domain;

internal static class DeviceFactsCommand
{
    internal static int Run(string[] args)
    {
        if (args.Length > 0 && args[0] == "--facts-publish") return Publish(args);
        if (args.Length != 6 || args[0] != "--facts-use-case")
        {
            Console.Error.WriteLine("Usage: --facts-use-case SOURCE HOST_FQDN USE_CASE EXPECTED_SOURCE_SHA256 NEW_OUTPUT");
            return 64;
        }
        try
        {
            // Bound the read before allocating; reject growth as the broker reader does.
            using var input = new FileStream(Path.GetFullPath(args[1]), FileMode.Open, FileAccess.Read, FileShare.Read);
            if (input.Length is 0 or > 1048576) throw new InvalidDataException("Unsupported facts file size.");
            var bytes = new byte[(int)input.Length];
            input.ReadExactly(bytes);
            if (input.ReadByte() != -1) throw new InvalidDataException("Source changed during read.");
            var prepared = DeviceFactsEditor.PrepareUseCase(bytes, args[4], args[2], args[3]);
            var outputPath = Path.GetFullPath(args[5]);
            // CreateNew forbids replacing input, existing drafts or the live mounted file.
            // If writing fails, a partial draft can remain. Nothing publishes it automatically.
            using (var output = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                output.Write(prepared);
                output.Flush(flushToDisk: true);
            }
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                status = "prepared-not-published",
                sourceSha256 = Convert.ToHexString(SHA256.HashData(bytes)),
                outputSha256 = Convert.ToHexString(SHA256.HashData(prepared)),
                revision = JsonFileDeviceFactsSource.Parse(prepared, args[2])!.SourceVersion,
                hostname = args[2], useCase = args[3], outputPath
            }));
            return 0;
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or ArgumentException or OverflowException)
        {
            Console.Error.WriteLine("Facts edit refused: " + error.Message);
            return 1;
        }
    }

    private static int Publish(string[] args)
    {
        if (args.Length != 5)
        {
            Console.Error.WriteLine("Usage: --facts-publish ABSOLUTE_TARGET REVIEWED_DRAFT EXPECTED_SOURCE_SHA256 EXPECTED_DRAFT_SHA256");
            return 64;
        }
        try
        {
            var receipt = DeviceFactsPublisher.Publish(args[1], DeviceFactsPublisher.Read(args[2]), args[3], args[4]);
            Console.WriteLine(JsonSerializer.Serialize(new { status = "published", publication = receipt }));
            return 0;
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or ArgumentException or OverflowException or PlatformNotSupportedException)
        {
            // Failure may occur after rename. Never retry by recalculating expected hashes.
            Console.Error.WriteLine("Publication did not complete cleanly: " + error.Message + " Reconcile target and retained history before retrying.");
            return 1;
        }
    }
}
