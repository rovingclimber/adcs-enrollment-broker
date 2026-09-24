using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using PkiProxy.Domain;

internal static class DeviceFactsEditorTests
{
    internal static void Run()
    {
        var source = File.ReadAllBytes("lab/device-facts/devices.client001-engineering-v3.json");
        var hash = Convert.ToHexString(SHA256.HashData(source));
        const string host = "CLIENT-001.example.test";
        var edited = DeviceFactsEditor.PrepareUseCase(source, hash.ToLowerInvariant(), host.ToLowerInvariant(), "lab-validation");
        var facts = JsonFileDeviceFactsSource.Parse(edited, host)!;
        if (facts.SourceVersion != 4 || facts.UseCase != "lab-validation") throw new InvalidOperationException("Wrong facts edit.");
        var before = JsonNode.Parse(source)!;
        var after = JsonNode.Parse(edited)!;
        after["revision"] = 3;
        after["devices"]![1]!["useCase"] = "engineering";
        if (!JsonNode.DeepEquals(before, after)) throw new InvalidOperationException("Editor changed unrelated fields.");
        var checks = 2;
        var proposal = JsonNode.Parse(source)!.AsObject();
        proposal["devices"]![1]!["location"] = "new office";
        var proposedBytes = Encoding.UTF8.GetBytes(proposal.ToJsonString());
        var documentEdit = DeviceFactsEditor.PrepareDocument(source, hash, proposedBytes);
        if (JsonFileDeviceFactsSource.Parse(documentEdit, host) is not { SourceVersion: 4, Location: "new office" })
            throw new InvalidOperationException("Workbench document edit failed.");
        proposal["devices"]!.AsArray().RemoveAt(1);
        var removed = DeviceFactsEditor.PrepareDocument(source, hash, Encoding.UTF8.GetBytes(proposal.ToJsonString()));
        if (JsonFileDeviceFactsSource.Parse(removed, host) is not null) throw new InvalidOperationException("Workbench remove failed.");
        var createdDevice = JsonNode.Parse(source)!["devices"]![1]!.DeepClone();
        createdDevice["hostname"] = "NEW-DEVICE.example.test"; createdDevice["assetId"] = "new-asset";
        proposal["devices"]!.AsArray().Add(createdDevice);
        var created = DeviceFactsEditor.PrepareDocument(source, hash, Encoding.UTF8.GetBytes(proposal.ToJsonString()));
        if (JsonFileDeviceFactsSource.Parse(created, "NEW-DEVICE.example.test") is not { AssetId: "new-asset" })
            throw new InvalidOperationException("Workbench create failed.");
        checks += 3;
        void RejectDocument(byte[] data, string expected)
        {
            try { DeviceFactsEditor.PrepareDocument(source, expected, data); }
            catch (InvalidDataException) { checks++; return; }
            throw new InvalidOperationException("Unsafe workbench document accepted.");
        }
        RejectDocument(proposedBytes, new string('0', 64));
        RejectDocument(source, hash);
        var altered = JsonNode.Parse(proposedBytes)!; altered["revision"] = 99;
        RejectDocument(Encoding.UTF8.GetBytes(altered.ToJsonString()), hash);
        altered = JsonNode.Parse(proposedBytes)!; altered["useCases"]![0]!["label"] = "Changed catalogue";
        RejectDocument(Encoding.UTF8.GetBytes(altered.ToJsonString()), hash);
        altered = JsonNode.Parse(proposedBytes)!; altered["devices"]![0]!["san"] = "untrusted";
        RejectDocument(Encoding.UTF8.GetBytes(altered.ToJsonString()), hash);
        altered = JsonNode.Parse(proposedBytes)!; altered["devices"]![1]!["hostname"] = altered["devices"]![0]!["hostname"]!.GetValue<string>();
        RejectDocument(Encoding.UTF8.GetBytes(altered.ToJsonString()), hash);
        void Reject(byte[] data, string expectedHash, string name, string useCase)
        {
            try { DeviceFactsEditor.PrepareUseCase(data, expectedHash, name, useCase); }
            catch (Exception e) when (e is InvalidDataException or OverflowException) { checks++; return; }
            throw new InvalidOperationException("Unsafe facts edit accepted.");
        }
        Reject(source, new string('0', 64), host, "lab-validation");
        Reject(source, "bad", host, "lab-validation");
        Reject(source, hash, host, "engineering");
        Reject(source, hash, host, "unknown");
        Reject(source, hash, "CLIENT-001", "lab-validation");
        Reject(source, hash, "missing.example.test", "lab-validation");
        foreach (var bad in new[]
        {
            Encoding.UTF8.GetString(source).Replace("\"revision\": 3", "\"revision\": 9223372036854775807", StringComparison.Ordinal),
            Encoding.UTF8.GetString(source).Replace("\"revision\": 3", "\"revision\": 3, \"revision\": 3", StringComparison.Ordinal),
            Encoding.UTF8.GetString(source).Replace("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"san\": \"evil\"", StringComparison.Ordinal)
        })
        {
            var data = Encoding.UTF8.GetBytes(bad);
            Reject(data, Convert.ToHexString(SHA256.HashData(data)), host, "lab-validation");
        }
        var bom = new byte[] { 0xef, 0xbb, 0xbf }.Concat(source).ToArray();
        _ = DeviceFactsEditor.PrepareUseCase(bom, Convert.ToHexString(SHA256.HashData(bom)), host, "lab-validation");
        checks++;
        var directory = Path.Combine(Path.GetTempPath(), "facts-editor-test-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(directory);
        try
        {
            var input = Path.Combine(directory, "source.json");
            var output = Path.Combine(directory, "next.json");
            File.WriteAllBytes(input, source);
            string[] command = ["--facts-use-case", input, host, "lab-validation", hash, output];
            if (DeviceFactsCommand.Run(command) != 0 || !File.ReadAllBytes(output).AsSpan().SequenceEqual(edited))
                throw new InvalidOperationException("Command draft differs from validated edit.");
            if (DeviceFactsCommand.Run(command) != 1 || !File.ReadAllBytes(output).AsSpan().SequenceEqual(edited))
                throw new InvalidOperationException("Existing draft overwritten.");
            command[5] = input;
            if (DeviceFactsCommand.Run(command) != 1 || !File.ReadAllBytes(input).AsSpan().SequenceEqual(source))
                throw new InvalidOperationException("Source overwritten.");
            command[5] = Path.Combine(directory, "rejected.json");
            command[4] = new string('0', 64);
            if (DeviceFactsCommand.Run(command) != 1 || File.Exists(command[5]))
                throw new InvalidOperationException("Rejected edit created a file.");
            if (DeviceFactsCommand.Run(["--facts-typo"]) != 64)
                throw new InvalidOperationException("Unknown facts command not refused.");
            checks += 5;
        }
        finally { System.IO.Directory.Delete(directory, recursive: true); } // Unique test-owned directory only.
        Console.WriteLine($"Offline facts editor checks passed: {checks}.");
    }
}
