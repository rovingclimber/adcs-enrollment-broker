using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PkiProxy.Domain;
using PkiProxy.Protocol.Cmc;

internal static class DeviceFactsFileTests
{
    public static async Task RunAsync()
    {
        var checks = 0;
        void Check(bool condition, string label)
        { if (!condition) throw new InvalidOperationException("Facts file: " + label); checks++; }
        const string host = "CLIENT-PHYSICAL-001.example.test";
        var example = await File.ReadAllTextAsync("lab/device-facts/devices.example.json");
        var facts = JsonFileDeviceFactsSource.Parse(Encoding.UTF8.GetBytes(example), host.ToLowerInvariant());
        Check(facts is { UseCase: "lab-validation", SourceVersion: 1, AssetId: "asset-physical-001" },
            "example file supplies typed facts by case-insensitive FQDN");
        Check(facts!.DirectoryDistinguishedName == string.Empty, "file cannot supply directory DN");
        Check(JsonFileDeviceFactsSource.Parse(new byte[] { 0xef, 0xbb, 0xbf }.Concat(Encoding.UTF8.GetBytes(example)).ToArray(), host)?.AssetId == facts.AssetId,
            "UTF8 BOM from Windows text editors is supported");
        Check(JsonFileDeviceFactsSource.Parse(Encoding.UTF8.GetBytes(example), "CLIENT-PHYSICAL-001") is null,
            "short hostname is not an alias for authoritative FQDN");
        Check(JsonFileDeviceFactsSource.Parse(Encoding.UTF8.GetBytes(example), "missing.example.test") is null,
            "unknown host is not enrolled");
        var invalidDocuments = new[]
        {
            "", "null", "[]", "{}", "{", example + "{}",
            example.Replace("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"schemaVersion\": 1", StringComparison.Ordinal),
            example.Replace("\"revision\": 1", "\"revision\": 0", StringComparison.Ordinal),
            example.Replace("\"schemaVersion\": 1", "\"schemaVersion\": 2", StringComparison.Ordinal),
            example.Replace("\"useCase\": \"lab-validation\"", "\"useCase\": \"unknown-choice\"", StringComparison.Ordinal),
            example.Replace("\"assetId\": \"asset-physical-001\"", "\"assetId\": \"\"", StringComparison.Ordinal),
            example.Replace("CLIENT-001.example.test", "client-physical-001.EXAMPLE.TEST", StringComparison.Ordinal),
            example.Replace("asset-virtual-001", "asset-physical-001", StringComparison.Ordinal),
            example.Replace("\"location\": \"office\"", "\"location\": \"office\", \"san\": \"urn:evil:claim\"", StringComparison.Ordinal),
            example.Replace(host, "*.example.test", StringComparison.Ordinal),
            example.Replace("\"deviceClass\": \"workstation\"", "\"deviceClass\": null", StringComparison.Ordinal),
            example.Replace("\"location\": \"office\"", "\"location\": \"a\\nline\"", StringComparison.Ordinal)
        };
        foreach (var invalid in invalidDocuments)
        {
            try { JsonFileDeviceFactsSource.Parse(Encoding.UTF8.GetBytes(invalid), host); throw new InvalidOperationException("Invalid facts accepted"); }
            catch (InvalidDataException) { checks++; }
        }
        var temp = Path.Combine(Path.GetTempPath(), "pkiproxy-facts-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(temp);
        try
        {
            var path = Path.Combine(temp, "devices.json");
            await File.WriteAllTextAsync(path, example);
            var catalog = await JsonFileImmutableAssetCatalog.LoadAsync(path);
            Check(catalog.SourceRevision == 1, "catalog snapshots the validated source revision");
            Check(catalog.Contains("asset-physical-001") && catalog.Contains("asset-virtual-001"),
                "catalog contains every exact authoritative asset ID");
            Check(!catalog.Contains("LAB-PHYSICAL-001") && !catalog.Contains(" asset-physical-001") &&
                !catalog.Contains("asset-physical-001 ") && !catalog.Contains("missing-asset"),
                "catalog membership is ordinal exact without normalization");
            var bomCatalogPath = Path.Combine(temp, "bom-catalog.json");
            await File.WriteAllBytesAsync(bomCatalogPath,
                new byte[] { 0xef, 0xbb, 0xbf }.Concat(Encoding.UTF8.GetBytes(example)).ToArray());
            Check((await JsonFileImmutableAssetCatalog.LoadAsync(bomCatalogPath)).Contains("asset-physical-001"),
                "catalog accepts the same UTF8 BOM as facts lookup");
            var source = new JsonFileDeviceFactsSource(path);
            var policy = new NativeCmcPolicy("1.3.6.1.4.1.55555.670.3", 101, 0,
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
            const string signingEku = "1.3.6.1.4.1.55555.670.1";
            var authorizer = new NativeDomainEnrollmentAuthorizer(source,
                new("urn:example:pki-broker:lab:fact:v1:profile:broker-pilot", "urn:example:pki-broker:lab:fact:v1:"),
                policy, new("1.3.6.1.4.1.55555.670.2", 2, 0, signingEku));
            var computer = new AuthenticatedDirectoryComputer("ad-fixture-object",
                "CN=CLIENT-PHYSICAL-001,CN=Computers,DC=test,DC=corp", host);
            using var deviceKey = RSA.Create(2048);
            var cmc = IncomingCmcRequestTests.CreateDomainFixture(deviceKey);
            using var signerKey = RSA.Create(2048);
            var signerRequest = new CertificateRequest("CN=Ephemeral facts test signer", signerKey,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            signerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            signerRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(signingEku) }, false));
            var now = DateTimeOffset.UtcNow;
            using var signer = signerRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddHours(1));
            var first = (await authorizer.AuthorizeAsync(computer, cmc, default)).Enrollment!;
            var firstOutput = first.Build(signer, now);
            Check(Uris(firstOutput).Contains("urn:example:pki-broker:lab:fact:v1:use-case:lab-validation"),
                "actual downstream SAN reads use-case from disk");

            var replacement = example.Replace("\"revision\": 1", "\"revision\": 2", StringComparison.Ordinal)
                .Replace("\"useCase\": \"lab-validation\"", "\"useCase\": \"engineering\"", StringComparison.Ordinal)
                .Replace("\"assetId\": \"asset-physical-001\"", "\"assetId\": \"lab-physical-002\"", StringComparison.Ordinal);
            var staged = Path.Combine(temp, "devices.next.json");
            await File.WriteAllTextAsync(staged, replacement);
            File.Move(staged, path, overwrite: true);
            Check(catalog.SourceRevision == 1 && catalog.Contains("asset-physical-001") &&
                !catalog.Contains("lab-physical-002"),
                "existing catalog is immutable after atomic facts replacement");
            var reloadedCatalog = await JsonFileImmutableAssetCatalog.LoadAsync(path);
            Check(reloadedCatalog.SourceRevision == 2 && reloadedCatalog.Contains("lab-physical-002") &&
                !reloadedCatalog.Contains("asset-physical-001"),
                "explicit catalog reload sees the validated replacement");
            var second = (await authorizer.AuthorizeAsync(computer, cmc, default)).Enrollment!;
            var secondOutput = second.Build(signer, now);
            Check(first.FactsSourceVersion == 1 && second.FactsSourceVersion == 2,
                "file revision retained in authorization");
            Check(first.AssetId == "asset-physical-001" && second.AssetId == "lab-physical-002",
                "facts source reopens and preserves exact replacement asset ID");
            Check(Uris(secondOutput).Contains("urn:example:pki-broker:lab:fact:v1:use-case:engineering") &&
                !Uris(secondOutput).Contains("urn:example:pki-broker:lab:fact:v1:use-case:lab-validation"),
                "edit changes next enrollment SAN without restarting source or authorizer");
            Check(Uris(first.Build(signer, now)).Contains("urn:example:pki-broker:lab:fact:v1:use-case:lab-validation"),
                "authorized transaction keeps its original fact snapshot");
            Check(firstOutput.SubjectNameDer.AsSpan().SequenceEqual(secondOutput.SubjectNameDer) &&
                firstOutput.OriginalRequestBinding.Matches(secondOutput.OriginalRequestBinding),
                "changing use-case never replaces AD subject or device key");

            var invalidCatalogPath = Path.Combine(temp, "invalid-catalog.json");
            foreach (var invalid in invalidDocuments)
            {
                await File.WriteAllTextAsync(invalidCatalogPath, invalid);
                try { await JsonFileImmutableAssetCatalog.LoadAsync(invalidCatalogPath); throw new InvalidOperationException("Invalid catalog facts accepted"); }
                catch (InvalidDataException) { checks++; }
            }
            await File.WriteAllBytesAsync(invalidCatalogPath, new byte[1048577]);
            try { await JsonFileImmutableAssetCatalog.LoadAsync(invalidCatalogPath); throw new InvalidOperationException("Oversized catalog facts accepted"); }
            catch (InvalidDataException) { checks++; }
            try { await JsonFileImmutableAssetCatalog.LoadAsync("devices.json"); throw new InvalidOperationException("Relative catalog path accepted"); }
            catch (ArgumentException) { checks++; }
            using (var catalogCancellation = new CancellationTokenSource())
            {
                catalogCancellation.Cancel();
                try { await JsonFileImmutableAssetCatalog.LoadAsync(path, catalogCancellation.Token); throw new InvalidOperationException("Cancelled catalog load completed"); }
                catch (OperationCanceledException) { checks++; }
            }

            await File.WriteAllTextAsync(path, "malformed");
            try { await source.FindByDnsHostNameAsync(host, default); throw new InvalidOperationException("Bad edit used stale facts"); }
            catch (InvalidDataException) { checks++; }
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            try { await source.FindByDnsHostNameAsync(host, cancelled.Token); throw new InvalidOperationException("Cancelled lookup returned facts"); }
            catch (OperationCanceledException) { checks++; }
        }
        finally { System.IO.Directory.Delete(temp, recursive: true); } // Test-owned unique directory only.
        Console.WriteLine($"Editable facts file / changed-use-case SAN checks passed: {checks}.");
    }

    private static HashSet<string> Uris(CmcEnrollmentRequest request)
    {
        var names = new AsnReader(request.SanExtensionDer, AsnEncodingRules.DER).ReadSequence();
        var result = new HashSet<string>(StringComparer.Ordinal);
        while (names.HasData)
        {
            if (names.PeekTag().TagValue == 6)
                result.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6)));
            else names.ReadEncodedValue();
        }
        return result;
    }
}
