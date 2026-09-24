using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using PkiProxy.Authentication;

namespace PkiProxy.Domain;

internal sealed record OperationalFactsAsset(string AssetId, string Hostname,
    string DeviceClass, string UseCase, string Location, string ManagementDomain);
internal sealed record OperationalFactsSnapshot(long Revision, string Sha256,
    IReadOnlyList<OperationalFactsAsset> Assets);
internal sealed record OperationalFactsUpdate(string DeviceClass, string UseCase,
    string Location, string ManagementDomain);
internal sealed record OperationalFactsWrite(long Revision, string Sha256,
    OperationalFactsAsset Asset, bool Changed, string? Transaction = null);

internal enum OperationalFactsWriteResult
{
    Updated,
    Unchanged,
    UnknownAsset,
    InvalidSelection,
    PreconditionFailed,
    Busy,
    Blocked
}

internal sealed record OperationalFactsWriteOutcome(OperationalFactsWriteResult Result,
    OperationalFactsWrite? Write = null);

internal sealed class OperationalFactsManagement : IDisposable
{
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectory = PrivateFile | UnixFileMode.UserExecute;
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 4
    };
    private static readonly JsonSerializerOptions OutputJson = new() { WriteIndented = true };
    private readonly string factsPath;
    private readonly Dictionary<string, ImmutableIdentity> identities;
    private readonly HashSet<string> allowedDeviceClasses;
    private readonly HashSet<string> allowedUseCases;
    private readonly HashSet<string> allowedLocations;
    private readonly HashSet<string> allowedManagementDomains;
    private readonly JsonNode useCaseCatalogue;
    private readonly BootstrapTechnicianAuthenticator readers;
    private readonly BootstrapTechnicianAuthenticator writers;
    private readonly SemaphoreSlim writeGate = new(1, 1);
    private bool writesBlocked;

    private OperationalFactsManagement(string factsPath, Configuration configuration,
        BootstrapTechnicianAuthenticator readers, BootstrapTechnicianAuthenticator writers,
        JsonObject initial)
    {
        this.factsPath = factsPath;
        this.readers = readers;
        this.writers = writers;
        var devices = initial["devices"]!.AsArray();
        identities = new(StringComparer.Ordinal);
        allowedDeviceClasses = Catalogue(configuration.AllowedDeviceClasses, "device class");
        allowedLocations = Catalogue(configuration.AllowedLocations, "location");
        allowedManagementDomains = Catalogue(configuration.AllowedManagementDomains, "management domain");
        foreach (var node in devices)
        {
            var device = node!.AsObject();
            var assetId = Text(device, "assetId");
            var hostname = Text(device, "hostname");
            if (!TechnicianRoutePolicy.IsCanonicalAssetId(assetId) ||
                !identities.TryAdd(assetId, new(assetId, hostname)))
                throw new InvalidDataException("Facts management requires unique route-safe immutable asset identities.");
            if (!allowedDeviceClasses.Contains(Text(device, "deviceClass")) ||
                !allowedLocations.Contains(Text(device, "location")) ||
                !allowedManagementDomains.Contains(Text(device, "managementDomain")))
                throw new InvalidDataException("Existing device facts are outside the configured fact catalogues.");
        }
        allowedUseCases = initial["useCases"]!.AsArray().Select(node =>
            Text(node!.AsObject(), "id")).ToHashSet(StringComparer.Ordinal);
        useCaseCatalogue = initial["useCases"]!.DeepClone();
        if (identities.Count == 0 || allowedDeviceClasses.Count == 0 || allowedLocations.Count == 0 ||
            allowedManagementDomains.Count == 0 || allowedUseCases.Count == 0 ||
            identities.Count > configuration.MaximumAssets)
            throw new InvalidDataException("Facts management catalogue is empty or exceeds configured bounds.");
    }

    internal static async Task<OperationalFactsManagement> LoadAsync(string configurationPath,
        string expectedFactsPath, BootstrapTechnicianAuthenticator readers,
        BootstrapTechnicianAuthenticator writers,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Operational facts management requires Linux.");
        if (!Path.IsPathFullyQualified(configurationPath))
            throw new ArgumentException("Absolute facts management configuration path required.");
        var info = new FileInfo(configurationPath);
        if (!info.Exists || info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            info.Length is <= 0 or > 65_536 || File.GetUnixFileMode(configurationPath) != PrivateFile)
            throw new IOException("Owner-only regular facts management configuration required.");
        Configuration value;
        try
        {
            await using var stream = new FileStream(configurationPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            value = await JsonSerializer.DeserializeAsync<Configuration>(stream, StrictJson, cancellationToken)
                ?? throw new InvalidDataException("Missing facts management configuration.");
        }
        catch (JsonException error)
        { throw new InvalidDataException("Invalid facts management configuration JSON.", error); }
        if (value.Version != 1 || value.MaximumAssets is < 1 or > 1000 ||
            !Path.IsPathFullyQualified(value.DeviceFactsFile) ||
            !string.Equals(Path.GetFullPath(value.DeviceFactsFile), Path.GetFullPath(expectedFactsPath),
                StringComparison.Ordinal))
            throw new InvalidDataException("Invalid facts management configuration or facts authority mismatch.");

        var factsInfo = new FileInfo(value.DeviceFactsFile);
        var factsParent = Path.GetDirectoryName(Path.GetFullPath(value.DeviceFactsFile))!;
        if (!factsInfo.Exists || factsInfo.LinkTarget is not null ||
            factsInfo.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            File.GetUnixFileMode(value.DeviceFactsFile) != PrivateFile ||
            new DirectoryInfo(factsParent).LinkTarget is not null ||
            File.GetUnixFileMode(factsParent) != PrivateDirectory)
            throw new IOException("Owner-only regular facts authority and directory required.");

        _ = DeviceFactsPublisher.Reconcile(value.DeviceFactsFile);
        var bytes = DeviceFactsPublisher.Read(value.DeviceFactsFile);
        _ = JsonFileDeviceFactsSource.Parse(bytes, null);
        var initial = Document(bytes);
        return new(Path.GetFullPath(value.DeviceFactsFile), value,
            readers ?? throw new ArgumentNullException(nameof(readers)),
            writers ?? throw new ArgumentNullException(nameof(writers)), initial);
    }

    internal BootstrapTechnicianAuthorization Authorize(
        Microsoft.AspNetCore.Authentication.AuthenticateResult authentication,
        TechnicianCapability capability, DateTimeOffset now) => capability switch
        {
            TechnicianCapability.FactsRead => readers.Authorize(authentication, now),
            TechnicianCapability.FactsWrite => writers.Authorize(authentication, now),
            _ => throw new ArgumentOutOfRangeException(nameof(capability))
        };
    internal string DeviceFactsFile => factsPath;

    internal OperationalFactsSnapshot ReadAll()
    {
        var current = ReadCurrent();
        return new(current.Revision, current.Hash,
            current.Devices.Values.OrderBy(item => item.AssetId, StringComparer.Ordinal).ToArray());
    }

    internal OperationalFactsAsset? Read(string assetId)
    {
        if (!TechnicianRoutePolicy.IsCanonicalAssetId(assetId) || !identities.ContainsKey(assetId))
            return null;
        return ReadCurrent().Devices.GetValueOrDefault(assetId);
    }

    internal async Task<OperationalFactsWriteOutcome> PutAsync(string assetId,
        long expectedRevision, OperationalFactsUpdate update, string actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        if (!TechnicianRoutePolicy.IsCanonicalAssetId(assetId) || !identities.TryGetValue(assetId, out var identity))
            return new(OperationalFactsWriteResult.UnknownAsset);
        if (!Allowed(update)) return new(OperationalFactsWriteResult.InvalidSelection);
        if (actor is not { Length: 39 } || !actor.StartsWith("ad:", StringComparison.Ordinal) ||
            !Guid.TryParseExact(actor.AsSpan(3), "D", out _))
            throw new ArgumentException("Immutable authenticated technician subject required.", nameof(actor));
        if (!await writeGate.WaitAsync(0, cancellationToken))
            return new(OperationalFactsWriteResult.Busy);
        try
        {
            if (writesBlocked) return new(OperationalFactsWriteResult.Blocked);
            var current = ReadCurrent();
            if (current.Revision != expectedRevision)
                return new(OperationalFactsWriteResult.PreconditionFailed);
            if (current.Devices.TryGetValue(assetId, out var existing) &&
                existing.DeviceClass == update.DeviceClass && existing.UseCase == update.UseCase &&
                existing.Location == update.Location && existing.ManagementDomain == update.ManagementDomain)
                return new(OperationalFactsWriteResult.Unchanged,
                    new(current.Revision, current.Hash, existing, false));

            var document = current.Document;
            var devices = document["devices"]!.AsArray();
            var target = devices.Select(node => node!.AsObject()).SingleOrDefault(node =>
                Text(node, "assetId") == assetId);
            if (target is null)
            {
                target = new JsonObject { ["hostname"] = identity.Hostname, ["assetId"] = identity.AssetId };
                devices.Add(target);
            }
            target["hostname"] = identity.Hostname;
            target["assetId"] = identity.AssetId;
            target["deviceClass"] = update.DeviceClass;
            target["useCase"] = update.UseCase;
            target["location"] = update.Location;
            target["managementDomain"] = update.ManagementDomain;
            document["revision"] = current.Revision;
            var proposal = JsonSerializer.SerializeToUtf8Bytes(document, OutputJson);
            var draft = DeviceFactsEditor.PrepareDocument(current.Bytes, current.Hash, proposal);
            FactsPublication publication;
            try
            {
                publication = DeviceFactsPublisher.Publish(factsPath, draft, current.Hash,
                    Convert.ToHexString(SHA256.HashData(draft)), operatorIdentity: actor,
                    operatorCapability: TechnicianCapabilities.FactsWrite);
            }
            catch
            {
                // A thrown call can be after the atomic rename. A restarted process
                // must reconcile durable images before another write is allowed.
                writesBlocked = true;
                throw;
            }
            var updated = ReadCurrent();
            if (updated.Revision != publication.Revision || updated.Hash != publication.PublishedSha256 ||
                !updated.Devices.TryGetValue(assetId, out var selected))
            {
                writesBlocked = true;
                throw new IOException("Published facts could not be reconciled in-process.");
            }
            return new(OperationalFactsWriteResult.Updated,
                new(updated.Revision, updated.Hash, selected, true, publication.Transaction));
        }
        finally { writeGate.Release(); }
    }

    private Current ReadCurrent()
    {
        var bytes = DeviceFactsPublisher.Read(factsPath);
        _ = JsonFileDeviceFactsSource.Parse(bytes, null);
        var document = Document(bytes);
        if (!JsonNode.DeepEquals(useCaseCatalogue, document["useCases"]))
            throw new InvalidDataException("The operational facts catalogue changed outside the manager.");
        var records = new Dictionary<string, OperationalFactsAsset>(StringComparer.Ordinal);
        foreach (var node in document["devices"]!.AsArray())
        {
            var item = node!.AsObject();
            var assetId = Text(item, "assetId");
            var parsed = Asset(item);
            if (!identities.TryGetValue(assetId, out var immutable) ||
                !string.Equals(Text(item, "hostname"), immutable.Hostname, StringComparison.OrdinalIgnoreCase) ||
                !Allowed(new(parsed.DeviceClass, parsed.UseCase, parsed.Location, parsed.ManagementDomain)) ||
                !records.TryAdd(assetId, parsed))
                throw new InvalidDataException("Immutable facts asset identity changed outside the manager.");
        }
        return new(document["revision"]!.GetValue<long>(),
            Convert.ToHexString(SHA256.HashData(bytes)), bytes, document, records);
    }

    private bool Allowed(OperationalFactsUpdate value) =>
        Bounded(value.DeviceClass) && Bounded(value.UseCase) && Bounded(value.Location) &&
        Bounded(value.ManagementDomain) && allowedDeviceClasses.Contains(value.DeviceClass) &&
        allowedUseCases.Contains(value.UseCase) && allowedLocations.Contains(value.Location) &&
        allowedManagementDomains.Contains(value.ManagementDomain);
    private static HashSet<string> Catalogue(string[]? values, string label)
    {
        if (values is null || values.Length is 0 or > 100 || values.Any(value => !Bounded(value)))
            throw new InvalidDataException("Invalid " + label + " catalogue.");
        var result = values.ToHashSet(StringComparer.Ordinal);
        if (result.Count != values.Length) throw new InvalidDataException("Duplicate " + label + " catalogue value.");
        return result;
    }
    private static bool Bounded(string? value) => value is { Length: > 0 and <= 256 } &&
        !value.Any(char.IsControl);
    private static OperationalFactsAsset Asset(JsonObject value) => new(Text(value, "assetId"),
        Text(value, "hostname"), Text(value, "deviceClass"), Text(value, "useCase"),
        Text(value, "location"), Text(value, "managementDomain"));
    private static string Text(JsonObject value, string name) => value[name]!.GetValue<string>();
    private static JsonObject Document(ReadOnlyMemory<byte> bytes)
    {
        var span = bytes.Span;
        if (span.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) span = span[3..];
        return JsonNode.Parse(span)!.AsObject();
    }

    public void Dispose() => writeGate.Dispose();

    internal sealed record Configuration(int Version, string DeviceFactsFile, int MaximumAssets,
        string[] AllowedDeviceClasses, string[] AllowedLocations, string[] AllowedManagementDomains);
    private sealed record ImmutableIdentity(string AssetId, string Hostname);
    private sealed record Current(long Revision, string Hash, byte[] Bytes, JsonObject Document,
        Dictionary<string, OperationalFactsAsset> Devices);
}
