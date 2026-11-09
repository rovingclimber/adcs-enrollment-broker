using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PkiProxy.Domain;

// Editable MVP source of truth, not a client-uploaded file. Mount read-only in
// the broker and let the administrator/editor own the containing directory.
// Reopen for every enrollment so atomic replacement takes effect without restart.
internal sealed class JsonFileDeviceFactsSource : IDomainDeviceFactsSource, IAuthoritativeDeviceFactsSource
{
    private readonly string path;

    public JsonFileDeviceFactsSource(string path)
    {
        this.path = ValidatedDeviceFactsSnapshot.RequireAbsolutePath(path);
    }

    public ValueTask<AuthoritativeDeviceFacts?> FindByDnsHostNameAsync(string dnsHostName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dnsHostName);
        return ReadAsync(dnsHostName, cancellationToken);
    }

    public ValueTask<AuthoritativeDeviceFacts?> FindByDirectoryObjectIdAsync(
        string directoryObjectId, CancellationToken cancellationToken)
    {
        // The editable file has no directory-object authority. Keeping this
        // interface member closed prevents a bootstrap asset from being
        // confused with an authenticated AD object identifier.
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<AuthoritativeDeviceFacts?>(null);
    }

    public async ValueTask<AuthoritativeDeviceFacts?> FindByAssetIdAsync(
        string assetId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(assetId);
        var snapshot = await ValidatedDeviceFactsSnapshot.LoadAsync(path, cancellationToken);
        return snapshot.FindByAssetId(assetId);
    }

    internal async Task ValidateAsync(CancellationToken cancellationToken) =>
        _ = await ValidatedDeviceFactsSnapshot.LoadAsync(path, cancellationToken);

    internal Task<(ValidatedDeviceFactsSnapshot Snapshot, DateTimeOffset LastWriteTime)>
        LoadSnapshotWithWriteTimeAsync(CancellationToken cancellationToken) =>
        ValidatedDeviceFactsSnapshot.LoadWithWriteTimeAsync(path, cancellationToken);

    private async ValueTask<AuthoritativeDeviceFacts?> ReadAsync(string? dnsHostName, CancellationToken cancellationToken)
    {
        var snapshot = await ValidatedDeviceFactsSnapshot.LoadAsync(path, cancellationToken);
        return snapshot.FindByDnsHostName(dnsHostName);
    }

    internal static AuthoritativeDeviceFacts? Parse(ReadOnlyMemory<byte> utf8, string? dnsHostName) =>
        ValidatedDeviceFactsSnapshot.Parse(utf8).FindByDnsHostName(dnsHostName);
}

internal sealed class JsonFileImmutableAssetCatalog : IImmutableAssetCatalog
{
    private readonly FrozenDictionary<string, string> assetHostnames;

    private JsonFileImmutableAssetCatalog(ValidatedDeviceFactsSnapshot snapshot)
    {
        SourceRevision = snapshot.Revision;
        assetHostnames = snapshot.EnumerateAssetHostnames().ToFrozenDictionary(StringComparer.Ordinal);
    }

    internal long SourceRevision { get; }

    internal static async Task<JsonFileImmutableAssetCatalog> LoadAsync(
        string path,
        CancellationToken cancellationToken = default) =>
        new(await ValidatedDeviceFactsSnapshot.LoadAsync(path, cancellationToken));

    public bool Contains(string authoritativeAssetId) => assetHostnames.ContainsKey(authoritativeAssetId);

    public string? FindDnsHostName(string authoritativeAssetId) =>
        assetHostnames.GetValueOrDefault(authoritativeAssetId);
}

// One validated document image backs both hostname facts lookup and immutable
// asset membership. Its source records and collections never escape this type.
internal sealed class ValidatedDeviceFactsSnapshot
{
    private const int MaximumBytes = 1048576;
    private readonly Device[] devices;
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8
    };

    private ValidatedDeviceFactsSnapshot(long revision, Device[] devices)
    {
        Revision = revision;
        this.devices = [.. devices];
    }

    internal long Revision { get; }

    internal static string RequireAbsolutePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
            throw new ArgumentException("Facts file needs an absolute path.", nameof(path));
        return path;
    }

    internal static async Task<ValidatedDeviceFactsSnapshot> LoadAsync(
        string path, CancellationToken cancellationToken) =>
        (await LoadCoreAsync(path, captureWriteTime: false, cancellationToken)).Snapshot;

    internal static Task<(ValidatedDeviceFactsSnapshot Snapshot, DateTimeOffset LastWriteTime)> LoadWithWriteTimeAsync(
        string path, CancellationToken cancellationToken) =>
        LoadCoreAsync(path, captureWriteTime: true, cancellationToken);

    private static async Task<(ValidatedDeviceFactsSnapshot Snapshot, DateTimeOffset LastWriteTime)> LoadCoreAsync(
        string path,
        bool captureWriteTime,
        CancellationToken cancellationToken)
    {
        path = RequireAbsolutePath(path);
        cancellationToken.ThrowIfCancellationRequested();
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read | FileShare.Delete, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        DateTimeOffset lastWriteTime = captureWriteTime ? File.GetLastWriteTimeUtc(stream.SafeFileHandle) : default;
        if (stream.Length is 0 or > MaximumBytes)
            throw new InvalidDataException("Unsupported device facts file size.");
        var bytes = new byte[(int)stream.Length];
        await stream.ReadExactlyAsync(bytes, cancellationToken);
        if (await stream.ReadAsync(new byte[1], cancellationToken) != 0 ||
            (captureWriteTime && File.GetLastWriteTimeUtc(stream.SafeFileHandle) != lastWriteTime.UtcDateTime))
            throw new InvalidDataException("Facts file changed during read; publish edits by atomic replacement.");
        return (Parse(bytes), lastWriteTime);
    }

    internal static ValidatedDeviceFactsSnapshot Parse(ReadOnlyMemory<byte> utf8)
    {
        if (utf8.Length is 0 or > MaximumBytes) throw new InvalidDataException("Unsupported device facts file size.");
        if (utf8.Span.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) utf8 = utf8[3..];
        try
        {
            using var document = JsonDocument.Parse(utf8, new JsonDocumentOptions { MaxDepth = 8 });
            RejectDuplicateProperties(document.RootElement);
            var data = document.RootElement.Deserialize<FactsFile>(Options)
                ?? throw new InvalidDataException("Device facts document is empty.");
            if (data.SchemaVersion != 1 || data.Revision < 1 || data.Devices is null || data.Devices.Length > 1000 ||
                data.UseCases is null || data.UseCases.Length is 0 or > 100)
                throw new InvalidDataException("Unsupported device facts schema, revision or record count.");
            if (data.UseCases.Any(useCase => useCase is null || !IsValue(useCase.Id) || !IsValue(useCase.Label)))
                throw new InvalidDataException("Invalid or duplicate use-case definition.");
            var useCases = data.UseCases.Select(useCase => useCase.Id).ToHashSet(StringComparer.Ordinal);
            if (useCases.Count != data.UseCases.Length)
                throw new InvalidDataException("Invalid or duplicate use-case definition.");
            if (data.Devices.Any(device => device is null || !IsHostname(device.Hostname) ||
                    !IsValue(device.AssetId) || !IsValue(device.DeviceClass) || !IsValue(device.Location) ||
                    !IsValue(device.ManagementDomain) || device.UseCase is null || !useCases.Contains(device.UseCase)) ||
                data.Devices.Select(device => device.Hostname).Distinct(StringComparer.OrdinalIgnoreCase).Count() != data.Devices.Length ||
                data.Devices.Select(device => device.AssetId).Distinct(StringComparer.Ordinal).Count() != data.Devices.Length)
                throw new InvalidDataException("Invalid, ambiguous or unclassified device facts record.");
            ValidateDirectoryBindings(data.Devices);
            return new(data.Revision, data.Devices);
        }
        catch (JsonException exception)
        { throw new InvalidDataException("Invalid device facts JSON.", exception); }
    }

    private static void ValidateDirectoryBindings(IEnumerable<Device> devices)
    {
        var boundIds = devices.Select(device => device.DirectoryObjectId).Where(id => id.HasValue).ToArray();
        if (boundIds.Contains(Guid.Empty) || boundIds.Distinct().Count() != boundIds.Length)
            throw new InvalidDataException("Invalid or duplicate directory object binding.");
    }

    internal IEnumerable<KeyValuePair<string, string>> EnumerateAssetHostnames() =>
        devices.Select(device => KeyValuePair.Create(device.AssetId, device.Hostname));

    internal bool HasSameDirectoryBindings(ValidatedDeviceFactsSnapshot other) =>
        DirectoryBindings().ToHashSet().SetEquals(other.DirectoryBindings());

    private IEnumerable<(Guid? ObjectId, string AssetId, string Hostname)> DirectoryBindings() =>
        devices.Where(device => device.DirectoryObjectId.HasValue)
            .Select(device => (device.DirectoryObjectId, device.AssetId, device.Hostname.ToUpperInvariant()));

    internal AuthoritativeDeviceFacts? FindByDnsHostName(string? dnsHostName)
    {
        var selected = devices.FirstOrDefault(device =>
            device.Hostname.Equals(dnsHostName, StringComparison.OrdinalIgnoreCase));
        // This source has no authority to supply AD's DN. The native domain
        // authorizer supplies that separately from the authenticated object.
        return selected is null ? null : Facts(selected);
    }

    internal AuthoritativeDeviceFacts? FindByAssetId(string? assetId)
    {
        var selected = devices.FirstOrDefault(device =>
            device.AssetId.Equals(assetId, StringComparison.Ordinal));
        return selected is null ? null : Facts(selected);
    }

    private AuthoritativeDeviceFacts Facts(Device selected) => new(selected.AssetId, string.Empty,
        selected.DeviceClass, selected.UseCase, selected.Location, selected.ManagementDomain,
        Revision, selected.Hostname) { DirectoryObjectId = selected.DirectoryObjectId };

    private static bool IsValue(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 256 && !value.Any(char.IsControl);
    internal static bool IsHostname([NotNullWhen(true)] string? value) => value is { Length: > 0 and <= 253 } && value.Contains('.') &&
        value.Split('.').All(label => label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-' &&
            label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'));
    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate device facts JSON property.");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) RejectDuplicateProperties(item);
    }

    private sealed record FactsFile(int SchemaVersion, long Revision, UseCase[] UseCases, Device[] Devices);
    private sealed record UseCase(string Id, string Label);
    private sealed record Device(string Hostname, string AssetId, string DeviceClass, string UseCase,
        string Location, string ManagementDomain, Guid? DirectoryObjectId = null);
}
