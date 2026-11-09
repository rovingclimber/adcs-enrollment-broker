using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using PkiProxy.Signing;

namespace PkiProxy.Domain;

internal enum FactsConnectorMode { Snapshot, Live }
internal enum FactsIdentityField { Hostname, AssetId }
internal enum FactsIdentityPlacement { PathSegment, Query, Header, JsonBody }

internal sealed record HttpFactsConnectorProfile(
    int Version,
    FactsConnectorMode Mode,
    string BaseUri,
    string Method,
    string Path,
    FactsIdentityField IdentityField,
    FactsIdentityPlacement IdentityPlacement,
    string? IdentityName,
    string? IdentityPrefix,
    string? IdentitySuffix,
    Dictionary<string, string>? Query,
    Dictionary<string, string>? Headers,
    HttpFactsAuthentication Authentication,
    HttpFactsResponse Response,
    int TimeoutSeconds = 10,
    int MaximumResponseBytes = 262144,
    int MaximumJsonDepth = 16,
    int MaximumCacheAgeSeconds = 86400,
    string? TrustRootFile = null);

internal sealed record HttpFactsAuthentication(
    string Type,
    string? BearerTokenFile = null,
    string? ClientCertificateFile = null,
    string? ClientPrivateKeyFile = null,
    string? UsernameFile = null,
    string? PasswordFile = null,
    string? ApiKeyHeader = null,
    string? ApiKeyFile = null);

internal sealed record HttpFactsResponse(
    string RecordPointer,
    string Cardinality,
    Dictionary<string, string> Mappings);

internal sealed class HttpFactsConnector : IDisposable
{
    private const string HostnameField = "hostname";
    private const string AssetIdField = "assetId";
    private const string DeviceClassField = "deviceClass";
    private const string UseCaseField = "useCase";
    private const string LocationField = "location";
    private const string ManagementDomainField = "managementDomain";
    private const string ZeroOrOne = "zero-or-one";
    private const string BearerMtls = "bearer-mtls";
    private const string BasicMtls = "basic-mtls";
    private const string ApiKeyMtls = "api-key-mtls";
    private const int MaximumProfileBytes = 65536;
    private static readonly string[] FactNames =
        [HostnameField, AssetIdField, DeviceClassField, UseCaseField, LocationField, ManagementDomainField];
    private static readonly JsonSerializerOptions ProfileJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 12,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) }
    };
    private static readonly JsonSerializerOptions OutputJson = new() { WriteIndented = true };

    private readonly HttpFactsConnectorProfile profile;
    private readonly HttpClient client;
    private readonly bool ownsClient;

    private HttpFactsConnector(HttpFactsConnectorProfile profile, HttpClient client, bool ownsClient)
    {
        this.profile = profile;
        this.client = client;
        this.ownsClient = ownsClient;
    }

    internal HttpFactsConnectorProfile Profile => profile;

    internal static HttpFactsConnector Load(string profilePath)
    {
        if (!Path.IsPathFullyQualified(profilePath))
            throw new InvalidOperationException("Absolute connector profile path required.");
        var bytes = OperatingSystem.IsLinux()
            ? LinuxSecretFile.ReadAllBytes(profilePath, MaximumProfileBytes,
                "Owner-only connector profile file required.")
            : File.ReadAllBytes(profilePath);
        if (bytes.Length is 0 or > MaximumProfileBytes)
            throw new InvalidDataException("Unsupported connector profile size.");
        var profile = ParseProfile(bytes);
        var handler = BuildHandler(profile);
        return new(profile, new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan }, true);
    }

    internal static HttpFactsConnector CreateForTests(HttpFactsConnectorProfile profile, HttpMessageHandler handler)
    {
        Validate(profile, validateFiles: false);
        return new(profile, new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan }, true);
    }

    internal static HttpFactsConnectorProfile ParseProfile(ReadOnlyMemory<byte> bytes) =>
        ParseProfile(bytes, OperatingSystem.IsLinux());

    internal static HttpFactsConnectorProfile ParseProfile(ReadOnlyMemory<byte> bytes, bool validateFiles)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 12 });
            RejectDuplicates(document.RootElement);
            var value = JsonSerializer.Deserialize<HttpFactsConnectorProfile>(bytes.Span, ProfileJson)
                ?? throw new InvalidDataException("Connector profile is empty.");
            Validate(value, validateFiles);
            return value;
        }
        catch (JsonException error) { throw new InvalidDataException("Invalid connector profile JSON.", error); }
    }

    internal async Task<AuthoritativeDeviceFacts?> FetchAsync(
        string identity, long sourceVersion, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(profile.TimeoutSeconds));
        try
        {
            return await FetchCoreAsync(identity, sourceVersion, deadline.Token);
        }
        catch (OperationCanceledException error) when (deadline.IsCancellationRequested &&
            !cancellationToken.IsCancellationRequested)
        {
            const string message = "Facts source lookup timed out.";
            throw new TaskCanceledException(message, new TimeoutException(message, error), deadline.Token);
        }
    }

    private async Task<AuthoritativeDeviceFacts?> FetchCoreAsync(
        string identity, long sourceVersion, CancellationToken cancellationToken)
    {
        ValidateIdentity(identity);
        using var request = BuildRequest(identity);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound && profile.Response.Cardinality == ZeroOrOne) return null;
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("Facts source returned a non-success status.", null, response.StatusCode);
        if (response.Content.Headers.ContentType?.MediaType is not "application/json" and not "application/problem+json")
            throw new InvalidDataException("Facts source must return JSON.");
        var declared = response.Content.Headers.ContentLength;
        if (declared is < 0 || declared > profile.MaximumResponseBytes)
            throw new InvalidDataException("Facts response exceeds the configured bound.");
        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var bounded = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var count = await input.ReadAsync(buffer, cancellationToken);
            if (count == 0) break;
            if (bounded.Length + count > profile.MaximumResponseBytes)
                throw new InvalidDataException("Facts response exceeds the configured bound.");
            await bounded.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
        }
        try
        {
            using var document = JsonDocument.Parse(bounded.ToArray(),
                new JsonDocumentOptions { MaxDepth = profile.MaximumJsonDepth });
            RejectDuplicates(document.RootElement);
            var record = SelectRecord(document.RootElement);
            if (record is null) return null;
            var mapped = FactNames.ToDictionary(name => name,
                name => ScalarAt(record.Value, profile.Response.Mappings[name], name), StringComparer.Ordinal);
            if (profile.IdentityField == FactsIdentityField.Hostname &&
                !mapped[HostnameField].Equals(identity, StringComparison.OrdinalIgnoreCase) ||
                profile.IdentityField == FactsIdentityField.AssetId &&
                !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(mapped[AssetIdField]), Encoding.UTF8.GetBytes(identity)))
                throw new InvalidDataException("Facts response identity does not match the requested device.");
            return new(mapped[AssetIdField], string.Empty, mapped[DeviceClassField], mapped[UseCaseField],
                mapped[LocationField], mapped[ManagementDomainField], sourceVersion, mapped[HostnameField]);
        }
        catch (JsonException error) { throw new InvalidDataException("Invalid facts response JSON.", error); }
    }

    internal async Task<byte[]> PrepareSnapshotAsync(ReadOnlyMemory<byte> current, string expectedHash,
        CancellationToken cancellationToken)
    {
        if (profile.Mode != FactsConnectorMode.Snapshot)
            throw new InvalidOperationException("Snapshot preparation requires snapshot connector mode.");
        var actual = Convert.ToHexString(SHA256.HashData(current.Span));
        if (!actual.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Source changed before connector refresh.");
        _ = ValidatedDeviceFactsSnapshot.Parse(current);
        var root = JsonNode.Parse(current.Span)!.AsObject();
        var revision = root["revision"]!.GetValue<long>();
        var devices = root["devices"]!.AsArray();
        var replacements = new List<AuthoritativeDeviceFacts>(devices.Count);
        var changed = false;
        foreach (var node in devices)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var device = node!.AsObject();
            var identity = profile.IdentityField == FactsIdentityField.Hostname
                ? device[HostnameField]!.GetValue<string>() : device[AssetIdField]!.GetValue<string>();
            var fetched = await FetchAsync(identity, checked(revision + 1), cancellationToken)
                ?? throw new InvalidDataException("Snapshot refresh requires exactly one record for every device.");
            replacements.Add(fetched);
        }
        for (var index = 0; index < devices.Count; index++)
        {
            var old = devices[index]!.AsObject();
            var value = replacements[index];
            // Snapshot refresh updates governed facts but cannot silently replace the immutable catalogue.
            if (!old[HostnameField]!.GetValue<string>().Equals(value.AuthoritativeDnsHostName, StringComparison.OrdinalIgnoreCase) ||
                old[AssetIdField]!.GetValue<string>() != value.AssetId)
                throw new InvalidDataException("Connector cannot change immutable hostname or asset identity.");
            changed |= old[DeviceClassField]!.GetValue<string>() != value.DeviceClass ||
                old[UseCaseField]!.GetValue<string>() != value.UseCase ||
                old[LocationField]!.GetValue<string>() != value.Location ||
                old[ManagementDomainField]!.GetValue<string>() != value.ManagementDomain;
            old[DeviceClassField] = value.DeviceClass;
            old[UseCaseField] = value.UseCase;
            old[LocationField] = value.Location;
            old[ManagementDomainField] = value.ManagementDomain;
        }
        if (!changed) return current.ToArray();
        var candidateWithoutRevisionChange = JsonSerializer.SerializeToUtf8Bytes(root, OutputJson);
        return DeviceFactsEditor.PrepareDocument(current, expectedHash, candidateWithoutRevisionChange);
    }

    private HttpRequestMessage BuildRequest(string identity)
    {
        var baseUri = new Uri(profile.BaseUri, UriKind.Absolute);
        var path = profile.Path;
        var placedIdentity = string.Concat(profile.IdentityPrefix, identity, profile.IdentitySuffix);
        var query = profile.Query is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(profile.Query, StringComparer.Ordinal);
        if (profile.IdentityPlacement == FactsIdentityPlacement.PathSegment)
            path = path.Replace("{identity}", Uri.EscapeDataString(placedIdentity), StringComparison.Ordinal);
        else if (profile.IdentityPlacement == FactsIdentityPlacement.Query)
            query.Add(profile.IdentityName!, placedIdentity);
        var builder = new UriBuilder(baseUri) { Path = path };
        if (query.Count != 0)
            builder.Query = string.Join("&", query.OrderBy(item => item.Key, StringComparer.Ordinal)
                .Select(item => $"{Uri.EscapeDataString(item.Key)}={Uri.EscapeDataString(item.Value)}"));
        var request = new HttpRequestMessage(new HttpMethod(profile.Method), builder.Uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (profile.Headers is not null)
            foreach (var header in profile.Headers) request.Headers.Add(header.Key, header.Value);
        if (profile.IdentityPlacement == FactsIdentityPlacement.Header)
            request.Headers.Add(profile.IdentityName!, placedIdentity);
        if (profile.IdentityPlacement == FactsIdentityPlacement.JsonBody)
        {
            var body = new JsonObject { [profile.IdentityName!] = placedIdentity };
            request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        }
        if (profile.Authentication.Type is "bearer" or BearerMtls)
        {
            var secret = LinuxSecretFile.ReadAllBytes(profile.Authentication.BearerTokenFile!, 16384,
                "Owner-only connector bearer-token file required.");
            try
            {
                var token = Encoding.UTF8.GetString(secret).TrimEnd('\r', '\n');
                if (token.Length is 0 or > 8192 || token.Any(char.IsWhiteSpace) || token.Any(char.IsControl))
                    throw new InvalidOperationException("Invalid connector bearer token.");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
            finally { CryptographicOperations.ZeroMemory(secret); }
        }
        else if (profile.Authentication.Type is "basic" or BasicMtls)
        {
            var username = ReadTextSecret(profile.Authentication.UsernameFile!, 1024,
                "Owner-only connector username file required.");
            var password = ReadTextSecret(profile.Authentication.PasswordFile!, 8192,
                "Owner-only connector password file required.", allowWhitespace: true);
            if (username.Contains(':')) throw new InvalidOperationException("Connector username cannot contain a colon.");
            var credentials = Encoding.UTF8.GetBytes(username + ":" + password);
            try
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(credentials));
            }
            finally { CryptographicOperations.ZeroMemory(credentials); }
        }
        else if (profile.Authentication.Type is "api-key" or ApiKeyMtls)
        {
            var apiKey = ReadTextSecret(profile.Authentication.ApiKeyFile!, 8192,
                "Owner-only connector API-key file required.");
            request.Headers.Add(profile.Authentication.ApiKeyHeader!, apiKey);
        }
        return request;
    }

    private JsonElement? SelectRecord(JsonElement root)
    {
        var selected = Pointer(root, profile.Response.RecordPointer);
        if (selected.ValueKind == JsonValueKind.Array)
        {
            var records = selected.EnumerateArray().Take(2).ToArray();
            if (records.Length == 0 && profile.Response.Cardinality == ZeroOrOne) return null;
            if (records.Length != 1) throw new InvalidDataException("Facts response cardinality rejected.");
            return records[0];
        }
        if (selected.ValueKind == JsonValueKind.Null && profile.Response.Cardinality == ZeroOrOne) return null;
        if (selected.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Facts record must be a JSON object.");
        return selected;
    }

    private static string ScalarAt(JsonElement record, string pointer, string name)
    {
        var value = Pointer(record, pointer);
        if (value.ValueKind != JsonValueKind.String) throw new InvalidDataException($"Mapped {name} must be a string.");
        var text = value.GetString();
        if (string.IsNullOrWhiteSpace(text) || text.Length > 256 || text.Any(char.IsControl))
            throw new InvalidDataException($"Mapped {name} is invalid.");
        return text;
    }

    private static JsonElement Pointer(JsonElement root, string pointer)
    {
        if (pointer == "") return root;
        if (!pointer.StartsWith('/') || pointer.Length > 1024)
            throw new InvalidDataException("Invalid JSON Pointer.");
        var current = root;
        foreach (var encoded in pointer[1..].Split('/'))
        {
            var token = encoded.Replace("~1", "/", StringComparison.Ordinal)
                .Replace("~0", "~", StringComparison.Ordinal);
            if (current.ValueKind == JsonValueKind.Object)
            {
                if (!current.TryGetProperty(token, out current)) throw new InvalidDataException("Mapped JSON Pointer is missing.");
            }
            else if (current.ValueKind == JsonValueKind.Array && int.TryParse(token, out var index) && index >= 0 && index < current.GetArrayLength())
                current = current[index];
            else throw new InvalidDataException("Mapped JSON Pointer is invalid for the response.");
        }
        return current;
    }

    internal static SocketsHttpHandler BuildHandler(HttpFactsConnectorProfile profile)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(Math.Min(profile.TimeoutSeconds, 10)),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            MaxConnectionsPerServer = 2,
            UseCookies = false
        };
        if (profile.Authentication.Type is "mtls" or BearerMtls or BasicMtls or ApiKeyMtls)
            handler.SslOptions.ClientCertificates = [X509Certificate2.CreateFromPemFile(
                profile.Authentication.ClientCertificateFile!, profile.Authentication.ClientPrivateKeyFile!)];
        if (profile.TrustRootFile is not null)
        {
            // Keep hostname validation and the intermediates supplied in the TLS handshake.
            var chainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.Offline,
                RevocationFlag = X509RevocationFlag.ExcludeRoot,
                DisableCertificateDownloads = true
            };
            chainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            chainPolicy.CustomTrustStore.Add(X509CertificateLoader.LoadCertificateFromFile(profile.TrustRootFile));
            handler.SslOptions.CertificateChainPolicy = chainPolicy;
        }
        return handler;
    }

    private static void Validate(HttpFactsConnectorProfile value, bool validateFiles)
    {
        if (value.Version != 1 || !Enum.IsDefined(value.Mode) || !Enum.IsDefined(value.IdentityField) ||
            !Enum.IsDefined(value.IdentityPlacement) || value.TimeoutSeconds is < 1 or > 30 ||
            value.MaximumResponseBytes is < 1024 or > 1048576 || value.MaximumJsonDepth is < 2 or > 32 ||
            value.MaximumCacheAgeSeconds is < 60 or > 2678400)
            throw new InvalidDataException("Unsupported connector version or limits.");
        if (!Uri.TryCreate(value.BaseUri, UriKind.Absolute, out var origin) || origin.Scheme != "https" ||
            origin.UserInfo.Length != 0 || origin.Query.Length != 0 || origin.Fragment.Length != 0 || origin.AbsolutePath != "/" ||
            Uri.CheckHostName(origin.Host) == UriHostNameType.Unknown || origin.Port is < 1 or > 65535)
            throw new InvalidDataException("Connector requires an exact HTTPS origin.");
        if (value.Method is not "GET" and not "POST" || !value.Path.StartsWith('/') || value.Path.Contains('?') ||
            value.Path.Contains('#') || value.Path.Contains("//", StringComparison.Ordinal) || value.Path.Length > 2048)
            throw new InvalidDataException("Invalid connector method or path.");
        var tokenCount = value.Path.Split("{identity}", StringSplitOptions.None).Length - 1;
        if (value.IdentityPlacement == FactsIdentityPlacement.PathSegment && tokenCount != 1 ||
            value.IdentityPlacement != FactsIdentityPlacement.PathSegment && tokenCount != 0)
            throw new InvalidDataException("Path must contain the identity token exactly when path placement is selected.");
        if (value.IdentityPlacement != FactsIdentityPlacement.PathSegment &&
            !ValidToken(value.IdentityName, 128)) throw new InvalidDataException("Bounded identity field name required.");
        if (new[] { value.IdentityPrefix, value.IdentitySuffix }.Any(part =>
                part is { Length: > 256 } || part?.Any(char.IsControl) == true))
            throw new InvalidDataException("Invalid connector identity prefix or suffix.");
        if (value.IdentityPlacement == FactsIdentityPlacement.JsonBody && value.Method != "POST" ||
            value.IdentityPlacement != FactsIdentityPlacement.JsonBody && value.Method == "POST" && value.Headers?.ContainsKey("Content-Type") == true)
            throw new InvalidDataException("Invalid connector body configuration.");
        ValidateMap(value.Query, allowDollar: true);
        ValidateMap(value.Headers, allowDollar: false);
        if (value.Headers?.Keys.Any(name => name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) || name.Equals("Host", StringComparison.OrdinalIgnoreCase)) == true)
            throw new InvalidDataException("Security-sensitive connector headers are controlled by the engine.");
        if (value.Authentication is null || value.Authentication.Type is not
            ("none" or "bearer" or "basic" or "api-key" or "mtls" or BearerMtls or BasicMtls or ApiKeyMtls))
            throw new InvalidDataException("Unsupported connector authentication type.");
        var needsBearer = value.Authentication.Type is "bearer" or BearerMtls;
        var needsBasic = value.Authentication.Type is "basic" or BasicMtls;
        var needsApiKey = value.Authentication.Type is "api-key" or ApiKeyMtls;
        var needsMtls = value.Authentication.Type is "mtls" or BearerMtls or BasicMtls or ApiKeyMtls;
        if (needsBearer != (value.Authentication.BearerTokenFile is not null) ||
            needsBasic != (value.Authentication.UsernameFile is not null && value.Authentication.PasswordFile is not null) ||
            needsApiKey != (value.Authentication.ApiKeyFile is not null && ValidToken(value.Authentication.ApiKeyHeader, 128)) ||
            needsMtls != (value.Authentication.ClientCertificateFile is not null && value.Authentication.ClientPrivateKeyFile is not null))
            throw new InvalidDataException("Connector credential references do not match its authentication type.");
        if (value.Response is null || value.Response.Cardinality is not ("exactly-one" or ZeroOrOne) ||
            value.Response.RecordPointer is null || value.Response.Mappings is null ||
            value.Response.Mappings.Count != FactNames.Length ||
            FactNames.Any(name => !value.Response.Mappings.TryGetValue(name, out var pointer) || pointer is null || pointer.Length > 1024) ||
            value.Response.Mappings.Keys.Any(name => !FactNames.Contains(name, StringComparer.Ordinal)))
            throw new InvalidDataException("Complete exact connector response mappings required.");
        if (validateFiles)
        {
            foreach (var path in new[] { value.Authentication.BearerTokenFile, value.Authentication.ClientCertificateFile,
                         value.Authentication.ClientPrivateKeyFile, value.Authentication.UsernameFile,
                         value.Authentication.PasswordFile, value.Authentication.ApiKeyFile,
                         value.TrustRootFile }.Where(path => path is not null))
                LinuxSecretFile.Validate(path!, "Owner-only regular connector credential or trust file required.");
        }
    }

    private static string ReadTextSecret(string path, int maximumBytes, string failure, bool allowWhitespace = false)
    {
        var bytes = LinuxSecretFile.ReadAllBytes(path, maximumBytes, failure);
        try
        {
            var value = Encoding.UTF8.GetString(bytes).TrimEnd('\r', '\n');
            if (value.Length == 0 || value.Any(char.IsControl) || !allowWhitespace && value.Any(char.IsWhiteSpace))
                throw new InvalidOperationException(failure);
            return value;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void ValidateMap(Dictionary<string, string>? values, bool allowDollar)
    {
        if (values is null) return;
        if (values.Count > 32) throw new InvalidDataException("Too many connector values.");
        foreach (var pair in values)
            if (!ValidToken(pair.Key, 128, allowDollar) || pair.Value.Length > 2048 || pair.Value.Any(char.IsControl))
                throw new InvalidDataException("Invalid connector query or header value.");
    }

    private static bool ValidToken(string? value, int maximum, bool allowDollar = false) =>
        value is { Length: > 0 } && value.Length <= maximum &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' || allowDollar && character == '$');

    private static void ValidateIdentity(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 256 || value.Any(char.IsControl))
            throw new ArgumentException("Invalid connector lookup identity.", nameof(value));
    }

    private static void RejectDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate JSON property.");
                RejectDuplicates(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) RejectDuplicates(item);
    }

    public void Dispose() { if (ownsClient) client.Dispose(); }
}

internal sealed class LiveHttpDeviceFactsSource(
    HttpFactsConnector connector,
    JsonFileDeviceFactsSource cache,
    string cachePath,
    bool allowCacheFallback,
    TimeProvider? clock = null,
    bool ownsConnector = true) : IDomainDeviceFactsSource, IAuthoritativeDeviceFactsSource, IDisposable
{
    private readonly TimeProvider time = clock ?? TimeProvider.System;

    internal JsonFileDeviceFactsSource Cache => cache;
    internal string CachePath => Path.GetFullPath(cachePath);
    internal LiveHttpDeviceFactsSource ForRenewal() => new(connector, cache, cachePath, true, time, false);

    public async ValueTask<AuthoritativeDeviceFacts?> FindByDnsHostNameAsync(string dnsHostName, CancellationToken cancellationToken) =>
        await FindAsync(dnsHostName, byAsset: false, cancellationToken);

    public ValueTask<AuthoritativeDeviceFacts?> FindByDirectoryObjectIdAsync(string directoryObjectId, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); return ValueTask.FromResult<AuthoritativeDeviceFacts?>(null); }

    public async ValueTask<AuthoritativeDeviceFacts?> FindByAssetIdAsync(string assetId, CancellationToken cancellationToken) =>
        await FindAsync(assetId, byAsset: true, cancellationToken);

    private async ValueTask<AuthoritativeDeviceFacts?> FindAsync(string identity, bool byAsset, CancellationToken token)
    {
        var cached = byAsset ? await cache.FindByAssetIdAsync(identity, token) :
            await cache.FindByDnsHostNameAsync(identity, token);
        if (cached is null) return null; // Live lookups cannot invent immutable catalogue membership.
        var connectorIdentity = connector.Profile.IdentityField == FactsIdentityField.AssetId
            ? cached.AssetId : cached.AuthoritativeDnsHostName!;
        try
        {
            var fetched = await connector.FetchAsync(connectorIdentity, cached.SourceVersion, token);
            if (fetched is null || !SameIdentity(fetched, cached))
                throw new InvalidDataException("Live facts result disagrees with the immutable catalogue identity.");
            return fetched with { DirectoryObjectId = cached.DirectoryObjectId };
        }
        catch (HttpRequestException error) when (allowCacheFallback && IsTransient(error))
        {
            return await FallbackAsync(error);
        }
        catch (TaskCanceledException error) when (allowCacheFallback && !token.IsCancellationRequested &&
            error.InnerException is TimeoutException)
        {
            return await FallbackAsync(error);
        }

        async Task<AuthoritativeDeviceFacts> FallbackAsync(Exception error)
        {
            // Reopen after the outage so a publication during the request cannot
            // let superseded facts borrow the replacement file's freshness.
            var (snapshot, lastWriteTime) = await cache.LoadSnapshotWithWriteTimeAsync(token);
            var age = time.GetUtcNow() - lastWriteTime;
            if (age < TimeSpan.Zero || age > TimeSpan.FromSeconds(connector.Profile.MaximumCacheAgeSeconds))
                throw new InvalidOperationException("Facts cache is too old for renewal fallback.", error);
            var current = byAsset ? snapshot.FindByAssetId(identity) : snapshot.FindByDnsHostName(identity);
            if (current is null || !SameIdentity(current, cached) || current.DirectoryObjectId != cached.DirectoryObjectId ||
                current.SourceVersion < cached.SourceVersion ||
                (current.SourceVersion == cached.SourceVersion && current != cached))
                throw new InvalidOperationException("Facts cache changed inconsistently during renewal lookup.", error);
            return current;
        }
    }

    private static bool SameIdentity(AuthoritativeDeviceFacts left, AuthoritativeDeviceFacts right) =>
        string.Equals(left.AssetId, right.AssetId, StringComparison.Ordinal) &&
        string.Equals(left.AuthoritativeDnsHostName, right.AuthoritativeDnsHostName, StringComparison.OrdinalIgnoreCase);

    private static bool IsTransient(HttpRequestException error)
    {
        if (error.StatusCode is not { } status)
            return error.HttpRequestError is HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError;
        var code = (int)status;
        return status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests || code is >= 500 and <= 599;
    }

    public void Dispose() { if (ownsConnector) connector.Dispose(); }
}
