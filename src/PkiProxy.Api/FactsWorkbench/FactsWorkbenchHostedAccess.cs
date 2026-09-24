using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PkiProxy.FactsWorkbench;

internal sealed class FactsWorkbenchHostedAccess : IDisposable
{
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 4
    };
    private readonly Dictionary<string, string> allowedOperators;

    private FactsWorkbenchHostedAccess(HostedConfiguration value, IPAddress listenAddress,
        IPAddress trustedProxyAddress, Uri externalOrigin, X509Certificate2 certificate)
    {
        Value = value;
        ListenAddress = listenAddress;
        TrustedProxyAddress = trustedProxyAddress;
        ExternalOrigin = externalOrigin;
        Certificate = certificate;
        allowedOperators = value.AllowedOperators.ToDictionary(x => x, x => x, StringComparer.OrdinalIgnoreCase);
    }

    internal HostedConfiguration Value { get; }
    internal IPAddress ListenAddress { get; }
    internal IPAddress TrustedProxyAddress { get; }
    internal Uri ExternalOrigin { get; }
    internal X509Certificate2 Certificate { get; }

    internal static FactsWorkbenchHostedAccess Load(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Hosted facts workbench requires Linux.");
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Absolute hosted configuration path required.");
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || info.Length is <= 0 or > 65536 ||
            File.GetUnixFileMode(path) != PrivateFile)
            throw new IOException("Owner-only regular hosted configuration required.");
        HostedConfiguration value;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            value = JsonSerializer.Deserialize<HostedConfiguration>(stream, Options)
                ?? throw new InvalidDataException("Missing hosted configuration.");
        }
        catch (JsonException error) { throw new InvalidDataException("Invalid hosted configuration JSON.", error); }
        if (value.Version != 1 || value.HttpsPort is < 1 or > 65535 ||
            string.IsNullOrWhiteSpace(value.ListenAddress) || string.IsNullOrWhiteSpace(value.TrustedProxyAddress) ||
            string.IsNullOrWhiteSpace(value.ExternalOrigin) || string.IsNullOrWhiteSpace(value.TlsCertificateFile) ||
            string.IsNullOrWhiteSpace(value.TlsPrivateKeyFile) ||
            !IPAddress.TryParse(value.ListenAddress, out var listen) || listen.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            IPAddress.IsLoopback(listen) || listen.Equals(IPAddress.Any) ||
            !IPAddress.TryParse(value.TrustedProxyAddress, out var proxy) || proxy.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            proxy.Equals(IPAddress.Any) || proxy.Equals(listen) ||
            !Uri.TryCreate(value.ExternalOrigin, UriKind.Absolute, out var origin) || origin.Scheme != Uri.UriSchemeHttps ||
            origin.HostNameType != UriHostNameType.Dns || !string.IsNullOrEmpty(origin.UserInfo) ||
            origin.AbsolutePath != "/" || !string.IsNullOrEmpty(origin.Query) || !string.IsNullOrEmpty(origin.Fragment) ||
            value.AllowedOperators is null || value.AllowedOperators.Length is 0 or > 64 ||
            value.AllowedOperators.Any(x => !ValidIdentity(x)) ||
            value.AllowedOperators.Distinct(StringComparer.OrdinalIgnoreCase).Count() != value.AllowedOperators.Length ||
            !Path.IsPathFullyQualified(value.TlsCertificateFile) || !Path.IsPathFullyQualified(value.TlsPrivateKeyFile))
            throw new InvalidDataException("Invalid hosted workbench configuration.");
        var key = new FileInfo(value.TlsPrivateKeyFile);
        if (!key.Exists || key.LinkTarget is not null || File.GetUnixFileMode(value.TlsPrivateKeyFile) != PrivateFile)
            throw new IOException("Owner-only regular TLS private key required.");
        X509Certificate2? certificate = null;
        try
        {
            certificate = X509Certificate2.CreateFromPemFile(value.TlsCertificateFile, value.TlsPrivateKeyFile);
            using var publicKey = certificate.GetRSAPublicKey();
            var usages = certificate.Extensions.OfType<X509KeyUsageExtension>().ToArray();
            var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
            if (!certificate.HasPrivateKey || publicKey is null || publicKey.KeySize < 2048 ||
                DateTimeOffset.UtcNow.UtcDateTime < certificate.NotBefore.ToUniversalTime() ||
                DateTimeOffset.UtcNow.UtcDateTime >= certificate.NotAfter.ToUniversalTime() ||
                !certificate.MatchesHostname(origin.Host, allowWildcards: false, allowCommonName: false) ||
                usages.Length != 1 || (usages[0].KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment)) == 0 ||
                (usages[0].KeyUsages & ~(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment)) != 0 ||
                eku.Length != 1 || eku[0].EnhancedKeyUsages.Count != 1 ||
                eku[0].EnhancedKeyUsages[0].Value != "1.3.6.1.5.5.7.3.1" ||
                certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority))
                throw new InvalidDataException("Current TLS server credential required.");
            return new(value, listen, proxy, origin, certificate);
        }
        catch { certificate?.Dispose(); throw; }
    }

    internal string? Authenticate(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!context.Request.IsHttps || context.Connection.RemoteIpAddress is not { } peer ||
            !IsTrustedPeer(peer) ||
            !string.Equals(context.Request.Host.Host, ExternalOrigin.Host, StringComparison.OrdinalIgnoreCase) ||
            EffectivePort(context.Request.Host) != EffectivePort(ExternalOrigin) ||
            context.Request.Headers["Remote-Email"].Count != 1)
            return null;
        var actor = context.Request.Headers["Remote-Email"].ToString();
        return ValidIdentity(actor) && allowedOperators.TryGetValue(actor, out var canonical) ? canonical : null;
    }

    private bool IsTrustedPeer(IPAddress peer) =>
        peer.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? peer.Equals(TrustedProxyAddress)
            : peer.IsIPv4MappedToIPv6 && peer.MapToIPv4().Equals(TrustedProxyAddress);
    private static int EffectivePort(HostString host) => host.Port ?? 443;
    private static int EffectivePort(Uri uri) => uri.IsDefaultPort ? 443 : uri.Port;
    private static bool ValidIdentity(string? value) => value is { Length: > 2 and <= 320 } &&
        value.Contains('@') && !value.Any(char.IsWhiteSpace) && !value.Any(char.IsControl);
    public void Dispose() => Certificate.Dispose();

    internal sealed record HostedConfiguration(int Version, string ListenAddress, int HttpsPort,
        string ExternalOrigin, string TlsCertificateFile, string TlsPrivateKeyFile,
        string TrustedProxyAddress, string[] AllowedOperators);
}
