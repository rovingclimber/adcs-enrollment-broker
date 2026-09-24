using System.Globalization;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Authentication;

// Explicit opt-in only. Reading configuration is not deployment authorization.
internal sealed class KerberosListenerConfiguration : IDisposable
{
    internal KerberosHttpTransport Transport { get; }
    internal int ListenerPort { get; }
    internal int AuthorityPort { get; }
    private readonly X509Certificate2 certificate;
    private readonly int port;

    private KerberosListenerConfiguration(KerberosHttpTransport transport, X509Certificate2 certificate,
        int port, int authorityPort)
    {
        Transport = transport;
        ListenerPort = port;
        AuthorityPort = authorityPort;
        this.certificate = certificate;
        this.port = port;
    }

    internal static KerberosListenerConfiguration? Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("Broker:Kerberos");
        if (!section.GetChildren().Any()) return null;
        string[] allowed = ["Enabled", "ServicePrincipal", "Realm", "NetBiosDomain", "HttpsPort", "AuthorityPort", "TlsCertificateFile", "TlsPrivateKeyFile", "AllowedClientAddresses"];
        if (section.GetChildren().Any(child => !allowed.Contains(child.Key, StringComparer.OrdinalIgnoreCase)) ||
            !bool.TryParse(section["Enabled"], out var enabled))
            throw new InvalidOperationException("Explicit valid Broker:Kerberos configuration required.");
        if (!enabled) return null;
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux Kerberos listener only.");
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("KRB5_TRACE")))
            throw new InvalidOperationException("Kerberos credential tracing must be disabled.");
        string Required(string name) => !string.IsNullOrWhiteSpace(section[name]) ? section[name]! :
            throw new InvalidOperationException("Incomplete Broker:Kerberos configuration.");
        if (!int.TryParse(Required("HttpsPort"), NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
            throw new InvalidOperationException("Explicit HTTPS port required.");
        if (!int.TryParse(Required("AuthorityPort"), NumberStyles.None, CultureInfo.InvariantCulture, out var authorityPort) || authorityPort is < 1 or > 65535)
            throw new InvalidOperationException("Explicit HTTP authority port required.");
        var certPath = Required("TlsCertificateFile");
        var keyPath = Required("TlsPrivateKeyFile");
        var keytab = Environment.GetEnvironmentVariable("KRB5_KTNAME");
        if (keytab is null || !Path.IsPathFullyQualified(keytab) || !File.Exists(keytab) ||
            !Path.IsPathFullyQualified(certPath) || !Path.IsPathFullyQualified(keyPath))
            throw new InvalidOperationException("Absolute TLS file and KRB5_KTNAME paths required.");
        // Dedicated secret mounts readable only by the service user. Do not
        // dump contents, import a password or accept a world-readable keytab.
        var publicModes = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        if ((File.GetUnixFileMode(keyPath) & publicModes) != 0 || (File.GetUnixFileMode(keytab) & publicModes) != 0)
            throw new InvalidOperationException("TLS key and keytab require owner-only permissions.");
        var clients = Required("AllowedClientAddresses").Split(',', StringSplitOptions.TrimEntries).Select(value =>
            IPAddress.TryParse(value, out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? address : throw new InvalidOperationException("Exact IPv4 client addresses required.")).ToArray();
        var transport = new KerberosHttpTransport(Required("ServicePrincipal"), Required("Realm"), Required("NetBiosDomain"), allowedClients: clients, authorityPort: authorityPort);
        try
        {
            var certificate = X509Certificate2.CreateFromPemFile(certPath, keyPath);
            return new(transport, certificate, port, authorityPort);
        }
        catch { transport.Dispose(); throw; }
    }

    internal void Configure(WebApplicationBuilder builder)
    {
        builder.WebHost.ConfigureKestrel(server => {
            server.Limits.MaxConcurrentConnections = 128;
            server.Limits.MaxRequestHeadersTotalSize = 96 * 1024;
            server.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
            server.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(10);
            server.Listen(IPAddress.Any, port, listener => Transport.ConfigureListener(listener, certificate));
        });
    }

    public void Dispose() { Transport.Dispose(); certificate.Dispose(); }
}
