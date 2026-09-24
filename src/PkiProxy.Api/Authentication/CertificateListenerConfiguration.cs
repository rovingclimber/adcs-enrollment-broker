using System.Globalization;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Directory;
using PkiProxy.Domain;
using PkiProxy.Protocol.Xcep;

namespace PkiProxy.Authentication;

internal sealed class CertificateListenerConfiguration : IDisposable
{
    internal CertificateHttpTransport Transport { get; }
    internal CertificateRenewalPolicy Policy { get; }
    private readonly X509Certificate2 certificate, root;
    private readonly int port;
    private CertificateListenerConfiguration(CertificateHttpTransport transport, X509Certificate2 certificate,
        X509Certificate2 root, int port, CertificateRenewalPolicy policy)
    { Transport = transport; this.certificate = certificate; this.root = root; this.port = port; Policy = policy; }

    internal static CertificateListenerConfiguration? Load(IConfiguration configuration,
        BrokerEnrollmentPolicy? policy, bool issuanceEnabled)
    {
        var section = configuration.GetSection("Broker:Certificate");
        if (!section.GetChildren().Any()) return null;
        string[] allowed = ["Enabled", "Host", "HttpsPort", "AuthorityPort", "TlsCertificateFile", "TlsPrivateKeyFile", "AllowedClientAddresses", "PolicyServerId", "SharedPolicyIdentity"];
        if (section.GetChildren().Any(x => !allowed.Contains(x.Key, StringComparer.OrdinalIgnoreCase)) ||
            !bool.TryParse(section["Enabled"], out var enabled))
            throw new InvalidOperationException("Explicit valid certificate-listener configuration required.");
        if (!enabled) return null;
        if (!OperatingSystem.IsLinux() || policy is null || !issuanceEnabled ||
            !bool.TryParse(configuration["Broker:Issuance:RenewalEnabled"], out var renewal) || !renewal ||
            !bool.TryParse(configuration["Broker:Directory:Enabled"], out var directoryEnabled) || !directoryEnabled)
            throw new InvalidOperationException("Certificate listener requires Linux, policy, renewal issuance and directory authorization.");
        string Required(string key) => !string.IsNullOrWhiteSpace(configuration[key]) ? configuration[key]! :
            throw new InvalidOperationException("Incomplete certificate-listener dependency configuration.");
        int Port(string key) => int.TryParse(Required(key), NumberStyles.None, CultureInfo.InvariantCulture, out var value) && value is >= 1 and <= 65535
            ? value : throw new InvalidOperationException("Explicit valid certificate port required.");
        var port = Port("Broker:Certificate:HttpsPort");
        if (int.TryParse(configuration["Broker:Kerberos:HttpsPort"], out var kerberosPort) && port == kerberosPort)
            throw new InvalidOperationException("Certificate listener must not replace the Kerberos socket.");
        var authorityPort = Port("Broker:Certificate:AuthorityPort");
        var host = Required("Broker:Certificate:Host");
        var sharedIdentity = false;
        if (section["SharedPolicyIdentity"] is { } sharedValue && !bool.TryParse(sharedValue, out sharedIdentity))
            throw new InvalidOperationException("SharedPolicyIdentity must be an explicit Boolean when configured.");
        var renewalPolicy = CertificateRenewalPolicy.Create(policy, Required("Broker:Certificate:PolicyServerId"), host, authorityPort, sharedIdentity);
        var certPath = Required("Broker:Certificate:TlsCertificateFile");
        var keyPath = Required("Broker:Certificate:TlsPrivateKeyFile");
        if (!Path.IsPathFullyQualified(certPath) || !Path.IsPathFullyQualified(keyPath) ||
            new FileInfo(keyPath).LinkTarget is not null || File.GetUnixFileMode(keyPath) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
            throw new InvalidOperationException("Absolute certificate files and owner-only private key required.");
        var clients = Required("Broker:Certificate:AllowedClientAddresses").Split(',', StringSplitOptions.TrimEntries)
            .Select(x => IPAddress.TryParse(x, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? ip : throw new InvalidOperationException("Exact IPv4 peers required.")).ToArray();
        var root = X509CertificateLoader.LoadCertificate(policy.IssuingCaCertificateDer);
        X509Certificate2? certificate = null;
        CertificateHttpTransport? transport = null;
        try {
            certificate = X509Certificate2.CreateFromPemFile(certPath, keyPath);
            var crlPath = Required("Broker:Issuance:CrlFile");
            using var publicServer = X509CertificateLoader.LoadCertificate(certificate.RawData);
            if (!OpenSslCertificateVerifier.Load(root, crlPath).Verify(publicServer, CertificatePurpose.Server, host))
                throw new InvalidOperationException("Certificate-listener server identity/trust rejected.");
            var journal = new EnrollmentSubmissionJournal(Required("Broker:Issuance:JournalDirectory"));
            LinuxLdapPolicy.Validate();
            var directory = new ActiveDirectoryComputerResolver(new LdapComputerDirectory(
                Required("Broker:Directory:Server"), Required("Broker:Directory:BaseDn")), Required("Broker:Directory:RequiredGroupSid"));
            transport = new(host, authorityPort, clients, root, crlPath, new(root, crlPath, journal, directory));
            return new(transport, certificate, root, port, renewalPolicy);
        } catch { transport?.Dispose(); certificate?.Dispose(); root.Dispose(); throw; }
    }

    internal void Configure(WebApplicationBuilder builder) => builder.WebHost.ConfigureKestrel(server =>
        server.Listen(IPAddress.Any, port, listener => Transport.ConfigureListener(listener, certificate)));

    public void Dispose() { Transport.Dispose(); certificate.Dispose(); root.Dispose(); }
}
