using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using PkiProxy.Domain;
using PkiProxy.Directory;

namespace PkiProxy.Authentication;

// Dedicated direct-TLS listener, not a path-dependent certificate renegotiation
// on the Kerberos socket. No Program/config wiring until interoperability proof.
internal sealed class CertificateHttpTransport : IDisposable
{
    private readonly string host;
    private readonly int authorityPort;
    private readonly HashSet<IPAddress> allowedClients;
    private readonly X509Certificate2 root;
    private readonly string crlPath;
    private readonly CertificateDomainIdentityResolver resolver;
    private readonly SemaphoreSlim slots = new(8, 8);

    internal CertificateHttpTransport(string host, int authorityPort, IReadOnlyCollection<IPAddress> allowedClients,
        X509Certificate2 root, string crlPath, CertificateDomainIdentityResolver resolver)
    {
        if (Uri.CheckHostName(host) != UriHostNameType.Dns || !host.Contains('.') || host.Length > 253 ||
            authorityPort is < 1 or > 65535 || !Path.IsPathFullyQualified(crlPath))
            throw new ArgumentException("Explicit TLS authority and CRL path required.");
        this.allowedClients = new(allowedClients);
        if (this.allowedClients.Count is < 1 or > 8 || this.allowedClients.Any(x => x.Equals(IPAddress.Any) || x.Equals(IPAddress.IPv6Any)))
            throw new ArgumentException("One to eight exact peers required.");
        this.host = host; this.authorityPort = authorityPort;
        this.root = X509CertificateLoader.LoadCertificate(root.RawData);
        this.crlPath = crlPath; this.resolver = resolver;
    }

    internal void ConfigureListener(ListenOptions listener, X509Certificate2 serverCertificate)
    {
        listener.Protocols = HttpProtocols.Http1;
        listener.Use(next => connection => {
            var address = (connection.RemoteEndPoint as IPEndPoint)?.Address;
            if (address?.IsIPv4MappedToIPv6 == true) address = address.MapToIPv4();
            if (address is null || !allowedClients.Contains(address)) { connection.Abort(); return Task.CompletedTask; }
            return next(connection);
        });
        listener.UseHttps(serverCertificate, options => {
            options.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            options.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
            options.HandshakeTimeout = TimeSpan.FromSeconds(10);
            // Require a new client-certificate handshake on every connection.
            // Avoid ambiguous Linux TLS1.3 resumed peer identity until separately
            // proven; existing HTTP connections still reauthorize every request.
            options.OnAuthenticate = (_, ssl) => { ssl.AllowTlsResume = false; ssl.AllowRenegotiation = false; };
            // Replace ambient trust with the existing explicit lab-root/CRL
            // verifier. No unconditional acceptance or certificate URL fetches.
            options.ClientCertificateValidation = (certificate, _, _) => {
                if (!slots.Wait(0)) return false;
                try { return OpenSslCertificateVerifier.Load(root, crlPath).Verify(certificate, CertificatePurpose.Client); }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException)
                { return false; }
                finally { slots.Release(); }
            };
        });
        listener.Use(next => async connection => {
            var stream = connection.Features.Get<ISslStreamFeature>()?.SslStream;
            if (stream is null || !stream.IsMutuallyAuthenticated || stream.RemoteCertificate is null ||
                !string.Equals(stream.TargetHostName, host, StringComparison.OrdinalIgnoreCase))
            { connection.Abort(); return; }
            var binding = new ConnectionBinding(this, connection.ConnectionId, stream);
            connection.Features.Set(binding);
            try { await next(connection); }
            finally { connection.Features.Set<ConnectionBinding>(null); }
        });
    }

    private sealed record ConnectionBinding(CertificateHttpTransport Owner, string Id, SslStream Stream);

    internal async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var binding = context.Features.Get<ConnectionBinding>();
        var certificatePath = context.Request.Path.Equals("/cep/certificate/service.svc/CEP", StringComparison.OrdinalIgnoreCase) ||
            context.Request.Path.Equals("/ces/certificate/service.svc/CES", StringComparison.OrdinalIgnoreCase);
        if (binding is null && !certificatePath) { await next(context); return; }
        void Deny(int status) {
            context.Response.StatusCode = status; context.Response.ContentLength = 0;
            context.Response.Headers.CacheControl = "no-store"; context.Response.Headers.Connection = "close";
        }
        if (binding?.Owner != this || !certificatePath || !context.Request.IsHttps || context.Request.Protocol != "HTTP/1.1" ||
            context.Connection.Id != binding.Id || context.Features.Get<ISslStreamFeature>()?.SslStream != binding.Stream ||
            !string.Equals(context.Request.Host.Host, host, StringComparison.OrdinalIgnoreCase) ||
            context.Request.Host.Port.GetValueOrDefault(443) != authorityPort ||
            context.Features.Get<AuthorizedComputerFeature>() is not null ||
            context.Features.Get<AuthorizedCertificateComputerFeature>() is not null ||
            context.Request.Headers.Keys.Any(k => k.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
                k.Equals("Forwarded", StringComparison.OrdinalIgnoreCase) || k.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase) ||
                k.Equals("X-Client-Cert", StringComparison.OrdinalIgnoreCase)))
        { Deny(400); return; }
        if (context.Request.Method != "POST") { Deny(405); return; }
        if (!await slots.WaitAsync(0, context.RequestAborted)) { Deny(503); return; }
        CertificateDomainIdentity? identity;
        try {
            using var peer = X509CertificateLoader.LoadCertificate(binding.Stream.RemoteCertificate!.GetRawCertData());
            identity = await Task.Run(() => resolver.Resolve(peer, context.RequestAborted), context.RequestAborted);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { return; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or CryptographicException or
            ArgumentException or InvalidOperationException or System.Text.Json.JsonException or
            System.DirectoryServices.Protocols.LdapException or System.DirectoryServices.Protocols.DirectoryOperationException)
        { Deny(503); return; }
        finally { slots.Release(); }
        if (identity is null) { Deny(403); return; }
        context.Response.Headers.CacheControl = "no-store";
        context.Features.Set(new AuthorizedCertificateComputerFeature(identity));
        try { await next(context); }
        finally { context.Features.Set<AuthorizedCertificateComputerFeature>(null); }
    }

    public void Dispose() { root.Dispose(); slots.Dispose(); }
}
