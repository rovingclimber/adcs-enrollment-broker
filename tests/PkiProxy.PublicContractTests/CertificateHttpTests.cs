using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PkiProxy.Authentication;

internal static class CertificateHttpTests
{
    internal static async Task RunAsync(X509Certificate2 root, X509Certificate2 client, string crlPath,
        CertificateDomainIdentityResolver resolver)
    {
        const string host = "certificate.broker.test";
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=" + host, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        var authorityKey = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (authorityKey.PushSequence()) authorityKey.WriteOctetString(
            Convert.FromHexString(root.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single().SubjectKeyIdentifier!),
            new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0));
        req.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKey.Encode(), false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName(host); req.CertificateExtensions.Add(san.Build());
        using var leaf = req.Create(root, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(20), RandomNumberGenerator.GetBytes(16));
        using var server = leaf.CopyWithPrivateKey(key);
        CertificateEnabledConfigurationTests.Run(root, server, crlPath);
        using var transport = new CertificateHttpTransport(host, 443, [IPAddress.Loopback], root, crlPath, resolver);
        var builder = WebApplication.CreateSlimBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, endpoint => transport.ConfigureListener(endpoint, server)));
        await using var app = builder.Build(); app.Use(transport.InvokeAsync);
        var reached = 0;
        app.Run(context => {
            if (context.Features.Get<AuthorizedCertificateComputerFeature>()?.Identity.AssetId != "asset-1")
                throw new InvalidOperationException("Missing TLS-bound asset");
            Interlocked.Increment(ref reached); context.Response.StatusCode = 204; return Task.CompletedTask;
        });
        await app.StartAsync();
        var port = new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()).Port;
        var checks = 0;
        try {
            foreach (var protocol in new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
            {
            foreach (var scenario in new[] { "valid", "missing", "forwarded", "authorization", "wrong-host", "wrong-path", "get" })
            {
                using var handler = new SocketsHttpHandler { UseProxy = false, ConnectCallback = async (_, token) => {
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    try { await socket.ConnectAsync(IPAddress.Loopback, port, token); return new NetworkStream(socket, true); }
                    catch { socket.Dispose(); throw; }
                } };
                handler.SslOptions = new SslClientAuthenticationOptions {
                    AllowTlsResume = true, // Server must enforce fresh certificate handshakes.
                    EnabledSslProtocols = protocol,
                    ClientCertificates = scenario == "missing" ? new() : new() { client },
                    RemoteCertificateValidationCallback = (_, cert, _, errors) => cert is not null &&
                        (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 && cert.GetRawCertData().AsSpan().SequenceEqual(leaf.RawData)
                };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
                using var message = new HttpRequestMessage(scenario == "get" ? HttpMethod.Get : HttpMethod.Post,
                    "https://" + host + (scenario == "wrong-path" ? "/ces/kerberos/service.svc/CES" : "/ces/certificate/service.svc/CES"));
                if (scenario == "wrong-host") message.Headers.Host = "wrong.broker.test";
                if (scenario == "forwarded") message.Headers.Add("X-Forwarded-For", "192.0.2.1");
                if (scenario == "authorization") message.Headers.Add("Authorization", "Negotiate ZmFrZQ==");
                int? status = null;
                try { using var response = await http.SendAsync(message); status = (int)response.StatusCode; }
                // SocketsHttpHandler uses overridden Host for TLS target naming:
                // wrong-host is rejected during TLS, before HTTP authorization.
                catch (HttpRequestException) when (scenario is "missing" or "wrong-host") { }
                var expected = scenario == "valid" ? 204 : scenario == "get" ? 405 : scenario is "missing" or "wrong-host" ? (int?)null : 400;
                if (status != expected) throw new InvalidOperationException($"Certificate TLS case {scenario}: {status}, expected {expected}");
                checks++;
            }
            using var tcp = new TcpClient();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await tcp.ConnectAsync(IPAddress.Loopback, port, deadline.Token);
            using var tls = new SslStream(tcp.GetStream(), false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                AllowTlsResume = true,
                TargetHost = host, EnabledSslProtocols = protocol, ClientCertificates = new() { client },
                LocalCertificateSelectionCallback = (_, _, _, _, _) => client,
                RemoteCertificateValidationCallback = (_, cert, _, errors) => cert is not null &&
                    (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 && cert.GetRawCertData().AsSpan().SequenceEqual(leaf.RawData)
            }, deadline.Token);
            if (!tls.IsMutuallyAuthenticated || tls.SslProtocol != protocol)
                throw new InvalidOperationException($"Expected mutual {protocol}; negotiated={tls.SslProtocol}, mutual={tls.IsMutuallyAuthenticated}");
            var raw = System.Text.Encoding.ASCII.GetBytes("POST /ces/certificate/service.svc/CES HTTP/1.1\r\nHost: wrong.broker.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            await tls.WriteAsync(raw, deadline.Token);
            using var reader = new StreamReader(tls);
            var line = await reader.ReadLineAsync(deadline.Token);
            if (line is null || !line.StartsWith("HTTP/1.1 400 ", StringComparison.Ordinal))
                throw new InvalidOperationException("Correct SNI with wrong HTTP Host was not rejected");
            checks += 2;
            }
            if (reached != 2) throw new InvalidOperationException("Rejected peer reached application");
            Console.WriteLine($"Certificate TLS1.2/1.3 transport checks passed: {checks + 1} (loopback synthetic, not native Windows).");
        } finally { await app.StopAsync(); }
    }
}
