using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using PkiProxy.Authentication;
using PkiProxy.Directory;

internal static class KerberosHttpTests
{
    private const string Host = "broker.lab.example";
    private const string Path = "/cep/kerberos/service.svc/CEP";
    private const string Body = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body><test /></s:Body></s:Envelope>";
    internal static async Task RunAsync()
    {
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=HTTP test root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        var now = DateTimeOffset.UtcNow;
        using var root = rootReq.CreateSelfSigned(now.AddMinutes(-1), now.AddHours(1));
        using var key = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=" + Host, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName(Host); leafReq.CertificateExtensions.Add(san.Build());
        using var publicLeaf = leafReq.Create(root, now.AddMinutes(-1), now.AddMinutes(30), RandomNumberGenerator.GetBytes(16));
        using var leaf = publicLeaf.CopyWithPrivateKey(key);
        using var publicOtherLeaf = leafReq.Create(root, now.AddMinutes(-1), now.AddMinutes(30), RandomNumberGenerator.GetBytes(16));
        using var otherLeaf = publicOtherLeaf.CopyWithPrivateKey(key);
        using var transport = new KerberosHttpTransport("HTTP/" + Host + "@LAB.EXAMPLE", "LAB.EXAMPLE", "LAB",
            maximumExchanges: 1, exchangeTimeout: TimeSpan.FromSeconds(2), authorityPort: 443);
        using var deniedTransport = new KerberosHttpTransport("HTTP/" + Host + "@LAB.EXAMPLE", "LAB.EXAMPLE", "LAB",
            allowedClients: [IPAddress.Parse("192.0.2.1")]);
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders(); // Never log authorization headers/tokens.
        builder.WebHost.ConfigureKestrel(server => {
            server.Limits.MaxRequestHeadersTotalSize = 96 * 1024;
            server.Listen(IPAddress.Loopback, 0, listener => transport.ConfigureListener(listener, leaf));
            server.Listen(IPAddress.Loopback, 0, listener => transport.ConfigureListener(listener, otherLeaf));
            server.Listen(IPAddress.Loopback, 0, listener => deniedTransport.ConfigureListener(listener, leaf));
        });
        await using var app = builder.Build();
        app.Use(KerberosHttpAuthentication.InvokeAsync);
        var directory = new TestDirectory();
        using var directoryGate = new DirectoryHttpAuthorization(new(directory, TestDirectory.GroupSid));
        app.Use(directoryGate.InvokeAsync);
        var authenticated = 0;
        app.Run(async context => {
            var proof = context.Features.Get<AuthenticatedComputerFeature>();
            if (proof?.Identity.AccountName != "CLIENT01$") throw new InvalidOperationException("Missing actual machine proof");
            if (context.Features.Get<AuthorizedComputerFeature>()?.Computer.DnsHostName != "client01.lab.example")
                throw new InvalidOperationException("Missing AD-authorized request identity");
            using var reader = new StreamReader(context.Request.Body);
            if (await reader.ReadToEndAsync(context.RequestAborted) != Body) throw new InvalidOperationException("Authenticated request body changed");
            Interlocked.Increment(ref authenticated);
            context.Response.StatusCode = 204;
        });
        await app.StartAsync();
        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.ToArray();
        var port = new Uri(addresses[0]).Port;
        var otherPort = new Uri(addresses[1]).Port;
        var checks = 0;
        void Check(bool condition, string label) { if (!condition) throw new InvalidOperationException(label); checks++; }
        try
        {
            var sourceRejected = false;
            try { using var denied = await Wire.Connect(new Uri(addresses[2]).Port, root).WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (Exception error) when (error is IOException or AuthenticationException) { sourceRejected = true; }
            Check(sourceRejected && deniedTransport.ActiveExchanges == 0, "Unlisted source rejected before TLS/GSS");
            Check(KerberosListenerConfiguration.Load(new ConfigurationBuilder().Build()) is null, "No implicit activation");
            foreach (var invalid in new[] { "not-a-bool", "true" })
            {
                try
                {
                    using var setup = KerberosListenerConfiguration.Load(new ConfigurationBuilder().AddInMemoryCollection(
                        new Dictionary<string,string?> { ["Broker:Kerberos:Enabled"] = invalid }).Build());
                    throw new InvalidOperationException("Incomplete configuration accepted");
                }
                catch (InvalidOperationException e) when (e.Message != "Incomplete configuration accepted") { checks++; }
            }
            foreach (var bad in new[] { "Negotiate AB==", "Negotiate AA== ", "Negotiate \tAA==", "Negotiate " + new string('A', 87400) })
                Check(!KerberosHttpAuthentication.TryToken(bad, out _), "Bounded canonical header parsing");
            foreach (var protocol in new[] { "HTTP/2", "HTTP/3", "HTTP/1.1" })
            {
                var context = new DefaultHttpContext();
                context.Request.Path = Path; context.Request.Scheme = "https"; context.Request.Protocol = protocol;
                var reached = false;
                await KerberosHttpAuthentication.InvokeAsync(context, _ => { reached = true; return Task.CompletedTask; });
                Check(!reached && context.Response.StatusCode == 400, "No synthetic/proxy TLS or connection feature accepted");
            }
            foreach (var package in new[] { "Kerberos", "Negotiate" })
            {
                using var wire = await Wire.Connect(port, root);
                Check(wire.Stream.NegotiatedApplicationProtocol == SslApplicationProtocol.Http11, "HTTP/1.1 selected instead of multiplexed HTTP/2");
                var challenge = await wire.Request();
                Check(challenge.Status == 401 && challenge.Headers["WWW-Authenticate"] == "Negotiate", "Initial challenge");
                using var binding = wire.Stream.TransportContext!.GetChannelBinding(ChannelBindingKind.Endpoint)!;
                using var client = Client(package, binding);
                var token = client.GetOutgoingBlob(ReadOnlySpan<byte>.Empty, out _)!;
                var reply = await wire.Request("Negotiate " + Convert.ToBase64String(token));
                Check(reply.Status == 204 && reply.Headers["Connection"] == "close", "Authenticated one-request transport");
                var apRep = Convert.FromBase64String(reply.Headers["WWW-Authenticate"][10..]);
                _ = client.GetOutgoingBlob(apRep, out var status);
                Check(status == NegotiateAuthenticationStatusCode.Completed && client.IsMutuallyAuthenticated, "HTTP AP-REP mutual proof");
                Check(await wire.EndOfStream(), "Authenticated connection closes");
                using var replay = await Wire.Connect(port, root);
                Check((await replay.Request("Negotiate " + Convert.ToBase64String(token))).Status == 401, "HTTP replay rejected");
                using var other = await Wire.Connect(port, root);
                Check((await other.Request()).Status == 401, "No identity reuse across connections");
            }
            Check(authenticated == 2, "Only real successes reached next handler");
            using (var originalTls = await Wire.Connect(port, root))
            using (var otherTls = await Wire.Connect(otherPort, root))
            using (var originalBinding = originalTls.Stream.TransportContext!.GetChannelBinding(ChannelBindingKind.Endpoint)!)
            using (var client = Client("Negotiate", originalBinding))
            {
                var mismatched = client.GetOutgoingBlob(ReadOnlySpan<byte>.Empty, out _)!;
                Check((await otherTls.Request("Negotiate " + Convert.ToBase64String(mismatched))).Status == 401,
                    "Wrong actual TLS certificate binding rejected over HTTP");
            }
            foreach (var header in new[] { "Basic YTpi", "Negotiate !!!", "Negotiate ", "Negotiate AA==", "Negotiate AA==\r\nAuthorization: Negotiate AA==" })
            {
                using var wire = await Wire.Connect(port, root);
                Check((await wire.Request(header)).Status == 401, "Malformed/scheme/duplicate header rejected");
            }
            foreach (var extra in new[] { "Forwarded: proto=https\r\n", "X-Forwarded-User: CLIENT01$\r\n" })
            {
                using var wire = await Wire.Connect(port, root);
                Check((await wire.Request(extra: extra)).Status == 400, "Proxy assertion rejected");
            }
            using (var wire = await Wire.Connect(port, root))
                Check((await wire.Request(host: "other.lab.example")).Status == 400, "Wrong HTTP host rejected");
            using (var wire = await Wire.Connect(port, root))
                Check((await wire.Request(hostPort: port)).Status == 400, "Container port cannot replace configured HTTP authority port");
            using (var wire = await Wire.Connect(port, root))
                Check((await wire.Request(method: "GET")).Status == 405, "Non-POST rejected");
            foreach (var wrongService in new[] { false, true })
            {
                using var wire = await Wire.Connect(port, root);
                using var binding = wire.Stream.TransportContext!.GetChannelBinding(ChannelBindingKind.Endpoint)!;
                using var client = Client("Negotiate", wrongService ? binding : null,
                    wrongService ? "HTTP/other.lab.example" : "HTTP/" + Host);
                var token = client.GetOutgoingBlob(ReadOnlySpan<byte>.Empty, out _)!;
                Check((await wire.Request("Negotiate " + Convert.ToBase64String(token))).Status == 401, "Unbound/wrong-service HTTP rejected");
            }
            var negotiation = "Negotiate " + Convert.ToBase64String(OfferKerberos());
            using (var pending = await Wire.Connect(port, root))
            {
                var reply = await pending.Request(negotiation);
                Check(reply.Status == 401 && transport.ActiveExchanges == 1, "Real SPNEGO continuation owns slot");
                using var saturated = await Wire.Connect(port, root);
                Check((await saturated.Request(negotiation)).Status == 503, "Global exchange limit rejects saturation");
            }
            await Until(() => transport.ActiveExchanges == 0);
            Check(transport.ActiveExchanges == 0, "Disconnect releases partial GSS context");
            using (var idle = await Wire.Connect(port, root))
            {
                Check((await idle.Request(negotiation)).Status == 401, "Idle continuation started");
                await Until(() => transport.ActiveExchanges == 0);
                Check(await idle.EndOfStream(), "Idle deadline aborts connection and frees slot");
            }
            Check(authenticated == 2 && directory.Reads == 2 && transport.ActiveExchanges == 0, "Authentication failures never trigger directory reads");
            foreach (var mode in new[] { 1, 2, 0 })
            {
                directory.Mode = mode;
                using var wire = await Wire.Connect(port, root);
                using var binding = wire.Stream.TransportContext!.GetChannelBinding(ChannelBindingKind.Endpoint)!;
                using var client = Client("Negotiate", binding);
                var token = client.GetOutgoingBlob(ReadOnlySpan<byte>.Empty, out _)!;
                var reply = await wire.Request("Negotiate " + Convert.ToBase64String(token));
                Check(reply.Status == (mode == 1 ? 403 : mode == 2 ? 503 : 204), "Fresh directory group denial, outage, recovery");
                _ = client.GetOutgoingBlob(Convert.FromBase64String(reply.Headers["WWW-Authenticate"][10..]), out var status);
                Check(status == NegotiateAuthenticationStatusCode.Completed && client.IsMutuallyAuthenticated,
                    "Directory decision preserves mutual Kerberos response");
            }
            Check(authenticated == 3 && directory.Reads == 5, "No stale directory grant reused after failure");
            Console.WriteLine($"Kestrel HTTPS/Negotiate checks passed: {checks}. Real isolated Kerberos; native Windows still pending.");
        }
        finally { await app.StopAsync(); }
    }

    private static NegotiateAuthentication Client(string package, ChannelBinding? binding, string target = "HTTP/" + Host) =>
        new(new NegotiateAuthenticationClientOptions { Package = package, Credential = CredentialCache.DefaultNetworkCredentials,
            TargetName = target, Binding = binding, RequireMutualAuthentication = true, RequiredProtectionLevel = ProtectionLevel.Sign });

    private sealed class TestDirectory : IComputerDirectory
    {
        public DirectoryComputerRecord? FindComputer(Guid objectId, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Kerberos transport must use its authenticated account name");
        internal const string GroupSid = "S-1-5-21-1-2-3-1001";
        internal int Mode { get; set; }
        internal int Reads { get; private set; }
        public DirectoryComputerRecord? FindComputer(string accountName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Reads++;
            if (accountName != "CLIENT01$") throw new InvalidOperationException("Unexpected authenticated identity");
            if (Mode == 2) throw new InvalidOperationException("Test directory unavailable");
            return new(Guid.Parse("47440f0f-12fa-4838-a741-12b4e00a59f1"), accountName,
                "CN=CLIENT01,CN=Computers,DC=lab,DC=example", "client01.lab.example", 4096, 805306369,
                [ActiveDirectoryComputerResolver.EncodeDomainGroupSid(Mode == 1 ? "S-1-5-21-1-2-3-1002" : GroupSid)]);
        }
    }

    private static byte[] OfferKerberos()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence(new Asn1Tag(TagClass.Application, 0, true)))
        {
            writer.WriteObjectIdentifier("1.3.6.1.5.5.2");
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (writer.PushSequence())
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (writer.PushSequence()) writer.WriteObjectIdentifier("1.2.840.113554.1.2.2");
        }
        return writer.Encode();
    }

    private static async Task Until(Func<bool> condition)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!condition()) await Task.Delay(25, limit.Token);
    }

    private sealed class Wire : IDisposable
    {
        private readonly TcpClient socket;
        internal SslStream Stream { get; }
        private readonly int port;
        private Wire(TcpClient socket, SslStream stream, int port) { this.socket = socket; Stream = stream; this.port = port; }
        internal static async Task<Wire> Connect(int port, X509Certificate2 root)
        {
            var socket = new TcpClient();
            await socket.ConnectAsync(IPAddress.Loopback, port);
            var stream = new SslStream(socket.GetStream());
            var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
            policy.CustomTrustStore.Add(root); // Ephemeral root has no CRL service; no validation bypass.
            await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                TargetHost = Host, CertificateChainPolicy = policy, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11] });
            return new(socket, stream, port);
        }
        internal async Task<(int Status, Dictionary<string,string> Headers)> Request(string? authorization = null,
            string? host = null, string extra = "", string method = "POST", int? hostPort = null)
        {
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var request = $"{method} {Path} HTTP/1.1\r\nHost: {host ?? Host}:{hostPort ?? 443}\r\nContent-Length: {Encoding.ASCII.GetByteCount(Body)}\r\n" +
                (authorization is null ? "" : "Authorization: " + authorization + "\r\n") + extra + "\r\n" + Body;
            await Stream.WriteAsync(Encoding.ASCII.GetBytes(request), limit.Token);
            using var bytes = new MemoryStream();
            var one = new byte[1];
            while (bytes.Length < 100000)
            {
                if (await Stream.ReadAsync(one, limit.Token) == 0) throw new IOException("Unexpected HTTP EOF");
                bytes.WriteByte(one[0]);
                var buffer = bytes.GetBuffer(); var size = (int)bytes.Length;
                if (size >= 4 && buffer.AsSpan(size - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
            }
            var lines = Encoding.ASCII.GetString(bytes.ToArray()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
            var headers = lines.Skip(1).Select(line => line.Split(':', 2)).ToDictionary(p => p[0], p => p[1].Trim(), StringComparer.OrdinalIgnoreCase);
            return (int.Parse(lines[0].Split(' ')[1]), headers);
        }
        internal async Task<bool> EndOfStream()
        {
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { return await Stream.ReadAsync(new byte[1], limit.Token) == 0; }
            catch (IOException) { return true; } // Deadline may reset TCP rather than send TLS close_notify.
        }
        public void Dispose() { Stream.Dispose(); socket.Dispose(); }
    }
}
