using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Authentication;
using PkiProxy.Domain;

namespace PkiProxy.Protocol.Wstep;

internal sealed record CesTransportResponse(HttpStatusCode StatusCode, byte[] Body);

// One authenticated HTTP exchange, no automatic auth/redirect/application retry.
// Any exception after calling SendAsync is an uncertain submission outcome.
internal static class KerberosCesTransport
{
    internal static async Task<CesTransportResponse> SendAsync(Uri endpoint, X509Certificate2 trustedRoot,
        OpenSslCertificateVerifier revocation, byte[] soap, string action, CancellationToken cancellationToken)
    {
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps || endpoint.Port != 443 ||
            endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0 ||
            Uri.CheckHostName(endpoint.Host) != UriHostNameType.Dns || !endpoint.Host.Contains('.') ||
            soap.Length is 0 or > 1_048_576 || action.Length is 0 or > 512 || action.Any(c => char.IsControl(c) || c == '"'))
            throw new ArgumentException("Explicit bounded HTTPS CES request required.");
        var chainPolicy = CreatePreliminaryTlsChainPolicy(trustedRoot);
        ChannelBinding? binding = null;
        NegotiateAuthentication? kerberos = null;
        var connections = 0;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        using var handler = new SocketsHttpHandler {
            AllowAutoRedirect = false, UseProxy = false, UseCookies = false, Credentials = null,
            AutomaticDecompression = DecompressionMethods.None, MaxResponseHeadersLength = 32,
            ConnectTimeout = TimeSpan.FromSeconds(10), MaxConnectionsPerServer = 1,
            SslOptions = new SslClientAuthenticationOptions {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13, CertificateChainPolicy = chainPolicy,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, peer, _, errors) => {
                    if (errors != SslPolicyErrors.None || peer is null) return false;
                    using var leaf = X509CertificateLoader.LoadCertificate(peer.GetRawCertData());
                    return revocation.Verify(leaf, CertificatePurpose.Server, endpoint.DnsSafeHost);
                } },
            PlaintextStreamFilter = (context, _) => {
                if (Interlocked.Increment(ref connections) != 1 || context.NegotiatedHttpVersion != HttpVersion.Version11 ||
                    context.PlaintextStream is not SslStream { IsAuthenticated: true, IsEncrypted: true, IsServer: false } tls)
                    throw new AuthenticationException("Single authenticated TLS connection required; retry prohibited.");
                binding = tls.TransportContext.GetChannelBinding(ChannelBindingKind.Endpoint)
                    ?? throw new AuthenticationException("TLS endpoint channel binding unavailable.");
                TlsEndpointBinding.GetApplicationData(binding); // Validate provider structure, never invent a binding.
                kerberos = new NegotiateAuthentication(new NegotiateAuthenticationClientOptions {
                    Package = "Kerberos", Credential = CredentialCache.DefaultNetworkCredentials,
                    TargetName = "HTTP/" + endpoint.DnsSafeHost, RequireMutualAuthentication = true,
                    RequiredProtectionLevel = ProtectionLevel.None, Binding = binding });
                var token = kerberos.GetOutgoingBlob((string?)null, out var status);
                if (status != NegotiateAuthenticationStatusCode.ContinueNeeded || string.IsNullOrEmpty(token))
                    throw new AuthenticationException("Kerberos initiation failed.");
                context.InitialRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", token);
                return ValueTask.FromResult(context.PlaintextStream);
            }
        };
        using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) {
            Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = new ByteArrayContent(soap) };
        request.Headers.ConnectionClose = true;
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/soap+xml; charset=utf-8; action=\"" + action + "\"");
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            var tokens = response.Headers.WwwAuthenticate.Where(h => h.Scheme.Equals("Negotiate", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (kerberos is null || tokens.Length != 1 || string.IsNullOrEmpty(tokens[0].Parameter))
                throw new AuthenticationException("CES mutual Kerberos reply absent.");
            var outgoing = kerberos.GetOutgoingBlob(tokens[0].Parameter, out var status);
            if (status != NegotiateAuthenticationStatusCode.Completed || !string.IsNullOrEmpty(outgoing) ||
                !kerberos.IsAuthenticated || !kerberos.IsMutuallyAuthenticated || kerberos.Package != "Kerberos")
                throw new AuthenticationException("CES mutual Kerberos verification failed.");
            if (response.Content.Headers.ContentLength is > 1_048_576)
                throw new InvalidDataException("CES response too large.");
            await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
            using var body = new MemoryStream(); var buffer = new byte[8192];
            while (true)
            {
                var length = await stream.ReadAsync(buffer, deadline.Token);
                if (length == 0) break;
                if (body.Length + length > 1_048_576) throw new InvalidDataException("CES response too large.");
                body.Write(buffer, 0, length);
            }
            return new(response.StatusCode, body.ToArray());
        }
        finally { kerberos?.Dispose(); binding?.Dispose(); }
    }

    internal static X509ChainPolicy CreatePreliminaryTlsChainPolicy(X509Certificate2 trustedRoot)
    {
        var chainPolicy = new X509ChainPolicy {
            // BCL cannot retrieve this lab's LDAP CDP on Linux. The mandatory
            // callback below verifies the actual peer against a signed CRL using
            // OpenSSL. No peer is admitted on BCL NoCheck alone.
            TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck,
            RevocationFlag = X509RevocationFlag.ExcludeRoot, DisableCertificateDownloads = true,
            UrlRetrievalTimeout = TimeSpan.Zero };
        chainPolicy.CustomTrustStore.Add(trustedRoot);
        chainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        return chainPolicy;
    }
}
