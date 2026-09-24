using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Authentication;

internal static class TlsEndpointBindingTests
{
    public static async Task<byte[]> VerifyAsync()
    {
        using (var unconnected = new SslStream(new MemoryStream()))
        {
            try { TlsEndpointBinding.FromServerStream(unconnected); throw new InvalidOperationException("Unauthenticated TLS accepted"); }
            catch (AuthenticationException) { }
        }
        byte[]? binding = null;
        foreach (var hash in new[] { HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 })
            foreach (var protocol in new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
                binding = await VerifyConnectionAsync(hash, protocol);
        return binding!;
    }

    private static async Task<byte[]> VerifyConnectionAsync(HashAlgorithmName hash, SslProtocols protocol)
    {
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Ephemeral TLS test root", rootKey, hash, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        var now = DateTimeOffset.UtcNow;
        using var root = rootRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddHours(1));
        using var serverKey = RSA.Create(2048);
        var request = new CertificateRequest("CN=broker.lab.example", serverKey, hash, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("broker.lab.example");
        request.CertificateExtensions.Add(san.Build());
        using var publicLeaf = request.Create(root, now.AddMinutes(-1), now.AddMinutes(30), RandomNumberGenerator.GetBytes(16));
        using var leaf = publicLeaf.CopyWithPrivateKey(serverKey);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var clientSocket = new TcpClient();
        var accept = listener.AcceptTcpClientAsync();
        await clientSocket.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        using var serverSocket = await accept;
        using var serverStream = new SslStream(serverSocket.GetStream());
        using var clientStream = new SslStream(clientSocket.GetStream());
        var trust = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck }; // Ephemeral test CA has no revocation service.
        trust.CustomTrustStore.Add(root);
        var serverTask = serverStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions {
            ServerCertificate = leaf, EnabledSslProtocols = protocol });
        var clientTask = clientStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
            TargetHost = "broker.lab.example", CertificateChainPolicy = trust,
            EnabledSslProtocols = protocol });
        await Task.WhenAll(serverTask, clientTask).WaitAsync(TimeSpan.FromSeconds(10));
        using var clientBinding = clientStream.TransportContext!.GetChannelBinding(ChannelBindingKind.Endpoint)!;
        var actual = TlsEndpointBinding.FromServerStream(serverStream);
        var expected = "tls-server-end-point:"u8.ToArray().Concat(leaf.GetCertHash(hash)).ToArray();
        if (!actual.AsSpan().SequenceEqual(expected) ||
            !actual.AsSpan().SequenceEqual(TlsEndpointBinding.GetApplicationData(clientBinding)))
            throw new InvalidOperationException("Actual TLS endpoint binding differs from the validated server certificate.");
        try { TlsEndpointBinding.FromServerStream(clientStream); throw new InvalidOperationException("Client stream accepted as server"); }
        catch (AuthenticationException) { }
        Console.WriteLine($"PASS real TLS {protocol}/{hash}: validated name/chain, actual local server leaf matches client CBT.");
        return actual;
    }
}
