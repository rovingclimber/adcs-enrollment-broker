using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using PkiProxy.FactsWorkbench;

internal static class FactsWorkbenchHostedAccessTests
{
    internal static void Run()
    {
        if (!OperatingSystem.IsLinux())
        {
            Console.WriteLine("Hosted facts access checks skipped: Linux file modes required.");
            return;
        }
        var root = Directory.CreateTempSubdirectory("facts-hosted-access-");
        File.SetUnixFileMode(root.FullName,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var checks = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException("Hosted facts access: " + label);
            checks++;
        }
        try
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=facts.example.test", key,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("facts.example.test");
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            var certPath = Path.Combine(root.FullName, "server.pem");
            var keyPath = Path.Combine(root.FullName, "server.key");
            var configPath = Path.Combine(root.FullName, "hosted.json");
            File.WriteAllText(certPath, certificate.ExportCertificatePem());
            File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var value = new FactsWorkbenchHostedAccess.HostedConfiguration(1, "192.0.2.13", 8443,
                "https://facts.example.test:8443", certPath, keyPath, "198.51.100.10",
                ["avery@example.com", "operator@example.com"]);
            File.WriteAllText(configPath, JsonSerializer.Serialize(value));
            File.SetUnixFileMode(configPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            using var access = FactsWorkbenchHostedAccess.Load(configPath);
            Check(access.ListenAddress.Equals(IPAddress.Parse("192.0.2.13")) && access.Value.HttpsPort == 8443,
                "loads exact listener");

            DefaultHttpContext Context(string actor = "avery@example.com")
            {
                var context = new DefaultHttpContext();
                context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.10");
                context.Request.Scheme = "https";
                context.Request.Host = new HostString("facts.example.test", 8443);
                context.Request.Headers["Remote-Email"] = actor;
                return context;
            }
            Check(access.Authenticate(Context()) == "avery@example.com", "trusted proxy and allowed actor accepted");
            Check(access.Authenticate(Context("AVERY@EXAMPLE.COM")) == "avery@example.com",
                "allowed actor is reduced to its configured audit identity");
            var wrongPeer = Context(); wrongPeer.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.11");
            Check(access.Authenticate(wrongPeer) is null, "spoofed identity from wrong peer rejected");
            var unrelatedIpv6 = Context(); unrelatedIpv6.Connection.RemoteIpAddress = IPAddress.Parse("2001:db8::a4d:190a");
            Check(access.Authenticate(unrelatedIpv6) is null, "IPv6 low-bit proxy lookalike rejected");
            var mappedProxy = Context(); mappedProxy.Connection.RemoteIpAddress = IPAddress.Parse("::ffff:198.51.100.10");
            Check(access.Authenticate(mappedProxy) == "avery@example.com", "mapped form of exact IPv4 proxy accepted");
            var cleartext = Context(); cleartext.Request.Scheme = "http";
            Check(access.Authenticate(cleartext) is null, "cleartext upstream rejected");
            var wrongHost = Context(); wrongHost.Request.Host = new HostString("other.example.test", 8443);
            Check(access.Authenticate(wrongHost) is null, "wrong external host rejected");
            var wrongPort = Context(); wrongPort.Request.Host = new HostString("facts.example.test", 443);
            Check(access.Authenticate(wrongPort) is null, "wrong external port rejected");
            Check(access.Authenticate(Context("unknown@example.com")) is null, "unlisted actor rejected");
            var absent = Context(); absent.Request.Headers.Remove("Remote-Email");
            Check(access.Authenticate(absent) is null, "missing identity rejected");
            var multiple = Context();
            multiple.Request.Headers["Remote-Email"] =
                new Microsoft.Extensions.Primitives.StringValues(["avery@example.com", "operator@example.com"]);
            Check(access.Authenticate(multiple) is null, "ambiguous identity rejected");
            Check(access.Authenticate(Context("avery@example.com,operator@example.com")) is null,
                "comma-combined identity rejected");

            var noSanRequest = new CertificateRequest("CN=facts.example.test", key,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            noSanRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature, true));
            noSanRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            noSanRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            using var noSanCertificate = noSanRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            File.WriteAllText(certPath, noSanCertificate.ExportCertificatePem());
            try { _ = FactsWorkbenchHostedAccess.Load(configPath); throw new InvalidOperationException("CN-only certificate accepted."); }
            catch (InvalidDataException) { checks++; }

            var broadPurposeRequest = new CertificateRequest("CN=facts.example.test", key,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            broadPurposeRequest.CertificateExtensions.Add(san.Build());
            broadPurposeRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment, true));
            broadPurposeRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1"), new("1.3.6.1.5.5.7.3.2") }, true));
            broadPurposeRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            using var broadPurposeCertificate = broadPurposeRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            File.WriteAllText(certPath, broadPurposeCertificate.ExportCertificatePem());
            try { _ = FactsWorkbenchHostedAccess.Load(configPath); throw new InvalidOperationException("Broad-purpose certificate accepted."); }
            catch (InvalidDataException) { checks++; }

            File.SetUnixFileMode(configPath, UnixFileMode.UserRead | UnixFileMode.GroupRead);
            try { _ = FactsWorkbenchHostedAccess.Load(configPath); throw new InvalidOperationException("Public config accepted."); }
            catch (IOException) { checks++; }
            File.SetUnixFileMode(configPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.GroupRead);
            try { _ = FactsWorkbenchHostedAccess.Load(configPath); throw new InvalidOperationException("Public key accepted."); }
            catch (IOException) { checks++; }
        }
        finally { root.Delete(recursive: true); }
        Console.WriteLine($"Hosted facts access checks passed: {checks}.");
    }
}
