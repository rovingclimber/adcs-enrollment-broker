using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using PkiProxy.Authentication;
using PkiProxy.Protocol.Xcep;

internal static class CertificateEnabledConfigurationTests
{
    internal static void Run(X509Certificate2 root, X509Certificate2 server, string crlPath)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var path = System.IO.Directory.CreateTempSubdirectory("certificate-config-").FullName;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var env = new Dictionary<string, string?> {
            ["LDAPTLS_REQCERT"] = "demand", ["LDAPTLS_REQSAN"] = "demand",
            ["LDAPSASL_CBINDING"] = "tls-endpoint", ["LDAPSASL_NOCANON"] = "on",
            ["LDAPSASL_SECPROPS"] = "noanonymous,noplain,maxssf=0",
            ["LDAPTLS_CIPHER_SUITE"] = "NORMAL:-VERS-TLS1.0:-VERS-TLS1.1",
            ["LDAPTLS_CACERT"] = path + "/ca.pem", ["LDAPTLS_CRLFILE"] = crlPath,
            ["KRB5CCNAME"] = "FILE:" + path + "/cache",
            ["LDAPNOINIT"] = null, ["LDAPSASL_AUTHZID"] = null,
            ["LDAPSASL_AUTHCID"] = null, ["KRB5_TRACE"] = null
        };
        var saved = env.Keys.ToDictionary(x => x, Environment.GetEnvironmentVariable);
        try {
            File.WriteAllText(path + "/ca.pem", root.ExportCertificatePem());
            File.WriteAllText(path + "/server.pem", server.ExportCertificatePem());
            using var key = server.GetRSAPrivateKey()!;
            File.WriteAllText(path + "/server.key", key.ExportPkcs8PrivateKeyPem());
            File.SetUnixFileMode(path + "/server.key", UnixFileMode.UserRead | UnixFileMode.UserWrite);
            // Configuration-only sentinel, not a ticket or authentication proof.
            File.WriteAllText(path + "/cache", "not-a-kerberos-ticket");
            File.SetUnixFileMode(path + "/cache", UnixFileMode.UserRead | UnixFileMode.UserWrite);
            foreach (var item in env) Environment.SetEnvironmentVariable(item.Key, item.Value);
            var policy = new BrokerEnrollmentPolicy("baseline", "Test", "Machine", "1.2.3.4", root.RawData,
                new Uri("https://certificate.broker.test/ces/kerberos/service.svc/CES"), 2, 2048,
                0x88000000, 0, 0, 64, 31536000, 3628800, 101, 0, 1, DateTimeOffset.UtcNow);
            var values = new Dictionary<string,string?> {
                ["Broker:Certificate:Enabled"] = "true", ["Broker:Certificate:Host"] = "certificate.broker.test",
                ["Broker:Certificate:HttpsPort"] = "9443", ["Broker:Certificate:AuthorityPort"] = "9443",
                ["Broker:Certificate:PolicyServerId"] = "{057cfa10-6c6c-42a7-9d88-5126432214eb}",
                ["Broker:Certificate:TlsCertificateFile"] = path + "/server.pem",
                ["Broker:Certificate:TlsPrivateKeyFile"] = path + "/server.key",
                ["Broker:Certificate:AllowedClientAddresses"] = "127.0.0.1",
                ["Broker:Kerberos:HttpsPort"] = "8443", ["Broker:Issuance:RenewalEnabled"] = "true",
                ["Broker:Issuance:CrlFile"] = crlPath, ["Broker:Issuance:JournalDirectory"] = path,
                ["Broker:Directory:Enabled"] = "true", ["Broker:Directory:Server"] = "dc.test.invalid",
                ["Broker:Directory:BaseDn"] = "DC=test,DC=invalid",
                ["Broker:Directory:RequiredGroupSid"] = "S-1-5-21-1-2-3-1106"
            };
            var checks = 0;
            void Check(bool expected) {
                var accepted = false;
                try {
                    using var listener = CertificateListenerConfiguration.Load(new ConfigurationBuilder().AddInMemoryCollection(values).Build(), policy, true);
                    accepted = listener is not null && listener.Policy.Policy.RenewalOnly && listener.Policy.Policy.ClientAuthentication == 8;
                } catch (InvalidOperationException) when (!expected) { }
                if (accepted != expected) throw new InvalidOperationException("Enabled certificate configuration admission mismatch.");
                checks++;
            }
            Check(true);
            values["Broker:Certificate:SharedPolicyIdentity"] = "invalid"; Check(false);
            values["Broker:Certificate:SharedPolicyIdentity"] = "false"; Check(true);
            values["Broker:Certificate:SharedPolicyIdentity"] = "true"; Check(false);
            policy = policy with { PolicyServerId = values["Broker:Certificate:PolicyServerId"]! };
            Check(true);
            values["Broker:Certificate:SharedPolicyIdentity"] = "false"; Check(false);
            policy = policy with { PolicyServerId = "baseline" };
            values.Remove("Broker:Certificate:SharedPolicyIdentity");
            foreach (var change in new[] { ("Broker:Certificate:HttpsPort", "8443"),
                ("Broker:Certificate:PolicyServerId", "invalid"), ("Broker:Issuance:RenewalEnabled", "false"),
                ("Broker:Directory:Enabled", "false") }) {
                var prior = values[change.Item1]; values[change.Item1] = change.Item2;
                Check(false); values[change.Item1] = prior;
            }
            File.SetUnixFileMode(path + "/server.key", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
            Check(false);
            Console.WriteLine($"Enabled certificate configuration checks passed: {checks} (synthetic; no socket, directory bind or issuance).");
        } finally {
            foreach (var item in saved) Environment.SetEnvironmentVariable(item.Key, item.Value);
            System.IO.Directory.Delete(path, true);
        }
    }
}
