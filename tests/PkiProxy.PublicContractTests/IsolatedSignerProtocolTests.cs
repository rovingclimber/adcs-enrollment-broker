using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using PkiProxy.Domain;
using PkiProxy.Protocol.Cmc;
using PkiProxy.Signing;

internal static class IsolatedSignerProtocolTests
{
    private const string Profile = "urn:example:pkiproxy:test:profile:broker";
    private const string Template = "1.3.6.1.4.1.55555.670.2";
    private const string SignerEku = "1.3.6.1.4.1.55555.670.9";

    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), "pkiproxy-signer-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            ConfigurationSchemaTests(root);
            var token = RandomNumberGenerator.GetBytes(32);
            var tokenPath = Path.Combine(root, "token");
            await File.WriteAllBytesAsync(tokenPath, System.Text.Encoding.ASCII.GetBytes(Convert.ToHexString(token) + "\n"));
            File.SetUnixFileMode(tokenPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var loaded = SignerProtocol.LoadToken(tokenPath);
            Check(CryptographicOperations.FixedTimeEquals(token, loaded), "exact byte-oriented token load");

            File.SetUnixFileMode(tokenPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            Reject(() => SignerProtocol.LoadToken(tokenPath), "group-readable token");
            File.SetUnixFileMode(tokenPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Reject(() => SignerProtocol.LoadToken(root), "non-regular token path");
            var tokenLink = Path.Combine(root, "token-link");
            File.CreateSymbolicLink(tokenLink, tokenPath);
            Reject(() => SignerProtocol.LoadToken(tokenLink), "linked token path");

            using var key = RSA.Create(3072);
            var certificateRequest = new CertificateRequest("CN=isolated-signer-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(SignerEku) }, true));
            using var certificateWithKey = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(2));
            using var certificate = X509CertificateLoader.LoadCertificate(certificateWithKey.RawData);
            using var provider = new TestSignerKeyProvider(key, certificate);
            IsolatedSignerKeyProvider.VerifyReadiness(provider);
            Check(provider.SignCount == 1, "provider readiness challenge");

            var replayPath = Path.Combine(root, "replay.v1");
            var policy = new SigningIntentPolicy(Profile, Template, 2, 0, 16);
            policy.ValidateConfiguration();
            var replay = new SigningReplayWindow(16, replayPath);
            var socketPath = Path.Combine(root, "signer.sock");
            using var remote = new UnixSocketRsa(socketPath, loaded, certificate);
            var enrollment = CreateEnrollment();
            var metadata = new SigningIntentMetadata(SigningOperation.DomainEnrollment,
                SigningIntentMetadata.Correlate(SigningOperation.DomainEnrollment, "request-one"u8.ToArray()));

            var first = ServeOneAsync(socketPath, provider, token, SHA256.HashData(certificate.RawData), policy, replay, geteuid());
            await first.Ready;
            var built = CmcEnrollmentRequestBuilder.Build(enrollment.Csr, enrollment.Binding, enrollment.Identity,
                enrollment.Template, certificate, DateTimeOffset.UtcNow, remote, metadata);
            await first.Completion;
            VerifyCms(built.EncodedCms, certificate);
            Check(provider.SignCount == 2, "policy-approved CMC reaches provider once");

            // An identical lost-response retry is safe: correlation maps to the
            // same canonical intent and RSA-PKCS1 produces the same signature.
            var retry = ServeOneAsync(socketPath, provider, token, SHA256.HashData(certificate.RawData), policy, replay, geteuid());
            await retry.Ready;
            var repeated = CmcEnrollmentRequestBuilder.Build(enrollment.Csr, enrollment.Binding, enrollment.Identity,
                enrollment.Template, certificate, DateTimeOffset.UtcNow, remote, metadata);
            await retry.Completion;
            Check(built.EncodedCms.AsSpan().SequenceEqual(repeated.EncodedCms), "identical correlation retry is deterministic");

            // The durable correlation binding survives a sidecar restart.
            var restartedReplay = new SigningReplayWindow(16, replayPath);
            var restart = ServeOneAsync(socketPath, provider, token, SHA256.HashData(certificate.RawData), policy, restartedReplay, geteuid());
            await restart.Ready;
            _ = CmcEnrollmentRequestBuilder.Build(enrollment.Csr, enrollment.Binding, enrollment.Identity,
                enrollment.Template, certificate, DateTimeOffset.UtcNow, remote, metadata);
            await restart.Completion;

            var changed = enrollment with { Identity = enrollment.Identity with { SubjectAlternativeNameDnsNames = ["other.example.test"] } };
            var mismatch = ServeOneAsync(socketPath, provider, token, SHA256.HashData(certificate.RawData), policy, restartedReplay, geteuid());
            await mismatch.Ready;
            Reject(() => CmcEnrollmentRequestBuilder.Build(changed.Csr, changed.Binding, changed.Identity,
                changed.Template, certificate, DateTimeOffset.UtcNow, remote, metadata), "correlation reused for different intent");
            await mismatch.Completion;
            Check(provider.SignCount == 4, "mismatched replay never reaches provider");

            // The RSA facade cannot be used as a raw signing oracle.
            Reject(() => remote.SignHash(SHA256.HashData("raw"u8), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                "raw digest without intent");
            var wrongToken = RandomNumberGenerator.GetBytes(32);
            using (var wrongRemote = new UnixSocketRsa(socketPath, wrongToken, certificate))
            {
                var denied = ServeOneAsync(socketPath, provider, token, SHA256.HashData(certificate.RawData), policy,
                    restartedReplay, geteuid());
                await denied.Ready;
                Reject(() => CmcEnrollmentRequestBuilder.Build(enrollment.Csr, enrollment.Binding, enrollment.Identity,
                    enrollment.Template, certificate, DateTimeOffset.UtcNow, wrongRemote,
                    new(SigningOperation.DomainEnrollment, RandomNumberGenerator.GetBytes(32))), "wrong channel token");
                await denied.Completion;
            }
            CryptographicOperations.ZeroMemory(wrongToken);
            var unauthorized = ServeOneAsync(socketPath, provider, token, SHA256.HashData(certificate.RawData), policy,
                restartedReplay, geteuid() + 1);
            await unauthorized.Ready;
            Reject(() => CmcEnrollmentRequestBuilder.Build(enrollment.Csr, enrollment.Binding, enrollment.Identity,
                enrollment.Template, certificate, DateTimeOffset.UtcNow, remote,
                new(SigningOperation.DomainEnrollment, RandomNumberGenerator.GetBytes(32))), "unauthorized peer UID");
            await unauthorized.Completion;

            await ProtocolNegativeTests(root, token, certificate, provider, policy, enrollment, replayPath);
            ProviderConfigurationTests(root, key, certificate);

            File.SetUnixFileMode(tokenPath, UnixFileMode.UserRead | UnixFileMode.OtherRead);
            Reject(() => SignerProtocol.LoadToken(tokenPath), "world-readable token");
            Console.WriteLine("Isolated signer v2 checks passed: strict configuration schema, owner-only secrets, policy-bound CMC, canonical framing, durable replay, peer UID, deadlines, response correlation, explicit provider and no raw-digest fallback.");
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void ConfigurationSchemaTests(string root)
    {
        var common = new Dictionary<string, string?>
        {
            ["Broker:Signer:SocketPath"] = Path.Combine(root, "schema.sock"),
            ["Broker:Signer:AuthenticationTokenFile"] = Path.Combine(root, "schema-token"),
            ["Broker:Signer:CertificateSha256"] = new string('A', 64),
            ["Broker:Signer:MinimumRemainingValidityMinutes"] = "60",
            ["Broker:Signer:ApplicationPolicyOid"] = SignerEku,
            ["Broker:Signer:AllowedClientUid"] = "1654",
            ["Broker:Signer:IssuingCaFile"] = Path.Combine(root, "ca.pem"),
            ["Broker:Signer:CrlFile"] = Path.Combine(root, "ca.crl"),
            ["Broker:Signer:AllowedProfileUrn"] = Profile,
            ["Broker:Signer:AllowedTemplateOid"] = Template,
            ["Broker:Signer:AllowedTemplateMajorVersion"] = "2",
            ["Broker:Signer:AllowedTemplateMinorVersion"] = "0",
            ["Broker:Signer:MaximumReplayEntries"] = "16",
            ["Broker:Signer:ReplayStateFile"] = Path.Combine(root, "replay.v1")
        };
        var pem = new Dictionary<string, string?>(common)
        {
            ["Broker:Signer:provider"] = "pem-file",
            ["Broker:Signer:CertificateFile"] = Path.Combine(root, "signer.pem"),
            ["Broker:Signer:PrivateKeyFile"] = Path.Combine(root, "signer.key")
        };
        IsolatedSignerConfiguration.Validate(Section(pem));

        var pkcs11 = new Dictionary<string, string?>(common)
        {
            ["Broker:Signer:Provider"] = "pkcs11",
            ["Broker:Signer:ModulePath"] = "/usr/lib/pkcs11/provider.so",
            ["Broker:Signer:PinFile"] = Path.Combine(root, "pin"),
            ["Broker:Signer:TokenLabel"] = "signer",
            ["Broker:Signer:TokenSerial"] = "1234",
            ["Broker:Signer:KeyId"] = "01",
            ["Broker:Signer:MaximumSessions"] = "4"
        };
        IsolatedSignerConfiguration.Validate(Section(pkcs11));

        foreach (var hostileKey in new[]
        {
            "Broker:Signer:PinFiel",
            "Broker:Signer:Provider:Nested",
            "Broker:Signer:AllowedProfiles:0"
        })
        {
            var hostile = new Dictionary<string, string?>(pem) { [hostileKey] = "ignored" };
            Reject(() => IsolatedSignerConfiguration.Validate(Section(hostile)), "unknown or nested signer setting");
        }

        var rootValue = new Dictionary<string, string?>(pem) { ["Broker:Signer"] = "ignored" };
        Reject(() => IsolatedSignerConfiguration.Validate(Section(rootValue)), "scalar signer configuration root");

        var untouched = Path.Combine(root, "must-not-be-opened");
        var startupHostile = new Dictionary<string, string?>
        {
            ["Broker:Signer:SocketPath"] = Path.Combine(root, "must-not-listen.sock"),
            ["Broker:Signer:AuthenticationTokenFile"] = untouched,
            ["Broker:Signer:ProviderTypo"] = "pem-file"
        };
        Reject(() => IsolatedSignerConfiguration.Validate(Section(startupHostile)),
            "unknown startup setting before secret or listener activity");
        Check(!File.Exists(untouched) && !File.Exists(Path.Combine(root, "must-not-listen.sock")),
            "invalid configuration has no secret or listener side effect");
    }

    private static async Task ProtocolNegativeTests(string root, byte[] token, X509Certificate2 certificate,
        TestSignerKeyProvider provider, SigningIntentPolicy policy,
        (byte[] Csr, CsrBinding Binding, ControlledCertificateIdentity Identity, CmcTemplate Template) enrollment,
        string replayPath)
    {
        using var exportedKey = provider.ExportKey();
        using var localSigner = certificate.CopyWithPrivateKey(exportedKey);
        var localBuilt = CmcEnrollmentRequestBuilder.Build(enrollment.Csr, enrollment.Binding, enrollment.Identity,
            enrollment.Template, localSigner, DateTimeOffset.UtcNow);
        var cms = new SignedCms(); cms.Decode(localBuilt.EncodedCms);
        var payload = cms.ContentInfo.Content;
        var digest = SigningIntentPolicy.ComputeCmsSignatureDigest(payload);
        var correlation = RandomNumberGenerator.GetBytes(32);
        var valid = new SigningIntentRequest(SigningOperation.DomainEnrollment, correlation,
            SHA256.HashData(certificate.RawData), Profile, Template, 2, 0, payload, digest);
        policy.Validate(valid);
        var encoded = SignerProtocol.EncodeRequest(token, valid);
        Check(SignerProtocol.DecodeRequest(encoded).Payload.AsSpan().SequenceEqual(payload), "canonical round trip");

        var concurrentReplay = new SigningReplayWindow(16, Path.Combine(root, "replay-concurrent.v1"));
        var conflicting = valid with { Operation = SigningOperation.DomainRenewal };
        var contenders = await Task.WhenAll(Task.Run(() => concurrentReplay.TryAdmit(valid)),
            Task.Run(() => concurrentReplay.TryAdmit(conflicting)));
        Check(contenders.Count(result => result) == 1, "concurrent correlation conflict admits exactly one intent");
        Check(concurrentReplay.TryAdmit(contenders[0] ? valid : conflicting), "concurrent winner retries identically");

        Mutate(encoded, 4, 2, "unknown protocol version");
        Mutate(encoded, 0, (byte)'1', "legacy protocol magic");
        Mutate(encoded, 5, 99, "unknown operation");
        Mutate(encoded, 6, 2, "algorithm confusion");
        Mutate(encoded, 7, 1, "unknown flags");
        var wrongDigest = valid with { Digest = new byte[32] }; Reject(() => policy.Validate(wrongDigest), "digest mismatch");
        Reject(() => policy.Validate(valid with { ProfileUrn = Profile + ":other" }), "profile mismatch");
        Reject(() => policy.Validate(valid with { TemplateOid = "1.2.3.4" }), "template mismatch");
        Reject(() => policy.Validate(valid with { CertificateSha256 = new byte[31] }), "certificate pin shape");
        Reject(() => SignerProtocol.EncodeRequest(token, valid with { Payload = new byte[SigningIntentPolicy.MaximumPayloadBytes + 1] }),
            "oversized intent");
        var trailing = new byte[encoded.Length + 1]; encoded.CopyTo(trailing, 0);
        Reject(() => SignerProtocol.DecodeRequest(trailing), "trailing ambiguous encoding");
        CryptographicOperations.ZeroMemory(trailing);

        var response = SignerProtocol.EncodeResponse(0, correlation, new byte[384]);
        response[8] ^= 1;
        var responsePath = Path.Combine(root, "substitution.sock");
        using var remote = new UnixSocketRsa(responsePath, token.ToArray(), certificate);
        var fake = ServeFixedResponseAsync(responsePath, response);
        await fake.Ready;
        Reject(() =>
        {
            using var scope = remote.BeginEnrollmentIntent(new(SigningOperation.DomainEnrollment, correlation), Profile, Template, 2, 0, payload);
            _ = remote.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }, "response substitution");
        await fake.Completion;

        // An incomplete frame must be cancelled and never sign.
        var stalledPath = Path.Combine(root, "stalled.sock");
        var replay = new SigningReplayWindow(16, replayPath);
        var stalled = ServeStalledAsync(stalledPath, provider, token, SHA256.HashData(certificate.RawData), policy, replay);
        await stalled;
        Check(provider.SignCount == 4, "stalled request never reaches provider");
        CryptographicOperations.ZeroMemory(encoded); CryptographicOperations.ZeroMemory(digest);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
        Justification = "RunAsync returns before this helper on non-Linux platforms.")]
    private static void ProviderConfigurationTests(string root, RSA key, X509Certificate2 certificate)
    {
        var certificatePath = Path.Combine(root, "signer.pem");
        var privateKeyPath = Path.Combine(root, "signer.key");
        File.WriteAllText(certificatePath, certificate.ExportCertificatePem());
        File.WriteAllText(privateKeyPath, key.ExportPkcs8PrivateKeyPem());
        File.SetUnixFileMode(privateKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var values = new Dictionary<string, string?>
        {
            ["Broker:Signer:Provider"] = "pem-file", ["Broker:Signer:CertificateFile"] = certificatePath,
            ["Broker:Signer:PrivateKeyFile"] = privateKeyPath
        };
        using (var pem = IsolatedSignerKeyProvider.Load(Section(values))) IsolatedSignerKeyProvider.VerifyReadiness(pem);
        foreach (var absent in new string?[] { null, "", " ", "PEM-FILE", "unknown" })
        {
            values["Broker:Signer:Provider"] = absent;
            Reject(() => IsolatedSignerKeyProvider.Load(Section(values)), "absent, blank, noncanonical or unknown provider");
        }
        values["Broker:Signer:Provider"] = "pem-file"; values["Broker:Signer:ModulePath"] = "/hostile/module";
        Reject(() => IsolatedSignerKeyProvider.Load(Section(values)), "conflicting PEM and PKCS11 settings");
        values.Remove("Broker:Signer:ModulePath"); values["Broker:Signer:PrivateKeyFile"] = "relative.key";
        Reject(() => IsolatedSignerKeyProvider.Load(Section(values)), "hostile relative key path");

        const string environmentKey = "PKIPROXY_TEST_Broker__Signer__Provider";
        Environment.SetEnvironmentVariable(environmentKey, " ");
        try
        {
            var layered = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Broker:Signer:Provider"] = "pem-file", ["Broker:Signer:CertificateFile"] = certificatePath,
                ["Broker:Signer:PrivateKeyFile"] = privateKeyPath
            }).AddEnvironmentVariables("PKIPROXY_TEST_").Build();
            Reject(() => IsolatedSignerKeyProvider.Load(layered.GetSection("Broker:Signer")),
                "blank environment override cannot recover compatibility default");
        }
        finally { Environment.SetEnvironmentVariable(environmentKey, null); }
    }

    private static IConfigurationSection Section(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build().GetSection("Broker:Signer");

    private static (byte[] Csr, CsrBinding Binding, ControlledCertificateIdentity Identity, CmcTemplate Template) CreateEnrollment()
    {
        using var deviceKey = RSA.Create(2048);
        var request = new CertificateRequest("CN=ignored", deviceKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var csr = request.CreateSigningRequest();
        return (csr, CsrBinding.FromDer(csr),
            new("CN=device.example.test", [new Uri(Profile), new Uri("urn:example:pkiproxy:test:asset:one")], ["device.example.test"]),
            new(Template, 2, 0, SignerEku, TimeSpan.Zero, Profile));
    }

    private static void VerifyCms(byte[] encoded, X509Certificate2 certificate)
    {
        var cms = new SignedCms(); cms.Decode(encoded);
        var signer = cms.SignerInfos.Cast<SignerInfo>().Single(item => item.SignerIdentifier.Type != SubjectIdentifierType.NoSignature);
        signer.CheckSignature(new X509Certificate2Collection(certificate), verifySignatureOnly: true);
    }

    private static void Mutate(byte[] encoded, int offset, byte value, string label)
    {
        var copy = encoded.ToArray(); copy[offset] = value;
        Reject(() => SignerProtocol.DecodeRequest(copy), label);
        CryptographicOperations.ZeroMemory(copy);
    }

    private static (Task Ready, Task Completion) ServeOneAsync(string path, IIsolatedSignerKeyProvider provider, byte[] token,
        byte[] generation, SigningIntentPolicy policy, SigningReplayWindow replay, uint allowedUid)
    {
        var ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var completion = Task.Run(async () =>
        {
            if (File.Exists(path)) File.Delete(path);
            using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(path)); listener.Listen(1); ready.SetResult(true);
            using var client = await listener.AcceptAsync();
            await IsolatedSignerHost.HandleAsync(client, provider, token, generation, 60, allowedUid, policy, replay, CancellationToken.None);
            File.Delete(path);
        });
        return (ready.Task, completion);
    }

    private static (Task Ready, Task Completion) ServeFixedResponseAsync(string path, byte[] response)
    {
        var ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var completion = Task.Run(async () =>
        {
            if (File.Exists(path)) File.Delete(path);
            using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(path)); listener.Listen(1); ready.SetResult(true);
            using var client = await listener.AcceptAsync();
            using var stream = new NetworkStream(client); var buffer = new byte[SignerProtocol.MaximumRequestLength];
            while (await stream.ReadAsync(buffer) != 0) { }
            await stream.WriteAsync(response); File.Delete(path);
        });
        return (ready.Task, completion);
    }

    private static async Task ServeStalledAsync(string path, IIsolatedSignerKeyProvider provider, byte[] token, byte[] generation,
        SigningIntentPolicy policy, SigningReplayWindow replay)
    {
        if (File.Exists(path)) File.Delete(path);
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path)); listener.Listen(1);
        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        client.Connect(new UnixDomainSocketEndPoint(path));
        using var accepted = await listener.AcceptAsync();
        client.Send("PKS2"u8);
        await IsolatedSignerHost.HandleAsync(accepted, provider, token, generation, 60, geteuid(), policy, replay,
            CancellationToken.None, TimeSpan.FromMilliseconds(100));
        File.Delete(path);
    }

    private static void Reject(Action action, string label)
    {
        try { action(); }
        catch (Exception exception) when (exception is InvalidOperationException or CryptographicException or IOException) { return; }
        throw new InvalidOperationException("Unsafe isolated signer operation accepted: " + label);
    }

    private static void Check(bool condition, string label)
    { if (!condition) throw new InvalidOperationException("Isolated signer check failed: " + label); }

    private sealed class TestSignerKeyProvider : IIsolatedSignerKeyProvider
    {
        private readonly RSA key;
        private readonly X509Certificate2 certificate;
        private readonly byte[] spki;
        internal TestSignerKeyProvider(RSA key, X509Certificate2 certificate)
        { this.key = key; this.certificate = X509CertificateLoader.LoadCertificate(certificate.RawData); spki = key.ExportSubjectPublicKeyInfo(); }
        public int SignCount { get; private set; }
        public X509Certificate2 Certificate => certificate;
        public ReadOnlyMemory<byte> SubjectPublicKeyInfo => spki;
        public byte[] SignSha256Pkcs1(ReadOnlySpan<byte> hash)
        { SignCount++; return key.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); }
        internal RSA ExportKey() { var copy = RSA.Create(); copy.ImportParameters(key.ExportParameters(true)); return copy; }
        public void Dispose() { certificate.Dispose(); CryptographicOperations.ZeroMemory(spki); }
    }

    [DllImport("libc")]
    private static extern uint geteuid();
}
