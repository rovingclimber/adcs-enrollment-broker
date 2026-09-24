using Microsoft.Extensions.Configuration;
using PkiProxy.Signing;
using PkiProxy.Protocol.Cmc;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

internal static partial class Pkcs11SignerProviderTests
{
    private const string Label = "pkiproxy-ci";
    private const string UserPin = "64297531";
    private const string SoPin = "81357924";
    private const string KeyId = "5349474E4552";
    private const string UnsafeKeyId = "554E53414645";
    private static readonly string[] ModulePaths = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    ];

    internal static async Task RunAsync()
    {
        var attributes = Pkcs11IsolatedSignerKeyProvider.AttributeConstantsForTests;
        Check(attributes == (0x1UL, 0x2UL, 0x102UL, 0x103UL, 0x104UL, 0x105UL, 0x106UL,
            0x107UL, 0x108UL, 0x10cUL, 0x120UL, 0x121UL, 0x122UL), "PKCS#11 v2.x attribute constants");
        if (!OperatingSystem.IsLinux()) return;
        var moduleAlias = ModulePaths.FirstOrDefault(File.Exists);
        if (moduleAlias is null)
        {
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI")))
                throw new InvalidOperationException("CI must provide SoftHSM2 and OpenSC PKCS#11 tooling.");
            return;
        }
        var module = new FileInfo(moduleAlias).ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? moduleAlias;

        var configurationPath = Environment.GetEnvironmentVariable("SOFTHSM2_CONF");
        if (string.IsNullOrWhiteSpace(configurationPath) || !Path.IsPathFullyQualified(configurationPath) || !File.Exists(configurationPath))
            throw new InvalidOperationException("SoftHSM contract requires process-start configuration.");
        var root = Path.GetDirectoryName(configurationPath)!;
        try
        {
            Run("softhsm2-util", "--init-token", "--free", "--label", Label, "--so-pin", SoPin, "--pin", UserPin);
            var serial = SerialRegex().Match(Run("pkcs11-tool", "--module", module, "--list-slots")).Groups[1].Value;
            Check(serial.Length is > 0 and <= 16, "exact token serial discovered");
            GenerateDisposableKey(module, serial);
            var publicPath = Path.Combine(root, "signer-public.der");
            Run("pkcs11-tool", "--module", module, "--login", "--pin", UserPin, "--token-label", Label,
                "--read-object", "--type", "pubkey", "--id", KeyId, "--output-file", publicPath);
            using var publicKey = RSA.Create(); publicKey.ImportSubjectPublicKeyInfo(await File.ReadAllBytesAsync(publicPath), out _);
            using var caKey = RSA.Create(3072);
            var caRequest = new CertificateRequest("CN=AD CS Enrollment Broker CI test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            var signerNotAfter = new DateTimeOffset(ca.NotAfter.ToUniversalTime()).AddSeconds(-1);
            var signerRequest = new CertificateRequest("CN=AD CS Enrollment Broker SoftHSM signer", publicKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            signerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            signerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            signerRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.2.3.4") }, false));
            using var signerCertificate = signerRequest.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-1), signerNotAfter, RandomNumberGenerator.GetBytes(16));
            var certificatePath = Path.Combine(root, "signer.der"); await File.WriteAllBytesAsync(certificatePath, signerCertificate.RawData);
            Run("pkcs11-tool", "--module", module, "--login", "--pin", UserPin, "--token-label", Label,
                "--write-object", certificatePath, "--type", "cert", "--id", KeyId, "--label", "signer");

            var pinPath = Path.Combine(root, "pin"); await File.WriteAllTextAsync(pinPath, UserPin + "\n");
            File.SetUnixFileMode(pinPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var values = Settings(module, pinPath, serial);
            DiagnoseStrictFixture(module, serial);
            using var provider = (Pkcs11IsolatedSignerKeyProvider)IsolatedSignerKeyProvider.Load(Section(values));
            IsolatedSignerKeyProvider.VerifyReadiness(provider);
            Check(!provider.Certificate.HasPrivateKey && provider.Certificate.RawData.AsSpan().SequenceEqual(signerCertificate.RawData), "public certificate only");
            CmcEnrollmentRequestBuilder.ValidateExternalSigner(provider.Certificate, "1.2.3.4", DateTimeOffset.UtcNow);
            Reject(() => CmcEnrollmentRequestBuilder.ValidateSigner(provider.Certificate, "1.2.3.4", DateTimeOffset.UtcNow), "attached-key profile remains strict");
            Check(provider.SubjectPublicKeyInfo.Span.SequenceEqual(publicKey.ExportSubjectPublicKeyInfo()), "token/certificate SPKI match");

            var digests = Enumerable.Range(0, 24).Select(i => SHA256.HashData(BitConverter.GetBytes(i))).ToArray();
            var signatures = await Task.WhenAll(digests.Select(digest => Task.Run(() => provider.SignSha256Pkcs1(digest))));
            Check(signatures.Select((signature, i) => publicKey.VerifyHash(digests[i], signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)).All(value => value),
                "bounded overlapping sessions produce exact SHA256/PKCS1 signatures");
            Reject(() => provider.SignSha256Pkcs1(new byte[20]), "algorithm downgrade");
            var afterRejectedRequest = provider.SignSha256Pkcs1(SHA256.HashData("still-ready"u8));
            Check(publicKey.VerifyHash(SHA256.HashData("still-ready"u8), afterRejectedRequest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                "rejected request cannot log out or fault another session");

            var wrongToken = new Dictionary<string, string?>(values) { ["Broker:Signer:TokenSerial"] = "0000000000000000" };
            Reject(() => IsolatedSignerKeyProvider.Load(Section(wrongToken)), "wrong token selector");
            var wrongKey = new Dictionary<string, string?>(values) { ["Broker:Signer:KeyId"] = "00" };
            Reject(() => IsolatedSignerKeyProvider.Load(Section(wrongKey)), "wrong key selector");
            var wrongPinPath = Path.Combine(root, "wrong-pin"); await File.WriteAllTextAsync(wrongPinPath, "not-the-pin");
            File.SetUnixFileMode(wrongPinPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var wrongPin = new Dictionary<string, string?>(values) { ["Broker:Signer:PinFile"] = wrongPinPath };
            var pinFailure = Reject(() => IsolatedSignerKeyProvider.Load(Section(wrongPin)), "wrong login");
            Check(!pinFailure.ToString().Contains("not-the-pin", StringComparison.Ordinal), "PIN absent from errors");
            File.SetUnixFileMode(pinPath, UnixFileMode.UserRead | UnixFileMode.OtherRead);
            Reject(() => IsolatedSignerKeyProvider.Load(Section(values)), "readable PIN file");
            File.SetUnixFileMode(pinPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            foreach (var hostile in new[] { "0", "17", "not-a-number" })
            {
                var invalid = new Dictionary<string, string?>(values) { ["Broker:Signer:MaximumSessions"] = hostile };
                Reject(() => IsolatedSignerKeyProvider.Load(Section(invalid)), "hostile session limit");
            }
            var relativeModule = new Dictionary<string, string?>(values) { ["Broker:Signer:ModulePath"] = "libsofthsm2.so" };
            Reject(() => IsolatedSignerKeyProvider.Load(Section(relativeModule)), "relative module");

            GenerateDisposableKey(module, serial, UnsafeKeyId, decrypt: true);
            var unsafePublicPath = Path.Combine(root, "unsafe-public.der");
            Run("pkcs11-tool", "--module", module, "--login", "--pin", UserPin, "--token-label", Label,
                "--read-object", "--type", "pubkey", "--id", UnsafeKeyId, "--output-file", unsafePublicPath);
            using var unsafePublicKey = RSA.Create(); unsafePublicKey.ImportSubjectPublicKeyInfo(await File.ReadAllBytesAsync(unsafePublicPath), out _);
            var unsafeRequest = new CertificateRequest("CN=Rejected decrypt-capable signer", unsafePublicKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var unsafeCertificate = unsafeRequest.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-1), signerNotAfter, RandomNumberGenerator.GetBytes(16));
            var unsafeCertificatePath = Path.Combine(root, "unsafe.der"); await File.WriteAllBytesAsync(unsafeCertificatePath, unsafeCertificate.RawData);
            Run("pkcs11-tool", "--module", module, "--login", "--pin", UserPin, "--token-label", Label,
                "--write-object", unsafeCertificatePath, "--type", "cert", "--id", UnsafeKeyId, "--label", "unsafe");
            var unsafeAttributes = new Dictionary<string, string?>(values) { ["Broker:Signer:KeyId"] = UnsafeKeyId };
            Reject(() => IsolatedSignerKeyProvider.Load(Section(unsafeAttributes)), "decrypt-capable private key");

            provider.Dispose();
            Reject(() => provider.SignSha256Pkcs1(SHA256.HashData("after-dispose"u8)), "disposed provider");
            using (var restartedProvider = (Pkcs11IsolatedSignerKeyProvider)IsolatedSignerKeyProvider.Load(Section(values)))
                IsolatedSignerKeyProvider.VerifyReadiness(restartedProvider);

            Run("pkcs11-tool", "--module", module, "--login", "--pin", UserPin, "--token-label", Label,
                "--write-object", certificatePath, "--type", "cert", "--id", KeyId, "--label", "duplicate");
            Reject(() => IsolatedSignerKeyProvider.Load(Section(values)), "ambiguous certificate object");
            Console.WriteLine("PKCS#11 signer checks passed: real SoftHSM RSA3072, strict and unsafe attributes, SPKI, concurrency, restart, ambiguity, PIN/config and disposal failures.");
        }
        finally
        {
            // The CI shell owns and removes the disposable token directory.
        }
    }

    private static Dictionary<string, string?> Settings(string module, string pinPath, string serial) => new()
    {
        ["Broker:Signer:Provider"] = "pkcs11", ["Broker:Signer:ModulePath"] = module,
        ["Broker:Signer:PinFile"] = pinPath, ["Broker:Signer:TokenLabel"] = Label,
        ["Broker:Signer:TokenSerial"] = serial, ["Broker:Signer:KeyId"] = KeyId,
        ["Broker:Signer:MaximumSessions"] = "4"
    };

    private static IConfigurationSection Section(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build().GetSection("Broker:Signer");

    private static void DiagnoseStrictFixture(string modulePath, string serial)
    {
        using var module = new Pkcs11Module(modulePath);
        var slots = module.FindTokenSlots(Label, serial);
        Check(slots.Length == 1, "exact token selector");
        Check(module.SupportsRsaPkcsSigning(slots[0]), "CKM_RSA_PKCS sign mechanism");
        using var session = module.OpenSession(slots[0]);
        var pin = System.Text.Encoding.ASCII.GetBytes(UserPin);
        try { session.Login(pin); } finally { CryptographicOperations.ZeroMemory(pin); }
        var id = Convert.FromHexString(KeyId);
        var privateKeys = session.FindObjects(3, id); var publicKeys = session.FindObjects(2, id); var certificates = session.FindObjects(1, id);
        Check(privateKeys.Length == 1 && publicKeys.Length == 1 && certificates.Length == 1, "one object of each required class");
        Check(session.ReadBoolean(privateKeys[0], 1), "private key is token object");
        Check(session.ReadBoolean(privateKeys[0], 2), "private key CKA_PRIVATE");
        Check(session.ReadBoolean(privateKeys[0], 0x103), "private key CKA_SENSITIVE");
        Check(!session.ReadBoolean(privateKeys[0], 0x162), "private key CKA_EXTRACTABLE false");
        Check(session.ReadBoolean(privateKeys[0], 0x108), "private key CKA_SIGN");
        Check(!session.ReadBoolean(privateKeys[0], 0x105), "private key CKA_DECRYPT false");
        Check(!session.ReadBoolean(privateKeys[0], 0x107), "private key CKA_UNWRAP false");
        Check(!session.ReadBoolean(privateKeys[0], 0x10c), "private key CKA_DERIVE false");
        Check(session.ReadUlong(privateKeys[0], 0x100) == 0, "private RSA key type");
        Check(session.ReadBoolean(publicKeys[0], 1) && session.ReadUlong(publicKeys[0], 0x100) == 0 &&
            session.ReadUlong(publicKeys[0], 0x121) >= 3072, "public RSA3072 token object");
        Check(session.ReadBoolean(certificates[0], 1) && session.ReadUlong(certificates[0], 0x80) == 0, "X.509 token object");
        CryptographicOperations.ZeroMemory(id);
    }

    private static void GenerateDisposableKey(string modulePath, string serial, string keyId = KeyId, bool decrypt = false)
    {
        using var module = new Pkcs11Module(modulePath);
        var slot = module.FindTokenSlots(Label, serial).Single();
        using var session = module.OpenWritableSessionForTests(slot);
        var pin = System.Text.Encoding.ASCII.GetBytes(UserPin);
        try { session.Login(pin); } finally { CryptographicOperations.ZeroMemory(pin); }
        var id = Convert.FromHexString(keyId);
        try
        {
            session.GenerateRsaKeyPairForTests(id, decrypt ? "unsafe" : "signer", decrypt);
            var key = session.FindObjects(3, id).Single();
            Check(session.ReadBoolean(key, 0x105) == decrypt && !session.ReadBoolean(key, 0x107) &&
                !session.ReadBoolean(key, 0x10c) && !session.ReadBoolean(key, 0x162),
                "disposable fixture creation-template readback");
        }
        finally { CryptographicOperations.ZeroMemory(id); }
    }

    private static string Run(string file, params string[] arguments)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false } };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        process.StartInfo.Environment["SOFTHSM2_CONF"] = Environment.GetEnvironmentVariable("SOFTHSM2_CONF");
        process.Start(); var output = process.StandardOutput.ReadToEnd(); var error = process.StandardError.ReadToEnd(); process.WaitForExit();
        if (process.ExitCode != 0) throw new InvalidOperationException("PKCS#11 test fixture command failed: " + file + " " + error);
        return output + error;
    }

    private static Exception Reject(Action action, string label)
    {
        try { action(); }
        catch (Exception exception) when (exception is InvalidOperationException or CryptographicException or ObjectDisposedException) { return exception; }
        throw new InvalidOperationException("Unsafe PKCS#11 operation accepted: " + label);
    }

    private static void Check(bool condition, string label)
    { if (!condition) throw new InvalidOperationException("PKCS#11 signer check failed: " + label); }

    [GeneratedRegex(@"token label\s*:\s*pkiproxy-ci[\s\S]*?serial num\s*:\s*([0-9a-fA-F]+)", RegexOptions.IgnoreCase)]
    private static partial Regex SerialRegex();
}
