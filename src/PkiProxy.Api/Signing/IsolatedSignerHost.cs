using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;
using PkiProxy.Protocol.Cmc;
using System.Runtime.InteropServices;

namespace PkiProxy.Signing;

internal static class IsolatedSignerHost
{
    internal static async Task<int> RunAsync(string[] args)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("The isolated signer requires Linux Unix sockets.");
        var configuration = new ConfigurationBuilder().AddEnvironmentVariables().Build();
        var section = configuration.GetSection("Broker:Signer");
        IsolatedSignerConfiguration.Validate(section);
        string Required(string key) => !string.IsNullOrWhiteSpace(section[key]) ? section[key]! :
            throw new InvalidOperationException($"Missing isolated signer setting {key}.");
        string Absolute(string key)
        {
            var value = Required(key);
            if (!Path.IsPathFullyQualified(value)) throw new InvalidOperationException("Absolute isolated signer paths required.");
            return value;
        }

        var socketPath = Absolute("SocketPath");
        var token = SignerProtocol.LoadToken(Absolute("AuthenticationTokenFile"));
        using var signer = IsolatedSignerKeyProvider.Load(section);
        var expectedHash = Convert.FromHexString(Required("CertificateSha256"));
        if (expectedHash.Length != 32 || !CryptographicOperations.FixedTimeEquals(expectedHash, SHA256.HashData(signer.Certificate.RawDataMemory.Span)))
            throw new CryptographicException("Isolated signer certificate generation mismatch.");
        if (!int.TryParse(Required("MinimumRemainingValidityMinutes"), out var minutes) || minutes is < 60 or > 10_080)
            throw new InvalidOperationException("Invalid isolated signer validity window.");
        var requiredEku = Required("ApplicationPolicyOid");
        if (!uint.TryParse(Required("AllowedClientUid"), out var allowedClientUid) || allowedClientUid == 0)
            throw new InvalidOperationException("A non-root broker listener UID is required.");
        if (!int.TryParse(Required("AllowedTemplateMajorVersion"), out var templateMajor) || templateMajor < 0 ||
            !int.TryParse(Required("AllowedTemplateMinorVersion"), out var templateMinor) || templateMinor < 0 ||
            !int.TryParse(Required("MaximumReplayEntries"), out var maximumReplayEntries))
            throw new InvalidOperationException("Invalid isolated signer intent policy.");
        var policy = new SigningIntentPolicy(Required("AllowedProfileUrn"), Required("AllowedTemplateOid"),
            templateMajor, templateMinor, maximumReplayEntries);
        policy.ValidateConfiguration();
        var replay = new SigningReplayWindow(policy.MaximumReplayEntries, Absolute("ReplayStateFile"));
        CmcEnrollmentRequestBuilder.ValidateExternalSigner(signer.Certificate, requiredEku, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(minutes));
        using var root = X509CertificateLoader.LoadCertificateFromFile(Absolute("IssuingCaFile"));
        using var publicSigner = X509CertificateLoader.LoadCertificate(signer.Certificate.RawData);
        if (!OpenSslCertificateVerifier.Load(root, Absolute("CrlFile")).Verify(publicSigner, CertificatePurpose.Signing))
            throw new CryptographicException("Isolated signer trust/currentness/revocation rejected.");
        IsolatedSignerKeyProvider.VerifyReadiness(signer);

        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(socketPath)!);
        if (File.Exists(socketPath)) File.Delete(socketPath);
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(socketPath));
        File.SetUnixFileMode(socketPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite);
        listener.Listen(16);
        using var shutdown = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; shutdown.Cancel(); };
        try
        {
            while (!shutdown.IsCancellationRequested)
            {
                using var client = await listener.AcceptAsync(shutdown.Token);
                await HandleAsync(client, signer, token, expectedHash, minutes, allowedClientUid, policy, replay, shutdown.Token);
            }
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        finally { try { File.Delete(socketPath); } catch { } CryptographicOperations.ZeroMemory(token); }
        return 0;
    }

    internal static async Task HandleAsync(Socket client, IIsolatedSignerKeyProvider signer, byte[] token, byte[] certificateHash,
        int minimumMinutes, uint allowedClientUid, SigningIntentPolicy policy, SigningReplayWindow replay,
        CancellationToken cancellationToken, TimeSpan? requestDeadline = null)
    {
        byte[]? request = null;
        byte[]? signature = null;
        SigningIntentRequest? intent = null;
        try
        {
            if (GetPeerUid(client) != allowedClientUid) return;
            client.ReceiveTimeout = client.SendTimeout = 10_000;
            using var stream = new NetworkStream(client, ownsSocket: false);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(requestDeadline ?? TimeSpan.FromSeconds(10));
            var header = new byte[SignerProtocol.RequestHeaderLength];
            try
            {
                await SignerProtocol.ReadExactlyAsync(stream, header, deadline.Token);
                var length = SignerProtocol.DecodeFrameLength(header);
                request = new byte[length]; header.CopyTo(request, 0);
                await SignerProtocol.ReadExactlyAsync(stream, request.AsMemory(header.Length), deadline.Token);
                var trailing = new byte[1];
                if (await stream.ReadAsync(trailing, deadline.Token) != 0)
                    throw new CryptographicException("Signing intent rejected.");
            }
            finally { CryptographicOperations.ZeroMemory(header); }
            intent = SignerProtocol.DecodeRequest(request);
            if (!CryptographicOperations.FixedTimeEquals(request.AsSpan(12, 32), token) ||
                !CryptographicOperations.FixedTimeEquals(intent.CertificateSha256, certificateHash) ||
                signer.Certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow.AddMinutes(minimumMinutes))
                throw new CryptographicException("Signing intent rejected.");
            policy.Validate(intent);
            if (!replay.TryAdmit(intent)) throw new CryptographicException("Signing intent rejected.");
            signature = signer.SignSha256Pkcs1(intent.Digest);
            var response = SignerProtocol.EncodeResponse(0, intent.CorrelationId, signature);
            try { await stream.WriteAsync(response, deadline.Token); }
            finally { CryptographicOperations.ZeroMemory(response); }
        }
        catch (Exception exception) when (exception is IOException or SocketException or CryptographicException or OperationCanceledException)
        {
            // Deliberately no request, key or exception output from this boundary.
        }
        finally
        {
            if (request is not null) CryptographicOperations.ZeroMemory(request);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
            if (intent is not null)
            {
                CryptographicOperations.ZeroMemory(intent.CorrelationId); CryptographicOperations.ZeroMemory(intent.CertificateSha256);
                CryptographicOperations.ZeroMemory(intent.Payload); CryptographicOperations.ZeroMemory(intent.Digest);
            }
        }
    }

    private static uint GetPeerUid(Socket socket)
    {
        var credential = new UCred();
        uint length = checked((uint)Marshal.SizeOf<UCred>());
        if (getsockopt(socket.Handle.ToInt32(), 1, 17, ref credential, ref length) != 0 ||
            length != Marshal.SizeOf<UCred>())
            throw new SocketException(Marshal.GetLastPInvokeError());
        return credential.Uid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UCred { internal int Pid; internal uint Uid; internal uint Gid; }

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(int socket, int level, int optionName, ref UCred value, ref uint length);
}

internal static class IsolatedSignerConfiguration
{
    private static readonly HashSet<string> AllowedKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "Provider", "SocketPath", "AuthenticationTokenFile", "CertificateFile", "PrivateKeyFile",
        "CertificateSha256", "MinimumRemainingValidityMinutes", "ApplicationPolicyOid", "AllowedClientUid",
        "IssuingCaFile", "CrlFile", "AllowedProfileUrn", "AllowedTemplateOid", "AllowedTemplateMajorVersion",
        "AllowedTemplateMinorVersion", "MaximumReplayEntries", "ReplayStateFile", "ModulePath", "PinFile",
        "TokenLabel", "TokenSerial", "KeyId", "MaximumSessions"
    };

    internal static void Validate(IConfigurationSection section)
    {
        if (!string.IsNullOrWhiteSpace(section.Value))
            throw new InvalidOperationException("Unsupported isolated signer configuration shape.");

        foreach (var child in section.GetChildren())
        {
            if (!AllowedKeys.Contains(child.Key) || child.GetChildren().Any())
                throw new InvalidOperationException("Unsupported isolated signer configuration key or shape.");
        }
    }
}
