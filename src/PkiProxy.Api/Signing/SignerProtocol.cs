using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace PkiProxy.Signing;

internal static class SignerProtocol
{
    internal static ReadOnlySpan<byte> RequestMagic => "PKS2"u8;
    internal static ReadOnlySpan<byte> ResponseMagic => "PKR2"u8;
    internal const byte Version = 1;
    internal const byte Sha256RsaPkcs1 = 1;
    internal const int TokenLength = 32;
    internal const int HashLength = 32;
    internal const int CorrelationLength = 32;
    internal const int MaximumProfileBytes = 512;
    internal const int MaximumTemplateBytes = 128;
    internal const int RequestHeaderLength = 156;
    internal const int ResponseHeaderLength = 42;
    internal const int MaximumRequestLength = RequestHeaderLength + MaximumProfileBytes + MaximumTemplateBytes + SigningIntentPolicy.MaximumPayloadBytes;

    internal static byte[] LoadToken(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("The isolated signer requires Linux Unix sockets.");
        var encoded = LinuxSecretFile.ReadAllBytes(path, 66, "Owner-only signer authentication token file required.");
        try
        {
            var length = encoded.Length;
            while (length > 0 && encoded[length - 1] is (byte)'\r' or (byte)'\n') length--;
            if (length != TokenLength * 2) throw new InvalidOperationException("Invalid signer authentication token.");
            Span<byte> token = stackalloc byte[TokenLength];
            for (var index = 0; index < TokenLength; index++)
            {
                var high = HexNibble(encoded[index * 2]); var low = HexNibble(encoded[index * 2 + 1]);
                if (high < 0 || low < 0) throw new InvalidOperationException("Invalid signer authentication token.");
                token[index] = checked((byte)((high << 4) | low));
            }
            return token.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    internal static byte[] EncodeRequest(ReadOnlySpan<byte> token, SigningIntentRequest request)
    {
        if (token.Length != TokenLength || request.CertificateSha256.Length != HashLength ||
            request.CorrelationId.Length != CorrelationLength || request.Digest.Length != HashLength ||
            !Enum.IsDefined(request.Operation))
            throw new CryptographicException("Invalid signer request shape.");
        var profile = Encoding.UTF8.GetBytes(request.ProfileUrn);
        var template = Encoding.ASCII.GetBytes(request.TemplateOid);
        try
        {
            if (profile.Length > MaximumProfileBytes || template.Length > MaximumTemplateBytes ||
                request.Payload.Length > SigningIntentPolicy.MaximumPayloadBytes)
                throw new CryptographicException("Invalid signer request shape.");
            var length = checked(RequestHeaderLength + profile.Length + template.Length + request.Payload.Length);
            var encoded = new byte[length];
            var span = encoded.AsSpan();
            RequestMagic.CopyTo(span); span[4] = Version; span[5] = (byte)request.Operation;
            span[6] = Sha256RsaPkcs1; span[7] = 0;
            BinaryPrimitives.WriteInt32BigEndian(span[8..12], length);
            token.CopyTo(span[12..44]); request.CertificateSha256.CopyTo(span[44..76]);
            request.CorrelationId.CopyTo(span[76..108]);
            BinaryPrimitives.WriteInt32BigEndian(span[108..112], request.TemplateMajorVersion);
            BinaryPrimitives.WriteInt32BigEndian(span[112..116], request.TemplateMinorVersion);
            BinaryPrimitives.WriteUInt16BigEndian(span[116..118], checked((ushort)profile.Length));
            BinaryPrimitives.WriteUInt16BigEndian(span[118..120], checked((ushort)template.Length));
            BinaryPrimitives.WriteInt32BigEndian(span[120..124], request.Payload.Length);
            request.Digest.CopyTo(span[124..156]);
            profile.CopyTo(span[156..]); template.CopyTo(span[(156 + profile.Length)..]);
            request.Payload.CopyTo(span[(156 + profile.Length + template.Length)..]);
            return encoded;
        }
        finally { CryptographicOperations.ZeroMemory(profile); CryptographicOperations.ZeroMemory(template); }
    }

    internal static SigningIntentRequest DecodeRequest(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < RequestHeaderLength || encoded.Length > MaximumRequestLength ||
            !encoded[..4].SequenceEqual(RequestMagic) || encoded[4] != Version || encoded[6] != Sha256RsaPkcs1 || encoded[7] != 0 ||
            BinaryPrimitives.ReadInt32BigEndian(encoded[8..12]) != encoded.Length)
            throw new CryptographicException("Signing intent rejected.");
        var operation = (SigningOperation)encoded[5];
        if (!Enum.IsDefined(operation)) throw new CryptographicException("Signing intent rejected.");
        var profileLength = BinaryPrimitives.ReadUInt16BigEndian(encoded[116..118]);
        var templateLength = BinaryPrimitives.ReadUInt16BigEndian(encoded[118..120]);
        var payloadLength = BinaryPrimitives.ReadInt32BigEndian(encoded[120..124]);
        if (profileLength > MaximumProfileBytes || templateLength > MaximumTemplateBytes || payloadLength < 0 ||
            payloadLength > SigningIntentPolicy.MaximumPayloadBytes ||
            RequestHeaderLength + profileLength + templateLength + payloadLength != encoded.Length)
            throw new CryptographicException("Signing intent rejected.");
        var profileBytes = encoded.Slice(RequestHeaderLength, profileLength);
        var templateBytes = encoded.Slice(RequestHeaderLength + profileLength, templateLength);
        if (!IsCanonicalAscii(profileBytes) || !IsCanonicalAscii(templateBytes))
            throw new CryptographicException("Signing intent rejected.");
        return new(operation, encoded[76..108].ToArray(), encoded[44..76].ToArray(),
            Encoding.UTF8.GetString(profileBytes), Encoding.ASCII.GetString(templateBytes),
            BinaryPrimitives.ReadInt32BigEndian(encoded[108..112]), BinaryPrimitives.ReadInt32BigEndian(encoded[112..116]),
            encoded[(RequestHeaderLength + profileLength + templateLength)..].ToArray(), encoded[124..156].ToArray());
    }

    internal static int DecodeFrameLength(ReadOnlySpan<byte> header)
    {
        if (header.Length != RequestHeaderLength || !header[..4].SequenceEqual(RequestMagic) || header[4] != Version)
            throw new CryptographicException("Signing intent rejected.");
        var length = BinaryPrimitives.ReadInt32BigEndian(header[8..12]);
        if (length < RequestHeaderLength || length > MaximumRequestLength) throw new CryptographicException("Signing intent rejected.");
        return length;
    }

    internal static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken token)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer[read..], token);
            if (count == 0) throw new EndOfStreamException("Signer connection closed early.");
            read += count;
        }
    }

    internal static byte[] EncodeResponse(byte status, ReadOnlySpan<byte> correlation, ReadOnlySpan<byte> signature)
    {
        if (correlation.Length != CorrelationLength || status > 1 || signature.Length > ushort.MaxValue ||
            (status == 0 && signature.Length == 0) || (status != 0 && signature.Length != 0))
            throw new CryptographicException("Invalid signer response shape.");
        var response = new byte[ResponseHeaderLength + signature.Length];
        ResponseMagic.CopyTo(response); response[4] = Version; response[5] = status; response[6] = response[7] = 0;
        correlation.CopyTo(response.AsSpan(8, CorrelationLength));
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(40, 2), checked((ushort)signature.Length));
        signature.CopyTo(response.AsSpan(ResponseHeaderLength));
        return response;
    }

    private static bool IsCanonicalAscii(ReadOnlySpan<byte> value)
    {
        foreach (var item in value) if (item is < 0x21 or > 0x7e) return false;
        return true;
    }

    private static int HexNibble(byte value) => value switch
    {
        >= (byte)'0' and <= (byte)'9' => value - (byte)'0',
        >= (byte)'A' and <= (byte)'F' => value - (byte)'A' + 10,
        >= (byte)'a' and <= (byte)'f' => value - (byte)'a' + 10,
        _ => -1
    };
}

internal static class LinuxSecretFile
{
    private const uint RegularFile = 0x8000;
    private const uint FileTypeMask = 0xF000;
    private const uint OwnerReadWrite = 0x180;
    private const uint PermissionMask = 0x1FF;

    internal static byte[] ReadAllBytes(string path, int maximumBytes, string failure)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumBytes, 1);
        using var handle = OpenAndValidate(path, failure, out var metadata);
        if (metadata.Size is <= 0 || metadata.Size > maximumBytes) throw new InvalidOperationException(failure);
        var value = new byte[checked((int)metadata.Size)];
        using var stream = new FileStream(handle, FileAccess.Read);
        stream.ReadExactly(value);
        return value;
    }

    internal static void Validate(string path, string failure)
    {
        using var handle = OpenAndValidate(path, failure, out _);
    }

    private static SafeFileHandle OpenAndValidate(string path, string failure, out LinuxStat metadata)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Owner validation requires Linux.");
        if (!Path.IsPathFullyQualified(path) || new FileInfo(path).LinkTarget is not null)
            throw new InvalidOperationException(failure);
        SafeFileHandle? handle = null;
        try
        {
            handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (fstat(handle.DangerousGetHandle().ToInt32(), out metadata) != 0 ||
                (metadata.Mode & FileTypeMask) != RegularFile ||
                (metadata.Mode & PermissionMask) != OwnerReadWrite || metadata.Uid != geteuid())
                throw new InvalidOperationException(failure);
            return handle;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            handle?.Dispose();
            throw new InvalidOperationException(failure);
        }
        catch
        {
            handle?.Dispose();
            throw;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStat
    {
        internal ulong Device;
        internal ulong Inode;
        internal ulong LinkCount;
        internal uint Mode;
        internal uint Uid;
        internal uint Gid;
        internal int Padding;
        internal ulong RDevice;
        internal long Size;
        internal long BlockSize;
        internal long Blocks;
        internal long AccessSeconds;
        internal long AccessNanoseconds;
        internal long ModificationSeconds;
        internal long ModificationNanoseconds;
        internal long ChangeSeconds;
        internal long ChangeNanoseconds;
        internal long Reserved0;
        internal long Reserved1;
        internal long Reserved2;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int fstat(int descriptor, out LinuxStat metadata);

    [DllImport("libc")]
    private static extern uint geteuid();
}

internal sealed class UnixSocketRsa : RSA
{
    private readonly string socketPath;
    private readonly byte[] token;
    private readonly byte[] certificateSha256;
    private readonly RSA publicKey;
    private readonly AsyncLocal<SigningIntentRequest?> intent = new();

    internal UnixSocketRsa(string socketPath, byte[] token, X509Certificate2 certificate)
    {
        if (!Path.IsPathFullyQualified(socketPath)) throw new InvalidOperationException("Absolute signer socket path required.");
        this.socketPath = socketPath;
        if (token.Length != SignerProtocol.TokenLength) throw new InvalidOperationException("Invalid signer authentication token.");
        this.token = token.ToArray(); CryptographicOperations.ZeroMemory(token);
        certificateSha256 = SHA256.HashData(certificate.RawDataMemory.Span);
        publicKey = certificate.GetRSAPublicKey() ?? throw new CryptographicException("RSA signer certificate required.");
        KeySizeValue = publicKey.KeySize;
        LegalKeySizesValue = publicKey.LegalKeySizes;
    }

    internal IDisposable BeginEnrollmentIntent(SigningIntentMetadata metadata, string profileUrn, string templateOid,
        int major, int minor, ReadOnlySpan<byte> payload)
    {
        var snapshot = metadata.Snapshot();
        return Begin(new(snapshot.Operation, snapshot.CorrelationId, certificateSha256.ToArray(), profileUrn, templateOid,
            major, minor, payload.ToArray(), SigningIntentPolicy.ComputeCmsSignatureDigest(payload)));
    }

    internal IDisposable BeginSelfTest()
    {
        var payload = SigningIntentPolicy.SelfTestPayload.ToArray();
        return Begin(new(SigningOperation.InternalSelfTest, RandomNumberGenerator.GetBytes(SignerProtocol.CorrelationLength),
            certificateSha256.ToArray(), "", "", 0, 0, payload, SHA256.HashData(payload)));
    }

    private IntentScope Begin(SigningIntentRequest value)
    {
        if (intent.Value is not null) throw new InvalidOperationException("Nested signing intent rejected.");
        intent.Value = value;
        return new IntentScope(this, value);
    }

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(hash);
        var current = intent.Value ?? throw new CryptographicException("A policy-bound signing intent is required.");
        if (hashAlgorithm != HashAlgorithmName.SHA256 || padding != RSASignaturePadding.Pkcs1 || hash.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(hash, current.Digest))
            throw new CryptographicException("The signer accepts only the bound RSA PKCS#1 SHA-256 intent.");
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        socket.SendTimeout = socket.ReceiveTimeout = 10_000;
        socket.Connect(new UnixDomainSocketEndPoint(socketPath));
        using var stream = new NetworkStream(socket, ownsSocket: false);
        var request = SignerProtocol.EncodeRequest(token, current);
        try { stream.Write(request); socket.Shutdown(SocketShutdown.Send); }
        finally { CryptographicOperations.ZeroMemory(request); }
        Span<byte> header = stackalloc byte[SignerProtocol.ResponseHeaderLength];
        stream.ReadExactly(header);
        if (!header[..4].SequenceEqual(SignerProtocol.ResponseMagic) || header[4] != SignerProtocol.Version ||
            header[6] != 0 || header[7] != 0 ||
            !CryptographicOperations.FixedTimeEquals(header[8..40], current.CorrelationId))
            throw new CryptographicException("Invalid isolated signer response.");
        var length = BinaryPrimitives.ReadUInt16BigEndian(header[40..42]);
        if (header[5] != 0) throw new CryptographicException("Isolated signer rejected the request.");
        if (length != KeySize / 8) throw new CryptographicException("Invalid isolated signer response.");
        var signature = new byte[length];
        stream.ReadExactly(signature);
        if (!publicKey.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            CryptographicOperations.ZeroMemory(signature);
            throw new CryptographicException("Invalid isolated signer response.");
        }
        return signature;
    }

    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) =>
        publicKey.VerifyHash(hash, signature, hashAlgorithm, padding);
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters) throw new CryptographicException("Private key export is prohibited.");
        return publicKey.ExportParameters(false);
    }
    public override void ImportParameters(RSAParameters parameters) => throw new NotSupportedException();
    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) => throw new NotSupportedException();
    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) => publicKey.Encrypt(data, padding);
    protected override void Dispose(bool disposing)
    {
        if (disposing) { publicKey.Dispose(); CryptographicOperations.ZeroMemory(token); CryptographicOperations.ZeroMemory(certificateSha256); }
        base.Dispose(disposing);
    }

    private sealed class IntentScope : IDisposable
    {
        private readonly UnixSocketRsa owner;
        private readonly SigningIntentRequest value;
        private int disposed;

        internal IntentScope(UnixSocketRsa owner, SigningIntentRequest value)
        {
            this.owner = owner;
            this.value = value;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            if (!ReferenceEquals(owner.intent.Value, value)) throw new InvalidOperationException("Signing intent scope mismatch.");
            owner.intent.Value = null;
            CryptographicOperations.ZeroMemory(value.CorrelationId); CryptographicOperations.ZeroMemory(value.CertificateSha256);
            CryptographicOperations.ZeroMemory(value.Payload); CryptographicOperations.ZeroMemory(value.Digest);
        }
    }
}
