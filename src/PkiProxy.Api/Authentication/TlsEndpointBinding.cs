using System.Buffers.Binary;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Authentication;

internal static class TlsEndpointBinding
{
    public static byte[] FromServerStream(SslStream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.IsServer || !stream.IsAuthenticated || !stream.IsEncrypted || stream.LocalCertificate is null)
            throw new AuthenticationException("An authenticated server TLS stream is required.");
        // .NET10 Unix GetChannelBinding(Endpoint) hashes the REMOTE certificate.
        // On an acceptor that is absent (or a client cert), not the TLS server's
        // certificate. RFC5929 requires the actual negotiated local leaf here.
        // Never substitute a configured cert, proxy header or client assertion.
        using var certificate = X509CertificateLoader.LoadCertificate(stream.LocalCertificate.GetRawCertData());
        var hash = certificate.SignatureAlgorithm.Value switch
        {
            "1.2.840.113549.1.1.11" or "1.2.840.10045.4.3.2" => SHA256.HashData(certificate.RawDataMemory.Span),
            "1.2.840.113549.1.1.12" or "1.2.840.10045.4.3.3" => SHA384.HashData(certificate.RawDataMemory.Span),
            "1.2.840.113549.1.1.13" or "1.2.840.10045.4.3.4" => SHA512.HashData(certificate.RawDataMemory.Span),
            _ => throw new AuthenticationException("TLS leaf signature algorithm is outside the supported binding profile.")
        };
        // Deliberately narrow TLS-leaf profile: no SHA1/MD5, RSA-PSS parameter
        // interpretation, or unknown algorithm fallback. This is not a generic
        // implementation of every RFC5929 certificate signature algorithm.
        return "tls-server-end-point:"u8.ToArray().Concat(hash).ToArray();
    }

    // Client-side provider binding extraction, also used by interoperability
    // tests. Server callers MUST use FromServerStream instead (see above).
    public static byte[] GetApplicationData(ChannelBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        var acquired = false;
        try
        {
            binding.DangerousAddRef(ref acquired);
            if (binding.IsInvalid || binding.Size is < 32 or > 4096)
                throw new ArgumentException("Invalid TLS endpoint binding.", nameof(binding));
            var bytes = new byte[binding.Size];
            Marshal.Copy(binding.DangerousGetHandle(), bytes, 0, bytes.Length);
            // SEC_CHANNEL_BINDINGS: eight 32-bit words, application length/offset
            // in the final two. No address bindings are permitted in this profile.
            if (bytes.AsSpan(0, 24).IndexOfAnyExcept((byte)0) >= 0)
                throw new ArgumentException("Unexpected address channel binding.", nameof(binding));
            var length = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(24));
            var offset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(28));
            if (offset < 32 || offset > bytes.Length || length > bytes.Length - offset)
                throw new ArgumentException("Invalid TLS binding offsets.", nameof(binding));
            var result = bytes.AsSpan((int)offset, (int)length).ToArray();
            ValidateApplicationData(result);
            return result;
        }
        finally { if (acquired) binding.DangerousRelease(); }
    }

    internal static void ValidateApplicationData(ReadOnlySpan<byte> value)
    {
        // SHA256/384/512 endpoint digests only. SHA1/MD5 leaf signatures require
        // SHA256 per RFC5929. Certificate signature choice is separately governed.
        ReadOnlySpan<byte> prefix = "tls-server-end-point:"u8;
        if (!value.StartsWith(prefix) || value.Length - prefix.Length is not (32 or 48 or 64))
            throw new ArgumentException("A supported TLS server-end-point binding is required.", nameof(value));
    }
}
