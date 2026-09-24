using System.Formats.Asn1;
using System.Security.Cryptography;

namespace PkiProxy.Domain;

// A bootstrap attestation is bound to both values. The CSR hash prevents a
// same-key request from changing its signed request content; the SPKI hash
// makes the public-key binding explicit for later renewal correlation.
internal sealed record CsrBinding(byte[] CsrSha256, byte[] SubjectPublicKeyInfoSha256)
{
    private const int Sha256Length = 32;

    public static CsrBinding FromDer(ReadOnlySpan<byte> certificationRequestDer)
    {
        if (certificationRequestDer.IsEmpty)
        {
            throw new ArgumentException("A DER certificate request is required.", nameof(certificationRequestDer));
        }

        var csrBytes = certificationRequestDer.ToArray();
        var subjectPublicKeyInfo = ExtractSubjectPublicKeyInfo(csrBytes);
        return new CsrBinding(
            SHA256.HashData(csrBytes),
            SHA256.HashData(subjectPublicKeyInfo.Span));
    }

    public bool Matches(CsrBinding candidate) =>
        candidate is not null &&
        CryptographicOperations.FixedTimeEquals(CsrSha256, candidate.CsrSha256) &&
        CryptographicOperations.FixedTimeEquals(SubjectPublicKeyInfoSha256, candidate.SubjectPublicKeyInfoSha256);

    public bool HasExpectedLengths() =>
        CsrSha256 is { Length: Sha256Length } && SubjectPublicKeyInfoSha256 is { Length: Sha256Length };

    internal CsrBinding Snapshot()
    {
        if (!HasExpectedLengths()) throw new ArgumentException("Exact SHA256 bindings required.");
        return new(CsrSha256.ToArray(), SubjectPublicKeyInfoSha256.ToArray());
    }

    internal static byte[] ExtractSubjectPublicKeyInfoDer(ReadOnlySpan<byte> certificationRequestDer) =>
        ExtractSubjectPublicKeyInfo(certificationRequestDer.ToArray()).ToArray();

    private static ReadOnlyMemory<byte> ExtractSubjectPublicKeyInfo(byte[] certificationRequestDer)
    {
        try
        {
            var request = new AsnReader(certificationRequestDer, AsnEncodingRules.DER);
            var requestSequence = request.ReadSequence();
            var requestInfo = requestSequence.ReadSequence();

            // CertificationRequestInfo ::= SEQUENCE { version, subject,
            // subjectPKInfo, attributes }. Read the first two encoded values
            // rather than interpreting client-provided subject content.
            _ = requestInfo.ReadEncodedValue();
            _ = requestInfo.ReadEncodedValue();
            var subjectPublicKeyInfo = requestInfo.ReadEncodedValue();

            // The attributes field, signatureAlgorithm and signature are not
            // trusted for identity, but their DER structure must be consumed
            // so a truncated or concatenated value cannot acquire a binding.
            _ = requestInfo.ReadEncodedValue();
            requestInfo.ThrowIfNotEmpty();
            _ = requestSequence.ReadEncodedValue();
            _ = requestSequence.ReadBitString(out _);
            requestSequence.ThrowIfNotEmpty();
            request.ThrowIfNotEmpty();

            if (subjectPublicKeyInfo.IsEmpty)
            {
                throw new CryptographicException("The PKCS#10 request has no SubjectPublicKeyInfo.");
            }

            return subjectPublicKeyInfo;
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("The certificate request is not valid DER PKCS#10.", exception);
        }
    }
}
