using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Domain;

internal sealed record IncomingCsrPolicy(IReadOnlySet<string> AllowedExtensionOids)
{
    public static IncomingCsrPolicy NoClientExtensions { get; } =
        new(new HashSet<string>(StringComparer.Ordinal));
}

internal enum IncomingCsrValidationResult
{
    Valid,
    InvalidPkcs10,
    DisallowedExtension
}

internal sealed record IncomingCsrValidation(
    IncomingCsrValidationResult Result,
    string? ExtensionOid);

internal static class IncomingCsrPolicyValidator
{
    public static IncomingCsrValidation Validate(ReadOnlySpan<byte> certificationRequestDer, IncomingCsrPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        try
        {
            var request = CertificateRequest.LoadSigningRequest(
                certificationRequestDer.ToArray(),
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
            foreach (X509Extension extension in request.CertificateExtensions)
            {
                if (extension.Oid?.Value is not { } oid || !policy.AllowedExtensionOids.Contains(oid))
                {
                    return new IncomingCsrValidation(IncomingCsrValidationResult.DisallowedExtension, extension.Oid?.Value);
                }
            }

            return new IncomingCsrValidation(IncomingCsrValidationResult.Valid, null);
        }
        catch (CryptographicException)
        {
            return new IncomingCsrValidation(IncomingCsrValidationResult.InvalidPkcs10, null);
        }
        catch (NotSupportedException)
        {
            // Includes a digest-only/null signature presented as client POP.
            return new IncomingCsrValidation(IncomingCsrValidationResult.InvalidPkcs10, null);
        }
    }
}
