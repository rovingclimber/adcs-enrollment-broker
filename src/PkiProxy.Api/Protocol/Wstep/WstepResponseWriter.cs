using System.Xml.Linq;

namespace PkiProxy.Protocol.Wstep;

internal static class WstepResponseWriter
{
    private const int MaximumCertificateBytes = 65_536;
    private const int MaximumFullPkiResponseBytes = 786_432;
    private const int MaximumLanguageLength = 128;
    private const string X509V3TokenType =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    private const string Pkcs7ValueType =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7";
    private const string Base64EncodingType =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary";

    public const string ResponseAction = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep";

    private static readonly XNamespace Wst = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static readonly XNamespace Wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static readonly XNamespace Wstep = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
    private static readonly XNamespace Xsi = "http://www.w3.org/2001/XMLSchema-instance";

    public static XElement CreateIssued(
        ReadOnlySpan<byte> certificateDer,
        ReadOnlySpan<byte> fullPkiResponseDer,
        string? requestId,
        string language)
    {
        if (certificateDer.IsEmpty || certificateDer.Length > MaximumCertificateBytes ||
            fullPkiResponseDer.IsEmpty || fullPkiResponseDer.Length > MaximumFullPkiResponseBytes)
        {
            throw new ArgumentException("An issued certificate and full PKI response are required.");
        }

        ValidateLanguage(language);
        ValidateRequestId(requestId);
        return Collection(Response(
            // The disposition is an issuer-facing, human-readable message;
            // the MS-WSTEP examples use the literal "Issued" rather than an
            // invented status URI.
            Disposition("Issued", language),
            new XElement(Wsse + "BinarySecurityToken",
                new XAttribute("ValueType", Pkcs7ValueType),
                new XAttribute("EncodingType", Base64EncodingType),
                Convert.ToBase64String(fullPkiResponseDer)),
            new XElement(Wst + "RequestedSecurityToken",
                new XElement(Wsse + "BinarySecurityToken",
                    new XAttribute("ValueType", X509V3TokenType),
                    new XAttribute("EncodingType", Base64EncodingType),
                    Convert.ToBase64String(certificateDer))),
            RequestId(requestId)));
    }

    public static XElement CreatePending(string requestId, string language)
    {
        ValidateRequestId(requestId, allowNull: false);
        ValidateLanguage(language);
        return Collection(Response(
            Disposition("Pending", language),
            RequestId(requestId)));
    }

    private static XElement Collection(XElement response) =>
        new(Wst + "RequestSecurityTokenResponseCollection", response);

    private static XElement Response(params object?[] content) =>
        new(Wst + "RequestSecurityTokenResponse",
            new XElement(Wst + "TokenType", X509V3TokenType),
            content);

    private static XElement Disposition(string value, string language) =>
        new(Wstep + "DispositionMessage",
            new XAttribute(XNamespace.Xml + "lang", language),
            value);

    // MS-WSTEP 3.1.4.1.3.4 requires RequestID to be present: it contains the
    // issuer's request identifier, or is explicitly nil when the issuer did
    // not supply one. Omitting it is observably different to Windows clients.
    private static XElement RequestId(string? requestId) =>
        requestId is null
            ? new XElement(Wstep + "RequestID", new XAttribute(Xsi + "nil", "true"))
            : new XElement(Wstep + "RequestID", requestId);

    private static void ValidateRequestId(string? requestId, bool allowNull = true)
    {
        if (requestId is null)
        {
            if (allowNull) return;
            throw new ArgumentNullException(nameof(requestId));
        }
        if (requestId.Length == 0 || requestId.Length > WstepRequestContract.MaximumRequestIdLength ||
            requestId != requestId.Trim() || requestId.Any(char.IsControl))
            throw new ArgumentException("RequestID must be a bounded, unambiguous scalar.", nameof(requestId));
    }

    private static void ValidateLanguage(string language)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(language);
        if (language.Length > MaximumLanguageLength || language != language.Trim() || language.Any(char.IsControl))
            throw new ArgumentException("Language must be a bounded scalar.", nameof(language));
    }
}
