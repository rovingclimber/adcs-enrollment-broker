using System.Xml.Linq;

namespace PkiProxy.Protocol.Wstep;

internal enum WstepRequestKind
{
    Issue,
    QueryTokenStatus,
    KeyExchangeToken
}

internal sealed record WstepRequest(
    WstepRequestKind Kind,
    byte[]? CertificateRequestDer,
    string? RequestId,
    string? Context);

internal static class WstepRequestContract
{
    public const int MaximumContextLength = 2048;
    public const int MaximumRequestIdLength = 256;
    public const int MaximumBinaryTokenBytes = InboundRequestLimits.DefaultMaximumDecodedBinaryBytes;
    public const string EnrollmentAction = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep";
    public const string KetAction = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/KET";

    private const string IssueRequestType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
    private const string QueryTokenStatusRequestType = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/QueryTokenStatus";
    private const string KetRequestType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/KET";
    private const string X509V3TokenType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    private const string Base64EncodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary";

    private static readonly XNamespace Wst = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static readonly XNamespace Wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static readonly XNamespace Wstep = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";

    public static bool TryParse(XElement operation, string? soapAction, out WstepRequest? request, out string? errorCode)
        => TryParse(operation, soapAction, MaximumBinaryTokenBytes, out request, out errorCode);

    public static bool TryParse(XElement operation, string? soapAction, int maximumBinaryTokenBytes,
        out WstepRequest? request, out string? errorCode)
    {
        request = null;
        errorCode = null;
        if (operation.Name != Wst + "RequestSecurityToken")
        {
            errorCode = "UnexpectedWstepOperation";
            return false;
        }

        // MS-WSTEP section 3.1.4.1.3.3 permits arbitrary WS-Trust extension
        // elements and says to ignore ones that WSTEP does not use. Its own
        // extension elements are, however, maxOccurs=1. Reject ambiguity only
        // for those security-relevant fields; do not reject valid clients just
        // because they send an unrelated WS-Trust extension.
        if (!HasAtMostOne(operation, Wsse + "BinarySecurityToken") ||
            !HasAtMostOne(operation, Wst + "RequestKET") ||
            !HasAtMostOne(operation, Wstep + "RequestID"))
        {
            errorCode = "DuplicateWstepExtension";
            return false;
        }

        if (!TryGetSingleValue(operation, Wst + "TokenType", out var tokenType) || tokenType != X509V3TokenType ||
            !TryGetSingleValue(operation, Wst + "RequestType", out var requestType))
        {
            errorCode = "InvalidWstepTokenOrRequestType";
            return false;
        }

        var context = (string?)operation.Attribute("Context");
        if (context is not null && !IsBoundedScalar(context, MaximumContextLength, allowEmpty: true))
        {
            errorCode = "InvalidWstepContext";
            return false;
        }
        if (requestType == IssueRequestType && soapAction == EnrollmentAction)
        {
            if (!TryGetCertificateRequest(operation, maximumBinaryTokenBytes, out var certificateRequest, out errorCode))
            {
                return false;
            }

            request = new WstepRequest(WstepRequestKind.Issue, certificateRequest, null, context);
            return true;
        }

        if (requestType == QueryTokenStatusRequestType && soapAction == EnrollmentAction)
        {
            if (!TryGetRequestId(operation, out var requestId))
            {
                errorCode = "InvalidWstepRequestId";
                return false;
            }

            request = new WstepRequest(WstepRequestKind.QueryTokenStatus, null, requestId, context);
            return true;
        }

        if (requestType == KetRequestType && soapAction == KetAction && operation.Element(Wst + "RequestKET") is not null)
        {
            request = new WstepRequest(WstepRequestKind.KeyExchangeToken, null, null, context);
            return true;
        }

        errorCode = "InvalidWstepActionAndRequestType";
        return false;
    }

    private static bool TryGetSingleValue(XElement parent, XName name, out string value)
    {
        value = string.Empty;
        var elements = parent.Elements(name).ToList();
        if (elements.Count != 1)
        {
            return false;
        }

        value = elements[0].Value.Trim();
        return value.Length > 0;
    }

    private static bool TryGetRequestId(XElement parent, out string value)
    {
        value = string.Empty;
        var elements = parent.Elements(Wstep + "RequestID").ToList();
        if (elements.Count != 1) return false;
        value = elements[0].Value;
        return IsBoundedScalar(value, MaximumRequestIdLength, allowEmpty: false);
    }

    private static bool IsBoundedScalar(string value, int maximumLength, bool allowEmpty) =>
        (allowEmpty || value.Length > 0) && value.Length <= maximumLength &&
        value == value.Trim() && !value.Any(char.IsControl);

    private static bool HasAtMostOne(XElement parent, XName name) =>
        parent.Elements(name).Take(2).Count() <= 1;

    private static bool TryGetCertificateRequest(XElement operation, int maximumBinaryTokenBytes,
        out byte[]? certificateRequest, out string? errorCode)
    {
        certificateRequest = null;
        errorCode = null;
        var tokens = operation.Elements(Wsse + "BinarySecurityToken").ToList();
        if (tokens.Count != 1 || !string.Equals((string?)tokens[0].Attribute("EncodingType"), Base64EncodingType, StringComparison.Ordinal))
        {
            errorCode = "InvalidWstepBinarySecurityToken";
            return false;
        }

        var encoded = tokens[0].Value;
        var nonWhitespaceLength = encoded.Count(c => !char.IsWhiteSpace(c));
        if (maximumBinaryTokenBytes is < 1 or > 1_048_576)
        {
            errorCode = "InvalidWstepBinarySecurityToken";
            return false;
        }
        var maximumEncodedLength = ((maximumBinaryTokenBytes + 2) / 3) * 4;
        if (nonWhitespaceLength == 0 || nonWhitespaceLength > maximumEncodedLength)
        {
            errorCode = "InvalidWstepBinarySecurityToken";
            return false;
        }

        try
        {
            certificateRequest = Convert.FromBase64String(encoded);
            if (certificateRequest.Length == 0 || certificateRequest.Length > maximumBinaryTokenBytes)
            {
                errorCode = "InvalidWstepBinarySecurityToken";
                return false;
            }

            return true;
        }
        catch (FormatException)
        {
            errorCode = "InvalidWstepBinarySecurityToken";
            return false;
        }
    }
}
