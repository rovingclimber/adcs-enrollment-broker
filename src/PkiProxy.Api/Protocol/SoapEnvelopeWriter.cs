using System.Xml.Linq;

namespace PkiProxy.Protocol;

internal static class SoapEnvelopeWriter
{
    private static readonly XNamespace Soap12 = "http://www.w3.org/2003/05/soap-envelope";
    private static readonly XNamespace WsAddressing = "http://www.w3.org/2005/08/addressing";

    public const string XcepGetPoliciesResponseAction =
        "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse";

    public static XDocument CreateResponse(XElement operationResponse, string responseAction, string? requestMessageId)
    {
        ArgumentNullException.ThrowIfNull(operationResponse);
        ArgumentException.ThrowIfNullOrWhiteSpace(responseAction);

        var header = new XElement(Soap12 + "Header",
            new XElement(WsAddressing + "Action", responseAction),
            new XElement(WsAddressing + "MessageID", $"urn:uuid:{Guid.NewGuid():D}"));
        if (!string.IsNullOrWhiteSpace(requestMessageId))
        {
            header.Add(new XElement(WsAddressing + "RelatesTo", requestMessageId));
        }

        return new XDocument(
            new XElement(Soap12 + "Envelope",
                new XAttribute(XNamespace.Xmlns + "s", Soap12),
                new XAttribute(XNamespace.Xmlns + "a", WsAddressing),
                header,
                new XElement(Soap12 + "Body", operationResponse)));
    }
}
