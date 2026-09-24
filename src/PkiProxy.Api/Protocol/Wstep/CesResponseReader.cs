using System.Globalization;
using System.Net;
using System.Xml;
using System.Xml.Linq;

namespace PkiProxy.Protocol.Wstep;

// Parsed bytes are NOT release-authorized certificates. Caller must validate
// the full PKI response and the leaf against the bound enrollment and CRL.
internal sealed record ParsedCesResponse(int RequestId, byte[] CertificateDer, byte[] FullPkiResponse);

internal static class CesResponseReader
{
    private static readonly XNamespace Soap = "http://www.w3.org/2003/05/soap-envelope";
    private static readonly XNamespace Address = "http://www.w3.org/2005/08/addressing";
    private static readonly XNamespace Trust = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static readonly XNamespace Security = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static readonly XNamespace Enrollment = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
    private const string LeafType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

    internal static ParsedCesResponse ReadIssued(CesTransportResponse response, string expectedMessageId)
    {
        if (response.StatusCode != HttpStatusCode.OK || response.Body.Length is 0 or > 1_048_576 ||
            !Uri.TryCreate(expectedMessageId, UriKind.Absolute, out _))
            throw new InvalidDataException("Bounded successful correlated CES response required.");
        try
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
                MaxCharactersInDocument = 1_048_576, IgnoreComments = true, IgnoreProcessingInstructions = true };
            using var stream = new MemoryStream(response.Body, writable: false);
            using (var depthReader = XmlReader.Create(stream, settings))
                while (depthReader.Read()) if (depthReader.Depth > 32) throw new InvalidDataException("CES XML too deeply nested.");
            stream.Position = 0;
            using var reader = XmlReader.Create(stream, settings);
            var document = XDocument.Load(reader);
            var parsed = SoapEnvelopeReader.Parse(document);
            if (!parsed.IsValid || parsed.WsAddressingAction != WstepResponseWriter.ResponseAction)
                throw new InvalidDataException("Unexpected CES SOAP envelope/action.");
            var header = Single(document.Root!, Soap + "Header");
            if (Text(Single(header, Address + "Action")) != WstepResponseWriter.ResponseAction ||
                Text(Single(header, Address + "RelatesTo")) != expectedMessageId)
                throw new InvalidDataException("CES response correlation failed.");
            var collection = parsed.Operation!;
            if (collection.Name != Trust + "RequestSecurityTokenResponseCollection" || collection.Elements().Count() != 1)
                throw new InvalidDataException("One CES response required.");
            var reply = Single(collection, Trust + "RequestSecurityTokenResponse");
            // Disposition is human-readable/localized, not a machine success code.
            _ = Text(Single(reply, Enrollment + "DispositionMessage"));
            if (Text(Single(reply, Trust + "TokenType")) != LeafType)
                throw new InvalidDataException("Unexpected CES token type.");
            var requestId = Text(Single(reply, Enrollment + "RequestID"));
            if (!int.TryParse(requestId, NumberStyles.None, CultureInfo.InvariantCulture, out var id) || id <= 0)
                throw new InvalidDataException("Concrete positive CA request ID required.");
            var requested = Single(reply, Trust + "RequestedSecurityToken");
            if (requested.Elements().Count() != 1) throw new InvalidDataException("One issued token required.");
            var leaf = Token(Single(requested, Security + "BinarySecurityToken"), LeafType, 65_536);
            var full = Token(Single(reply, Security + "BinarySecurityToken"), Security.NamespaceName + "#PKCS7", 786_432);
            return new(id, leaf, full);
        }
        catch (Exception exception) when (exception is XmlException or FormatException or InvalidOperationException)
        { throw new InvalidDataException("Malformed or ambiguous CES response.", exception); }
    }

    private static XElement Single(XElement parent, XName name) => parent.Elements(name).Single();
    private static string Text(XElement element)
    {
        if (element.HasElements || element.Attributes().Any(a => a.Name.LocalName == "nil"))
            throw new InvalidDataException("Concrete scalar CES value required.");
        return element.Value.Trim();
    }
    private static byte[] Token(XElement element, string type, int maximumBytes)
    {
        if ((string?)element.Attribute("ValueType") != type ||
            (string?)element.Attribute("EncodingType") != Security.NamespaceName + "#base64binary")
            throw new InvalidDataException("Unexpected CES binary token encoding.");
        var bytes = Convert.FromBase64String(Text(element));
        if (bytes.Length == 0 || bytes.Length > maximumBytes) throw new InvalidDataException("CES token size invalid.");
        return bytes;
    }
}
