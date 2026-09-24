using System.Net;
using System.Text;
using System.Xml.Linq;
using PkiProxy.Protocol;
using PkiProxy.Protocol.Wstep;
using PkiProxy.Domain;

internal static class CesResponseReaderTests
{
    internal static void Run()
    {
        const string message = "urn:uuid:9d967f4a-1f90-4a79-b39c-acb9b9e09c25";
        XNamespace address = "http://www.w3.org/2005/08/addressing";
        XNamespace trust = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
        XNamespace enrollment = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
        XNamespace security = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        // Bytes intentionally opaque: parsing must not claim certificate validation.
        XDocument Good() => SoapEnvelopeWriter.CreateResponse(WstepResponseWriter.CreateIssued([1, 2], [3, 4], "27", "en-GB"), WstepResponseWriter.ResponseAction, message);
        CesTransportResponse Transport(XDocument doc) => new(HttpStatusCode.OK, Encoding.UTF8.GetBytes(doc.ToString()));
        var result = CesResponseReader.ReadIssued(Transport(Good()), message);
        if (result.RequestId != 27 || !result.CertificateDer.SequenceEqual(new byte[] { 1, 2 }) ||
            !result.FullPkiResponse.SequenceEqual(new byte[] { 3, 4 })) throw new InvalidOperationException("CES parsing failed.");
        var checks = 1;
        var outgoing = NativeCesEnrollmentIssuer.CreateRequest(new Uri("https://ces.invalid/service.svc/CES"), message, [1, 2, 3]);
        var outgoingEnvelope = SoapEnvelopeReader.Parse(XDocument.Parse(Encoding.UTF8.GetString(outgoing)));
        if (!outgoingEnvelope.IsValid || outgoingEnvelope.WsAddressingMessageId != message ||
            !WstepRequestContract.TryParse(outgoingEnvelope.Operation!, outgoingEnvelope.WsAddressingAction, out var outgoingRequest, out _) ||
            !outgoingRequest!.CertificateRequestDer!.SequenceEqual(new byte[] { 1, 2, 3 }))
            throw new InvalidOperationException("Outgoing authorized CMC request contract failed.");
        checks++;
        void Reject(CesTransportResponse response)
        {
            try { CesResponseReader.ReadIssued(response, message); }
            catch (InvalidDataException) { checks++; return; }
            throw new InvalidOperationException("Unsafe CES response accepted.");
        }
        foreach (var name in new[] { address + "Action", address + "RelatesTo", enrollment + "RequestID", trust + "RequestedSecurityToken", trust + "RequestSecurityTokenResponse" })
        {
            var doc = Good(); var node = doc.Descendants(name).Single(); node.AddAfterSelf(new XElement(node)); Reject(Transport(doc));
            doc = Good(); doc.Descendants(name).Single().Remove(); Reject(Transport(doc));
        }
        foreach (var name in new[] { address + "Action", address + "RelatesTo", enrollment + "RequestID", trust + "TokenType" })
        {
            var doc = Good(); doc.Descendants(name).Single().Value = "incorrect"; Reject(Transport(doc));
        }
        foreach (var attribute in new[] { "ValueType", "EncodingType" })
        {
            var doc = Good(); doc.Descendants(security + "BinarySecurityToken").First().SetAttributeValue(attribute, "wrong"); Reject(Transport(doc));
        }
        var badBase64 = Good(); badBase64.Descendants(security + "BinarySecurityToken").Last().Value = "!!!"; Reject(Transport(badBase64));
        var nested = Good(); nested.Descendants(address + "RelatesTo").Single().ReplaceNodes(new XElement("nested", message)); Reject(Transport(nested));
        Reject(new(HttpStatusCode.InternalServerError, Transport(Good()).Body));
        Reject(new(HttpStatusCode.OK, new byte[1_048_577]));
        Reject(new(HttpStatusCode.OK, Encoding.UTF8.GetBytes("<!DOCTYPE x [<!ENTITY e 'value'>]><x>&e;</x>")));
        Console.WriteLine($"CES response parsing checks passed: {checks}.");
    }
}
