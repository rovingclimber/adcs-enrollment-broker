using System.Text;
using System.Xml.Linq;

namespace PkiProxy.Protocol;

internal static class SoapFaults
{
    private static readonly XNamespace Soap12 = "http://www.w3.org/2003/05/soap-envelope";
    private static readonly XNamespace Broker = "urn:example:pki-broker:pki-broker:faults:v1";

    public static IResult Sender(string correlationId, string code, string reason) =>
        Create("Sender", StatusCodes.Status400BadRequest, correlationId, code, reason);

    public static IResult Receiver(string correlationId, string code, string reason) =>
        Create("Receiver", StatusCodes.Status501NotImplemented, correlationId, code, reason);

    public static IResult ProcessingFailure(string correlationId) =>
        Create("Receiver", StatusCodes.Status500InternalServerError, correlationId,
            "EnrollmentNotReleased", "Enrollment was not released. Reconciliation may be required before retrying.");

    private static IResult Create(
        string soapCode,
        int statusCode,
        string correlationId,
        string detailCode,
        string reason)
    {
        var envelope = new XDocument(
            new XElement(Soap12 + "Envelope",
                new XAttribute(XNamespace.Xmlns + "s", Soap12),
                new XAttribute(XNamespace.Xmlns + "b", Broker),
                new XElement(Soap12 + "Body",
                    new XElement(Soap12 + "Fault",
                        new XElement(Soap12 + "Code",
                            new XElement(Soap12 + "Value", $"s:{soapCode}")),
                        new XElement(Soap12 + "Reason",
                            new XElement(Soap12 + "Text",
                                new XAttribute(XNamespace.Xml + "lang", "en-GB"),
                                reason)),
                        new XElement(Soap12 + "Detail",
                            new XElement(Broker + "BrokerFault",
                                new XElement(Broker + "Code", detailCode),
                                new XElement(Broker + "CorrelationId", correlationId)))))));

        return Results.Content(
            envelope.ToString(SaveOptions.DisableFormatting),
            "application/soap+xml; charset=utf-8",
            Encoding.UTF8,
            statusCode);
    }
}
