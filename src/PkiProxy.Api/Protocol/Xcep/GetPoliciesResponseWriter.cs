using System.Xml.Linq;

namespace PkiProxy.Protocol.Xcep;

// This represents the MS-XCEP "unchanged" response shape only. It is deliberately
// separate from endpoint authentication and from the future broker-policy projection.
internal static class GetPoliciesResponseWriter
{
    private static readonly XNamespace Xcep = XcepNamespaces.EnrollmentPolicy;
    private static readonly XNamespace Xsi = XcepNamespaces.XmlSchemaInstance;

    public static XElement CreatePoliciesNotChanged(string policyServerId, uint nextUpdateHours)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyServerId);
        ArgumentOutOfRangeException.ThrowIfZero(nextUpdateHours);

        return new XElement(Xcep + "GetPoliciesResponse",
            new XElement(Xcep + "response",
                new XElement(Xcep + "policyID", policyServerId),
                Nil("policyFriendlyName"),
                new XElement(Xcep + "nextUpdateHours", nextUpdateHours),
                new XElement(Xcep + "policiesNotChanged", true),
                Nil("policies")),
            Nil("cAs"),
            Nil("oIDs"));
    }

    private static XElement Nil(string localName) =>
        new(Xcep + localName, new XAttribute(Xsi + "nil", "true"));
}
