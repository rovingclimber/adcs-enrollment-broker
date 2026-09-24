using System.Globalization;
using System.Xml.Linq;

namespace PkiProxy.Protocol.Xcep;

internal sealed record GetPoliciesRequest(
    DateTimeOffset? LastUpdate,
    string? PreferredLanguage,
    IReadOnlySet<string> PolicyOids,
    int? ClientVersion,
    int? ServerVersion);

internal static class GetPoliciesContract
{
    private static readonly XNamespace Xcep = XcepNamespaces.EnrollmentPolicy;
    private static readonly XNamespace Xsi = XcepNamespaces.XmlSchemaInstance;

    public static bool TryParse(
        XElement operation,
        out GetPoliciesRequest? request,
        out string? errorCode)
    {
        request = null;
        errorCode = null;

        if (operation.Name != Xcep + "GetPolicies")
        {
            errorCode = "UnexpectedXcepOperation";
            return false;
        }

        var children = operation.Elements().ToList();
        if (children.Count != 2 || children[0].Name != Xcep + "client" ||
            children[1].Name != Xcep + "requestFilter")
        {
            errorCode = "InvalidGetPoliciesSequence";
            return false;
        }

        if (IsNil(children[0]))
        {
            errorCode = "MissingXcepClient";
            return false;
        }

        if (!TryParseClient(children[0], out var lastUpdate, out var language, out errorCode) ||
            !TryParseFilter(children[1], out var policyOids, out var clientVersion, out var serverVersion, out errorCode))
        {
            return false;
        }

        request = new GetPoliciesRequest(lastUpdate, language, policyOids, clientVersion, serverVersion);
        return true;
    }

    private static bool TryParseClient(
        XElement client,
        out DateTimeOffset? lastUpdate,
        out string? language,
        out string? errorCode)
    {
        lastUpdate = null;
        language = null;
        errorCode = null;
        var children = client.Elements().ToList();
        if (children.Count < 2 || children[0].Name != Xcep + "lastUpdate" ||
            children[1].Name != Xcep + "preferredLanguage")
        {
            errorCode = "InvalidXcepClientSequence";
            return false;
        }

        var parsedLastUpdate = default(DateTimeOffset);
        if (!IsNil(children[0]) && !DateTimeOffset.TryParse(
                children[0].Value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out parsedLastUpdate))
        {
            errorCode = "InvalidXcepLastUpdate";
            return false;
        }

        lastUpdate = IsNil(children[0]) ? null : parsedLastUpdate;
        if (!IsNil(children[1]))
        {
            language = children[1].Value.Trim();
            if (language.Length == 0)
            {
                errorCode = "InvalidXcepPreferredLanguage";
                return false;
            }
        }

        return true;
    }

    private static bool TryParseFilter(
        XElement filter,
        out IReadOnlySet<string> policyOids,
        out int? clientVersion,
        out int? serverVersion,
        out string? errorCode)
    {
        policyOids = new HashSet<string>(StringComparer.Ordinal);
        clientVersion = null;
        serverVersion = null;
        errorCode = null;

        if (IsNil(filter))
        {
            return true;
        }

        var children = filter.Elements().ToList();
        if (children.Count < 3 || children[0].Name != Xcep + "policyOIDs" ||
            children[1].Name != Xcep + "clientVersion" || children[2].Name != Xcep + "serverVersion")
        {
            errorCode = "InvalidXcepRequestFilterSequence";
            return false;
        }

        if (!TryParseOidFilter(children[0], out policyOids) ||
            !TryParseOptionalInt(children[1], out clientVersion) ||
            !TryParseOptionalInt(children[2], out serverVersion))
        {
            errorCode = "InvalidXcepRequestFilter";
            return false;
        }

        return true;
    }

    private static bool TryParseOidFilter(XElement policyOidsElement, out IReadOnlySet<string> policyOids)
    {
        var parsed = new HashSet<string>(StringComparer.Ordinal);
        policyOids = parsed;
        if (IsNil(policyOidsElement))
        {
            return true;
        }

        foreach (var oidElement in policyOidsElement.Elements())
        {
            if (oidElement.Name != Xcep + "oid")
            {
                return false;
            }

            var oid = oidElement.Value.Trim();
            if (!IsOid(oid) || !parsed.Add(oid))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryParseOptionalInt(XElement element, out int? value)
    {
        value = null;
        if (IsNil(element))
        {
            return true;
        }

        if (!int.TryParse(element.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return false;
        }

        value = parsed;
        return true;
    }

    private static bool IsNil(XElement element) =>
        string.Equals((string?)element.Attribute(Xsi + "nil"), "true", StringComparison.OrdinalIgnoreCase) ||
        string.Equals((string?)element.Attribute(Xsi + "nil"), "1", StringComparison.Ordinal);

    private static bool IsOid(string value)
    {
        var parts = value.Split('.', StringSplitOptions.None);
        return parts.Length >= 2 && parts.All(part =>
            part.Length > 0 && part.All(char.IsAsciiDigit));
    }
}
