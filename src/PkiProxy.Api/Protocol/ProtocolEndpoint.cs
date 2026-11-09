namespace PkiProxy.Protocol;

internal sealed record ProtocolEndpoint(string Protocol, string Authentication)
{
    private static readonly HashSet<string> AuthenticationModes =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "kerberos",
            "bootstrap",
            "certificate"
        };

    public static bool TryParse(
        PathString path,
        string authentication,
        out ProtocolEndpoint endpoint)
    {
        endpoint = null!;
        if (!AuthenticationModes.Contains(authentication))
        {
            return false;
        }

        string protocol;
        if (path.StartsWithSegments("/cep", StringComparison.OrdinalIgnoreCase))
            protocol = "MS-XCEP";
        else if (path.StartsWithSegments("/ces", StringComparison.OrdinalIgnoreCase))
            protocol = "MS-WSTEP";
        else
            return false;

        endpoint = new ProtocolEndpoint(protocol, authentication.ToLowerInvariant());
        return true;
    }
}
