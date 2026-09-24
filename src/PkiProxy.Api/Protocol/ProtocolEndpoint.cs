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

        var protocol = path.StartsWithSegments("/cep", StringComparison.OrdinalIgnoreCase)
            ? "MS-XCEP"
            : path.StartsWithSegments("/ces", StringComparison.OrdinalIgnoreCase)
                ? "MS-WSTEP"
                : null;

        if (protocol is null)
        {
            return false;
        }

        endpoint = new ProtocolEndpoint(protocol, authentication.ToLowerInvariant());
        return true;
    }
}
