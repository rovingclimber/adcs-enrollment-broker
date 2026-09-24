namespace PkiProxy.Directory;

// Parsing is deliberately separate from GSS authentication so hostile principal
// spellings can be tested without manufacturing an authenticated context.
internal sealed record KerberosUserIdentity(string AccountName)
{
    private static readonly HashSet<string> BuiltInAccounts = new(StringComparer.OrdinalIgnoreCase)
    {
        "Administrator", "Guest", "krbtgt", "DefaultAccount", "WDAGUtilityAccount"
    };

    internal static KerberosUserIdentity? FromAuthenticatedPeerName(
        string? peerName, string dnsRealm, string netBiosDomain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dnsRealm);
        ArgumentException.ThrowIfNullOrWhiteSpace(netBiosDomain);
        if (peerName is null || peerName.Length is < 3 or > 320) return null;

        string candidate;
        var slash = peerName.IndexOf('\\');
        var at = peerName.IndexOf('@');
        if (slash > 0 && at < 0 &&
            peerName[..slash].Equals(netBiosDomain, StringComparison.OrdinalIgnoreCase))
            candidate = peerName[(slash + 1)..];
        else if (at > 0 && slash < 0 &&
            peerName[(at + 1)..].Equals(dnsRealm, StringComparison.OrdinalIgnoreCase))
            candidate = peerName[..at];
        else return null;

        if (candidate.Length is < 1 or > 64 || candidate.EndsWith('$') ||
            BuiltInAccounts.Contains(candidate) ||
            candidate.Any(character => !char.IsAsciiLetterOrDigit(character) &&
                character is not '-' and not '_' and not '.'))
            return null;
        return new(candidate);
    }
}
