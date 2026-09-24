using System.Net.Security;
using PkiProxy.Authentication;

namespace PkiProxy.Directory;

// Constructible only from an OS-validated, completed server security context.
// Transport must additionally enforce HTTPS, channel/service binding, bounded
// handshakes and connection ownership. This class does not implement HTTP auth.
internal sealed class KerberosComputerIdentity
{
    private KerberosComputerIdentity(string accountName) => AccountName = accountName;
    public string AccountName { get; }

    public static KerberosComputerIdentity? FromContext(
        LinuxKerberosAcceptor context, string dnsRealm, string netBiosDomain)
    {
        ArgumentNullException.ThrowIfNull(context);
        var peer = context.GetAuthenticatedPeerName();
        return peer is not null && TryParseAccountName(peer, dnsRealm, netBiosDomain, out var account)
            ? new(account!) : null;
    }

    internal static KerberosComputerIdentity? FromAuthenticatedPeerName(
        string peerName, string dnsRealm, string netBiosDomain) =>
        TryParseAccountName(peerName, dnsRealm, netBiosDomain, out var account) ? new(account!) : null;

    public static KerberosComputerIdentity? FromContext(
        NegotiateAuthentication context, string dnsRealm, string netBiosDomain)
    {
        ArgumentNullException.ThrowIfNull(context);
        // Windows SSPI path only. Linux must use the binding-enforcing native
        // acceptor above, never silently fall back to the framework's acceptor.
        if (!OperatingSystem.IsWindows() || !context.IsServer || !context.IsAuthenticated || !context.IsMutuallyAuthenticated ||
            !string.Equals(context.Package, "Kerberos", StringComparison.Ordinal)) return null;
        return TryParseAccountName(context.RemoteIdentity.Name, dnsRealm, netBiosDomain, out var account)
            ? new(account!) : null;
    }

    // Parsing alone is NOT authentication. Kept separate to test hostile names
    // without manufacturing fake authenticated security contexts.
    internal static bool TryParseAccountName(string? name, string dnsRealm, string netBiosDomain, out string? account)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dnsRealm);
        ArgumentException.ThrowIfNullOrWhiteSpace(netBiosDomain);
        account = null;
        if (name is null || name.Length > 320) return false;
        string candidate;
        var slash = name.IndexOf('\\');
        var at = name.IndexOf('@');
        if (slash > 0 && at < 0 && name[..slash].Equals(netBiosDomain, StringComparison.OrdinalIgnoreCase))
            candidate = name[(slash + 1)..];
        else if (at > 0 && slash < 0 && name[(at + 1)..].Equals(dnsRealm, StringComparison.OrdinalIgnoreCase))
            candidate = name[..at];
        else return false;
        // Explicit bounded AD machine sAMAccountName profile, no service/host
        // principals, enterprise user UPN aliases, LDAP metacharacters or whitespace.
        if (candidate.Length is < 2 or > 64 || candidate[^1] != '$' ||
            candidate[..^1].Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_')) return false;
        account = candidate;
        return true;
    }
}
