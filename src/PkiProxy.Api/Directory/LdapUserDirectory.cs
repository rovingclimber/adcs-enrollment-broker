using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Text;

namespace PkiProxy.Directory;

// One fresh, bounded, read-only LDAPS connection per technician decision. It
// uses only the broker's managed Kerberos cache and never delegated credentials.
internal sealed class LdapUserDirectory : IUserDirectory
{
    private static readonly string[] Attributes =
        ["objectGUID", "sAMAccountName", "userAccountControl", "sAMAccountType", "tokenGroups"];
    private readonly string server;
    private readonly string baseDn;
    private readonly Action<string>? observe;

    internal LdapUserDirectory(string server, string baseDn, Action<string>? observe = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(server);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDn);
        if (Uri.CheckHostName(server) != UriHostNameType.Dns || !server.Contains('.') ||
            server.Length > 253)
            throw new ArgumentException("An explicit directory server FQDN is required.", nameof(server));
        if (baseDn.Length > 4096 || baseDn.Any(char.IsControl))
            throw new ArgumentException("Invalid directory base DN.", nameof(baseDn));
        this.server = server; this.baseDn = baseDn; this.observe = observe;
    }

    public DirectoryUserRecord? FindUser(string accountName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);
        if (accountName.Length > 64 ||
            accountName.Any(character => !char.IsAsciiLetterOrDigit(character) &&
                character is not '-' and not '_' and not '.'))
            throw new ArgumentException("Invalid bounded user account name.", nameof(accountName));
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = CreateConnection();
        connection.Bind();
        var escaped = EscapeFilter(accountName);
        var initial = Search(connection, baseDn,
            "(&(objectClass=user)(objectCategory=person)(sAMAccountName=" + escaped + "))",
            SearchScope.Subtree, ["objectGUID"], cancellationToken);
        if (initial is null) { observe?.Invoke("no-unique-user"); return null; }
        var guid = Bytes(initial, "objectGUID");
        if (guid is not { Length: 16 }) { observe?.Invoke("invalid-object-guid"); return null; }

        var boundFilter = "(&(objectClass=user)(objectCategory=person)(objectGUID=" +
            EscapeBinary(guid) + "))";
        var entry = Search(connection, initial.DistinguishedName, boundFilter,
            SearchScope.Base, Attributes, cancellationToken);
        if (entry is null || !guid.AsSpan().SequenceEqual(Bytes(entry, "objectGUID")))
        { observe?.Invoke("object-bound-read-failed"); return null; }

        var groups = entry.Attributes["tokenGroups"];
        if (groups is null || groups.Count is 0 or > 1024 ||
            !int.TryParse(Text(entry, "userAccountControl"), NumberStyles.None,
                CultureInfo.InvariantCulture, out var uac) ||
            !int.TryParse(Text(entry, "sAMAccountType"), NumberStyles.None,
                CultureInfo.InvariantCulture, out var accountType))
        { observe?.Invoke("missing-groups-or-account-flags"); return null; }
        var groupValues = new List<byte[]>();
        foreach (var value in groups.GetValues(typeof(byte[])))
        {
            if (value is not byte[] bytes || bytes.Length is < 8 or > 68 ||
                bytes[0] != 1 || bytes.Length != 8 + bytes[1] * 4)
            { observe?.Invoke("invalid-group-sid"); return null; }
            groupValues.Add(bytes.ToArray());
        }
        var sam = Text(entry, "sAMAccountName");
        if (sam is null) { observe?.Invoke("missing-user-name"); return null; }
        observe?.Invoke("user-record-resolved");
        return new(new Guid(guid), sam, uac, accountType, groupValues);
    }

    private LdapConnection CreateConnection()
    {
        LinuxLdapPolicy.Validate();
        if (AppContext.TryGetSwitch("System.DirectoryServices.Protocols.UseBasicAuthFallback",
                out var basicFallback) && basicFallback)
            throw new InvalidOperationException("LDAP basic-auth fallback must be disabled.");
        var connection = new LdapConnection(new LdapDirectoryIdentifier(server, 636), null,
            OperatingSystem.IsWindows() ? AuthType.Kerberos : AuthType.Negotiate)
        { Timeout = TimeSpan.FromSeconds(10) };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = true;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        return connection;
    }

    private static SearchResultEntry? Search(LdapConnection connection, string dn,
        string filter, SearchScope scope, string[] attributes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var request = new SearchRequest(dn, filter, scope, attributes)
        { SizeLimit = 2, TimeLimit = TimeSpan.FromSeconds(5) };
        request.Controls.Add(new DomainScopeControl { IsCritical = true, ServerSide = true });
        var result = (SearchResponse)connection.SendRequest(request, TimeSpan.FromSeconds(10));
        cancellationToken.ThrowIfCancellationRequested();
        return result.ResultCode == ResultCode.Success && result.References.Count == 0 &&
            result.Entries.Count == 1 ? result.Entries[0] : null;
    }

    private static string? Text(SearchResultEntry entry, string attribute)
    {
        var values = entry.Attributes[attribute];
        return values?.Count == 1 &&
            values.GetValues(typeof(string))[0] is string text ? text : null;
    }

    private static byte[]? Bytes(SearchResultEntry entry, string attribute)
    {
        var values = entry.Attributes[attribute];
        return values?.Count == 1 &&
            values.GetValues(typeof(byte[]))[0] is byte[] bytes ? bytes : null;
    }

    internal static string EscapeFilter(string text) =>
        EscapeBinary(Encoding.UTF8.GetBytes(text));

    private static string EscapeBinary(byte[] bytes) => string.Concat(bytes.Select(
        value => "\\" + value.ToString("x2", CultureInfo.InvariantCulture)));
}
