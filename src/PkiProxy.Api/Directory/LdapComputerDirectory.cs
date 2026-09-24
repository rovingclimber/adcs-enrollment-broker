using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Text;

namespace PkiProxy.Directory;

// One bounded read-only LDAPS connection per resolution. Uses the broker's own
// OS credentials/ticket cache; never a delegated device ticket or a password DTO.
internal sealed class LdapComputerDirectory : IComputerDirectory
{
    private readonly string server;
    private readonly string baseDn;
    private readonly Action<string>? observe;
    private static readonly string[] Attributes = ["objectGUID", "sAMAccountName", "dNSHostName",
        "userAccountControl", "sAMAccountType", "tokenGroups"];

    public LdapComputerDirectory(string server, string baseDn, Action<string>? observe = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(server);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDn);
        if (Uri.CheckHostName(server) != UriHostNameType.Dns || !server.Contains('.') || server.Length > 253)
            throw new ArgumentException("An explicit directory server FQDN is required.", nameof(server));
        if (baseDn.Length > 4096 || baseDn.Any(char.IsControl)) throw new ArgumentException("Invalid directory base DN.", nameof(baseDn));
        this.server = server; this.baseDn = baseDn; this.observe = observe;
    }

    public DirectoryComputerRecord? FindComputer(string accountName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);
        if (accountName.Length > 64) throw new ArgumentException("Account name too long.", nameof(accountName));
        return FindComputerCore("(&(objectClass=computer)(sAMAccountName=" + EscapeFilter(accountName) + "))", null, cancellationToken);
    }

    public DirectoryComputerRecord? FindComputer(Guid objectId, CancellationToken cancellationToken)
    {
        if (objectId == Guid.Empty) throw new ArgumentException("Nonempty object GUID required.", nameof(objectId));
        return FindComputerCore(CreateObjectFilter(objectId), objectId, cancellationToken);
    }

    internal static string CreateObjectFilter(Guid objectId) =>
        "(&(objectClass=computer)(objectGUID=" + EscapeBinary(objectId.ToByteArray()) + "))";

    private DirectoryComputerRecord? FindComputerCore(string filter, Guid? expectedObject, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = CreateConnection();
        connection.Bind();
        var initial = Search(connection, baseDn, filter, SearchScope.Subtree, ["objectGUID"], cancellationToken);
        if (initial is null) { observe?.Invoke("no-unique-computer"); return null; }
        var guid = Bytes(initial, "objectGUID");
        if (guid is not { Length: 16 }) { observe?.Invoke("invalid-object-guid"); return null; }
        if (expectedObject.HasValue && new Guid(guid) != expectedObject.Value)
        { observe?.Invoke("object-guid-mismatch"); return null; }
        // tokenGroups is a computed BASE-only attribute. Pin this second read to
        // the exact GUID as well as DN, so delete/recreate cannot switch objects.
        var boundFilter = "(&(objectClass=computer)(objectGUID=" + EscapeBinary(guid) + "))";
        var entry = Search(connection, initial.DistinguishedName, boundFilter, SearchScope.Base, Attributes, cancellationToken);
        if (entry is null || !guid.AsSpan().SequenceEqual(Bytes(entry, "objectGUID")))
        { observe?.Invoke("object-bound-read-failed"); return null; }
        var groups = entry.Attributes["tokenGroups"];
        if (groups is null || groups.Count is 0 or > 1024 ||
            !int.TryParse(Text(entry, "userAccountControl"), NumberStyles.None, CultureInfo.InvariantCulture, out var uac) ||
            !int.TryParse(Text(entry, "sAMAccountType"), NumberStyles.None, CultureInfo.InvariantCulture, out var accountType))
        { observe?.Invoke("missing-groups-or-account-flags"); return null; }
        var groupValues = new List<byte[]>();
        foreach (var value in groups.GetValues(typeof(byte[])))
        {
            if (value is not byte[] bytes || bytes.Length is < 8 or > 68 || bytes[0] != 1 || bytes.Length != 8 + bytes[1] * 4)
            { observe?.Invoke("invalid-group-sid"); return null; }
            groupValues.Add(bytes.ToArray());
        }
        var sam = Text(entry, "sAMAccountName"); var dns = Text(entry, "dNSHostName");
        if (sam is null || dns is null) { observe?.Invoke("missing-computer-name"); return null; }
        observe?.Invoke("computer-record-resolved");
        return new(new Guid(guid), sam, entry.DistinguishedName, dns, uac, accountType, groupValues);
    }

    private LdapConnection CreateConnection()
    {
        LinuxLdapPolicy.Validate();
        if (AppContext.TryGetSwitch("System.DirectoryServices.Protocols.UseBasicAuthFallback", out var basicFallback) && basicFallback)
            throw new InvalidOperationException("LDAP basic-auth fallback must be disabled.");
        // On Linux the pinned provider's Negotiate/null-credential path invokes
        // OpenLDAP SASL GSSAPI. Windows can explicitly request Kerberos SSPI.
        var connection = new LdapConnection(new LdapDirectoryIdentifier(server, 636), null,
            OperatingSystem.IsWindows() ? AuthType.Kerberos : AuthType.Negotiate)
        { Timeout = TimeSpan.FromSeconds(10) };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = true;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        // No server certificate callback, plaintext/basic fallback or redirects.
        return connection;
    }

    private static SearchResultEntry? Search(LdapConnection connection, string dn, string filter,
        SearchScope scope, string[] attributes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var request = CreateSearchRequest(dn, filter, scope, attributes);
        var result = (SearchResponse)connection.SendRequest(request, TimeSpan.FromSeconds(10));
        cancellationToken.ThrowIfCancellationRequested();
        return result.ResultCode == ResultCode.Success && result.References.Count == 0 && result.Entries.Count == 1
            ? result.Entries[0] : null;
    }

    internal static SearchRequest CreateSearchRequest(string dn, string filter, SearchScope scope, string[] attributes)
    {
        var request = new SearchRequest(dn, filter, scope, attributes)
        { SizeLimit = 2, TimeLimit = TimeSpan.FromSeconds(5) };
        // Domain-root subtree reads otherwise include referrals to application
        // naming contexts even when the computer result is unique. Request an
        // explicitly domain-scoped search; still reject any returned referrals.
        request.Controls.Add(new DomainScopeControl { IsCritical = true, ServerSide = true });
        return request;
    }

    private static string? Text(SearchResultEntry entry, string attribute)
    {
        var values = entry.Attributes[attribute];
        return values?.Count == 1 && values.GetValues(typeof(string))[0] is string text ? text : null;
    }
    private static byte[]? Bytes(SearchResultEntry entry, string attribute)
    {
        var values = entry.Attributes[attribute];
        // The indexer may decode binary values as text. Ask for the wire bytes
        // explicitly, particularly for objectGUID/SID values that happen to be UTF8.
        return values?.Count == 1 && values.GetValues(typeof(byte[]))[0] is byte[] bytes ? bytes : null;
    }
    internal static string EscapeFilter(string text) => EscapeBinary(Encoding.UTF8.GetBytes(text));
    private static string EscapeBinary(byte[] bytes) => string.Concat(bytes.Select(b => "\\" + b.ToString("x2", CultureInfo.InvariantCulture)));
}
