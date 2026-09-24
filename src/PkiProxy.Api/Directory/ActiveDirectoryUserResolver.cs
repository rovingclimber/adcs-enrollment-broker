using System.Buffers.Binary;
using System.Globalization;

namespace PkiProxy.Directory;

internal sealed record DirectoryUserRecord(Guid ObjectId, string AccountName,
    int UserAccountControl, int SamAccountType, IReadOnlyCollection<byte[]> TokenGroups);

internal sealed record AuthenticatedDirectoryUser(Guid ObjectId, string AccountName);
internal sealed record DirectoryUserAuthorization(AuthenticatedDirectoryUser? User, bool Authorized);

internal interface IUserDirectory
{
    DirectoryUserRecord? FindUser(string accountName, CancellationToken cancellationToken);
}

internal sealed class ActiveDirectoryUserResolver
{
    private readonly IUserDirectory directory;
    private readonly byte[] requiredGroupSid;

    internal ActiveDirectoryUserResolver(IUserDirectory directory, string requiredGroupSid)
    {
        this.directory = directory ?? throw new ArgumentNullException(nameof(directory));
        this.requiredGroupSid = EncodeDomainGroupSid(requiredGroupSid);
    }

    internal AuthenticatedDirectoryUser? Resolve(KerberosUserIdentity identity,
        CancellationToken cancellationToken)
    {
        var result = ResolveAuthorization(identity, cancellationToken);
        return result.Authorized ? result.User : null;
    }

    internal DirectoryUserAuthorization ResolveAuthorization(KerberosUserIdentity identity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        cancellationToken.ThrowIfCancellationRequested();
        var record = directory.FindUser(identity.AccountName, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return ValidateAuthorizationRecord(identity.AccountName, record, requiredGroupSid);
    }

    internal static AuthenticatedDirectoryUser? ValidateRecord(string accountName,
        DirectoryUserRecord? record, ReadOnlySpan<byte> requiredGroupSid)
    {
        var result = ValidateAuthorizationRecord(accountName, record, requiredGroupSid);
        return result.Authorized ? result.User : null;
    }

    internal static DirectoryUserAuthorization ValidateAuthorizationRecord(string accountName,
        DirectoryUserRecord? record, ReadOnlySpan<byte> requiredGroupSid)
    {
        if (record is null || record.ObjectId == Guid.Empty || requiredGroupSid.Length != 28 ||
            !string.Equals(accountName, record.AccountName, StringComparison.OrdinalIgnoreCase) ||
            record.SamAccountType != 805306368 || // SAM_USER_OBJECT
            (record.UserAccountControl & 2) != 0 || // ACCOUNTDISABLE
            record.TokenGroups.Count is 0 or > 1024)
            return new(null, false);
        var allowed = false;
        foreach (var group in record.TokenGroups)
        {
            if (group is null || group.Length is < 8 or > 68 || group[0] != 1 ||
                group.Length != 8 + group[1] * 4)
                return new(null, false);
            if (requiredGroupSid.SequenceEqual(group)) allowed = true;
        }
        return new(new(record.ObjectId, record.AccountName), allowed);
    }

    // Restrict authorization configuration to a full domain SID plus RID. This
    // prevents name, suffix and well-known-group matching.
    internal static byte[] EncodeDomainGroupSid(string sid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);
        var parts = sid.Split('-');
        if (parts.Length != 8 || parts[0] != "S" || parts[1] != "1" ||
            parts[2] != "5" || parts[3] != "21")
            throw new ArgumentException("An explicit AD domain-group SID is required.", nameof(sid));
        var bytes = new byte[28];
        bytes[0] = 1; bytes[1] = 5; bytes[7] = 5;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), 21);
        for (var index = 4; index < 8; index++)
        {
            if (!uint.TryParse(parts[index], NumberStyles.None, CultureInfo.InvariantCulture,
                    out var subAuthority))
                throw new ArgumentException("Invalid group SID.", nameof(sid));
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12 + (index - 4) * 4), subAuthority);
        }
        return bytes;
    }
}
