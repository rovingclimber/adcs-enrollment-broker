using System.Buffers.Binary;
using System.Globalization;
using PkiProxy.Domain;
using PkiProxy.Protocol.Cmc;

namespace PkiProxy.Directory;

internal sealed record DirectoryComputerRecord(Guid ObjectId, string AccountName,
    string DistinguishedName, string DnsHostName, int UserAccountControl, int SamAccountType,
    IReadOnlyCollection<byte[]> TokenGroups);

internal interface IComputerDirectory
{
    DirectoryComputerRecord? FindComputer(string accountName, CancellationToken cancellationToken);
    DirectoryComputerRecord? FindComputer(Guid objectId, CancellationToken cancellationToken);
}

internal sealed class ActiveDirectoryComputerResolver
{
    private readonly IComputerDirectory directory;
    private readonly byte[] requiredGroupSid;

    public ActiveDirectoryComputerResolver(IComputerDirectory directory, string requiredGroupSid)
    {
        this.directory = directory;
        this.requiredGroupSid = EncodeDomainGroupSid(requiredGroupSid);
    }

    public AuthenticatedDirectoryComputer? Resolve(KerberosComputerIdentity identity, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        cancellationToken.ThrowIfCancellationRequested();
        var record = directory.FindComputer(identity.AccountName, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return ValidateRecord(identity.AccountName, record, requiredGroupSid);
    }

    // Used only after durable certificate binding/trust is established. No name
    // derived from a certificate or request can replace the receipt's object GUID.
    public AuthenticatedDirectoryComputer? Resolve(Guid objectId, CancellationToken cancellationToken)
    {
        if (objectId == Guid.Empty) return null;
        cancellationToken.ThrowIfCancellationRequested();
        var record = directory.FindComputer(objectId, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (record is null || record.ObjectId != objectId) return null;
        return ValidateRecord(record.AccountName, record, requiredGroupSid);
    }

    // LDAP data is authoritative only after the reader established a trusted
    // connection and exact object binding. This function also serves offline tests.
    internal static AuthenticatedDirectoryComputer? ValidateRecord(string accountName,
        DirectoryComputerRecord? record, ReadOnlySpan<byte> requiredGroupSid)
    {
        if (record is null || record.ObjectId == Guid.Empty || requiredGroupSid.Length != 28 ||
            !string.Equals(accountName, record.AccountName, StringComparison.OrdinalIgnoreCase) ||
            record.SamAccountType != 805306369 || // SAM_MACHINE_ACCOUNT
            (record.UserAccountControl & 4096) == 0 || // WORKSTATION_TRUST_ACCOUNT
            (record.UserAccountControl & (2 | 8192 | 67108864)) != 0 || // disabled / DC / RODC
            record.TokenGroups.Count is 0 or > 1024) return null;
        var groupAllowed = false;
        foreach (var group in record.TokenGroups)
            if (requiredGroupSid.SequenceEqual(group)) groupAllowed = true;
        if (!groupAllowed) return null;
        try
        {
            // Reuse the exact DN/DNS encoder the signing path will use; discard DER.
            _ = CmcEnrollmentRequestBuilder.EncodeIdentity(new(record.DistinguishedName,
                [new Uri("urn:example:directory-validation")], [record.DnsHostName]));
            return new(record.ObjectId.ToString("D"), record.DistinguishedName, record.DnsHostName);
        }
        catch (Exception e) when (e is ArgumentException or System.Security.Cryptography.CryptographicException)
        { return null; }
    }

    // Cross-platform encoding of an explicit AD domain-group SID, no dependency
    // on Windows-only SecurityIdentifier APIs and no textual suffix matching.
    internal static byte[] EncodeDomainGroupSid(string sid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);
        var parts = sid.Split('-');
        if (parts.Length != 8 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "21")
            throw new ArgumentException("An explicit AD domain-group SID is required.", nameof(sid));
        var bytes = new byte[28]; bytes[0] = 1; bytes[1] = 5; bytes[7] = 5;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), 21);
        for (var i = 4; i < 8; i++)
        {
            if (!uint.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out var subAuthority))
                throw new ArgumentException("Invalid group SID.", nameof(sid));
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12 + (i - 4) * 4), subAuthority);
        }
        return bytes;
    }
}
