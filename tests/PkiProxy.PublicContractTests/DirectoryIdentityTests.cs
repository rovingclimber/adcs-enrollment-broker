using System.Buffers.Binary;
using System.DirectoryServices.Protocols;
using PkiProxy.Directory;

internal static class DirectoryIdentityTests
{
    public static void Run()
    {
        var checks = 0;
        void Check(bool result, string label)
        { if (!result) throw new InvalidOperationException("Directory identity: " + label); checks++; }
        foreach (var name in new[] { "TEST\\PC-123$", "test\\pc_123$", "PC-123$@EXAMPLE.TEST", "pc_123$@example.test" })
            Check(KerberosComputerIdentity.TryParseAccountName(name, "example.test", "TEST", out var account) &&
                account!.EndsWith('$'), "supported OS-authenticated machine name forms");
        foreach (var name in new string?[] { null, "", "PC$", "TEST\\user", "user@example.test", "OTHER\\PC$",
            "PC$@OTHER.CORP", "PC$@example.test.evil", "TEST\\PC$@example.test", "HOST/pc.example.test@EXAMPLE.TEST",
            "TEST\\PC\\$", "TEST\\PC*$", "TEST\\PC)$", "TEST\\PC\0$", "TEST\\PC $", "TEST\\$",
            "TEST\\" + new string('a', 64) + "$", "TEST\\PC$$" })
            Check(!KerberosComputerIdentity.TryParseAccountName(name, "example.test", "TEST", out _), "reject malformed/user/foreign principal");
        Check(LdapComputerDirectory.EscapeFilter("*)(x=\0") == "\\2a\\29\\28\\78\\3d\\00", "LDAP filter bytes are escaped");
        Check(LdapComputerDirectory.EscapeFilter("é") == "\\c3\\a9", "LDAP filter UTF8 octets");
        Check(LdapComputerDirectory.CreateObjectFilter(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff")) ==
            "(&(objectClass=computer)(objectGUID=\\33\\22\\11\\00\\55\\44\\77\\66\\88\\99\\aa\\bb\\cc\\dd\\ee\\ff))",
            "GUID filter uses exact AD binary byte ordering, not display text");
        var search = LdapComputerDirectory.CreateSearchRequest("DC=test,DC=corp", "(objectClass=computer)", SearchScope.Subtree, ["objectGUID"]);
        Check(search.SizeLimit == 2 && search.TimeLimit == TimeSpan.FromSeconds(5) &&
            search.Controls.Count == 1 && search.Controls[0] is DomainScopeControl { IsCritical: true, ServerSide: true },
            "bounded domain-scoped search suppresses application-partition referrals without following them");
        const string group = "S-1-5-21-100-200-300-515";
        var groupBytes = ActiveDirectoryComputerResolver.EncodeDomainGroupSid(group);
        Check(groupBytes.Length == 28 && groupBytes[0] == 1 && groupBytes[1] == 5 && groupBytes[7] == 5 &&
            BinaryPrimitives.ReadUInt32LittleEndian(groupBytes.AsSpan(8)) == 21 &&
            BinaryPrimitives.ReadUInt32LittleEndian(groupBytes.AsSpan(24)) == 515, "SID binary exact encoding");
        foreach (var invalid in new[] { "", "S-1-5-32-544", "S-1-5-21-1-2-3", "S-1-5-21-1-2-3-*",
            "S-1-5-21-1-2-3-4294967296", "S-1-5-21-1-2-3--1" })
        {
            try { ActiveDirectoryComputerResolver.EncodeDomainGroupSid(invalid); throw new InvalidOperationException("Invalid group accepted"); }
            catch (ArgumentException) { checks++; }
        }
        var record = new DirectoryComputerRecord(Guid.NewGuid(), "PC-123$", "CN=PC-123,CN=Computers,DC=test,DC=corp",
            "pc-123.example.test", 4096, 805306369, [groupBytes]);
        var allowed = ActiveDirectoryComputerResolver.ValidateRecord("pc-123$", record, groupBytes);
        Check(allowed is not null && allowed.ObjectId == record.ObjectId.ToString("D") &&
            allowed.DnsHostName == record.DnsHostName && allowed.DistinguishedName == record.DistinguishedName,
            "authorized computer maps exact AD fields");
        foreach (var bad in new DirectoryComputerRecord?[]
        {
            null, record with { ObjectId = Guid.Empty }, record with { AccountName = "DIFFERENT$" },
            record with { UserAccountControl = 4098 }, record with { UserAccountControl = 8192 },
            record with { UserAccountControl = 4096 | 8192 }, record with { UserAccountControl = 4096 | 67108864 },
            record with { UserAccountControl = 512 }, record with { SamAccountType = 805306368 },
            record with { DistinguishedName = "" }, record with { DnsHostName = "*.example.test" },
            record with { TokenGroups = [] }, record with { TokenGroups = [groupBytes[..^1]] },
            record with { TokenGroups = [ActiveDirectoryComputerResolver.EncodeDomainGroupSid("S-1-5-21-100-200-999-515")] },
            record with { TokenGroups = Enumerable.Repeat(groupBytes, 1025).ToArray() }
        }) Check(ActiveDirectoryComputerResolver.ValidateRecord("PC-123$", bad, groupBytes) is null,
            "disabled/DC/user/malformed/nonmember records fail closed");
        Check(ActiveDirectoryComputerResolver.ValidateRecord("PC-123$", record, []) is null, "missing group policy never allows enrollment");
        var objectDirectory = new ObjectDirectory { Record = record };
        var resolver = new ActiveDirectoryComputerResolver(objectDirectory, group);
        Check(resolver.Resolve(record.ObjectId, default)?.ObjectId == record.ObjectId.ToString("D"), "receipt GUID resolves exact current identity");
        objectDirectory.Record = record with { AccountName = "RENAMED$", DnsHostName = "renamed.example.test" };
        Check(resolver.Resolve(record.ObjectId, default)?.DnsHostName == "renamed.example.test", "rename follows current AD fields, not old certificate name");
        foreach (var invalid in new DirectoryComputerRecord?[] { null, record with { ObjectId = Guid.NewGuid() },
            record with { UserAccountControl = 4098 }, record with { TokenGroups = [] }, record with { SamAccountType = 805306368 } })
        {
            objectDirectory.Record = invalid;
            Check(resolver.Resolve(record.ObjectId, default) is null, "deleted/recreated/disabled/nonmember/user object denied");
        }
        Check(resolver.Resolve(Guid.Empty, default) is null, "empty receipt identity denied");
        objectDirectory.Record = record;
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        try { resolver.Resolve(record.ObjectId, cancelled.Token); throw new InvalidOperationException("Cancellation ignored"); }
        catch (OperationCanceledException) { checks++; }
        Console.WriteLine($"Kerberos name / AD computer authorization checks passed: {checks}.");
    }

    private sealed class ObjectDirectory : IComputerDirectory
    {
        internal DirectoryComputerRecord? Record { get; set; }
        public DirectoryComputerRecord? FindComputer(string accountName, CancellationToken token) =>
            throw new InvalidOperationException("Certificate lookup must not guess an account name");
        public DirectoryComputerRecord? FindComputer(Guid objectId, CancellationToken token) => Record;
    }
}
