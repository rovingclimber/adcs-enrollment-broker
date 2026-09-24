namespace PkiProxy.Directory;

// Pinned OpenLDAP/GnuTLS deployment profile. Native library defaults alone are
// not an application trust policy; validate before any credential-bearing bind.
internal static class LinuxLdapPolicy
{
    internal static void Validate()
    {
        if (!OperatingSystem.IsLinux()) return;
        if (!HasStrictSettings(Environment.GetEnvironmentVariable))
            throw new InvalidOperationException("Explicit strict Linux LDAP settings required.");
        foreach (var name in new[] { "LDAPTLS_CACERT", "LDAPTLS_CRLFILE" })
        {
            var path = Environment.GetEnvironmentVariable(name);
            if (path is null || !Path.IsPathFullyQualified(path) || !File.Exists(path) ||
                new FileInfo(path).Length is < 1 or > 1_048_576)
                throw new InvalidOperationException("Explicit bounded LDAP trust and CRL files required.");
        }
        var cache = Environment.GetEnvironmentVariable("KRB5CCNAME");
        if (cache is null || !cache.StartsWith("FILE:", StringComparison.Ordinal) ||
            !Path.IsPathFullyQualified(cache[5..]) || !File.Exists(cache[5..]))
            throw new InvalidOperationException("Managed broker-owned Kerberos file cache required.");
        var publicModes = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        if ((File.GetUnixFileMode(cache[5..]) & publicModes) != 0)
            throw new InvalidOperationException("Broker ticket cache must be owner-only.");
    }

    internal static bool HasStrictSettings(Func<string, string?> get) =>
        get("LDAPNOINIT") is null && get("LDAPSASL_AUTHZID") is null && get("LDAPSASL_AUTHCID") is null &&
        string.IsNullOrEmpty(get("KRB5_TRACE")) &&
        get("LDAPTLS_REQCERT") == "demand" && get("LDAPTLS_REQSAN") == "demand" &&
        get("LDAPSASL_CBINDING") == "tls-endpoint" && get("LDAPSASL_NOCANON") == "on" &&
        // MS-ADTS forbids an extra SASL message-protection layer inside TLS.
        get("LDAPSASL_SECPROPS") == "noanonymous,noplain,maxssf=0" &&
        get("LDAPTLS_CIPHER_SUITE") == "NORMAL:-VERS-TLS1.0:-VERS-TLS1.1";
}
