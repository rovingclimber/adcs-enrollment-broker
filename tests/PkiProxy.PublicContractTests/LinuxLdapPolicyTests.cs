using PkiProxy.Directory;

internal static class LinuxLdapPolicyTests
{
    internal static void Run()
    {
        var settings = new Dictionary<string, string>(StringComparer.Ordinal) {
            ["LDAPTLS_REQCERT"] = "demand", ["LDAPTLS_REQSAN"] = "demand",
            ["LDAPSASL_CBINDING"] = "tls-endpoint", ["LDAPSASL_NOCANON"] = "on",
            ["LDAPSASL_SECPROPS"] = "noanonymous,noplain,maxssf=0",
            ["LDAPTLS_CIPHER_SUITE"] = "NORMAL:-VERS-TLS1.0:-VERS-TLS1.1" };
        var count = 0;
        void Check(bool expected)
        {
            if (LinuxLdapPolicy.HasStrictSettings(name => settings.GetValueOrDefault(name)) != expected)
                throw new InvalidOperationException("Unexpected Linux LDAP profile validation.");
            count++;
        }
        Check(true);
        foreach (var key in settings.Keys.ToArray())
        {
            var original = settings[key]; settings.Remove(key); Check(false);
            settings[key] = "untrusted"; Check(false); settings[key] = original;
        }
        foreach (var key in new[] { "LDAPNOINIT", "LDAPSASL_AUTHZID", "LDAPSASL_AUTHCID", "KRB5_TRACE" })
        { settings[key] = "untrusted"; Check(false); settings.Remove(key); }
        Check(true);
        Console.WriteLine($"Linux LDAPS strict configuration checks passed: {count}.");
    }
}
