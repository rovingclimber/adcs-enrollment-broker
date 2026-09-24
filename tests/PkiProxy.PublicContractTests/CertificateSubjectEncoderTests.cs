using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;

internal static class CertificateSubjectEncoderTests
{
    internal static void Run()
    {
        const string dn="CN=CLIENT-001,CN=Computers,DC=test,DC=corp";
        // Synthetic certificate DN: DC values are IA5String (0x16).
        const string native="305531143012060A0992268993F22C6401191604636F727031143012060A0992268993F22C6401191604746573743112301006035504031309436F6D707574657273311330110603550403130A434C49454E542D303031";
        if(Convert.ToHexString(CertificateSubjectEncoder.Encode(dn)) != native) throw new InvalidOperationException("Native DC encoding mismatch.");
        var plain="CN=unchanged,OU=Devices";
        if(!CertificateSubjectEncoder.Encode(plain).SequenceEqual(new X500DistinguishedName(plain).RawData)) throw new InvalidOperationException("Non-DC encoding changed.");
        foreach(var changed in new[]{dn.Replace("test","other",StringComparison.Ordinal),dn.Replace("CLIENT-001","OTHER",StringComparison.Ordinal),"CN=Computers,CN=CLIENT-001,DC=test,DC=corp"})
            if(Convert.ToHexString(CertificateSubjectEncoder.Encode(changed)) == native) throw new InvalidOperationException("Identity change ignored.");
        foreach(var invalid in new[]{"CN=test,DC=-bad","CN=test,DC=bad-","CN=test,DC=bad_name","CN=tést,DC=test"})
        {
            try { CertificateSubjectEncoder.Encode(invalid); }
            catch(ArgumentException) { continue; }
            throw new InvalidOperationException("Invalid DN accepted.");
        }
        Console.WriteLine("Authoritative subject encoding checks passed: 9.");
    }
}
