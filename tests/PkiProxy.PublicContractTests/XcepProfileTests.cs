using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using PkiProxy.Protocol.Xcep;

internal static class XcepProfileTests
{
    internal static void Run(XElement response, BrokerEnrollmentPolicy policy)
    {
        XNamespace ns = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy";
        var count = 0;
        void Check(bool value) { if (!value) throw new InvalidOperationException("XCEP machine profile mismatch."); count++; }
        var oids = response.Element(ns + "oIDs")!.Elements().ToDictionary(
            e => (int)e.Element(ns + "oIDReferenceID")!, e => e.Element(ns + "value")!.Value);
        var attributes = response.Descendants(ns + "attributes").Single();
        Check(oids[(int)attributes.Element(ns + "hashAlgorithmOIDReference")!] == "2.16.840.1.101.3.4.2.1");
        var key = attributes.Element(ns + "privateKeyAttributes")!;
        Check(oids[(int)key.Element(ns + "algorithmOIDReference")!] == "1.2.840.113549.1.1.1");
        Check(key.Element(ns + "cryptoProviders")!.Elements().Single().Value == "Microsoft Software Key Storage Provider");
        var extensions = attributes.Element(ns + "extensions")!.Elements().ToDictionary(
            e => oids[(int)e.Element(ns + "oIDReference")!]);
        Check(extensions.Count == 4);
        foreach (var (oid, extension) in extensions)
            Check((bool)extension.Element(ns + "critical")! == (oid == "2.5.29.15"));
        byte[] Value(string oid) => Convert.FromBase64String(extensions[oid].Element(ns + "value")!.Value);
        var reader = new AsnReader(Value("1.3.6.1.4.1.311.21.7"), AsnEncodingRules.DER);
        var template = reader.ReadSequence();
        Check(template.ReadObjectIdentifier() == policy.TemplateOid && template.ReadInteger() == policy.MajorRevision);
        Check(!template.HasData); reader.ThrowIfNotEmpty();
        var eku = new X509EnhancedKeyUsageExtension();
        eku.CopyFrom(new X509Extension("2.5.29.37", Value("2.5.29.37"), false));
        Check(eku.EnhancedKeyUsages.Count == 1 && eku.EnhancedKeyUsages[0].Value == "1.3.6.1.5.5.7.3.2");
        var ku = new X509KeyUsageExtension();
        ku.CopyFrom(new X509Extension("2.5.29.15", Value("2.5.29.15"), true));
        Check(ku.KeyUsages == (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment));
        reader = new AsnReader(Value("1.3.6.1.4.1.311.21.10"), AsnEncodingRules.DER);
        var policies = reader.ReadSequence(); var application = policies.ReadSequence();
        Check(application.ReadObjectIdentifier() == "1.3.6.1.5.5.7.3.2");
        application.ThrowIfNotEmpty(); policies.ThrowIfNotEmpty(); reader.ThrowIfNotEmpty();
        Check(!extensions.ContainsKey("2.5.29.17"));
        Console.WriteLine($"XCEP native machine profile checks passed: {count}.");
    }
}
