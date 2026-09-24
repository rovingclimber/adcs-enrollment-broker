using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Domain;

// Bounded authoritative ASCII DN profile. Preserve RDNs, OIDs and values;
// encode domainComponent as IA5String (RFC5280/4519), unlike Linux's generic
// X500DistinguishedName encoder which can emit PrintableString for this OID.
internal static class CertificateSubjectEncoder
{
    internal static byte[] Encode(string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        if(distinguishedName.Length > 4096 || distinguishedName.Any(c=>c is < ' ' or > '~'))
            throw new ArgumentException("Unsupported authoritative DN profile.",nameof(distinguishedName));
        var encoded=new X500DistinguishedName(distinguishedName).RawData;
        var reader=new AsnReader(encoded,AsnEncodingRules.DER);
        var sequence=reader.ReadSequence();
        var writer=new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        while(sequence.HasData)
        {
            var rdn=sequence.ReadSetOf();
            using(writer.PushSetOf())
            while(rdn.HasData)
            {
                var attribute=rdn.ReadSequence(); var oid=attribute.ReadObjectIdentifier();
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(oid);
                    if(oid == "0.9.2342.19200300.100.1.25")
                    {
                        var tag=attribute.PeekTag();
                        if(tag.TagClass != TagClass.Universal || tag.TagValue is not (12 or 19 or 22))
                            throw new ArgumentException("Unsupported domain component encoding.");
                        var label=attribute.ReadCharacterString((UniversalTagNumber)tag.TagValue);
                        if(label.Length is < 1 or > 63 || label[0]=='-' || label[^1]=='-' ||
                            label.Any(c=>!char.IsAsciiLetterOrDigit(c) && c!='-'))
                            throw new ArgumentException("Invalid domain component label.");
                        writer.WriteCharacterString(UniversalTagNumber.IA5String,label);
                    }
                    else writer.WriteEncodedValue(attribute.ReadEncodedValue().Span);
                }
                attribute.ThrowIfNotEmpty();
            }
        }
        reader.ThrowIfNotEmpty();
        var result=writer.Encode();
        if(result.Length<=2) throw new ArgumentException("Authoritative subject required.");
        return result;
    }
}
