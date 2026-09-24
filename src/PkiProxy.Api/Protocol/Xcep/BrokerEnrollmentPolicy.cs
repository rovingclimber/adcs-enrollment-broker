using System.Xml.Linq;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PkiProxy.Protocol.Xcep;

// This is the policy projection boundary. Its values originate from the
// broker-only AD CS template and issuing CA configuration, never from a CEP
// caller. No default instance is registered: an incomplete configuration must
// fail closed rather than advertise an invented template or CA.
internal sealed record BrokerEnrollmentPolicy(
    string PolicyServerId,
    string PolicyFriendlyName,
    string TemplateCommonName,
    string TemplateOid,
    byte[] IssuingCaCertificateDer,
    Uri EnrollmentUri,
    uint ClientAuthentication,
    uint MinimumKeyLength,
    uint SubjectNameFlags,
    uint PrivateKeyFlags,
    uint EnrollmentFlags,
    uint GeneralFlags,
    ulong ValidityPeriodSeconds,
    ulong RenewalPeriodSeconds,
    uint MajorRevision,
    uint? MinorRevision,
    uint NextUpdateHours,
    DateTimeOffset UpdatedAt,
    bool RenewalOnly = false)
{
    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(PolicyServerId);
        ArgumentException.ThrowIfNullOrWhiteSpace(PolicyFriendlyName);
        ArgumentException.ThrowIfNullOrWhiteSpace(TemplateCommonName);
        ArgumentException.ThrowIfNullOrWhiteSpace(TemplateOid);
        ArgumentNullException.ThrowIfNull(IssuingCaCertificateDer);
        ArgumentNullException.ThrowIfNull(EnrollmentUri);

        if (!IsOid(TemplateOid) || IssuingCaCertificateDer.Length == 0 ||
            !EnrollmentUri.IsAbsoluteUri || !IsClientAuthenticationSupported(ClientAuthentication) ||
            MinimumKeyLength == 0 || ValidityPeriodSeconds == 0 || RenewalPeriodSeconds == 0 ||
            MajorRevision == 0 || NextUpdateHours == 0)
        {
            throw new InvalidOperationException("The broker enrollment policy is incomplete or invalid.");
        }
    }

    private static bool IsClientAuthenticationSupported(uint value) => value is 1 or 2 or 4 or 8;

    private static bool IsOid(string value)
    {
        var parts = value.Split('.', StringSplitOptions.None);
        return parts.Length >= 2 && parts.All(part =>
            part.Length > 0 && part.All(char.IsAsciiDigit));
    }
}

internal static class BrokerEnrollmentPolicyResponseWriter
{
    private static readonly XNamespace Xcep = XcepNamespaces.EnrollmentPolicy;
    private static readonly XNamespace Xsi = XcepNamespaces.XmlSchemaInstance;

    public static XElement Create(BrokerEnrollmentPolicy policy, IReadOnlySet<string> requestedPolicyOids)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(requestedPolicyOids);
        policy.Validate();

        var includePolicy = requestedPolicyOids.Count == 0 || requestedPolicyOids.Contains(policy.TemplateOid);
        return new XElement(Xcep + "GetPoliciesResponse",
            new XElement(Xcep + "response",
                new XElement(Xcep + "policyID", policy.PolicyServerId),
                new XElement(Xcep + "policyFriendlyName", policy.PolicyFriendlyName),
                new XElement(Xcep + "nextUpdateHours", policy.NextUpdateHours),
                new XElement(Xcep + "policiesNotChanged", false),
                includePolicy ? Policies(policy) : Nil("policies")),
            includePolicy ? CertificateAuthorities(policy) : Nil("cAs"),
            includePolicy ? Oids(policy) : Nil("oIDs"));
    }

    private static XElement Policies(BrokerEnrollmentPolicy policy) =>
        new(Xcep + "policies",
            new XElement(Xcep + "policy",
                new XElement(Xcep + "policyOIDReference", 1),
                new XElement(Xcep + "cAs", new XElement(Xcep + "cAReference", 1)),
                Attributes(policy)));

    private static XElement Attributes(BrokerEnrollmentPolicy policy) =>
        new(Xcep + "attributes",
            new XElement(Xcep + "commonName", policy.TemplateCommonName),
            new XElement(Xcep + "policySchema", 3),
            new XElement(Xcep + "certificateValidity",
                new XElement(Xcep + "validityPeriodSeconds", policy.ValidityPeriodSeconds),
                new XElement(Xcep + "renewalPeriodSeconds", policy.RenewalPeriodSeconds)),
            new XElement(Xcep + "permission",
                new XElement(Xcep + "enroll", true),
                new XElement(Xcep + "autoEnroll", true)),
            new XElement(Xcep + "privateKeyAttributes",
                new XElement(Xcep + "minimalKeyLength", policy.MinimumKeyLength),
                Nil("keySpec"),
                Nil("keyUsageProperty"),
                Nil("permissions"),
                new XElement(Xcep + "algorithmOIDReference", 2),
                new XElement(Xcep + "cryptoProviders",
                    new XElement(Xcep + "provider", "Microsoft Software Key Storage Provider"))),
            new XElement(Xcep + "revision",
                new XElement(Xcep + "majorRevision", policy.MajorRevision),
                policy.MinorRevision is { } minorRevision
                    ? new XElement(Xcep + "minorRevision", minorRevision)
                    : Nil("minorRevision")),
            Nil("supersededPolicies"),
            new XElement(Xcep + "privateKeyFlags", policy.PrivateKeyFlags),
            new XElement(Xcep + "subjectNameFlags", policy.SubjectNameFlags),
            new XElement(Xcep + "enrollmentFlags", policy.EnrollmentFlags),
            new XElement(Xcep + "generalFlags", policy.GeneralFlags),
            new XElement(Xcep + "hashAlgorithmOIDReference", 3),
            Nil("rARequirements"),
            Nil("keyArchivalAttributes"),
            Extensions(policy));

    private static XElement CertificateAuthorities(BrokerEnrollmentPolicy policy) =>
        new(Xcep + "cAs",
            new XElement(Xcep + "cA",
                new XElement(Xcep + "uris",
                    new XElement(Xcep + "cAURI",
                        new XElement(Xcep + "clientAuthentication", policy.ClientAuthentication),
                        new XElement(Xcep + "uri", policy.EnrollmentUri.AbsoluteUri),
                        new XElement(Xcep + "priority", 0),
                        new XElement(Xcep + "renewalOnly", policy.RenewalOnly))),
                new XElement(Xcep + "certificate", Convert.ToBase64String(policy.IssuingCaCertificateDer)),
                new XElement(Xcep + "enrollPermission", true),
                new XElement(Xcep + "cAReferenceID", 1)));

    private static XElement Oids(BrokerEnrollmentPolicy policy) =>
        new(Xcep + "oIDs",
            new XElement(Xcep + "oID",
                new XElement(Xcep + "value", policy.TemplateOid),
                new XElement(Xcep + "group", 9),
                new XElement(Xcep + "oIDReferenceID", 1),
                new XElement(Xcep + "defaultName", policy.TemplateCommonName)),
            Oid(2, "1.2.840.113549.1.1.1", 3, "RSA"),
            Oid(3, "2.16.840.1.101.3.4.2.1", 1, "SHA256"),
            Oid(4, "1.3.6.1.4.1.311.21.7", 6, "Certificate Template Information"),
            Oid(5, "2.5.29.37", 6, "Enhanced Key Usage"),
            Oid(6, "2.5.29.15", 6, "Key Usage"),
            Oid(7, "1.3.6.1.4.1.311.21.10", 6, "Application Policies"));

    private static XElement Oid(int reference, string value, int group, string name) =>
        new(Xcep + "oID", new XElement(Xcep + "value", value), new XElement(Xcep + "group", group),
            new XElement(Xcep + "oIDReferenceID", reference), new XElement(Xcep + "defaultName", name));

    // Fixed machine EAP-TLS profile. These are enrollment hints, not authority:
    // downstream subject/DNS/URNs must still be reconstructed from AD and facts.
    private static XElement Extensions(BrokerEnrollmentPolicy policy)
    {
        var template = new AsnWriter(AsnEncodingRules.DER);
        using (template.PushSequence())
        {
            template.WriteObjectIdentifier(policy.TemplateOid);
            template.WriteInteger(policy.MajorRevision);
            if (policy.MinorRevision is > 0) template.WriteInteger(policy.MinorRevision.Value);
        }
        var eku = new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false);
        var ku = new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true);
        var application = new AsnWriter(AsnEncodingRules.DER);
        using (application.PushSequence())
        using (application.PushSequence()) application.WriteObjectIdentifier("1.3.6.1.5.5.7.3.2");
        return new XElement(Xcep + "extensions", Extension(4, false, template.Encode()),
            Extension(5, false, eku.RawData), Extension(6, true, ku.RawData), Extension(7, false, application.Encode()));
    }

    private static XElement Extension(int reference, bool critical, byte[] value) =>
        new(Xcep + "extension", new XElement(Xcep + "oIDReference", reference),
            new XElement(Xcep + "critical", critical), new XElement(Xcep + "value", Convert.ToBase64String(value)));

    private static XElement Nil(string localName) =>
        new(Xcep + localName, new XAttribute(Xsi + "nil", "true"));
}
