using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PkiProxy.Protocol.Xcep;

internal static class BrokerPolicyConfiguration
{
    private static readonly JsonSerializerOptions Options = new() {
        RespectRequiredConstructorParameters = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 8 };

    internal static BrokerEnrollmentPolicy Load(string policyPath, string trustedCaPath, string brokerHost)
    {
        using var trustedCa = X509Certificate2.CreateFromPem(Encoding.UTF8.GetString(ReadBounded(trustedCaPath)));
        return Parse(ReadBounded(policyPath), trustedCa, brokerHost);
    }

    internal static BrokerEnrollmentPolicy Parse(byte[] bytes, X509Certificate2 trustedCa, string brokerHost)
    {
        if (bytes.Length is 0 or > 1_048_576) throw new InvalidDataException("Bounded policy document required.");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            document.RootElement.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1))
            throw new InvalidDataException("Unambiguous policy object required.");
        var policy = JsonSerializer.Deserialize<BrokerEnrollmentPolicy>(bytes, Options)
            ?? throw new InvalidDataException("Policy document is empty.");
        policy.Validate();
        using var ca = X509CertificateLoader.LoadCertificate(policy.IssuingCaCertificateDer);
        if (!ca.RawData.AsSpan().SequenceEqual(trustedCa.RawData) ||
            ca.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority != true ||
            ca.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
            ca.NotAfter.ToUniversalTime() <= DateTime.UtcNow ||
            policy.ClientAuthentication != 2 || policy.RenewalOnly || policy.MinimumKeyLength < 2048 ||
            policy.EnrollmentUri.Scheme != Uri.UriSchemeHttps || policy.EnrollmentUri.Port != 443 ||
            !policy.EnrollmentUri.Host.Equals(brokerHost, StringComparison.OrdinalIgnoreCase) ||
            policy.EnrollmentUri.AbsolutePath != "/ces/kerberos/service.svc/CES" ||
            policy.EnrollmentUri.UserInfo.Length != 0 || policy.EnrollmentUri.Query.Length != 0 || policy.EnrollmentUri.Fragment.Length != 0 ||
            policy.PrivateKeyFlags != 0 || policy.GeneralFlags != 64 || policy.SubjectNameFlags != 0x88000000 ||
            policy.EnrollmentFlags != 0 || policy.RenewalPeriodSeconds >= policy.ValidityPeriodSeconds)
            throw new InvalidDataException("Policy must bind the trusted CA and same-broker machine enrollment endpoint.");
        return policy;
    }

    private static byte[] ReadBounded(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new InvalidDataException("Absolute policy/trust file path required.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length is 0 or > 1_048_576) throw new InvalidDataException("Bounded policy/trust file required.");
        var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("Policy file changed while reading.");
        return bytes;
    }
}
