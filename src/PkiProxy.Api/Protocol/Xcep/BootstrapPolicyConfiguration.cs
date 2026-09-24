using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PkiProxy.Protocol.Xcep;

internal static class BootstrapPolicyConfiguration
{
    private const int MaximumFileBytes = 1_048_576;
    private const string BootstrapEnrollmentPath = "/ces/bootstrap/service.svc/CES";
    private const string KerberosEnrollmentPath = "/ces/kerberos/service.svc/CES";

    private static readonly JsonSerializerOptions Options = new()
    {
        RespectRequiredConstructorParameters = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8
    };

    internal static BrokerEnrollmentPolicy Load(string policyPath, string trustedCaPath, string brokerHost)
    {
        using var trustedCa = X509Certificate2.CreateFromPem(Encoding.UTF8.GetString(ReadBounded(trustedCaPath)));
        return Parse(ReadBounded(policyPath), trustedCa, brokerHost);
    }

    internal static BrokerEnrollmentPolicy Parse(byte[] bytes, X509Certificate2 trustedCa, string brokerHost)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(trustedCa);
        ArgumentException.ThrowIfNullOrWhiteSpace(brokerHost);

        if (bytes.Length is 0 or > MaximumFileBytes)
            throw new InvalidDataException("Bounded bootstrap policy document required.");

        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            document.RootElement.EnumerateObject().GroupBy(property => property.Name, StringComparer.Ordinal)
                .Any(group => group.Count() != 1))
            throw new InvalidDataException("Unambiguous bootstrap policy object required.");

        var policy = JsonSerializer.Deserialize<BrokerEnrollmentPolicy>(bytes, Options)
            ?? throw new InvalidDataException("Bootstrap policy document is empty.");
        policy.Validate();
        ValidateBootstrapShape(policy, brokerHost);
        ValidateTrustedCa(policy, trustedCa);
        return policy;
    }

    internal static void ValidateComposition(
        BrokerEnrollmentPolicy bootstrapPolicy,
        BrokerEnrollmentPolicy kerberosPolicy,
        string brokerHost)
    {
        ArgumentNullException.ThrowIfNull(bootstrapPolicy);
        ArgumentNullException.ThrowIfNull(kerberosPolicy);
        ArgumentException.ThrowIfNullOrWhiteSpace(brokerHost);

        bootstrapPolicy.Validate();
        kerberosPolicy.Validate();
        ValidateBootstrapShape(bootstrapPolicy, brokerHost);
        ValidateKerberosShape(kerberosPolicy, brokerHost);

        if (bootstrapPolicy.PolicyServerId.Equals(kerberosPolicy.PolicyServerId, StringComparison.OrdinalIgnoreCase) ||
            bootstrapPolicy.TemplateOid.Equals(kerberosPolicy.TemplateOid, StringComparison.Ordinal))
            throw new InvalidDataException("Bootstrap and Kerberos policies require distinct identities and templates.");
    }

    private static void ValidateBootstrapShape(BrokerEnrollmentPolicy policy, string brokerHost)
    {
        if (policy.ClientAuthentication != 1 || policy.RenewalOnly ||
            !HasSharedMachinePolicyConstraints(policy) ||
            !HasExactEndpoint(policy, brokerHost, BootstrapEnrollmentPath))
            throw new InvalidDataException("Bootstrap policy must be anonymous and bind the same-broker bootstrap endpoint.");
    }

    private static void ValidateKerberosShape(BrokerEnrollmentPolicy policy, string brokerHost)
    {
        if (policy.ClientAuthentication != 2 || policy.RenewalOnly ||
            !HasSharedMachinePolicyConstraints(policy) ||
            !HasExactEndpoint(policy, brokerHost, KerberosEnrollmentPath))
            throw new InvalidDataException("Composition requires one valid Kerberos domain policy.");
    }

    private static bool HasSharedMachinePolicyConstraints(BrokerEnrollmentPolicy policy) =>
        policy.MinimumKeyLength >= 2048 &&
        policy.PrivateKeyFlags == 0 &&
        policy.GeneralFlags == 64 &&
        policy.SubjectNameFlags == 0x88000000 &&
        policy.EnrollmentFlags == 0 &&
        policy.RenewalPeriodSeconds < policy.ValidityPeriodSeconds;

    private static bool HasExactEndpoint(BrokerEnrollmentPolicy policy, string brokerHost, string path) =>
        policy.EnrollmentUri.IsAbsoluteUri &&
        policy.EnrollmentUri.Scheme == Uri.UriSchemeHttps &&
        policy.EnrollmentUri.Port == 443 &&
        policy.EnrollmentUri.Host.Equals(brokerHost, StringComparison.OrdinalIgnoreCase) &&
        policy.EnrollmentUri.AbsolutePath == path &&
        policy.EnrollmentUri.UserInfo.Length == 0 &&
        policy.EnrollmentUri.Query.Length == 0 &&
        policy.EnrollmentUri.Fragment.Length == 0;

    private static void ValidateTrustedCa(BrokerEnrollmentPolicy policy, X509Certificate2 trustedCa)
    {
        using var configuredCa = X509CertificateLoader.LoadCertificate(policy.IssuingCaCertificateDer);
        var now = DateTime.UtcNow;
        if (!configuredCa.RawData.AsSpan().SequenceEqual(trustedCa.RawData) ||
            configuredCa.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority != true ||
            configuredCa.NotBefore.ToUniversalTime() > now ||
            configuredCa.NotAfter.ToUniversalTime() <= now)
            throw new InvalidDataException("Bootstrap policy must contain the exact currently valid trusted CA certificate.");
    }

    private static byte[] ReadBounded(string path)
    {
        if (!Path.IsPathFullyQualified(path))
            throw new InvalidDataException("Absolute bootstrap policy/trust file path required.");

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length is 0 or > MaximumFileBytes)
            throw new InvalidDataException("Bounded bootstrap policy/trust file required.");

        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1)
            throw new InvalidDataException("Bootstrap policy/trust file changed while reading.");
        return bytes;
    }
}
