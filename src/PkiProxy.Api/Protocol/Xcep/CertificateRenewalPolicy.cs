namespace PkiProxy.Protocol.Xcep;

// Separate identity remains the isolated pilot default. Shared identity is an
// explicit experiment for native automatic renewal, not an interoperability claim.
internal sealed record CertificateRenewalPolicy(BrokerEnrollmentPolicy Policy)
{
    internal static CertificateRenewalPolicy Create(BrokerEnrollmentPolicy baseline,
        string policyId, string host, int authorityPort, bool sharedPolicyIdentity = false)
    {
        baseline.Validate();
        if (!Guid.TryParse(policyId, out var id) || id == Guid.Empty ||
            (sharedPolicyIdentity
                ? !Guid.TryParse(baseline.PolicyServerId, out var sharedId) || id != sharedId
                : Guid.TryParse(baseline.PolicyServerId, out var oldId) && id == oldId) ||
            baseline.ClientAuthentication != 2 || baseline.RenewalOnly ||
            Uri.CheckHostName(host) != UriHostNameType.Dns || !host.Contains('.') ||
            !host.Equals(baseline.EnrollmentUri.Host, StringComparison.OrdinalIgnoreCase) ||
            authorityPort is < 1 or > 65535)
            throw new InvalidOperationException("Explicit policy identity mode and same-broker certificate authority required.");
        var policy = baseline with {
            PolicyServerId = id.ToString("B"),
            PolicyFriendlyName = baseline.PolicyFriendlyName + " (certificate renewal)",
            EnrollmentUri = new UriBuilder(Uri.UriSchemeHttps, host, authorityPort,
                "/ces/certificate/service.svc/CES").Uri,
            ClientAuthentication = 8,
            RenewalOnly = true
        };
        policy.Validate();
        return new(policy);
    }
}
