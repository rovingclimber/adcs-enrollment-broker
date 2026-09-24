using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using PkiProxy.Authentication;
using PkiProxy.Directory;
using PkiProxy.Protocol.Xcep;

namespace PkiProxy.Domain;

internal sealed class BootstrapDeployment
{
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 6
    };

    private BootstrapDeployment(BrokerEnrollmentPolicy policy,
        BootstrapIngressAdmission admission, BootstrapEnrollmentWorkflow workflow,
        BootstrapEnrollmentIssuanceService issuance,
        BootstrapKerberosAuthenticationService authentication,
        BootstrapTechnicianAuthenticator bootstrapApprovalAuthorization,
        BootstrapTechnicianAuthenticator factsReadAuthorization,
        BootstrapTechnicianAuthenticator factsWriteAuthorization,
        string deviceFactsFile)
    {
        Policy = policy;
        Admission = admission;
        Workflow = workflow;
        Issuance = issuance;
        Authentication = authentication;
        BootstrapApprovalAuthorization = bootstrapApprovalAuthorization;
        FactsReadAuthorization = factsReadAuthorization;
        FactsWriteAuthorization = factsWriteAuthorization;
        DeviceFactsFile = deviceFactsFile;
    }

    internal BrokerEnrollmentPolicy Policy { get; }
    internal BootstrapIngressAdmission Admission { get; }
    internal BootstrapEnrollmentWorkflow Workflow { get; }
    internal BootstrapEnrollmentIssuanceService Issuance { get; }
    internal BootstrapKerberosAuthenticationService Authentication { get; }
    internal BootstrapTechnicianAuthenticator BootstrapApprovalAuthorization { get; }
    internal BootstrapTechnicianAuthenticator FactsReadAuthorization { get; }
    internal BootstrapTechnicianAuthenticator FactsWriteAuthorization { get; }
    internal string DeviceFactsFile { get; }

    internal static async Task<BootstrapDeployment> LoadAsync(string path,
        BrokerEnrollmentPolicy kerberosPolicy, NativeEnrollmentService nativeEnrollment,
        KerberosListenerConfiguration kerberosListener,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Bootstrap hosting requires Linux.");
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Absolute bootstrap configuration path required.");
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || info.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            info.Length is <= 0 or > 65_536 || File.GetUnixFileMode(path) != PrivateFile)
            throw new IOException("Owner-only regular bootstrap configuration required.");

        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var value = await DeserializeConfigurationAsync(stream, cancellationToken);

        ValidateConfiguration(value);
        ValidateListenerBinding(value, kerberosListener.AuthorityPort, kerberosListener.ListenerPort);
        var kerberosTransport = kerberosListener.Transport;
        if (!string.Equals(value.BrokerHost, kerberosTransport.Host,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Bootstrap host must use the configured Kerberos HTTP service.");
        var paths = new[] { value.IntakeDirectory, value.AttestationDirectory, value.PairingDirectory, value.TransactionDirectory }
            .Select(Path.GetFullPath).ToArray();
        if (paths.Distinct(StringComparer.Ordinal).Count() != paths.Length)
            throw new InvalidDataException("Bootstrap state stores require distinct directories.");

        var policy = BootstrapPolicyConfiguration.Load(value.PolicyFile, value.TrustedCaFile, value.BrokerHost);
        BootstrapPolicyConfiguration.ValidateComposition(policy, kerberosPolicy, value.BrokerHost);
        var assets = await JsonFileImmutableAssetCatalog.LoadAsync(value.DeviceFactsFile, cancellationToken);
        var attestations = new FileBootstrapAttestationStore(value.AttestationDirectory);
        var pairingPolicy = new BootstrapPairingPolicy(TimeSpan.FromMinutes(value.LifetimeMinutes),
            value.MaximumAttempts, value.MaximumActiveSessions,
            TimeSpan.FromMinutes(value.MaximumTechnicianAuthenticationAgeMinutes));
        var pairings = new FileBootstrapPairingCoordinator(value.PairingDirectory,
            attestations, assets, pairingPolicy);
        var transactions = new FileBootstrapEnrollmentTransactionStore(value.TransactionDirectory);
        var intake = new FileBootstrapIntakeLedger(value.IntakeDirectory,
            new BootstrapIntakeQuota(value.MaximumActiveSessions, value.MaximumActiveBytes,
                value.MaximumHistoryRecords, value.MaximumHistoryBytes));
        intake.BindStoreGeneration(value.AttestationDirectory, value.PairingDirectory,
            value.TransactionDirectory);
        var authoritativeFacts = new JsonFileDeviceFactsSource(value.DeviceFactsFile);
        await authoritativeFacts.ValidateAsync(cancellationToken);
        BootstrapTechnicianAuthenticator Authorization(TechnicianCapability capability) => new(
            new BootstrapTechnicianAuthenticationPolicy(
                [BootstrapKerberosAuthenticationService.Scheme],
                BootstrapKerberosAuthenticationService.SubjectClaim, 39,
                TechnicianCapabilities.ClaimType, TechnicianCapabilities.Value(capability),
                TimeSpan.FromMinutes(value.MaximumTechnicianAuthenticationAgeMinutes)));
        var bootstrapApprovalAuthorization = Authorization(TechnicianCapability.BootstrapApprove);
        var factsReadAuthorization = Authorization(TechnicianCapability.FactsRead);
        var factsWriteAuthorization = Authorization(TechnicianCapability.FactsWrite);
        var admissionPolicy = new BootstrapIngressAdmissionPolicy(value.BrokerHost,
            value.AllowedPeers.Select(IPAddress.Parse).ToArray(), TimeSpan.FromSeconds(value.RateWindowSeconds),
            value.PerPeerRequestLimit, value.PerPeerConcurrency, value.GlobalConcurrency,
            value.ExternalAuthorityPort, value.InternalListenerPort);
        LinuxLdapPolicy.Validate();
        var technicianDirectory = new LdapUserDirectory(value.TechnicianDirectoryServer,
            value.TechnicianDirectoryBaseDn);
        var technicianAuthentication = new BootstrapKerberosAuthenticationService(
            new Dictionary<TechnicianCapability, ActiveDirectoryUserResolver>
            {
                [TechnicianCapability.BootstrapApprove] = new(technicianDirectory,
                    value.BootstrapApprovalRequiredGroupSid),
                [TechnicianCapability.FactsRead] = new(technicianDirectory,
                    value.FactsReadRequiredGroupSid),
                [TechnicianCapability.FactsWrite] = new(technicianDirectory,
                    value.FactsWriteRequiredGroupSid)
            },
            kerberosTransport.Realm, kerberosTransport.NetBiosDomain);
        return new(policy, new BootstrapIngressAdmission(admissionPolicy),
            new BootstrapEnrollmentWorkflow(transactions, pairings, intake,
                bootstrapApprovalAuthorization, IncomingCsrPolicy.NoClientExtensions,
                TimeSpan.FromMinutes(value.LifetimeMinutes)),
            nativeEnrollment.CreateBootstrapIssuance(transactions, authoritativeFacts),
            technicianAuthentication, bootstrapApprovalAuthorization, factsReadAuthorization,
            factsWriteAuthorization, Path.GetFullPath(value.DeviceFactsFile));
    }

    internal static void ValidateConfiguration(Configuration value)
    {
        if (value.Version != 5 || value.ExternalAuthorityPort is < 1 or > 65535 ||
            value.InternalListenerPort is < 1 or > 65535 ||
            !Bounded(value.BrokerHost, 253) || !value.BrokerHost.Contains('.') ||
            value.BrokerHost.Any(char.IsUpper) || Uri.CheckHostName(value.BrokerHost) != UriHostNameType.Dns ||
            value.AllowedPeers is null || value.AllowedPeers.Length is < 1 or > 64 ||
            value.AllowedPeers.Any(peer => !IPAddress.TryParse(peer, out var address) ||
                address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) ||
            value.AllowedPeers.Distinct(StringComparer.Ordinal).Count() != value.AllowedPeers.Length ||
            value.RateWindowSeconds is < 1 or > 600 || value.PerPeerRequestLimit is < 1 or > 1000 ||
            value.PerPeerConcurrency is < 1 or > 16 || value.GlobalConcurrency < value.PerPeerConcurrency ||
            value.GlobalConcurrency > 256 || value.LifetimeMinutes is < 1 or > 30 ||
            value.MaximumAttempts is < 1 or > 10 || value.MaximumActiveSessions is < 1 or > 10_000 ||
            value.MaximumActiveBytes < BootstrapIntakeQuota.MinimumReservationBytes ||
            value.MaximumHistoryRecords < value.MaximumActiveSessions || value.MaximumHistoryRecords > 100_000 ||
            value.MaximumHistoryBytes < value.MaximumActiveBytes || value.MaximumHistoryBytes > 64L * 1024 * 1024 * 1024 ||
            value.MaximumTechnicianAuthenticationAgeMinutes is < 1 or > 60 ||
            !Bounded(value.TechnicianDirectoryServer, 253) ||
            Uri.CheckHostName(value.TechnicianDirectoryServer) != UriHostNameType.Dns ||
            !value.TechnicianDirectoryServer.Contains('.') ||
            value.TechnicianDirectoryServer.Any(char.IsUpper) ||
            string.IsNullOrWhiteSpace(value.TechnicianDirectoryBaseDn) ||
            value.TechnicianDirectoryBaseDn.Length > 4096 ||
            value.TechnicianDirectoryBaseDn.Any(char.IsControl) ||
            !ValidGroupSid(value.BootstrapApprovalRequiredGroupSid) ||
            !ValidGroupSid(value.FactsReadRequiredGroupSid) ||
            !ValidGroupSid(value.FactsWriteRequiredGroupSid) ||
            !DistinctGroupSids(value.BootstrapApprovalRequiredGroupSid,
                value.FactsReadRequiredGroupSid, value.FactsWriteRequiredGroupSid))
            throw new InvalidDataException("Invalid bounded bootstrap hosting configuration.");
        foreach (var candidate in new[] { value.PolicyFile, value.TrustedCaFile, value.DeviceFactsFile,
                     value.IntakeDirectory, value.AttestationDirectory, value.PairingDirectory, value.TransactionDirectory })
            if (string.IsNullOrWhiteSpace(candidate) || !Path.IsPathFullyQualified(candidate))
                throw new InvalidDataException("Absolute bootstrap file and store paths required.");
    }

    internal static async Task<Configuration> DeserializeConfigurationAsync(Stream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        try
        {
            return await JsonSerializer.DeserializeAsync<Configuration>(stream, Options, cancellationToken)
                ?? throw new InvalidDataException("Missing bootstrap configuration.");
        }
        catch (JsonException error) { throw new InvalidDataException("Invalid bootstrap configuration JSON.", error); }
    }

    internal static void ValidateListenerBinding(Configuration value,
        int externalAuthorityPort, int internalListenerPort)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.ExternalAuthorityPort != externalAuthorityPort ||
            value.InternalListenerPort != internalListenerPort)
            throw new InvalidDataException("Bootstrap ports must match the configured Kerberos listener binding.");
    }

    private static bool Bounded(string? value, int maximum) => value is { Length: > 0 } &&
        value.Length <= maximum && value.All(character => character is >= '!' and <= '~');

    private static bool ValidGroupSid(string? value)
    {
        try
        {
            _ = ActiveDirectoryUserResolver.EncodeDomainGroupSid(value!);
            return true;
        }
        catch (ArgumentException) { return false; }
    }

    private static bool DistinctGroupSids(params string[] values)
    {
        try
        {
            return values.Select(value => Convert.ToHexString(
                    ActiveDirectoryUserResolver.EncodeDomainGroupSid(value)))
                .Distinct(StringComparer.Ordinal).Count() == values.Length;
        }
        catch (ArgumentException) { return false; }
    }

    internal sealed record Configuration(int Version, string BrokerHost,
        int ExternalAuthorityPort, int InternalListenerPort,
        string[] AllowedPeers, int RateWindowSeconds, int PerPeerRequestLimit,
        int PerPeerConcurrency, int GlobalConcurrency, string PolicyFile, string TrustedCaFile,
        string DeviceFactsFile, string IntakeDirectory, string AttestationDirectory, string PairingDirectory,
        string TransactionDirectory, int LifetimeMinutes, int MaximumAttempts,
        int MaximumActiveSessions, long MaximumActiveBytes,
        int MaximumHistoryRecords, long MaximumHistoryBytes, string TechnicianDirectoryServer,
        string TechnicianDirectoryBaseDn, string BootstrapApprovalRequiredGroupSid,
        string FactsReadRequiredGroupSid, string FactsWriteRequiredGroupSid,
        int MaximumTechnicianAuthenticationAgeMinutes);
}
