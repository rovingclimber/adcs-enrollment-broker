namespace PkiProxy.Domain;

internal enum EnrollmentChannel
{
    DomainKerberos,
    BootstrapPending,
    CertificateRenewal
}

internal sealed record EnrollmentRequestIdentity(
    EnrollmentChannel Channel,
    string? DirectoryObjectId,
    string? ExistingCertificateThumbprint,
    string CsrSha256,
    string SubjectPublicKeyInfoSha256);

internal sealed record AuthoritativeDeviceFacts(
    string AssetId,
    string DirectoryDistinguishedName,
    string DeviceClass,
    string UseCase,
    string Location,
    string ManagementDomain,
    long SourceVersion,
    string? AuthoritativeDnsHostName = null)
{
    internal Guid? DirectoryObjectId { get; init; }
}

// Existing bare-CSR/bootstrap lookup contract. The native domain path uses
// IDomainDeviceFactsSource locates facts by authenticated AD dNSHostName.
// Initial issuance also requires the locally enrolled object GUID.
internal interface IAuthoritativeDeviceFactsSource
{
    ValueTask<AuthoritativeDeviceFacts?> FindByDirectoryObjectIdAsync(
        string directoryObjectId,
        CancellationToken cancellationToken);

    ValueTask<AuthoritativeDeviceFacts?> FindByAssetIdAsync(
        string assetId,
        CancellationToken cancellationToken);
}

internal sealed record ControlledCertificateIdentity(
    string SubjectDistinguishedName,
    IReadOnlyCollection<Uri> SubjectAlternativeNameUris,
    IReadOnlyCollection<string>? SubjectAlternativeNameDnsNames = null);
