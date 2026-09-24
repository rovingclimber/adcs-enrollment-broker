using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;

internal static class BootstrapAssetBindingTests
{
    internal static async Task RunAsync()
    {
        using var key = RSA.Create(2048);
        var csr = new CertificateRequest("CN=UNTRUSTED", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();
        var binding = CsrBinding.FromDer(csr);
        var now = DateTimeOffset.UtcNow;
        var facts = new AuthoritativeDeviceFacts("approved-asset", "CN=APPROVED", "workstation", "engineering", "lab", "workgroup", 1);
        var policy = new CertificateClaimPolicy("urn:example:pki-broker:lab:fact:v1:profile:broker-pilot", "urn:example:pki-broker:lab:fact:v1:");
        var count = 0;
        void Check(bool result, string message) { if (!result) throw new InvalidOperationException("Bootstrap asset binding: " + message); count++; }
        InMemoryBootstrapAttestationStore Store()
        {
            var store = new InMemoryBootstrapAttestationStore();
            store.Record(binding, now, TimeSpan.FromMinutes(5)); store.Attest(binding, "approved-asset", now);
            return store;
        }
        foreach (var wrongAsset in new[] { "different-asset", "APPROVED-ASSET" })
        {
            var store = Store();
            var authorizer = new BootstrapEnrollmentAuthorizer(store, new WrongResultSource(facts with { AssetId = wrongAsset }), policy, IncomingCsrPolicy.NoClientExtensions);
            var result = await authorizer.AuthorizeAsync(csr, now, default);
            Check(result.Result == BootstrapEnrollmentAuthorizationResult.InvalidAuthoritativeFacts && result.ControlledIdentity is null && result.Facts is null,
                "mismatched lookup response cannot supply identity");
            Check(store.GetAttestedAsset(binding, now).Result == BootstrapStoreResult.Attested, "lookup mismatch preserves approval");
        }
        using var cancellation = new CancellationTokenSource();
        var cancelStore = Store();
        var cancelled = new BootstrapEnrollmentAuthorizer(cancelStore, new WrongResultSource(facts, cancellation.Cancel), policy, IncomingCsrPolicy.NoClientExtensions);
        try { await cancelled.AuthorizeAsync(csr, now, cancellation.Token); throw new InvalidOperationException("Cancellation ignored"); }
        catch (OperationCanceledException) { count++; }
        Check(cancelStore.GetAttestedAsset(binding, now).Result == BootstrapStoreResult.Attested, "cancelled lookup must not consume approval");
        var swapped = new BootstrapEnrollmentAuthorizer(new SwappingStore(Store()), new WrongResultSource(facts), policy, IncomingCsrPolicy.NoClientExtensions);
        var swappedResult = await swapped.AuthorizeAsync(csr, now, default);
        Check(swappedResult.Result != BootstrapEnrollmentAuthorizationResult.Authorized && swappedResult.ControlledIdentity is null,
            "consumption result must still match approved asset");
        foreach (var elapsed in new[] { TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(6) })
        {
            var expiryStore = Store();
            var clock = new LookupClock();
            var expiring = new BootstrapEnrollmentAuthorizer(expiryStore,
                new WrongResultSource(facts, () => clock.Advance(elapsed)), policy,
                IncomingCsrPolicy.NoClientExtensions, clock);
            var expired = await expiring.AuthorizeAsync(csr, now, default);
            Check(expired.Result == BootstrapEnrollmentAuthorizationResult.AttestationExpired &&
                expired.Facts is null && expired.ControlledIdentity is null,
                "approval expiring during lookup must not authorize");
            Check(expiryStore.GetAttestedAsset(binding, now + elapsed).Result == BootstrapStoreResult.Expired,
                "expired approval cannot be reused");
        }
        var timelyClock = new LookupClock();
        var timely = new BootstrapEnrollmentAuthorizer(Store(),
            new WrongResultSource(facts, () => timelyClock.Advance(TimeSpan.FromMinutes(4))),
            policy, IncomingCsrPolicy.NoClientExtensions, timelyClock);
        Check((await timely.AuthorizeAsync(csr, now, default)).Result == BootstrapEnrollmentAuthorizationResult.Authorized,
            "valid approval before expiry still authorizes");
        Console.WriteLine($"Bootstrap authoritative-asset binding checks passed: {count}.");
    }

    private sealed class WrongResultSource(AuthoritativeDeviceFacts facts, Action? beforeReturn = null) : IAuthoritativeDeviceFactsSource
    {
        public ValueTask<AuthoritativeDeviceFacts?> FindByAssetIdAsync(string assetId, CancellationToken cancellationToken)
        { beforeReturn?.Invoke(); return ValueTask.FromResult<AuthoritativeDeviceFacts?>(facts); }
        public ValueTask<AuthoritativeDeviceFacts?> FindByDirectoryObjectIdAsync(string directoryObjectId, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
    private sealed class SwappingStore(IBootstrapAttestationStore inner) : IBootstrapAttestationStore
    {
        public BootstrapStoreResult Record(CsrBinding binding, DateTimeOffset now, TimeSpan lifetime) => inner.Record(binding, now, lifetime);
        public BootstrapStoreResult Attest(CsrBinding binding, string authoritativeAssetId, DateTimeOffset now) => inner.Attest(binding, authoritativeAssetId, now);
        public BootstrapAttestationLookup GetAttestedAsset(CsrBinding binding, DateTimeOffset now) => inner.GetAttestedAsset(binding, now);
        public BootstrapConsumeResult Consume(CsrBinding binding, DateTimeOffset now) => inner.Consume(binding, now) with { AuthoritativeAssetId = "different-asset" };
    }
    private sealed class LookupClock : TimeProvider
    {
        private long timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => timestamp;
        internal void Advance(TimeSpan duration) => timestamp += duration.Ticks;
    }
}
