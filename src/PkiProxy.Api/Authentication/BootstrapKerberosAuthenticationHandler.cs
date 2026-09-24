using System.DirectoryServices.Protocols;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using PkiProxy.Directory;

namespace PkiProxy.Authentication;

internal sealed record BootstrapKerberosFailureFeature(int Status);
internal sealed record BootstrapDirectoryResolution(AuthenticatedDirectoryUser? User,
    bool Authorized, bool CapacityAvailable);

internal enum TechnicianRouteKind
{
    None,
    BootstrapApproval,
    FactsCollection,
    FactsItemRead,
    FactsItemWrite
}

internal enum TechnicianCapability
{
    BootstrapApprove,
    FactsRead,
    FactsWrite
}

internal static class TechnicianCapabilities
{
    internal const string ClaimType = "urn:pkiproxy:technician-capability";
    internal const string BootstrapApprove = "bootstrap-approve";
    internal const string FactsRead = "facts-read";
    internal const string FactsWrite = "facts-write";

    internal static TechnicianCapability ForRoute(TechnicianRouteKind route) => route switch
    {
        TechnicianRouteKind.BootstrapApproval => TechnicianCapability.BootstrapApprove,
        TechnicianRouteKind.FactsCollection or TechnicianRouteKind.FactsItemRead => TechnicianCapability.FactsRead,
        TechnicianRouteKind.FactsItemWrite => TechnicianCapability.FactsWrite,
        _ => throw new ArgumentOutOfRangeException(nameof(route))
    };

    internal static string Value(TechnicianCapability capability) => capability switch
    {
        TechnicianCapability.BootstrapApprove => BootstrapApprove,
        TechnicianCapability.FactsRead => FactsRead,
        TechnicianCapability.FactsWrite => FactsWrite,
        _ => throw new ArgumentOutOfRangeException(nameof(capability))
    };
}

// Keep the Kerberos projection on a deliberately tiny set of canonical paths.
// Asset identifiers are logical keys only; encoded separators, dot segments and
// characters commonly interpreted by filesystems or routers never reach an
// endpoint or request body parser.
internal static class TechnicianRoutePolicy
{
    private const string ApprovalPath = "/bootstrap/technician/approve";
    private const string FactsCollectionPath = "/facts/technician/assets";
    private const string FactsItemPrefix = FactsCollectionPath + "/";

    internal static TechnicianRouteKind Classify(PathString path, string method,
        out string? assetId)
    {
        assetId = null;
        var value = path.Value;
        if (string.Equals(value, ApprovalPath, StringComparison.Ordinal))
            return HttpMethods.IsPost(method) ? TechnicianRouteKind.BootstrapApproval : TechnicianRouteKind.None;
        if (string.Equals(value, FactsCollectionPath, StringComparison.Ordinal))
            return HttpMethods.IsGet(method) ? TechnicianRouteKind.FactsCollection : TechnicianRouteKind.None;
        if (value is null || !value.StartsWith(FactsItemPrefix, StringComparison.Ordinal))
            return TechnicianRouteKind.None;
        var candidate = value[FactsItemPrefix.Length..];
        if (!IsCanonicalAssetId(candidate)) return TechnicianRouteKind.None;
        assetId = candidate;
        return HttpMethods.IsGet(method) ? TechnicianRouteKind.FactsItemRead :
            HttpMethods.IsPut(method) ? TechnicianRouteKind.FactsItemWrite : TechnicianRouteKind.None;
    }

    internal static bool IsCanonicalAssetId(string? value) =>
        value is { Length: > 0 and <= 128 } && value is not "." and not ".." &&
        char.IsAsciiLetterOrDigit(value[0]) &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
}

internal sealed class BootstrapKerberosAuthenticationService : IDisposable
{
    internal const string Scheme = "bootstrap-kerberos";
    internal const string SubjectClaim = "urn:pkiproxy:bootstrap:technician-subject";
    private readonly SemaphoreSlim directorySlots = new(8, 8);
    private readonly Dictionary<TechnicianCapability, ActiveDirectoryUserResolver> resolvers;

    internal BootstrapKerberosAuthenticationService(
        IReadOnlyDictionary<TechnicianCapability, ActiveDirectoryUserResolver> resolvers,
        string realm, string netBiosDomain)
    {
        ArgumentNullException.ThrowIfNull(resolvers);
        if (resolvers.Count != 3 || Enum.GetValues<TechnicianCapability>().Any(capability =>
                !resolvers.ContainsKey(capability) || resolvers[capability] is null))
            throw new ArgumentException("Every technician capability requires an exact directory resolver.",
                nameof(resolvers));
        this.resolvers = new Dictionary<TechnicianCapability, ActiveDirectoryUserResolver>(resolvers);
        ArgumentException.ThrowIfNullOrWhiteSpace(realm);
        ArgumentException.ThrowIfNullOrWhiteSpace(netBiosDomain);
        Realm = realm; NetBiosDomain = netBiosDomain;
    }

    internal string Realm { get; }
    internal string NetBiosDomain { get; }

    internal async Task<BootstrapDirectoryResolution> ResolveAsync(KerberosUserIdentity identity,
        TechnicianCapability capability, CancellationToken cancellationToken)
    {
        if (!await directorySlots.WaitAsync(0, cancellationToken))
            return new(null, false, false);
        try
        {
            var result = await Task.Run(() => resolvers[capability]
                .ResolveAuthorization(identity, cancellationToken), cancellationToken);
            return new(result.User, result.Authorized, true);
        }
        finally { directorySlots.Release(); }
    }

    public void Dispose() => directorySlots.Dispose();
}

internal sealed partial class BootstrapKerberosAuthenticationHandler
    : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly BootstrapKerberosAuthenticationService service;

    public BootstrapKerberosAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder,
        BootstrapKerberosAuthenticationService service)
        : base(options, logger, encoder) => this.service = service;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var route = TechnicianRoutePolicy.Classify(Request.Path, Request.Method, out _);
        if (route == TechnicianRouteKind.None)
            return AuthenticateResult.NoResult();
        var capability = TechnicianCapabilities.ForRoute(route);
        var capabilityValue = TechnicianCapabilities.Value(capability);
        var exchange = Context.Features.Get<KerberosHttpTransport.Exchange>();
        if (exchange is null || !KerberosHttpAuthentication.IsDirectBoundRequest(Context, exchange))
        {
            exchange?.Dispose();
            SetResponse(new(400));
            return AuthenticateResult.Fail("Direct channel-bound Kerberos transport required.");
        }
        if (!KerberosHttpAuthentication.TryToken(Request.Headers.Authorization, out var token))
        {
            exchange.Dispose();
            SetResponse(new(401));
            return AuthenticateResult.Fail("Invalid Negotiate authorization.");
        }

        HttpPeerAuthResult result;
        try { result = exchange.StepPeer(token); }
        finally
        {
            if (token is not null)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(token);
        }
        SetResponse(result);
        if (result.PeerName is null)
            return result.Continue ? AuthenticateResult.NoResult() :
                AuthenticateResult.Fail("Kerberos authentication did not complete.");

        var identity = KerberosUserIdentity.FromAuthenticatedPeerName(result.PeerName,
            service.Realm, service.NetBiosDomain);
        if (identity is null)
        {
            Context.Features.Set(new BootstrapKerberosFailureFeature(403));
            return AuthenticateResult.Fail("Authenticated principal is not an eligible domain user.");
        }

        BootstrapDirectoryResolution resolution;
        try { resolution = await service.ResolveAsync(identity, capability, Context.RequestAborted); }
        catch (OperationCanceledException) when (Context.RequestAborted.IsCancellationRequested)
        { return AuthenticateResult.Fail("Request cancelled."); }
        catch (Exception error) when (error is LdapException or DirectoryOperationException or
            InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            if (Logger.IsEnabled(LogLevel.Information))
                LogDecision(Logger, "unresolved", capabilityValue,
                    "directory-unavailable", Context.TraceIdentifier);
            Context.Features.Set(new BootstrapKerberosFailureFeature(503));
            return AuthenticateResult.Fail("Technician directory unavailable.");
        }
        if (!resolution.CapacityAvailable)
        {
            if (Logger.IsEnabled(LogLevel.Information))
                LogDecision(Logger, "unresolved", capabilityValue,
                    "directory-capacity", Context.TraceIdentifier);
            Context.Features.Set(new BootstrapKerberosFailureFeature(503));
            return AuthenticateResult.Fail("Technician directory unavailable.");
        }
        var user = resolution.User;
        if (user is null)
        {
            if (Logger.IsEnabled(LogLevel.Information))
                LogDecision(Logger, "unresolved", capabilityValue,
                    "forbidden", Context.TraceIdentifier);
            Context.Features.Set(new BootstrapKerberosFailureFeature(403));
            return AuthenticateResult.Fail("Technician capability authorization denied.");
        }

        var principal = "ad:" + user.ObjectId.ToString("D");
        if (!resolution.Authorized)
        {
            if (Logger.IsEnabled(LogLevel.Information))
                LogDecision(Logger, principal, capabilityValue,
                    "forbidden", Context.TraceIdentifier);
            Context.Features.Set(new BootstrapKerberosFailureFeature(403));
            return AuthenticateResult.Fail("Technician capability authorization denied.");
        }

        var ticket = CreateTicket(user, capability, DateTimeOffset.UtcNow);
        if (Logger.IsEnabled(LogLevel.Information))
            LogDecision(Logger, principal, capabilityValue, "allowed", Context.TraceIdentifier);
        return AuthenticateResult.Success(ticket);
    }

    internal static AuthenticationTicket CreateTicket(AuthenticatedDirectoryUser user,
        TechnicianCapability capability, DateTimeOffset issued)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (user.ObjectId == Guid.Empty)
            throw new ArgumentException("Nonempty directory object identifier required.", nameof(user));
        var claims = new[]
        {
            new Claim(BootstrapKerberosAuthenticationService.SubjectClaim,
                "ad:" + user.ObjectId.ToString("D")),
            new Claim(TechnicianCapabilities.ClaimType, TechnicianCapabilities.Value(capability))
        };
        var claimsIdentity = new ClaimsIdentity(claims,
            BootstrapKerberosAuthenticationService.Scheme,
            BootstrapKerberosAuthenticationService.SubjectClaim, ClaimTypes.Role);
        var properties = new AuthenticationProperties { IssuedUtc = issued };
        return new AuthenticationTicket(new ClaimsPrincipal(claimsIdentity),
            properties, BootstrapKerberosAuthenticationService.Scheme);
    }

    private void SetResponse(HttpPeerAuthResult result)
    {
        Context.Features.Set(new BootstrapKerberosFailureFeature(result.Status));
        Response.Headers.CacheControl = "no-store";
        if (result.Challenge is not null)
            Response.Headers.WWWAuthenticate = result.Challenge;
        else if (result.Status == StatusCodes.Status401Unauthorized)
            Response.Headers.WWWAuthenticate = "Negotiate";
        if (!result.Continue)
            Response.Headers.Connection = "close";
    }

    [LoggerMessage(EventId = 120, Level = LogLevel.Information,
        Message = "event=technician-capability-authorization principal={Principal} capability={Capability} decision={Decision} trace={Trace}")]
    private static partial void LogDecision(ILogger logger, string principal,
        string capability, string decision, string trace);
}
