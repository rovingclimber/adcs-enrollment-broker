using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using PkiProxy.Authentication;
using PkiProxy.Directory;

internal static class BootstrapKerberosAuthenticationTests
{
    private const string Realm = "LAB.EXAMPLE";
    private const string NetBios = "LAB";
    private const string GroupSid = "S-1-5-21-1-2-3-1401";
    private const string FactsReadGroupSid = "S-1-5-21-1-2-3-1402";
    private const string FactsWriteGroupSid = "S-1-5-21-1-2-3-1403";

    internal static async Task RunAsync()
    {
        var checks = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException(
                "Bootstrap Kerberos authentication: " + label);
            checks++;
        }

        foreach (var accepted in new[] { "avery@LAB.EXAMPLE", "LAB\\avery",
                     "Avery.Smith@lab.example" })
            Check(KerberosUserIdentity.FromAuthenticatedPeerName(accepted, Realm, NetBios)
                is not null, "accepts strict same-domain user principal");
        foreach (var rejected in new string?[]
        {
            null, "", "avery", "avery@OTHER.EXAMPLE", "OTHER\\avery",
            "CLIENT01$@LAB.EXAMPLE", "HTTP/broker.lab.example@LAB.EXAMPLE",
            "host/client@LAB.EXAMPLE", "LAB\\Administrator", "Guest@LAB.EXAMPLE",
            "krbtgt@LAB.EXAMPLE", "LAB\\avery\\extra", "a very@LAB.EXAMPLE",
            "@LAB.EXAMPLE", "avery@@LAB.EXAMPLE"
        })
            Check(KerberosUserIdentity.FromAuthenticatedPeerName(rejected, Realm, NetBios)
                is null, "rejects malformed, foreign, machine, service or built-in principal");

        var group = ActiveDirectoryUserResolver.EncodeDomainGroupSid(GroupSid);
        var objectId = Guid.Parse("389c3e26-f566-48b5-8de3-e35e6df76403");
        DirectoryUserRecord Record(string account = "avery", int uac = 512,
            int type = 805306368, IReadOnlyCollection<byte[]>? groups = null) =>
            new(objectId, account, uac, type, groups ?? [group]);
        var valid = ActiveDirectoryUserResolver.ValidateRecord("avery", Record(), group);
        Check(valid is { ObjectId: var id, AccountName: "avery" } && id == objectId,
            "active SAM_USER_OBJECT with exact tokenGroups SID is authorized");
        Check(ActiveDirectoryUserResolver.ValidateRecord("avery",
            Record(account: "other"), group) is null, "directory name substitution rejected");
        Check(ActiveDirectoryUserResolver.ValidateRecord("avery",
            Record(uac: 514), group) is null, "disabled user rejected");
        Check(ActiveDirectoryUserResolver.ValidateRecord("avery",
            Record(type: 805306369), group) is null, "machine account type rejected");
        Check(ActiveDirectoryUserResolver.ValidateRecord("avery",
            Record(groups: [ActiveDirectoryUserResolver.EncodeDomainGroupSid(
                "S-1-5-21-1-2-3-14010")]), group) is null,
            "group SID suffix does not authorize");
        Check(ActiveDirectoryUserResolver.ValidateRecord("avery",
            Record(groups: [group[..^1]]), group) is null, "malformed group SID rejected");
        Check(LdapUserDirectory.EscapeFilter("a*)(x") == "\\61\\2a\\29\\28\\78",
            "LDAP filter value is fully byte escaped");

        var readGroup = ActiveDirectoryUserResolver.EncodeDomainGroupSid(FactsReadGroupSid);
        var writeGroup = ActiveDirectoryUserResolver.EncodeDomainGroupSid(FactsWriteGroupSid);
        var directory = new FixedDirectory(new Dictionary<string, DirectoryUserRecord>(StringComparer.OrdinalIgnoreCase)
        {
            ["pairer"] = new(Guid.NewGuid(), "pairer", 512, 805306368, [group]),
            ["reader"] = new(Guid.NewGuid(), "reader", 512, 805306368, [readGroup]),
            ["writer"] = new(Guid.NewGuid(), "writer", 512, 805306368, [writeGroup]),
            ["combined"] = new(Guid.NewGuid(), "combined", 512, 805306368,
                [group, readGroup, writeGroup]),
            ["ordinary"] = new(Guid.NewGuid(), "ordinary", 512, 805306368,
                [ActiveDirectoryUserResolver.EncodeDomainGroupSid("S-1-5-21-1-2-3-1499")])
        });
        using var service = new BootstrapKerberosAuthenticationService(
            new Dictionary<TechnicianCapability, ActiveDirectoryUserResolver>
            {
                [TechnicianCapability.BootstrapApprove] = new(directory, GroupSid),
                [TechnicianCapability.FactsRead] = new(directory, FactsReadGroupSid),
                [TechnicianCapability.FactsWrite] = new(directory, FactsWriteGroupSid)
            }, Realm, NetBios);
        async Task<bool> Granted(string account, TechnicianCapability capability) =>
            (await service.ResolveAsync(KerberosUserIdentity.FromAuthenticatedPeerName(
                account + "@" + Realm, Realm, NetBios)!, capability, default)).Authorized;
        Check(await Granted("pairer", TechnicianCapability.BootstrapApprove) &&
              !await Granted("pairer", TechnicianCapability.FactsRead) &&
              !await Granted("pairer", TechnicianCapability.FactsWrite),
            "pairing-only membership grants only bootstrap approval");
        Check(!await Granted("reader", TechnicianCapability.BootstrapApprove) &&
              await Granted("reader", TechnicianCapability.FactsRead) &&
              !await Granted("reader", TechnicianCapability.FactsWrite),
            "facts-read membership grants only facts reads");
        Check(!await Granted("writer", TechnicianCapability.BootstrapApprove) &&
              !await Granted("writer", TechnicianCapability.FactsRead) &&
              await Granted("writer", TechnicianCapability.FactsWrite),
            "facts-write membership grants only facts writes");
        Check(Enum.GetValues<TechnicianCapability>().All(capability =>
                Granted("combined", capability).GetAwaiter().GetResult()),
            "explicit membership in all three groups grants each route-specific capability");
        Check(Enum.GetValues<TechnicianCapability>().All(capability =>
                !Granted("ordinary", capability).GetAwaiter().GetResult()),
            "ordinary authenticated user receives no technician capability");
        var ordinaryResolution = await service.ResolveAsync(
            KerberosUserIdentity.FromAuthenticatedPeerName("ordinary@" + Realm, Realm, NetBios)!,
            TechnicianCapability.BootstrapApprove, default);
        Check(ordinaryResolution is { User.ObjectId: var ordinaryId, Authorized: false } &&
              ordinaryId != Guid.Empty,
            "valid ordinary user retains immutable audit identity while capability is denied");

        var issued = DateTimeOffset.Parse("2026-09-19T18:00:00Z");
        var ticket = BootstrapKerberosAuthenticationHandler.CreateTicket(valid!,
            TechnicianCapability.BootstrapApprove, issued);
        var identities = ticket.Principal.Identities.ToArray();
        var claims = identities.Single().Claims.ToArray();
        Check(ticket.AuthenticationScheme == BootstrapKerberosAuthenticationService.Scheme &&
            identities.Length == 1 && identities[0].AuthenticationType == ticket.AuthenticationScheme &&
            claims.Length == 2, "ticket has one exact-scheme identity and two server claims");
        Check(claims.Count(claim => claim.Type == BootstrapKerberosAuthenticationService.SubjectClaim &&
                claim.Value == "ad:" + objectId.ToString("D")) == 1 &&
            claims.Count(claim => claim.Type == TechnicianCapabilities.ClaimType &&
                claim.Value == TechnicianCapabilities.BootstrapApprove) == 1,
            "ticket has one immutable directory subject and one approval grant");
        Check(ticket.Properties.IssuedUtc == issued, "ticket has the fresh server issue time");

        foreach (var status in new[] { 401, 403, 503 })
        {
            var body = new MemoryStream(
                "{\"TransactionId\":\"t\",\"DisplayCode\":\"123456\",\"AuthoritativeAssetId\":\"a\"}"u8.ToArray());
            var context = Context(AuthenticateResult.Fail("denied"), status, body);
            var intake = await BootstrapApprovalRequestReader.ReadAsync(context,
                BootstrapKerberosAuthenticationService.Scheme, default);
            Check(intake.FailureStatus == status && intake.Payload is null && body.Position == 0,
                status + " authentication result leaves approval body unread");
        }

        var successContext = Context(AuthenticateResult.Success(ticket), null,
            new MemoryStream("{\"TransactionId\":\"t\",\"DisplayCode\":\"123456\",\"AuthoritativeAssetId\":\"a\"}"u8.ToArray()));
        successContext.Request.ContentType = "application/json";
        successContext.Request.ContentLength = successContext.Request.Body.Length;
        var acceptedPayload = await BootstrapApprovalRequestReader.ReadAsync(successContext,
            BootstrapKerberosAuthenticationService.Scheme, default);
        Check(acceptedPayload is { FailureStatus: null, Payload.TransactionId: "t" },
            "only successful authentication permits bounded approval body parsing");

        var transportSource = File.ReadAllText(Path.GetFullPath(
            "src/PkiProxy.Api/Authentication/KerberosHttpTransport.cs"));
        Check(Count(transportSource, "new(owner.servicePrincipal, TlsEndpointBinding.FromServerStream(Stream))") == 1 &&
            Count(transportSource, "internal HttpPeerAuthResult StepPeer") == 1,
            "technician and computer projections share one connection-scoped GSS acceptor");
        var projectedUser = KerberosHttpTransport.ProjectComputerResult(
            new HttpPeerAuthResult(200, "Negotiate token", PeerName: "avery@LAB.EXAMPLE"),
            Realm, NetBios);
        Check(projectedUser.Status == 403 && projectedUser.Identity is null,
            "computer route still maps authenticated user principals to forbidden");

        Console.WriteLine($"Bootstrap Kerberos authentication checks passed ({checks}).");
    }

    private static DefaultHttpContext Context(AuthenticateResult result, int? failureStatus,
        Stream body)
    {
        var services = new ServiceCollection()
            .AddSingleton<IAuthenticationService>(new StubAuthenticationService(result))
            .BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Body = body;
        if (failureStatus is { } status)
            context.Features.Set(new BootstrapKerberosFailureFeature(status));
        return context;
    }

    private static int Count(string value, string token) =>
        value.Split(token, StringSplitOptions.None).Length - 1;

    private sealed class StubAuthenticationService(AuthenticateResult result)
        : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(result);
        public Task ChallengeAsync(HttpContext context, string? scheme,
            AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme,
            AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal,
            AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme,
            AuthenticationProperties? properties) => Task.CompletedTask;
    }

    private sealed class FixedDirectory(IReadOnlyDictionary<string, DirectoryUserRecord> records)
        : IUserDirectory
    {
        public DirectoryUserRecord? FindUser(string accountName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return records.GetValueOrDefault(accountName);
        }
    }
}
