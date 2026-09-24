using System.Security.Claims;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using PkiProxy.Authentication;
using PkiProxy.Domain;

internal static class OperationalFactsManagementTests
{
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectory = PrivateFile | UnixFileMode.UserExecute;
    private static readonly string Actor = "ad:389c3e26-f566-48b5-8de3-e35e6df76403";
    private static readonly string[] ExpectedAssets = ["asset-physical-001", "asset-virtual-001"];

    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux())
        {
            Console.WriteLine("Operational facts management checks skipped: Linux durability primitives required.");
            return;
        }
        var checks = 0;
        void Check(bool condition, string label)
        { if (!condition) throw new InvalidOperationException("Operational facts management: " + label); checks++; }
        var root = Path.Combine(Path.GetTempPath(), "operational-facts-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, PrivateDirectory);
        try
        {
            var manager = await CreateAsync(Path.Combine(root, "normal"));
            using (manager)
            {
                var snapshot = manager.ReadAll();
                Check(snapshot.Revision == 3 && snapshot.Assets.Count == 2 &&
                    snapshot.Assets.Select(asset => asset.AssetId).SequenceEqual(ExpectedAssets),
                    "bounded known-asset list");
                Check(manager.Read("asset-virtual-001") is { Hostname: "CLIENT-001.example.test", UseCase: "engineering" },
                    "server-owned identity read");
                Check(manager.Read("../devices.json") is null && manager.Read("unknown") is null,
                    "path-shaped and unknown assets rejected");

                var invalid = await manager.PutAsync("asset-virtual-001", 3,
                    new("arbitrary", "engineering", "identity-lab", "example.test"), Actor);
                Check(invalid.Result == OperationalFactsWriteResult.InvalidSelection,
                    "uncatalogued selector rejected");
                var unchanged = await manager.PutAsync("asset-virtual-001", 3,
                    new("virtual-workstation", "engineering", "identity-lab", "example.test"), Actor);
                Check(unchanged is { Result: OperationalFactsWriteResult.Unchanged, Write.Changed: false } &&
                    !Directory.Exists(Path.Combine(Path.GetDirectoryName(manager.DeviceFactsFile)!, ".facts-history")),
                    "no-op has no revision or audit transaction");

                var updated = await manager.PutAsync("asset-virtual-001", 3,
                    new("virtual-workstation", "lab-validation", "identity-lab", "example.test"), Actor);
                Check(updated is { Result: OperationalFactsWriteResult.Updated, Write.Revision: 4, Write.Changed: true },
                    "catalogued update committed");
                var target = manager.DeviceFactsFile;
                var reader = new JsonFileDeviceFactsSource(target);
                Check(await reader.FindByAssetIdAsync("asset-virtual-001", default) is
                    { UseCase: "lab-validation", SourceVersion: 4, AuthoritativeDnsHostName: "CLIENT-001.example.test" },
                    "existing enrollment reader sees only committed revision");
                var recovery = Directory.GetDirectories(Path.Combine(Path.GetDirectoryName(target)!, ".facts-history")).Single();
                using var intent = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(recovery, "intent.json")));
                using var committed = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(recovery, "committed.json")));
                Check(intent.RootElement.GetProperty("OperatorIdentity").GetString() == Actor &&
                    committed.RootElement.GetProperty("OperatorIdentity").GetString() == Actor &&
                    intent.RootElement.GetProperty("OperatorCapability").GetString() ==
                        TechnicianCapabilities.FactsWrite &&
                    committed.RootElement.GetProperty("OperatorCapability").GetString() ==
                        TechnicianCapabilities.FactsWrite &&
                    intent.RootElement.GetProperty("Publication").GetProperty("PreviousSha256").GetString()!.Length == 64 &&
                    committed.RootElement.GetProperty("PublishedSha256").GetString()!.Length == 64,
                    "sanitized actor and before-after hashes durably audited");
                Check(File.GetUnixFileMode(Path.Combine(recovery, "intent.json")) == PrivateFile &&
                    File.GetUnixFileMode(Path.Combine(recovery, "committed.json")) == PrivateFile,
                    "audit files owner-only");
                var stale = await manager.PutAsync("asset-virtual-001", 3,
                    new("virtual-workstation", "engineering", "identity-lab", "example.test"), Actor);
                Check(stale.Result == OperationalFactsWriteResult.PreconditionFailed &&
                    Directory.GetDirectories(Path.Combine(Path.GetDirectoryName(target)!, ".facts-history")).Length == 1,
                    "stale precondition creates no audit");

                var first = manager.PutAsync("asset-virtual-001", 4,
                    new("virtual-workstation", "engineering", "identity-lab", "example.test"), Actor);
                var second = manager.PutAsync("asset-virtual-001", 4,
                    new("virtual-workstation", "lab-validation", "field", "example.test"), Actor);
                var outcomes = await Task.WhenAll(first, second);
                Check(outcomes.Count(value => value.Result == OperationalFactsWriteResult.Updated) == 1 &&
                    outcomes.All(value => value.Result is OperationalFactsWriteResult.Updated or
                        OperationalFactsWriteResult.Busy or OperationalFactsWriteResult.PreconditionFailed),
                    "concurrent same-revision writes have at most one commit");
            }

            await RecoveryAsync(Path.Combine(root, "recover-before"), afterRename: false, Check);
            await RecoveryAsync(Path.Combine(root, "recover-after"), afterRename: true, Check);
            await LegacyHistoryAsync(Path.Combine(root, "legacy-history"), Check);
            RouteChecks(Check);
            await AuthenticationBeforeBodyAsync(Path.Combine(root, "auth"), Check);
        }
        finally { Directory.Delete(root, recursive: true); }
        Console.WriteLine($"Operational facts management checks passed: {checks}.");
    }

    [SupportedOSPlatform("linux")]
    private static async Task<OperationalFactsManagement> CreateAsync(string directory)
    {
        Directory.CreateDirectory(directory, PrivateDirectory);
        var facts = Path.Combine(directory, "devices.json");
        File.Copy("lab/device-facts/devices.client001-engineering-v3.json", facts);
        File.SetUnixFileMode(facts, PrivateFile);
        var config = Path.Combine(directory, "management.json");
        File.WriteAllText(config, JsonSerializer.Serialize(new OperationalFactsManagement.Configuration(1,
            facts, 1000, ["workstation", "virtual-workstation"],
            ["office", "identity-lab", "field"], ["example.test"])));
        File.SetUnixFileMode(config, PrivateFile);
        return await OperationalFactsManagement.LoadAsync(config, facts,
            Authenticator(TechnicianCapabilities.FactsRead),
            Authenticator(TechnicianCapabilities.FactsWrite));
    }

    private static BootstrapTechnicianAuthenticator Authenticator(string capability) => new(
        new BootstrapTechnicianAuthenticationPolicy(
            [BootstrapKerberosAuthenticationService.Scheme],
            BootstrapKerberosAuthenticationService.SubjectClaim, 39,
            TechnicianCapabilities.ClaimType, capability,
            TimeSpan.FromMinutes(5)));

    [SupportedOSPlatform("linux")]
    private static async Task RecoveryAsync(string directory, bool afterRename,
        Action<bool, string> check)
    {
        using var manager = await CreateAsync(directory);
        var target = manager.DeviceFactsFile;
        var source = DeviceFactsPublisher.Read(target);
        var sourceHash = Convert.ToHexString(SHA256.HashData(source));
        var draft = DeviceFactsEditor.PrepareUseCase(source, sourceHash,
            "CLIENT-001.example.test", "lab-validation");
        try
        {
            _ = DeviceFactsPublisher.Publish(target, draft, sourceHash,
                Convert.ToHexString(SHA256.HashData(draft)), stage =>
                {
                    if (stage == (afterRename ? "after-rename" : "before-rename"))
                        throw new IOException("injected crash");
                }, Actor, TechnicianCapabilities.FactsWrite);
            throw new InvalidOperationException("Injected recovery interruption did not occur.");
        }
        catch (IOException) { }
        manager.Dispose();
        using var recovered = await CreateFromExistingAsync(directory, target);
        var recovery = Directory.GetDirectories(Path.Combine(directory, ".facts-history")).Single();
        check(File.Exists(Path.Combine(recovery, afterRename ? "committed.json" : "aborted.json")),
            afterRename ? "post-rename crash finalized exactly" : "pre-rename crash recorded aborted");
        var revision = recovered.ReadAll().Revision;
        check(revision == (afterRename ? 4 : 3), "recovery exposes the proven revision only");
        // Reconciliation is idempotent.
        using var reopened = await CreateFromExistingAsync(directory, target);
        check(reopened.ReadAll().Revision == revision, "recovery markers replay idempotently");
    }

    [SupportedOSPlatform("linux")]
    private static async Task<OperationalFactsManagement> CreateFromExistingAsync(string directory,
        string target)
    {
        var config = Path.Combine(directory, "management.json");
        return await OperationalFactsManagement.LoadAsync(config, target,
            Authenticator(TechnicianCapabilities.FactsRead),
            Authenticator(TechnicianCapabilities.FactsWrite));
    }

    [SupportedOSPlatform("linux")]
    private static async Task LegacyHistoryAsync(string directory, Action<bool, string> check)
    {
        var manager = await CreateAsync(directory);
        var target = manager.DeviceFactsFile;
        manager.Dispose();
        var source = DeviceFactsPublisher.Read(target);
        var sourceHash = Convert.ToHexString(SHA256.HashData(source));
        var draft = DeviceFactsEditor.PrepareUseCase(source, sourceHash,
            "CLIENT-001.example.test", "lab-validation");
        var receipt = DeviceFactsPublisher.Publish(target, draft, sourceHash,
            Convert.ToHexString(SHA256.HashData(draft)), operatorIdentity: "legacy@example.com",
            operatorCapability: TechnicianCapabilities.FactsWrite);
        foreach (var name in new[] { "intent.json", "committed.json" })
        {
            var path = Path.Combine(receipt.RecoveryDirectory, name);
            var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
            node.Remove("OperatorIdentity"); // Schema before actor attribution was added.
            node.Remove("OperatorCapability");
            File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(node));
            File.SetUnixFileMode(path, PrivateFile);
        }
        using var recovered = await CreateFromExistingAsync(directory, target);
        check(recovered.ReadAll().Revision == 4, "completed legacy marker without actor remains readable");
        check(Directory.GetFiles(receipt.RecoveryDirectory, "*.json").Length == 4,
            "completed legacy transaction is not rewritten by reconciliation");
    }

    private static void RouteChecks(Action<bool, string> check)
    {
        check(TechnicianRoutePolicy.Classify("/facts/technician/assets", "GET", out _) ==
            TechnicianRouteKind.FactsCollection, "exact collection route accepted");
        check(TechnicianRoutePolicy.Classify("/facts/technician/assets/asset-virtual-001", "PUT", out var id) ==
            TechnicianRouteKind.FactsItemWrite && id == "asset-virtual-001", "canonical item route accepted");
        check(TechnicianCapabilities.ForRoute(TechnicianRouteKind.BootstrapApproval) ==
                TechnicianCapability.BootstrapApprove &&
              TechnicianCapabilities.ForRoute(TechnicianRouteKind.FactsCollection) ==
                TechnicianCapability.FactsRead &&
              TechnicianCapabilities.ForRoute(TechnicianRouteKind.FactsItemRead) ==
                TechnicianCapability.FactsRead &&
              TechnicianCapabilities.ForRoute(TechnicianRouteKind.FactsItemWrite) ==
                TechnicianCapability.FactsWrite,
            "each canonical route maps to one explicit capability");
        foreach (var method in new[] { "POST", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE" })
            check(TechnicianRoutePolicy.Classify("/facts/technician/assets/asset-virtual-001", method,
                    out _) == TechnicianRouteKind.None,
                "alternate facts verb has no capability: " + method);
        foreach (var path in new[] { "/facts/technician/assets/../x", "/facts/technician/assets/%2e%2e",
                     "/facts/technician/assets/a%2fb", "/facts/technician/assets/a/b",
                     "/facts/technician/assets/asset-virtual-001/", "/Facts/technician/assets/asset-virtual-001" })
            check(TechnicianRoutePolicy.Classify(path, "PUT", out _) == TechnicianRouteKind.None,
                "hostile or noncanonical route rejected: " + path);
    }

    [SupportedOSPlatform("linux")]
    private static async Task AuthenticationBeforeBodyAsync(string directory,
        Action<bool, string> check)
    {
        using var manager = await CreateAsync(directory);
        AuthenticateResult Ticket(TechnicianCapability capability) => AuthenticateResult.Success(
            BootstrapKerberosAuthenticationHandler.CreateTicket(
                new(Guid.Parse(Actor[3..]), "avery"), capability, DateTimeOffset.UtcNow));

        foreach (var capability in new[]
                 {
                     TechnicianCapability.BootstrapApprove,
                     TechnicianCapability.FactsWrite
                 })
        {
            foreach (var asset in new[] { "asset-virtual-001", "absent-asset" })
            {
                var denied = Context(Ticket(capability), Stream.Null, "GET",
                    "/facts/technician/assets/" + asset);
                var result = await OperationalFactsRequestHandler.ReadAsync(denied, asset, manager);
                check(Status(result) == 403,
                    capability + " read denial is identical for present and absent assets");
            }
        }
        var reader = Context(Ticket(TechnicianCapability.FactsRead), Stream.Null, "GET",
            "/facts/technician/assets/asset-virtual-001");
        check(Status(await OperationalFactsRequestHandler.ReadAsync(reader, "asset-virtual-001", manager))
                is null or 200,
            "facts-read capability can read a catalogued asset");

        foreach (var capability in new[]
                 {
                     TechnicianCapability.BootstrapApprove,
                     TechnicianCapability.FactsRead
                 })
        {
            var deniedBody = new MemoryStream(Encoding.UTF8.GetBytes(
                "{\"DeviceClass\":\"virtual-workstation\",\"UseCase\":\"engineering\",\"Location\":\"identity-lab\",\"ManagementDomain\":\"example.test\"}"));
            var denied = Context(Ticket(capability), deniedBody, "PUT",
                "/facts/technician/assets/asset-virtual-001");
            denied.Request.Headers.IfMatch = OperationalFactsRequestHandler.RevisionTag(3);
            denied.Request.ContentType = "application/json";
            denied.Request.ContentLength = deniedBody.Length;
            check(Status(await OperationalFactsRequestHandler.PutAsync(denied,
                    "asset-virtual-001", manager, default)) == 403 && deniedBody.Position == 0,
                capability + " cannot write facts and the body remains unread");
        }

        var body = new MemoryStream(Encoding.UTF8.GetBytes(
            "{\"DeviceClass\":\"virtual-workstation\",\"UseCase\":\"lab-validation\",\"Location\":\"identity-lab\",\"ManagementDomain\":\"example.test\"}"));
        var services = new ServiceCollection()
            .AddSingleton<IAuthenticationService>(new FailedAuthentication())
            .BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Method = "PUT";
        context.Request.Path = "/facts/technician/assets/asset-virtual-001";
        context.Request.Headers.IfMatch = OperationalFactsRequestHandler.RevisionTag(3);
        context.Request.ContentType = "application/json";
        context.Request.ContentLength = body.Length;
        context.Request.Body = body;
        _ = await OperationalFactsRequestHandler.PutAsync(context, "asset-virtual-001", manager, default);
        check(body.Position == 0, "authentication failure leaves update body unread");

        var oversized = new MemoryStream(new byte[1]);
        var oversizedContext = Context(Ticket(TechnicianCapability.FactsWrite), oversized);
        oversizedContext.Request.ContentLength = 4097;
        var oversizedResult = await OperationalFactsRequestHandler.PutAsync(oversizedContext,
            "asset-virtual-001", manager, default);
        check(oversized.Position == 0 && Status(oversizedResult) == 400,
            "oversize update rejected without reading body");

        var duplicate = new MemoryStream(Encoding.UTF8.GetBytes(
            "{\"DeviceClass\":\"virtual-workstation\",\"DeviceClass\":\"workstation\",\"UseCase\":\"lab-validation\",\"Location\":\"identity-lab\",\"ManagementDomain\":\"example.test\"}"));
        var duplicateContext = Context(Ticket(TechnicianCapability.FactsWrite), duplicate);
        var duplicateResult = await OperationalFactsRequestHandler.PutAsync(duplicateContext,
            "asset-virtual-001", manager, default);
        check(Status(duplicateResult) == 400 && manager.ReadAll().Revision == 3,
            "duplicate JSON property rejected without facts change");

        DefaultHttpContext Context(AuthenticateResult authentication, Stream requestBody,
            string method = "PUT", string path = "/facts/technician/assets/asset-virtual-001")
        {
            var scopedServices = new ServiceCollection()
                .AddSingleton<IAuthenticationService>(new FixedAuthentication(authentication))
                .BuildServiceProvider();
            var request = new DefaultHttpContext { RequestServices = scopedServices };
            request.Request.Method = method;
            request.Request.Path = path;
            request.Request.Headers.IfMatch = OperationalFactsRequestHandler.RevisionTag(3);
            request.Request.ContentType = "application/json";
            request.Request.ContentLength = requestBody.Length;
            request.Request.Body = requestBody;
            return request;
        }
        static int? Status(IResult result) => (result as IStatusCodeHttpResult)?.StatusCode;
    }

    private sealed class FailedAuthentication : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(AuthenticateResult.Fail("denied"));
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }
    private sealed class FixedAuthentication(AuthenticateResult result) : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => Task.FromResult(result);
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }
}
