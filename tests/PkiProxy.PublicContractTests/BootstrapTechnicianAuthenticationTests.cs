using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using PkiProxy.Authentication;

internal static class BootstrapTechnicianAuthenticationTests
{
    internal static void Run()
    {
        var now = DateTimeOffset.Parse("2026-09-14T18:00:00Z");
        var policy = new BootstrapTechnicianAuthenticationPolicy(
            ["webauthn"], "subject", 32, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5));
        var authenticator = new BootstrapTechnicianAuthenticator(policy);
        var checks = 0;
        void Check(bool condition, string label)
        {
            if (!condition) throw new InvalidOperationException("Bootstrap technician authentication: " + label);
            checks++;
        }
        AuthenticateResult Result(
            string scheme = "webauthn", string? identityScheme = null, IEnumerable<Claim>? claims = null,
            DateTimeOffset? issuedUtc = null, bool includeIssuedUtc = true, bool identityAuthenticated = true,
            params ClaimsIdentity[] additionalIdentities)
        {
            var identity = new ClaimsIdentity(claims ??
                [new Claim("subject", "technician:avery"), new Claim("authorization", "bootstrap-approve")],
                identityAuthenticated ? identityScheme ?? scheme : null);
            var principal = new ClaimsPrincipal([identity, .. additionalIdentities]);
            var properties = new AuthenticationProperties();
            if (includeIssuedUtc) properties.IssuedUtc = issuedUtc ?? now;
            return AuthenticateResult.Success(new AuthenticationTicket(principal, properties, scheme));
        }
        void Denies(BootstrapTechnicianAuthenticationResult expected, string label, AuthenticateResult result) =>
            Check(authenticator.Authorize(result, now) is { Result: var actual, Technician: null } && actual == expected, label);

        var success = authenticator.Authorize(Result(), now);
        Check(success.Result == BootstrapTechnicianAuthenticationResult.Authorized &&
            success.Technician is { Subject: "technician:avery", AuthenticationMethod: "webauthn",
                AuthenticatedAt: var at, Capability: "bootstrap-approve" } && at == now,
            "accepts an exact authenticated technician ticket");

        foreach (var required in new[] { "bootstrap-approve", "facts-read", "facts-write" })
        {
            var capabilityAuthenticator = new BootstrapTechnicianAuthenticator(
                new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 32,
                    "authorization", required, TimeSpan.FromMinutes(5)));
            foreach (var granted in new[] { "bootstrap-approve", "facts-read", "facts-write" })
            {
                var decision = capabilityAuthenticator.Authorize(Result(claims:
                    [new Claim("subject", "technician:avery"), new Claim("authorization", granted)]), now);
                Check((decision.Result == BootstrapTechnicianAuthenticationResult.Authorized) ==
                      (required == granted), required + " accepts only its exact route capability");
            }
        }

        Denies(BootstrapTechnicianAuthenticationResult.AuthenticationNotSucceeded, "refuses failed authentication", AuthenticateResult.Fail("failed"));
        Denies(BootstrapTechnicianAuthenticationResult.AuthenticationNotSucceeded, "refuses absent authentication", AuthenticateResult.NoResult());
        Denies(BootstrapTechnicianAuthenticationResult.AmbiguousAuthenticatedIdentity, "refuses no authenticated identity",
            Result(identityAuthenticated: false));
        Denies(BootstrapTechnicianAuthenticationResult.AmbiguousAuthenticatedIdentity, "refuses multiple authenticated identities",
            Result(additionalIdentities: [new ClaimsIdentity([new Claim("subject", "other")], "webauthn")]));
        Denies(BootstrapTechnicianAuthenticationResult.SchemeMismatch, "requires ticket and identity scheme equality",
            Result(identityScheme: "password"));
        Denies(BootstrapTechnicianAuthenticationResult.UnapprovedScheme, "requires an exact approved scheme",
            Result(scheme: "WebAuthn"));
        Denies(BootstrapTechnicianAuthenticationResult.MissingSubject, "requires a subject claim",
            Result(claims: [new Claim("authorization", "bootstrap-approve")]));
        Denies(BootstrapTechnicianAuthenticationResult.AmbiguousSubject, "refuses duplicate subject claims",
            Result(claims: [new Claim("subject", "technician:avery"), new Claim("subject", "technician:blake"), new Claim("authorization", "bootstrap-approve")]));
        Denies(BootstrapTechnicianAuthenticationResult.InvalidSubject, "refuses non-printable subjects",
            Result(claims: [new Claim("subject", "technician\n"), new Claim("authorization", "bootstrap-approve")]));
        Denies(BootstrapTechnicianAuthenticationResult.InvalidSubject, "refuses overlong subjects",
            Result(claims: [new Claim("subject", new string('a', 33)), new Claim("authorization", "bootstrap-approve")]));
        Denies(BootstrapTechnicianAuthenticationResult.MissingAuthorization, "requires exact authorization claim type and value",
            Result(claims: [new Claim("subject", "technician:avery"), new Claim("authorization", "Bootstrap-Approve")]));
        Denies(BootstrapTechnicianAuthenticationResult.MissingAuthorization, "requires exact authorization claim type casing",
            Result(claims: [new Claim("subject", "technician:avery"), new Claim("Authorization", "bootstrap-approve")]));
        Denies(BootstrapTechnicianAuthenticationResult.AmbiguousAuthorization, "refuses duplicate authorization claims",
            Result(claims: [new Claim("subject", "technician:avery"),
                new Claim("authorization", "bootstrap-approve"),
                new Claim("authorization", "bootstrap-approve")]));
        Denies(BootstrapTechnicianAuthenticationResult.MissingIssuedUtc, "requires issue timestamp",
            Result(includeIssuedUtc: false));
        Denies(BootstrapTechnicianAuthenticationResult.FutureIssuedUtc, "refuses future issue timestamp",
            Result(issuedUtc: now.AddSeconds(1)));
        Denies(BootstrapTechnicianAuthenticationResult.StaleIssuedUtc, "refuses stale authentication",
            Result(issuedUtc: now.AddMinutes(-5).AddTicks(-1)));
        Check(authenticator.Authorize(Result(issuedUtc: now.AddMinutes(-5)), now).Result ==
            BootstrapTechnicianAuthenticationResult.Authorized, "accepts the exact freshness boundary");

        foreach (var invalid in new Action[]
        {
            () => _ = new BootstrapTechnicianAuthenticationPolicy([], "subject", 32, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn", "webauthn"], "subject", 32, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(Enumerable.Repeat("webauthn", 9), "subject", 32, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["web authn"], "subject", 32, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy([new string('a', 65)], "subject", 32, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "", 32, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 0, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 257, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject\n", 32, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], new string('s', 257), 32, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 32, "", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 32, "authorization\n", "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 32, new string('a', 257), "bootstrap-approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 32, "authorization", "", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 32, "authorization", "bootstrap approve", TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 32, "authorization", new string('a', 257), TimeSpan.FromMinutes(5)),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 32, "authorization", "bootstrap-approve", TimeSpan.Zero),
            () => _ = new BootstrapTechnicianAuthenticationPolicy(["webauthn"], "subject", 32, "authorization", "bootstrap-approve", TimeSpan.FromHours(1) + TimeSpan.FromTicks(1))
        })
        {
            try { invalid(); throw new InvalidOperationException("Bootstrap technician authentication: invalid policy accepted"); }
            catch (ArgumentOutOfRangeException) { checks++; }
        }

        var mutableSchemes = new List<string> { "webauthn" };
        var snapshotted = new BootstrapTechnicianAuthenticator(new BootstrapTechnicianAuthenticationPolicy(
            mutableSchemes, "subject", 32, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5)));
        mutableSchemes[0] = "password";
        Check(snapshotted.Authorize(Result(), now).Result == BootstrapTechnicianAuthenticationResult.Authorized,
            "snapshots mutable approved-scheme input");

        Console.WriteLine($"Bootstrap technician authentication checks passed ({checks}).");
    }
}
