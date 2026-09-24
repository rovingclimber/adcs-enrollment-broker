using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authentication;
using PkiProxy.Authentication;
using PkiProxy.Domain;

internal static class BootstrapEnrollmentWorkflowTests
{
    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux())
        {
            Console.WriteLine("Bootstrap enrollment workflow checks skipped (Linux-only durable stores).");
            return;
        }

        var root = Directory.CreateTempSubdirectory("bootstrap-workflow-");
        try
        {
            var attestationsPath = PrivateDirectory(root, "attestations");
            var pairingsPath = PrivateDirectory(root, "pairings");
            var transactionsPath = PrivateDirectory(root, "transactions");
            var intakePath = PrivateDirectory(root, "intake");
            var factsPath = Path.Combine(root.FullName, "facts.json");
            await File.WriteAllTextAsync(factsPath, """
                {"schemaVersion":1,"revision":7,
                 "useCases":[{"id":"engineering","label":"Engineering"}],
                 "devices":[{"hostname":"workgroup-001.example.test","assetId":"asset-physical-001",
                   "deviceClass":"workstation","useCase":"engineering","location":"lab","managementDomain":"workgroup"}]}
                """);
            var assets = await JsonFileImmutableAssetCatalog.LoadAsync(factsPath);
            var now = DateTimeOffset.Parse("2026-09-19T12:00:00Z");
            using var key = RSA.Create(2048);
            var csr = new CertificateRequest("CN=UNTRUSTED", key, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1).CreateSigningRequest();
            var binding = CsrBinding.FromDer(csr);
            var checks = 0;
            void Check(bool condition, string label)
            {
                if (!condition) throw new InvalidOperationException("Bootstrap workflow: " + label);
                checks++;
            }

            BootstrapEnrollmentWorkflow Workflow() => new(
                new FileBootstrapEnrollmentTransactionStore(transactionsPath),
                new FileBootstrapPairingCoordinator(pairingsPath,
                    new FileBootstrapAttestationStore(attestationsPath), assets,
                    new BootstrapPairingPolicy(TimeSpan.FromMinutes(10), 3, 16, TimeSpan.FromMinutes(5))),
                new FileBootstrapIntakeLedger(intakePath,
                    new BootstrapIntakeQuota(16, 20 * 1024 * 1024, 64, 80 * 1024 * 1024)),
                new BootstrapTechnicianAuthenticator(new BootstrapTechnicianAuthenticationPolicy(
                    ["webauthn"], "subject", 64, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5))),
                IncomingCsrPolicy.NoClientExtensions, TimeSpan.FromMinutes(10));

            (BootstrapEnrollmentWorkflow Workflow, string Intake, string Attestations,
                string Pairings, string Transactions) Interruptible(string stage, int ordinal,
                CancellationTokenSource cancellation) 
            {
                var prefix = "cancel-" + ordinal + "-";
                var a = PrivateDirectory(root, prefix + "attestations");
                var p = PrivateDirectory(root, prefix + "pairings");
                var t = PrivateDirectory(root, prefix + "transactions");
                var i = PrivateDirectory(root, prefix + "intake");
                return (new BootstrapEnrollmentWorkflow(
                    new FileBootstrapEnrollmentTransactionStore(t),
                    new FileBootstrapPairingCoordinator(p, new FileBootstrapAttestationStore(a), assets,
                        new BootstrapPairingPolicy(TimeSpan.FromMinutes(10), 3, 16, TimeSpan.FromMinutes(5))),
                    new FileBootstrapIntakeLedger(i,
                        new BootstrapIntakeQuota(16, 40 * 1024 * 1024, 64, 160 * 1024 * 1024)),
                    new BootstrapTechnicianAuthenticator(new BootstrapTechnicianAuthenticationPolicy(
                        ["webauthn"], "subject", 64, "authorization", "bootstrap-approve", TimeSpan.FromMinutes(5))),
                    IncomingCsrPolicy.NoClientExtensions, TimeSpan.FromMinutes(10),
                    observed => { if (observed == stage) cancellation.Cancel(); }), i, a, p, t);
            }

            var workflow = Workflow();
            Check(workflow.Begin(new byte[] { 1, 2, 3 }, now).Result == BootstrapWorkflowResult.InvalidRequest,
                "invalid CSR creates no workflow grant");
            var cancellationStages = new[] { "before-reservation", "after-reservation", "after-transaction", "after-pairing" };
            for (var ordinal = 0; ordinal < cancellationStages.Length; ordinal++)
            {
                using var cancellation = new CancellationTokenSource();
                var interrupted = Interruptible(cancellationStages[ordinal], ordinal, cancellation);
                try
                {
                    _ = interrupted.Workflow.Begin(csr, now, cancellation.Token);
                    throw new InvalidOperationException("Cancelled intake completed.");
                }
                catch (OperationCanceledException) { }
                Check(new FileBootstrapIntakeLedger(interrupted.Intake,
                        new BootstrapIntakeQuota(16, 40 * 1024 * 1024, 64, 160 * 1024 * 1024))
                    .Inspect(now).HistoryRecords == 0 &&
                    Directory.EnumerateFiles(interrupted.Attestations).Any() == false &&
                    Directory.EnumerateFiles(interrupted.Pairings).Any() == false &&
                    Directory.EnumerateFiles(interrupted.Transactions).Any() == false,
                    "cancellation at " + cancellationStages[ordinal] + " leaves no cross-store residue");
            }
            var intake = workflow.Begin(csr, now);
            Check(intake is { Result: BootstrapWorkflowResult.PendingApproval, Ticket: not null } &&
                intake.Ticket.RequestId.Length == 32 && intake.Ticket.DisplayCode.Length == 6,
                "valid CSR produces one bounded pending ticket");
            var id = intake.Ticket!.RequestId;
            var transaction = new FileBootstrapEnrollmentTransactionStore(transactionsPath);
            Check(transaction.Lookup(id, binding, null, now).State == BootstrapTransactionState.RetainedUnbound,
                "pending pairing shares the retained transaction identifier");

            foreach (var capability in new[] { "facts-read", "facts-write" })
            {
                var wrongRoleExisting = Workflow().Approve(Ticket("technician:avery", now, capability), id,
                    intake.Ticket.DisplayCode, "asset-physical-001", now);
                var wrongRoleAbsent = Workflow().Approve(Ticket("technician:avery", now, capability),
                    new string('F', 32), "123456", "asset-physical-001", now);
                Check(wrongRoleExisting.Result == BootstrapWorkflowResult.AuthenticationRejected &&
                    wrongRoleAbsent.Result == BootstrapWorkflowResult.AuthenticationRejected,
                    capability + " cannot distinguish or approve existing and absent bootstrap transactions");
            }
            Check(new FileBootstrapPairingCoordinator(pairingsPath,
                    new FileBootstrapAttestationStore(attestationsPath), assets,
                    new BootstrapPairingPolicy(TimeSpan.FromMinutes(10), 3, 16, TimeSpan.FromMinutes(5)))
                .Lookup(id, now).AttemptsRemaining == 3,
                "cross-role denials occur before pairing state mutation");

            var stale = Workflow().Approve(Ticket("technician:avery", now.AddMinutes(-6)), id,
                intake.Ticket.DisplayCode, "asset-physical-001", now);
            Check(stale.Result == BootstrapWorkflowResult.AuthenticationRejected &&
                new FileBootstrapPairingCoordinator(pairingsPath, new FileBootstrapAttestationStore(attestationsPath),
                    assets, new BootstrapPairingPolicy(TimeSpan.FromMinutes(10), 3, 16, TimeSpan.FromMinutes(5)))
                    .Lookup(id, now).AttemptsRemaining == 3,
                "stale authentication is rejected before spending an attempt");

            var approved = Workflow().Approve(Ticket("technician:avery", now), id,
                intake.Ticket.DisplayCode, "asset-physical-001", now.AddMinutes(1));
            Check(approved is { Result: BootstrapWorkflowResult.Approved,
                    TransactionResult: BootstrapTransactionResult.AssetBound, Audit: not null } &&
                approved.Audit.RequestId == id && approved.Audit.AuthoritativeAssetId == "asset-physical-001",
                "authenticated technician binds the audited asset to the same transaction");
            Check(approved.Audit!.Capability == "bootstrap-approve",
                "durable pairing audit binds the approval capability");
            Check(transaction.Lookup(id, binding, "asset-physical-001", now.AddMinutes(1)).State ==
                BootstrapTransactionState.AssetBound,
                "approval stops before any submission claim or CA operation");
            Check(new FileBootstrapIntakeLedger(intakePath,
                    new BootstrapIntakeQuota(16, 20 * 1024 * 1024, 64, 80 * 1024 * 1024))
                .Inspect(now.AddMinutes(1)) is { ActiveRecords: 0, HistoryRecords: 1, Trusted: 1 },
                "durable approval releases anonymous capacity and retains bounded history");

            var replay = Workflow().Approve(Ticket("technician:avery", now), id,
                intake.Ticket.DisplayCode, "asset-physical-001", now.AddMinutes(2));
            Check(replay.Result == BootstrapWorkflowResult.Approved &&
                replay.TransactionResult == BootstrapTransactionResult.AlreadyBound,
                "exact authenticated retry reconciles a post-approval crash");
            var changedActor = Workflow().Approve(Ticket("technician:blake", now), id,
                intake.Ticket.DisplayCode, "asset-physical-001", now.AddMinutes(2));
            Check(changedActor.Result == BootstrapWorkflowResult.PairingRejected,
                "approved transaction cannot be reconciled by another actor");

            var conflictingId = new string('A', 32);
            transaction.Retain(csr, binding, now, TimeSpan.FromMinutes(10), conflictingId);
            Check(transaction.Retain(csr, binding, now, TimeSpan.FromMinutes(10), conflictingId).Result ==
                BootstrapTransactionResult.AlreadyRetained,
                "shared-ID exact replay is recognized without creating another transaction");
            try
            {
                new FileBootstrapPairingCoordinator(pairingsPath, new FileBootstrapAttestationStore(attestationsPath),
                    assets, new BootstrapPairingPolicy(TimeSpan.FromMinutes(10), 3, 16, TimeSpan.FromMinutes(5)))
                    .Begin(binding, now, "not-an-id");
                throw new InvalidOperationException("Malformed shared ID accepted.");
            }
            catch (ArgumentException) { checks++; }

            Console.WriteLine($"Bootstrap enrollment workflow checks passed ({checks}).");
        }
        finally { root.Delete(recursive: true); }
    }

    [SupportedOSPlatform("linux")]
    private static string PrivateDirectory(DirectoryInfo root, string name)
    {
        var directory = Directory.CreateDirectory(Path.Combine(root.FullName, name));
        File.SetUnixFileMode(directory.FullName,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return directory.FullName;
    }

    private static AuthenticateResult Ticket(string subject, DateTimeOffset issuedAt,
        string capability = "bootstrap-approve")
    {
        var identity = new ClaimsIdentity(
            [new Claim("subject", subject), new Claim("authorization", capability)], "webauthn");
        var properties = new AuthenticationProperties { IssuedUtc = issuedAt };
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), properties, "webauthn"));
    }
}
