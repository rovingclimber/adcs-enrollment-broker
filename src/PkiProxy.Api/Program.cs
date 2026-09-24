using PkiProxy.Protocol;
using PkiProxy;
using PkiProxy.Domain;
using PkiProxy.Authentication;
using PkiProxy.Directory;
using PkiProxy.Protocol.Xcep;
using PkiProxy.Signing;
using Microsoft.AspNetCore.Authentication;
using System.Security.Cryptography;

if (args.Length > 0 && args[0] == "--signer-sidecar")
{
    Environment.ExitCode = await IsolatedSignerHost.RunAsync(args);
    return;
}

// Explicit offline mode exits before loading credentials or starting any listener.
if (args.Length > 0 && args[0] == "--facts-workbench")
{
    Environment.ExitCode = await PkiProxy.FactsWorkbench.FactsWorkbenchHost.RunAsync(args);
    return;
}
if (args.Length > 0 && args[0].StartsWith("--facts-", StringComparison.Ordinal))
{
    Environment.ExitCode = DeviceFactsCommand.Run(args);
    return;
}

var builder = WebApplication.CreateSlimBuilder(args);
BrokerConfigurationBoundary.Validate(builder.Configuration);
var inboundLimits = InboundRequestLimits.Load(builder.Configuration);
builder.Services.AddSingleton(inboundLimits);
builder.WebHost.ConfigureKestrel(server => server.Limits.MaxRequestBodySize = inboundLimits.MaximumBodyBytes);
using var kerberosListener = KerberosListenerConfiguration.Load(builder.Configuration);
kerberosListener?.Configure(builder);
using var directoryAuthorization = DirectoryHttpAuthorization.Load(builder.Configuration, kerberosListener is not null);

BrokerEnrollmentPolicy? enrollmentPolicy = null;
if (builder.Configuration["Broker:XcepPolicyFile"] is { Length: > 0 } policyPath)
{
    if (directoryAuthorization is null || kerberosListener is null)
        throw new InvalidOperationException("Policy serving requires authenticated directory authorization.");
    var caPath = builder.Configuration["Broker:IssuingCaFile"] ?? throw new InvalidOperationException("Issuing CA trust file required.");
    enrollmentPolicy = BrokerPolicyConfiguration.Load(policyPath, caPath, kerberosListener.Transport.Host);
    builder.Services.AddSingleton(enrollmentPolicy);
}
IDomainDeviceFactsSource? deviceFacts = null;
if (builder.Configuration["Broker:DeviceFactsFile"] is { Length: > 0 } factsPath)
{
    deviceFacts = new JsonFileDeviceFactsSource(factsPath);
    builder.Services.AddSingleton(deviceFacts);
}
using var nativeEnrollment = NativeEnrollmentService.Load(builder.Configuration, enrollmentPolicy, deviceFacts,
    directoryAuthorization is not null && kerberosListener is not null);
if (nativeEnrollment is not null) builder.Services.AddSingleton(nativeEnrollment);
BootstrapDeployment? bootstrap = null;
var bootstrapConfigurationFile = builder.Configuration["Broker:BootstrapConfigurationFile"];
if (builder.Configuration.GetSection("Broker:Bootstrap").GetChildren().Any())
    throw new InvalidOperationException("Bootstrap configuration must use one protected configuration file.");
if (!string.IsNullOrWhiteSpace(bootstrapConfigurationFile))
{
    if (enrollmentPolicy is null)
        throw new InvalidOperationException("Bootstrap requires the distinct validated Kerberos policy composition.");
    if (nativeEnrollment is null)
        throw new InvalidOperationException("Bootstrap issuance requires the guarded signer and CES issuance composition.");
    bootstrap = await BootstrapDeployment.LoadAsync(bootstrapConfigurationFile, enrollmentPolicy,
        nativeEnrollment, kerberosListener!);
    builder.Services.AddSingleton(bootstrap);
    builder.Services.AddSingleton(bootstrap.Authentication);
    builder.Services.AddAuthentication()
        .AddScheme<AuthenticationSchemeOptions, BootstrapKerberosAuthenticationHandler>(
            BootstrapKerberosAuthenticationService.Scheme, _ => { });
}
OperationalFactsManagement? factsManagement = null;
var factsManagementConfigurationFile = builder.Configuration["Broker:FactsManagementConfigurationFile"];
if (builder.Configuration.GetSection("Broker:FactsManagement").GetChildren().Any())
    throw new InvalidOperationException("Facts management configuration must use one protected configuration file.");
if (!string.IsNullOrWhiteSpace(factsManagementConfigurationFile))
{
    if (bootstrap is null)
        throw new InvalidOperationException("Facts management requires the bootstrap technician Kerberos composition.");
    factsManagement = await OperationalFactsManagement.LoadAsync(factsManagementConfigurationFile,
        bootstrap.DeviceFactsFile, bootstrap.FactsReadAuthorization,
        bootstrap.FactsWriteAuthorization);
    builder.Services.AddSingleton(factsManagement);
}
using var certificateListener = CertificateListenerConfiguration.Load(builder.Configuration, enrollmentPolicy, nativeEnrollment is not null);
certificateListener?.Configure(builder);
if (certificateListener is not null) builder.Services.AddSingleton(certificateListener.Policy);
var readiness = new BrokerReadinessCheck(nativeEnrollment is null ? null : nativeEnrollment.CheckLocalReadinessAsync,
    TimeSpan.FromSeconds(60));
builder.Services.AddHealthChecks().AddCheck("local-issuance", readiness);
builder.Services.AddSingleton<IHostedService>(readiness);

var app = builder.Build();
if (bootstrap is not null)
{
    var registered = await app.Services.GetRequiredService<IAuthenticationSchemeProvider>()
        .GetSchemeAsync(BootstrapKerberosAuthenticationService.Scheme);
    if (registered is null)
        throw new InvalidOperationException("Configured bootstrap technician authentication scheme is not registered.");
    app.Use(async (context, next) =>
    {
        if (!IsBootstrapPath(context.Request.Path) &&
            TechnicianRoutePolicy.Classify(context.Request.Path, context.Request.Method, out _) ==
                TechnicianRouteKind.None)
        {
            await next(context);
            return;
        }
        var admitted = bootstrap.Admission.TryAcquire(context, DateTimeOffset.UtcNow, out var lease);
        if (admitted != BootstrapIngressAdmissionResult.Admitted)
        {
            context.Response.StatusCode = admitted is BootstrapIngressAdmissionResult.RateLimited or
                BootstrapIngressAdmissionResult.ConcurrencyLimited
                ? StatusCodes.Status429TooManyRequests : StatusCodes.Status403Forbidden;
            return;
        }
        context.Response.Headers["Cache-Control"] = "no-store";
        using (lease) await next(context);
    });
}
if (certificateListener is not null) app.Use(certificateListener.Transport.InvokeAsync);
if (kerberosListener is not null) app.Use(KerberosHttpAuthentication.InvokeAsync);
if (directoryAuthorization is not null) app.Use(directoryAuthorization.InvokeAsync);

app.MapGet("/healthz", () => Results.Ok(new { status = "healthy" }));

app.MapHealthChecks("/readyz");

app.MapPost("/cep/{authentication}/service.svc/CEP", HandleProtocolRequest);
app.MapPost("/ces/{authentication}/service.svc/CES", HandleProtocolRequest);
if (bootstrap is not null)
    app.MapPost("/bootstrap/technician/approve", HandleBootstrapApproval);
if (factsManagement is not null)
{
    app.MapGet("/facts/technician/assets", OperationalFactsRequestHandler.ListAsync);
    app.MapGet("/facts/technician/assets/{assetId}", OperationalFactsRequestHandler.ReadAsync);
    app.MapPut("/facts/technician/assets/{assetId}", OperationalFactsRequestHandler.PutAsync);
}

app.Run();

static async Task<IResult> HandleProtocolRequest(
    HttpContext context,
    string authentication,
    InboundRequestLimits inboundLimits,
    CancellationToken cancellationToken)
{
    if (!ProtocolEndpoint.TryParse(context.Request.Path, authentication, out var endpoint))
    {
        return Results.NotFound();
    }

    var envelope = await SoapEnvelopeReader.ReadAsync(context.Request, inboundLimits, cancellationToken);
    if (!envelope.IsValid)
    {
        return SoapFaults.Sender(
            context.TraceIdentifier,
            envelope.ErrorCode ?? "InvalidSoapEnvelope",
            "The request was not a valid supported SOAP envelope.");
    }

    var selectedPolicy = endpoint.Authentication switch {
        "kerberos" => context.RequestServices.GetService<BrokerEnrollmentPolicy>(),
        "certificate" => context.RequestServices.GetService<CertificateRenewalPolicy>()?.Policy,
        "bootstrap" => context.RequestServices.GetService<BootstrapDeployment>()?.Policy,
        _ => null
    };
    if (endpoint.Protocol == "MS-XCEP" && selectedPolicy is { } policy)
    {
        var kerberosAuthorized = context.Features.Get<AuthorizedComputerFeature>() is not null;
        var certificateAuthorized = context.Features.Get<AuthorizedCertificateComputerFeature>() is not null;
        var transportAuthorized = endpoint.Authentication switch
        {
            "kerberos" => kerberosAuthorized && !certificateAuthorized,
            "certificate" => certificateAuthorized && !kerberosAuthorized,
            "bootstrap" => !kerberosAuthorized && !certificateAuthorized,
            _ => false
        };
        if (!transportAuthorized)
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        var result = XcepPolicyDispatcher.Dispatch(envelope.Operation!, envelope.WsAddressingAction,
            envelope.WsAddressingMessageId, policy);
        return result.IsValid
            ? Results.Text(result.ResponseEnvelope!.ToString(System.Xml.Linq.SaveOptions.DisableFormatting), "application/soap+xml", System.Text.Encoding.UTF8)
            : SoapFaults.Sender(context.TraceIdentifier, result.ErrorCode!, "Unsupported enrollment policy request.");
    }

    if (endpoint.Protocol == "MS-WSTEP" && endpoint.Authentication is "kerberos" or "certificate" &&
        context.RequestServices.GetService<NativeEnrollmentService>() is { } enrollment)
        return await enrollment.HandleAsync(context, envelope, cancellationToken);

    if (endpoint.Protocol == "MS-WSTEP" && endpoint.Authentication == "bootstrap" &&
        context.RequestServices.GetService<BootstrapDeployment>() is { } bootstrap)
    {
        if (envelope.WsAddressingMessageId is not { Length: > 0 and <= 256 } messageId ||
            !Uri.TryCreate(messageId, UriKind.Absolute, out _) ||
            !PkiProxy.Protocol.Wstep.WstepRequestContract.TryParse(envelope.Operation!, envelope.WsAddressingAction,
                envelope.MaximumDecodedBinaryBytes,
                out var request, out _) ||
            request is null ||
            request.Context?.Length > PkiProxy.Protocol.Wstep.WstepRequestContract.MaximumContextLength ||
            request.Context?.Any(char.IsControl) == true)
            return SoapFaults.Sender(context.TraceIdentifier, "UnsupportedBootstrapRequest",
                "A correlated bootstrap Issue request is required.");
        try
        {
            System.Xml.Linq.XElement body;
            if (request.Kind == PkiProxy.Protocol.Wstep.WstepRequestKind.Issue)
            {
                var intake = bootstrap.Workflow.Begin(request.CertificateRequestDer!, DateTimeOffset.UtcNow,
                    cancellationToken);
                if (intake.Result != BootstrapWorkflowResult.PendingApproval || intake.Ticket is null)
                    return Results.StatusCode(StatusCodes.Status403Forbidden);
                context.Response.Headers["PkiProxy-Pairing-Code"] = intake.Ticket.DisplayCode;
                body = PkiProxy.Protocol.Wstep.WstepResponseWriter.CreatePending(intake.Ticket.RequestId, "en-GB");
            }
            else if (request.Kind == PkiProxy.Protocol.Wstep.WstepRequestKind.QueryTokenStatus &&
                request.RequestId is { } transactionId)
            {
                var outcome = await bootstrap.Issuance.QueryAsync(transactionId, DateTimeOffset.UtcNow, cancellationToken);
                if (outcome.Result is BootstrapIssuanceResult.Uncertain or BootstrapIssuanceResult.Rejected)
                    return SoapFaults.ProcessingFailure(context.TraceIdentifier);
                body = outcome.Result == BootstrapIssuanceResult.Issued && outcome.Response is { } issued
                    ? PkiProxy.Protocol.Wstep.WstepResponseWriter.CreateIssued(issued.CertificateDer,
                        issued.FullPkiResponseDer, issued.RequestId, "en-GB")
                    : PkiProxy.Protocol.Wstep.WstepResponseWriter.CreatePending(transactionId, "en-GB");
            }
            else
                return SoapFaults.Sender(context.TraceIdentifier, "UnsupportedBootstrapRequest",
                    "Only bootstrap Issue and QueryTokenStatus requests are supported.");

            context.Response.Headers["Cache-Control"] = "no-store";
            if (request.Context is not null) body.Elements().Single().SetAttributeValue("Context", request.Context);
            return Results.Text(SoapEnvelopeWriter.CreateResponse(body,
                    PkiProxy.Protocol.Wstep.WstepResponseWriter.ResponseAction, messageId)
                .ToString(System.Xml.Linq.SaveOptions.DisableFormatting), "application/soap+xml", System.Text.Encoding.UTF8);
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or
            CryptographicException or InvalidOperationException or ArgumentException)
        { return SoapFaults.ProcessingFailure(context.TraceIdentifier); }
    }

    // Remaining routes are intentionally a protocol-safe scaffold. They prove transport,
    // bounded XML parsing and SOAP fault behavior without claiming that the
    // MS-XCEP/MS-WSTEP message contracts or authentication are implemented.
    return SoapFaults.Receiver(
        context.TraceIdentifier,
        "ProtocolImplementationPending",
        $"{endpoint.Protocol} over {endpoint.Authentication} is not enabled yet.");
}

static bool IsBootstrapPath(PathString path) =>
    path.StartsWithSegments("/cep/bootstrap", StringComparison.OrdinalIgnoreCase) ||
    path.StartsWithSegments("/ces/bootstrap", StringComparison.OrdinalIgnoreCase) ||
    string.Equals(path.Value, "/bootstrap/technician/approve", StringComparison.OrdinalIgnoreCase);

static async Task<IResult> HandleBootstrapApproval(HttpContext context,
    BootstrapDeployment bootstrap, CancellationToken cancellationToken)
{
    context.Response.Headers["Cache-Control"] = "no-store";
    var intake = await BootstrapApprovalRequestReader.ReadAsync(context,
        BootstrapKerberosAuthenticationService.Scheme, cancellationToken);
    if (intake.FailureStatus is { } failureStatus)
        return Results.StatusCode(failureStatus);
    var payload = intake.Payload!;
    try
    {
        var result = bootstrap.Workflow.Approve(intake.Authentication, payload.TransactionId,
            payload.DisplayCode, payload.AuthoritativeAssetId, DateTimeOffset.UtcNow);
        return result.Result switch
        {
            BootstrapWorkflowResult.Approved => Results.Ok(new { status = "approved" }),
            BootstrapWorkflowResult.AuthenticationRejected => Results.Unauthorized(),
            BootstrapWorkflowResult.PairingRejected => Results.StatusCode(StatusCodes.Status403Forbidden),
            _ => Results.StatusCode(StatusCodes.Status409Conflict)
        };
    }
    catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or
        CryptographicException or InvalidOperationException or ArgumentException)
    { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
}

public partial class Program;
