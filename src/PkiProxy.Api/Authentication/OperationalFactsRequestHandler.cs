using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using PkiProxy.Domain;

namespace PkiProxy.Authentication;

internal static class OperationalFactsRequestHandler
{
    private const int MaximumBodyBytes = 4096;
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 2
    };

    internal static async Task<IResult> ListAsync(HttpContext context,
        OperationalFactsManagement management)
    {
        var authorization = await AuthorizeAsync(context, management, TechnicianCapability.FactsRead);
        if (authorization.Failure is { } failure) return failure;
        try
        {
            var snapshot = management.ReadAll();
            context.Response.Headers.ETag = RevisionTag(snapshot.Revision);
            return Results.Json(new { snapshot.Revision, snapshot.Sha256, Assets = snapshot.Assets });
        }
        catch (Exception error) when (SafeFailure(error))
        { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
    }

    internal static async Task<IResult> ReadAsync(HttpContext context, string assetId,
        OperationalFactsManagement management)
    {
        var authorization = await AuthorizeAsync(context, management, TechnicianCapability.FactsRead);
        if (authorization.Failure is { } failure) return failure;
        if (TechnicianRoutePolicy.Classify(context.Request.Path, context.Request.Method,
                out var routedAsset) != TechnicianRouteKind.FactsItemRead || routedAsset != assetId)
            return Results.NotFound();
        try
        {
            var snapshot = management.ReadAll();
            var asset = snapshot.Assets.SingleOrDefault(value => value.AssetId == assetId);
            if (asset is null) return Results.NotFound();
            context.Response.Headers.ETag = RevisionTag(snapshot.Revision);
            return Results.Json(new { snapshot.Revision, snapshot.Sha256, Asset = asset });
        }
        catch (Exception error) when (SafeFailure(error))
        { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
    }

    internal static async Task<IResult> PutAsync(HttpContext context, string assetId,
        OperationalFactsManagement management, CancellationToken cancellationToken)
    {
        // Authentication, fresh directory authorization and canonical route
        // checks all finish before request bytes are read.
        var authorization = await AuthorizeAsync(context, management, TechnicianCapability.FactsWrite);
        if (authorization.Failure is { } failure) return failure;
        if (TechnicianRoutePolicy.Classify(context.Request.Path, context.Request.Method,
                out var routedAsset) != TechnicianRouteKind.FactsItemWrite || routedAsset != assetId)
            return Results.NotFound();
        if (!TryRevision(context.Request.Headers.IfMatch.ToString(), out var expectedRevision))
            return Results.StatusCode(StatusCodes.Status428PreconditionRequired);
        var update = await ReadUpdateAsync(context.Request, cancellationToken);
        if (update is null) return Results.BadRequest(new { error = "A bounded exact facts update is required." });
        try
        {
            var outcome = await management.PutAsync(assetId, expectedRevision, update,
                authorization.Technician!.Subject, cancellationToken);
            return outcome.Result switch
            {
                OperationalFactsWriteResult.Updated or OperationalFactsWriteResult.Unchanged =>
                    WriteResult(context, outcome.Write!),
                OperationalFactsWriteResult.UnknownAsset => Results.NotFound(),
                OperationalFactsWriteResult.InvalidSelection => Results.BadRequest(new { error = "Every fact must be selected from its configured catalogue." }),
                OperationalFactsWriteResult.PreconditionFailed => Results.StatusCode(StatusCodes.Status412PreconditionFailed),
                OperationalFactsWriteResult.Busy => Results.StatusCode(StatusCodes.Status409Conflict),
                _ => Results.StatusCode(StatusCodes.Status503ServiceUnavailable)
            };
        }
        catch (Exception error) when (SafeFailure(error))
        { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
    }

    private static IResult WriteResult(HttpContext context, OperationalFactsWrite write)
    {
        context.Response.Headers.ETag = RevisionTag(write.Revision);
        return Results.Json(new { write.Revision, write.Sha256, write.Asset, write.Changed,
            write.Transaction });
    }

    private static async Task<Authorization> AuthorizeAsync(HttpContext context,
        OperationalFactsManagement management, TechnicianCapability capability)
    {
        var authentication = await context.AuthenticateAsync(BootstrapKerberosAuthenticationService.Scheme);
        if (!authentication.Succeeded)
            return new(null, Results.StatusCode(
                context.Features.Get<BootstrapKerberosFailureFeature>()?.Status ??
                StatusCodes.Status401Unauthorized));
        var authorization = management.Authorize(authentication, capability, DateTimeOffset.UtcNow);
        return authorization.Result == BootstrapTechnicianAuthenticationResult.Authorized &&
            authorization.Technician is not null
            ? new(authorization.Technician, null)
            : new(null, Results.StatusCode(StatusCodes.Status403Forbidden));
    }

    private static async Task<OperationalFactsUpdate?> ReadUpdateAsync(HttpRequest request,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength is not { } length || length is < 1 or > MaximumBodyBytes ||
            request.Headers.ContentEncoding.Count != 0 ||
            !string.Equals(request.ContentType, "application/json", StringComparison.OrdinalIgnoreCase))
            return null;
        try
        {
            var bytes = new byte[(int)length];
            await request.Body.ReadExactlyAsync(bytes, cancellationToken);
            if (await request.Body.ReadAsync(new byte[1], cancellationToken) != 0) return null;
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 2 });
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                document.RootElement.EnumerateObject().Select(property => property.Name)
                    .Distinct(StringComparer.Ordinal).Count() != 4 ||
                document.RootElement.EnumerateObject().Count() != 4)
                return null;
            return JsonSerializer.Deserialize<OperationalFactsUpdate>(bytes, StrictJson);
        }
        catch (Exception error) when (error is JsonException or IOException or EndOfStreamException)
        { return null; }
    }

    internal static string RevisionTag(long revision) => $"\"facts-{revision}\"";
    internal static bool TryRevision(string value, out long revision)
    {
        revision = 0;
        const string prefix = "\"facts-";
        return value.StartsWith(prefix, StringComparison.Ordinal) && value.EndsWith('"') &&
            long.TryParse(value.AsSpan(prefix.Length, value.Length - prefix.Length - 1),
                System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture,
                out revision) && revision > 0;
    }
    private static bool SafeFailure(Exception error) => error is InvalidDataException or IOException or
        UnauthorizedAccessException or OverflowException or ArgumentException or JsonException;
    private sealed record Authorization(AuthenticatedTechnician? Technician, IResult? Failure);
}
