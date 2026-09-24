using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;

namespace PkiProxy.Authentication;

internal sealed record BootstrapApprovalRequest(string TransactionId, string DisplayCode,
    string AuthoritativeAssetId);

internal sealed record BootstrapApprovalIntake(AuthenticateResult Authentication,
    BootstrapApprovalRequest? Payload, int? FailureStatus);

internal static class BootstrapApprovalRequestReader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 2
    };

    internal static async Task<BootstrapApprovalIntake> ReadAsync(HttpContext context,
        string scheme, CancellationToken cancellationToken)
    {
        var authentication = await context.AuthenticateAsync(scheme);
        if (!authentication.Succeeded)
            return new(authentication, null,
                context.Features.Get<BootstrapKerberosFailureFeature>()?.Status ??
                StatusCodes.Status401Unauthorized);

        const int maximumBytes = 4096;
        var request = context.Request;
        if (request.ContentLength is not { } contentLength ||
            contentLength is < 1 or > maximumBytes ||
            request.Headers.ContentEncoding.Count != 0 ||
            !string.Equals(request.ContentType, "application/json",
                StringComparison.OrdinalIgnoreCase))
            return new(authentication, null, StatusCodes.Status400BadRequest);
        try
        {
            var bytes = new byte[(int)contentLength];
            await request.Body.ReadExactlyAsync(bytes, cancellationToken);
            if (await request.Body.ReadAsync(new byte[1], cancellationToken) != 0)
                return new(authentication, null, StatusCodes.Status400BadRequest);
            var payload = JsonSerializer.Deserialize<BootstrapApprovalRequest>(bytes,
                JsonOptions);
            return new(authentication, payload,
                payload is null ? StatusCodes.Status400BadRequest : null);
        }
        catch (Exception error) when (error is JsonException or EndOfStreamException or IOException)
        {
            return new(authentication, null, StatusCodes.Status400BadRequest);
        }
    }
}
