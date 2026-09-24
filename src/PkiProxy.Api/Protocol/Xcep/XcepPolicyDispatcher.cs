using System.Xml.Linq;

namespace PkiProxy.Protocol.Xcep;

internal sealed record XcepDispatchResult(bool IsValid, XDocument? ResponseEnvelope, string? ErrorCode)
{
    public static XcepDispatchResult Invalid(string errorCode) => new(false, null, errorCode);

    public static XcepDispatchResult Success(XDocument responseEnvelope) => new(true, responseEnvelope, null);
}

internal static class XcepPolicyDispatcher
{
    public const string GetPoliciesAction =
        "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies";

    public static XcepDispatchResult Dispatch(
        XElement operation,
        string? soapAction,
        string? requestMessageId,
        BrokerEnrollmentPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(policy);
        if (!string.Equals(soapAction, GetPoliciesAction, StringComparison.Ordinal))
        {
            return XcepDispatchResult.Invalid("InvalidXcepSoapAction");
        }

        if (!GetPoliciesContract.TryParse(operation, out var request, out var errorCode))
        {
            return XcepDispatchResult.Invalid(errorCode ?? "InvalidGetPoliciesRequest");
        }

        var responseBody = request!.LastUpdate is { } lastUpdate && lastUpdate >= policy.UpdatedAt
            ? GetPoliciesResponseWriter.CreatePoliciesNotChanged(policy.PolicyServerId, policy.NextUpdateHours)
            : BrokerEnrollmentPolicyResponseWriter.Create(policy, request.PolicyOids);
        return XcepDispatchResult.Success(SoapEnvelopeWriter.CreateResponse(
            responseBody,
            SoapEnvelopeWriter.XcepGetPoliciesResponseAction,
            requestMessageId));
    }
}
