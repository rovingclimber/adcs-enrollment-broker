using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using PkiProxy.Domain;

namespace PkiProxy.Authentication;

internal enum BootstrapTechnicianAuthenticationResult
{
    Authorized,
    AuthenticationNotSucceeded,
    AmbiguousAuthenticatedIdentity,
    SchemeMismatch,
    UnapprovedScheme,
    MissingSubject,
    AmbiguousSubject,
    InvalidSubject,
    MissingAuthorization,
    AmbiguousAuthorization,
    MissingIssuedUtc,
    FutureIssuedUtc,
    StaleIssuedUtc
}

internal sealed record BootstrapTechnicianAuthorization(
    BootstrapTechnicianAuthenticationResult Result,
    AuthenticatedTechnician? Technician = null);

internal sealed class BootstrapTechnicianAuthenticationPolicy
{
    internal BootstrapTechnicianAuthenticationPolicy(
        IEnumerable<string> approvedAuthenticationSchemes,
        string subjectClaimType,
        int maximumSubjectLength,
        string requiredAuthorizationClaimType,
        string requiredAuthorizationClaimValue,
        TimeSpan maximumAuthenticationAge)
    {
        ArgumentNullException.ThrowIfNull(approvedAuthenticationSchemes);
        ApprovedAuthenticationSchemes = approvedAuthenticationSchemes.ToImmutableArray();
        if (ApprovedAuthenticationSchemes.IsDefaultOrEmpty || ApprovedAuthenticationSchemes.Length > 8 ||
            ApprovedAuthenticationSchemes.Any(scheme => !IsBoundedPrintable(scheme, 64)) ||
            ApprovedAuthenticationSchemes.Distinct(StringComparer.Ordinal).Count() != ApprovedAuthenticationSchemes.Length)
            throw new ArgumentOutOfRangeException(nameof(approvedAuthenticationSchemes));
        if (!IsBoundedPrintable(subjectClaimType, 256))
            throw new ArgumentOutOfRangeException(nameof(subjectClaimType));
        if (maximumSubjectLength is < 1 or > 256)
            throw new ArgumentOutOfRangeException(nameof(maximumSubjectLength));
        if (!IsBoundedPrintable(requiredAuthorizationClaimType, 256))
            throw new ArgumentOutOfRangeException(nameof(requiredAuthorizationClaimType));
        if (!IsBoundedPrintable(requiredAuthorizationClaimValue, 256))
            throw new ArgumentOutOfRangeException(nameof(requiredAuthorizationClaimValue));
        if (maximumAuthenticationAge <= TimeSpan.Zero || maximumAuthenticationAge > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(maximumAuthenticationAge));

        SubjectClaimType = subjectClaimType;
        MaximumSubjectLength = maximumSubjectLength;
        RequiredAuthorizationClaimType = requiredAuthorizationClaimType;
        RequiredAuthorizationClaimValue = requiredAuthorizationClaimValue;
        MaximumAuthenticationAge = maximumAuthenticationAge;
    }

    internal ImmutableArray<string> ApprovedAuthenticationSchemes { get; }
    internal string SubjectClaimType { get; }
    internal int MaximumSubjectLength { get; }
    internal string RequiredAuthorizationClaimType { get; }
    internal string RequiredAuthorizationClaimValue { get; }
    internal TimeSpan MaximumAuthenticationAge { get; }

    private static bool IsBoundedPrintable(string? value, int maximumLength) =>
        value is { Length: > 0 } && value.Length <= maximumLength &&
        value.All(character => character is >= '!' and <= '~');
}

internal sealed class BootstrapTechnicianAuthenticator
{
    private readonly BootstrapTechnicianAuthenticationPolicy _policy;

    internal BootstrapTechnicianAuthenticator(BootstrapTechnicianAuthenticationPolicy policy)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
    }

    internal BootstrapTechnicianAuthorization Authorize(AuthenticateResult authentication, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(authentication);
        if (!authentication.Succeeded)
            return Denied(BootstrapTechnicianAuthenticationResult.AuthenticationNotSucceeded);
        var ticket = authentication.Ticket!;

        var identities = ticket.Principal.Identities.Where(identity => identity.IsAuthenticated).ToArray();
        if (identities.Length != 1)
            return Denied(BootstrapTechnicianAuthenticationResult.AmbiguousAuthenticatedIdentity);
        var identity = identities[0];
        if (!string.Equals(ticket.AuthenticationScheme, identity.AuthenticationType, StringComparison.Ordinal))
            return Denied(BootstrapTechnicianAuthenticationResult.SchemeMismatch);
        if (!_policy.ApprovedAuthenticationSchemes.Contains(ticket.AuthenticationScheme, StringComparer.Ordinal))
            return Denied(BootstrapTechnicianAuthenticationResult.UnapprovedScheme);

        var subjects = identity.Claims.Where(claim =>
            string.Equals(claim.Type, _policy.SubjectClaimType, StringComparison.Ordinal)).ToArray();
        if (subjects.Length == 0)
            return Denied(BootstrapTechnicianAuthenticationResult.MissingSubject);
        if (subjects.Length != 1)
            return Denied(BootstrapTechnicianAuthenticationResult.AmbiguousSubject);
        if (!IsBoundedPrintable(subjects[0].Value, _policy.MaximumSubjectLength))
            return Denied(BootstrapTechnicianAuthenticationResult.InvalidSubject);
        var authorizations = identity.Claims.Where(claim =>
            string.Equals(claim.Type, _policy.RequiredAuthorizationClaimType, StringComparison.Ordinal)).ToArray();
        if (authorizations.Length == 0)
            return Denied(BootstrapTechnicianAuthenticationResult.MissingAuthorization);
        if (authorizations.Length != 1)
            return Denied(BootstrapTechnicianAuthenticationResult.AmbiguousAuthorization);
        if (!string.Equals(authorizations[0].Value,
                _policy.RequiredAuthorizationClaimValue, StringComparison.Ordinal))
            return Denied(BootstrapTechnicianAuthenticationResult.MissingAuthorization);

        if (ticket.Properties.IssuedUtc is not { } issuedUtc)
            return Denied(BootstrapTechnicianAuthenticationResult.MissingIssuedUtc);
        if (issuedUtc > now)
            return Denied(BootstrapTechnicianAuthenticationResult.FutureIssuedUtc);
        if (now - issuedUtc > _policy.MaximumAuthenticationAge)
            return Denied(BootstrapTechnicianAuthenticationResult.StaleIssuedUtc);

        return new(BootstrapTechnicianAuthenticationResult.Authorized,
            new AuthenticatedTechnician(subjects[0].Value, ticket.AuthenticationScheme, issuedUtc,
                _policy.RequiredAuthorizationClaimValue));
    }

    private static BootstrapTechnicianAuthorization Denied(BootstrapTechnicianAuthenticationResult result) => new(result);

    private static bool IsBoundedPrintable(string? value, int maximumLength) =>
        value is { Length: > 0 } && value.Length <= maximumLength &&
        value.All(character => character is >= '!' and <= '~');
}
