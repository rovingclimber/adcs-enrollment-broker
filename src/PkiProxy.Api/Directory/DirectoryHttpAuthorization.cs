using System.DirectoryServices.Protocols;
using PkiProxy.Authentication;
using PkiProxy.Domain;

namespace PkiProxy.Directory;

internal sealed record AuthorizedComputerFeature(AuthenticatedDirectoryComputer Computer);

internal sealed partial class DirectoryHttpAuthorization : IDisposable
{
    private readonly ActiveDirectoryComputerResolver resolver;
    private readonly SemaphoreSlim slots = new(8, 8);
    internal DirectoryHttpAuthorization(ActiveDirectoryComputerResolver resolver) => this.resolver = resolver;

    internal static DirectoryHttpAuthorization? Load(IConfiguration configuration, bool kerberosEnabled)
    {
        var section = configuration.GetSection("Broker:Directory");
        if (!section.GetChildren().Any()) return null;
        string[] allowed = ["Enabled", "Server", "BaseDn", "RequiredGroupSid"];
        if (section.GetChildren().Any(child => !allowed.Contains(child.Key, StringComparer.OrdinalIgnoreCase)) ||
            !bool.TryParse(section["Enabled"], out var enabled))
            throw new InvalidOperationException("Explicit valid Broker:Directory configuration required.");
        if (!enabled) return null;
        if (!kerberosEnabled) throw new InvalidOperationException("Directory authorization requires verified Kerberos transport.");
        string Required(string key) => !string.IsNullOrWhiteSpace(section[key]) ? section[key]! :
            throw new InvalidOperationException("Incomplete Broker:Directory configuration.");
        LinuxLdapPolicy.Validate();
        return new(new(new LdapComputerDirectory(Required("Server"), Required("BaseDn")), Required("RequiredGroupSid")));
    }

    internal async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        if (!KerberosHttpAuthentication.IsProtectedPath(context.Request.Path)) { await next(context); return; }
        var identity = context.Features.Get<AuthenticatedComputerFeature>()?.Identity;
        if (identity is null) { Deny(context, 403); return; }
        if (!await slots.WaitAsync(0, context.RequestAborted)) { Deny(context, 503); return; }
        AuthenticatedDirectoryComputer? computer;
        try
        {
            // Fresh bounded LDAP reads, no cached group grant or client-supplied DN/DNS.
            computer = await Task.Run(() => resolver.Resolve(identity, context.RequestAborted), context.RequestAborted);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { return; }
        catch (Exception error) when (error is LdapException or DirectoryOperationException or InvalidOperationException or
            IOException or UnauthorizedAccessException)
        { Log(context, identity.AccountName, "directory-unavailable"); Deny(context, 503); return; }
        finally { slots.Release(); }
        if (computer is null) { Log(context, identity.AccountName, "no-grant"); Deny(context, 403); return; }
        Log(context, identity.AccountName, "allowed");
        context.Features.Set(new AuthorizedComputerFeature(computer));
        try { await next(context); }
        finally { context.Features.Set<AuthorizedComputerFeature>(null); }
    }

    private static void Deny(HttpContext context, int status)
    {
        context.Response.StatusCode = status; context.Response.ContentLength = 0;
        context.Response.Headers.CacheControl = "no-store"; context.Response.Headers.Connection = "close";
    }

    private static void Log(HttpContext context, string computer, string decision)
    {
        var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PkiProxy.Directory");
        if (logger.IsEnabled(LogLevel.Information)) LogDecision(logger, computer, decision, context.TraceIdentifier);
    }

    [LoggerMessage(EventId = 110, Level = LogLevel.Information,
        Message = "event=directory-authorization computer={Computer} decision={Decision} trace={Trace}")]
    private static partial void LogDecision(ILogger logger, string computer, string decision, string trace);
    public void Dispose() => slots.Dispose();
}
