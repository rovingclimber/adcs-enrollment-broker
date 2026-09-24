using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using PkiProxy.Directory;

namespace PkiProxy.Authentication;

internal sealed class KerberosHttpTransport : IDisposable
{
    private readonly SemaphoreSlim slots;
    private readonly string servicePrincipal, realm, netBios;
    private readonly TimeSpan timeout;
    internal string Host { get; }
    internal string Realm => realm;
    internal string NetBiosDomain => netBios;
    internal int ActiveExchanges => maximumExchanges - slots.CurrentCount;
    private readonly int maximumExchanges;
    private readonly HashSet<IPAddress> allowedClients;
    private readonly int? authorityPort;

    public KerberosHttpTransport(string servicePrincipal, string realm, string netBios,
        int maximumExchanges = 64, TimeSpan? exchangeTimeout = null, IReadOnlyCollection<IPAddress>? allowedClients = null,
        int? authorityPort = null)
    {
        LinuxKerberosAcceptor.ValidateServicePrincipal(servicePrincipal);
        if (!servicePrincipal.EndsWith("@" + realm, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(netBios) || netBios.Length > 15 ||
            netBios.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
            throw new ArgumentException("Explicit matching Kerberos realm and NetBIOS domain required.");
        timeout = exchangeTimeout ?? TimeSpan.FromSeconds(30);
        if (maximumExchanges is < 1 or > 256 || timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(maximumExchanges));
        this.servicePrincipal = servicePrincipal; this.realm = realm; this.netBios = netBios;
        this.maximumExchanges = maximumExchanges;
        if (authorityPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(authorityPort));
        this.authorityPort = authorityPort;
        this.allowedClients = new(allowedClients ?? [IPAddress.Loopback, IPAddress.IPv6Loopback]);
        if (this.allowedClients.Count is < 1 or > 8 || this.allowedClients.Contains(IPAddress.Any) || this.allowedClients.Contains(IPAddress.IPv6Any))
            throw new ArgumentException("One to eight exact client addresses required.", nameof(allowedClients));
        Host = servicePrincipal[5..servicePrincipal.IndexOf('@')];
        slots = new(maximumExchanges, maximumExchanges);
    }

    // Must be installed after UseHttps and before Kestrel's HTTP middleware.
    // Feature ownership is the accepted TCP connection, not a header/id dictionary.
    internal void ConfigureListener(ListenOptions listener, X509Certificate2 certificate)
    {
        listener.Protocols = HttpProtocols.Http1;
        listener.Use(next => connection => {
            var address = (connection.RemoteEndPoint as IPEndPoint)?.Address;
            if (address?.IsIPv4MappedToIPv6 == true) address = address.MapToIPv4();
            if (address is null || !allowedClients.Contains(address))
            { connection.Abort(); return Task.CompletedTask; }
            return next(connection);
        });
        listener.UseHttps(certificate, https => {
            https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
            https.HandshakeTimeout = TimeSpan.FromSeconds(10);
        });
        listener.Use(next => async connection => {
            var stream = connection.Features.Get<ISslStreamFeature>()?.SslStream;
            if (stream is null || !stream.TargetHostName.Equals(Host, StringComparison.OrdinalIgnoreCase))
            { connection.Abort(); return; }
            using var state = new Exchange(this, connection, stream);
            connection.Features.Set(state);
            await next(connection);
        });
    }

    public void Dispose() => slots.Dispose();

    internal sealed class Exchange : IDisposable
    {
        private readonly object gate = new();
        private readonly KerberosHttpTransport owner;
        private readonly ConnectionContext connection;
        internal SslStream Stream { get; }
        internal string Host => owner.Host;
        internal int? AuthorityPort => owner.authorityPort;
        internal string ConnectionId => connection.ConnectionId;
        private LinuxKerberosAcceptor? acceptor;
        private Timer? timer;
        private bool terminal, held;
        private long started;

        internal Exchange(KerberosHttpTransport owner, ConnectionContext connection, SslStream stream)
        { this.owner = owner; this.connection = connection; Stream = stream; }

        internal HttpPeerAuthResult StepPeer(byte[]? token)
        {
            lock (gate)
            {
                if (terminal) return new(401);
                if (token is null)
                {
                    if (held) { Dispose(); return new(401); }
                    return new(401, "Negotiate", Continue: true);
                }
                if (!held)
                {
                    if (!owner.slots.Wait(0)) { Dispose(); return new(503); }
                    held = true;
                    started = System.Diagnostics.Stopwatch.GetTimestamp();
                    timer = new Timer(_ => Expire(), null, owner.timeout, Timeout.InfiniteTimeSpan);
                }
                try
                {
                    if (System.Diagnostics.Stopwatch.GetElapsedTime(started) >= owner.timeout)
                        throw new AuthenticationException("Authentication exchange expired.");
                    acceptor ??= new(owner.servicePrincipal, TlsEndpointBinding.FromServerStream(Stream));
                    var result = acceptor.Step(token);
                    if (System.Diagnostics.Stopwatch.GetElapsedTime(started) >= owner.timeout)
                        throw new AuthenticationException("Authentication exchange expired.");
                    var challenge = result.OutgoingToken.Length == 0 ? "Negotiate" :
                        "Negotiate " + Convert.ToBase64String(result.OutgoingToken);
                    if (!result.Completed) return new(401, challenge, Continue: true);
                    var peerName = acceptor.GetAuthenticatedPeerName();
                    Dispose(); // Snapshot valid only for this request; no connection auth cache.
                    return peerName is null ? new(403) : new(200, challenge, PeerName: peerName);
                }
                catch (AuthenticationException) { Dispose(); return new(401); }
                catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or
                    PlatformNotSupportedException or ArgumentException or InvalidOperationException)
                { Dispose(); return new(503); } // Provider/configuration failure, never anonymous fallthrough.
            }
        }

        internal HttpAuthResult Step(byte[]? token)
        {
            return ProjectComputerResult(StepPeer(token), owner.realm, owner.netBios);
        }

        private void Expire()
        {
            lock (gate)
            {
                if (terminal) return;
                Dispose();
            }
            connection.Abort(new ConnectionAbortedException("Kerberos exchange deadline exceeded."));
        }

        public void Dispose()
        {
            lock (gate)
            {
                if (terminal) return;
                terminal = true;
                timer?.Dispose(); timer = null;
                acceptor?.Dispose(); acceptor = null;
                if (held) { held = false; owner.slots.Release(); }
            }
        }
    }

    internal static HttpAuthResult ProjectComputerResult(HttpPeerAuthResult result,
        string realm, string netBios)
    {
        ArgumentNullException.ThrowIfNull(result);
        var identity = result.PeerName is null ? null :
            KerberosComputerIdentity.FromAuthenticatedPeerName(result.PeerName, realm, netBios);
        return new(result.PeerName is not null && identity is null ? 403 : result.Status,
            result.Challenge, result.Continue, identity);
    }
}

internal sealed record HttpAuthResult(int Status, string? Challenge = null, bool Continue = false,
    KerberosComputerIdentity? Identity = null);

internal sealed record HttpPeerAuthResult(int Status, string? Challenge = null, bool Continue = false,
    string? PeerName = null);

// Request-local proof only; the directory/group resolver still authorizes enrollment.
internal sealed record AuthenticatedComputerFeature(KerberosComputerIdentity Identity);

internal static partial class KerberosHttpAuthentication
{
    [LoggerMessage(EventId = 100, Level = LogLevel.Information, Message = "event=kerberos-auth computer={Computer} trace={Trace}")]
    private static partial void LogAuthenticated(ILogger logger, string computer, string trace);
    internal static bool IsProtectedPath(PathString path) =>
        path.Equals("/cep/kerberos/service.svc/CEP", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/ces/kerberos/service.svc/CES", StringComparison.OrdinalIgnoreCase);

    internal static async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        if (!IsProtectedPath(context.Request.Path)) { await next(context); return; }
        var exchange = context.Features.Get<KerberosHttpTransport.Exchange>();
        // Reject forwarded/proxy assertions instead of interpreting them. Direct
        // TLS only; HTTP/2 and3 are unsupported and cannot share identity state.
        if (exchange is null || !IsDirectBoundRequest(context, exchange))
        { exchange?.Dispose(); Respond(context, new(400)); return; }
        if (context.Request.Method != "POST")
        { exchange.Dispose(); Respond(context, new(405)); return; }
        if (!TryToken(context.Request.Headers.Authorization, out var token))
        { exchange.Dispose(); Respond(context, new(401)); return; }
        HttpAuthResult result;
        try { result = exchange.Step(token); }
        finally { if (token is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(token); }
        Respond(context, result);
        if (result.Identity is null) return;
        var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PkiProxy.Authentication");
        if (logger.IsEnabled(LogLevel.Information)) LogAuthenticated(logger, result.Identity.AccountName, context.TraceIdentifier);
        context.Features.Set(new AuthenticatedComputerFeature(result.Identity));
        try { await next(context); }
        finally { context.Features.Set<AuthenticatedComputerFeature>(null); }
    }

    internal static bool IsDirectBoundRequest(HttpContext context, KerberosHttpTransport.Exchange exchange) =>
        context.Request.IsHttps && context.Request.Protocol == "HTTP/1.1" &&
        context.Connection.Id == exchange.ConnectionId &&
        context.Features.Get<ISslStreamFeature>()?.SslStream == exchange.Stream &&
        context.Request.Host.Host.Equals(exchange.Host, StringComparison.OrdinalIgnoreCase) &&
        context.Request.Host.Port.GetValueOrDefault(443) == (exchange.AuthorityPort ?? context.Connection.LocalPort) &&
        !context.Request.Headers.Keys.Any(k => k.Equals("Forwarded", StringComparison.OrdinalIgnoreCase) ||
            k.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase));

    private static void Respond(HttpContext context, HttpAuthResult result)
    {
        context.Response.StatusCode = result.Status;
        context.Response.Headers.CacheControl = "no-store";
        if (result.Challenge is not null) context.Response.Headers.WWWAuthenticate = result.Challenge;
        if (!result.Continue) context.Response.Headers.Connection = "close";
        if (result.Identity is null) context.Response.ContentLength = 0;
    }

    internal static bool TryToken(Microsoft.Extensions.Primitives.StringValues values, out byte[]? token)
    {
        token = null;
        if (values.Count == 0) return true;
        if (values.Count != 1 || values[0] is not { } text || text.Length > 87398 ||
            !text.StartsWith("Negotiate ", StringComparison.OrdinalIgnoreCase)) return false;
        var encoded = text[10..];
        if (encoded.Length == 0 || encoded.Any(char.IsWhiteSpace)) return false;
        try
        {
            var decoded = Convert.FromBase64String(encoded);
            if (decoded.Length is < 1 or > 65536 || Convert.ToBase64String(decoded) != encoded)
            { System.Security.Cryptography.CryptographicOperations.ZeroMemory(decoded); return false; }
            token = decoded; return true;
        }
        catch (FormatException) { return false; }
    }
}
