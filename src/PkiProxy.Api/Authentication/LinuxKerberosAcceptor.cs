using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;

namespace PkiProxy.Authentication;

// MIT GSSAPI adapter: .NET10.0.11 Linux rejects strict ExtendedProtectionPolicy;
// Binding alone is ignored by its acceptor. Require CHANNEL_BOUND explicitly.
// One instance per authentication exchange, never shared across connections.
// KRB5_KTNAME must name the protected service-only keytab; no client delegation.
internal sealed class LinuxKerberosAcceptor : IDisposable
{
    private const uint ChannelBound = 2048, Mutual = 2, Delegated = 1;
    private static readonly byte[] KerberosOid = Convert.FromHexString("2A864886F712010202");
    private static readonly byte[] PrincipalNameOid = Convert.FromHexString("2A864886F71201020201");
    private readonly object gate = new();
    private readonly string servicePrincipal;
    private readonly NativeBytes? binding;
    private readonly long started = System.Diagnostics.Stopwatch.GetTimestamp();
    private nint credential, context;
    private int rounds;
    private bool disposed, completed;
    private string? peerName;

    public LinuxKerberosAcceptor(string servicePrincipal, ReadOnlySpan<byte> tlsEndpointBinding)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("MIT GSSAPI Linux adapter only.");
        ValidateServicePrincipal(servicePrincipal);
        TlsEndpointBinding.ValidateApplicationData(tlsEndpointBinding);
        this.servicePrincipal = servicePrincipal;
        binding = new NativeBytes(tlsEndpointBinding);
        nint name = 0, mechanisms = 0;
        try
        {
            using var text = new NativeBytes(Encoding.UTF8.GetBytes(servicePrincipal));
            using var oidBytes = new NativeBytes(PrincipalNameOid);
            var buffer = text.Buffer;
            var oid = new Gss.Oid { Length = (uint)PrincipalNameOid.Length, Elements = oidBytes.Pointer };
            Check(Gss.ImportName(out _, ref buffer, ref oid, out name));
            // Acquire for this exact Kerberos principal, not every name in a keytab.
            Check(Gss.AcquireCredential(out _, name, 0, 0, Gss.AcceptCredential, out credential, out mechanisms, out _));
        }
        catch { Dispose(); throw; }
        finally
        {
            if (name != 0) Gss.ReleaseName(out _, ref name);
            if (mechanisms != 0) Gss.ReleaseOidSet(out _, ref mechanisms);
        }
    }

    public (bool Completed, byte[] OutgoingToken) Step(ReadOnlySpan<byte> incoming)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (completed) throw new InvalidOperationException("Authentication exchange already completed.");
            if (incoming.Length is < 1 or > 65536 || ++rounds > 4 ||
                System.Diagnostics.Stopwatch.GetElapsedTime(started) > TimeSpan.FromSeconds(30))
            { Dispose(); throw new AuthenticationException("Kerberos exchange limit exceeded."); }
            using var inputBytes = new NativeBytes(incoming);
            var input = inputBytes.Buffer;
            var channels = new Gss.ChannelBindings { ApplicationData = binding!.Buffer };
            Gss.Buffer output = default;
            nint source = 0, delegatedCredential = 0;
            try
            {
                var status = Gss.Accept(out _, ref context, credential, ref input, ref channels,
                    out source, out var mechanism, out output, out var flags, out _, out delegatedCredential);
                // Only COMPLETE or CONTINUE_NEEDED; replay/duplicate/old tokens are errors.
                if (status is not 0 and not 1) throw new AuthenticationException("Kerberos token rejected.");
                if (delegatedCredential != 0 || (flags & Delegated) != 0)
                    throw new AuthenticationException("Delegated credentials are not accepted.");
                if (status == 0)
                {
                    if ((flags & (ChannelBound | Mutual)) != (ChannelBound | Mutual) || !IsKerberos(mechanism))
                        throw new AuthenticationException("Kerberos mutual authentication and TLS binding required.");
                    VerifyEstablishedContext();
                    completed = true;
                }
                return (completed, CopyBuffer(output, 65536));
            }
            catch { Dispose(); throw; }
            finally
            {
                if (source != 0) Gss.ReleaseName(out _, ref source);
                if (delegatedCredential != 0) Gss.ReleaseCredential(out _, ref delegatedCredential);
                if (output.Value != 0) Gss.ReleaseBuffer(out _, ref output);
            }
        }
    }

    internal string? GetAuthenticatedPeerName()
    {
        lock (gate) return !disposed && completed &&
            System.Diagnostics.Stopwatch.GetElapsedTime(started) <= TimeSpan.FromSeconds(30) ? peerName : null;
    }

    private void VerifyEstablishedContext()
    {
        nint source = 0, target = 0;
        try
        {
            Check(Gss.InquireContext(out _, context, out source, out target, out var lifetime,
                out var mechanism, out var flags, out var locallyInitiated, out var open));
            if (locallyInitiated != 0 || open != 1 || lifetime == 0 || !IsKerberos(mechanism) ||
                (flags & (ChannelBound | Mutual)) != (ChannelBound | Mutual) || (flags & Delegated) != 0 ||
                DisplayName(target) != servicePrincipal)
                throw new AuthenticationException("Unexpected Kerberos acceptor context.");
            peerName = DisplayName(source);
        }
        finally
        {
            if (source != 0) Gss.ReleaseName(out _, ref source);
            if (target != 0) Gss.ReleaseName(out _, ref target);
        }
    }

    private static string DisplayName(nint name)
    {
        Gss.Buffer output = default;
        try
        {
            Check(Gss.DisplayName(out _, name, out output, out _));
            var text = new UTF8Encoding(false, true).GetString(CopyBuffer(output, 1024));
            if (text.Length == 0 || text.Any(char.IsControl)) throw new AuthenticationException("Invalid Kerberos name.");
            return text;
        }
        finally { if (output.Value != 0) Gss.ReleaseBuffer(out _, ref output); }
    }

    private static bool IsKerberos(nint mechanism)
    {
        if (mechanism == 0) return false;
        var oid = Marshal.PtrToStructure<Gss.Oid>(mechanism);
        return oid.Length == KerberosOid.Length && oid.Elements != 0 &&
            CopyBuffer(new() { Length = oid.Length, Value = oid.Elements }, 64).AsSpan().SequenceEqual(KerberosOid);
    }

    private static byte[] CopyBuffer(Gss.Buffer buffer, int maximum)
    {
        if (buffer.Length > (nuint)maximum || (buffer.Length != 0 && buffer.Value == 0))
            throw new AuthenticationException("Invalid native GSSAPI buffer.");
        var result = new byte[(int)buffer.Length];
        if (result.Length != 0) Marshal.Copy(buffer.Value, result, 0, result.Length);
        return result;
    }

    private static void Check(uint status)
    { if (status != 0) throw new AuthenticationException("Kerberos provider operation failed."); }

    internal static void ValidateServicePrincipal(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var parts = value.Split('@');
        if (parts.Length != 2 || !parts[0].StartsWith("HTTP/", StringComparison.Ordinal) ||
            !ValidDns(parts[0][5..]) || !ValidDns(parts[1]))
            throw new ArgumentException("An explicit HTTP/FQDN@REALM principal is required.", nameof(value));
        static bool ValidDns(string name) => name.Length is > 0 and <= 253 && name.Contains('.') &&
            name.Split('.').All(label => label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-' &&
                label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'));
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true; completed = false; peerName = null;
            if (context != 0) Gss.DeleteContext(out _, ref context, 0);
            if (credential != 0) Gss.ReleaseCredential(out _, ref credential);
            binding?.Dispose();
        }
        GC.SuppressFinalize(this);
    }

    ~LinuxKerberosAcceptor() => Dispose();

    private sealed class NativeBytes : SafeHandle
    {
        private readonly int length;
        public unsafe NativeBytes(ReadOnlySpan<byte> data) : base(0, true)
        {
            length = data.Length;
            SetHandle(Marshal.AllocHGlobal(length));
            try { data.CopyTo(new Span<byte>((void*)handle, length)); }
            catch { Dispose(); throw; }
        }
        public override bool IsInvalid => handle == 0;
        public nint Pointer => DangerousGetHandle();
        public Gss.Buffer Buffer => new() { Length = (nuint)length, Value = Pointer };
        protected override unsafe bool ReleaseHandle()
        {
            // Avoid allocations in finalization; clear transient token storage.
            new Span<byte>((void*)handle, length).Clear();
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }
}

// MIT libgssapi C ABI. No managed marshalling of native-owned output buffers.
internal static partial class Gss
{
    private const string Library = "libgssapi_krb5.so.2";
    internal const int AcceptCredential = 2; // GSS_C_ACCEPT; 1 is INITIATE.
    [StructLayout(LayoutKind.Sequential)] internal struct Buffer { internal nuint Length; internal nint Value; }
    [StructLayout(LayoutKind.Sequential)] internal struct Oid { internal uint Length; internal nint Elements; }
    [StructLayout(LayoutKind.Sequential)] internal struct ChannelBindings
    {
        internal uint InitiatorAddressType; internal Buffer InitiatorAddress;
        internal uint AcceptorAddressType; internal Buffer AcceptorAddress;
        internal Buffer ApplicationData;
    }
    [LibraryImport(Library, EntryPoint="gss_import_name")]
    internal static partial uint ImportName(out uint minor, ref Buffer input, ref Oid type, out nint name);
    [LibraryImport(Library, EntryPoint="gss_acquire_cred")]
    internal static partial uint AcquireCredential(out uint minor, nint name, uint time, nint mechanisms, int usage,
        out nint credential, out nint actualMechanisms, out uint lifetime);
    [LibraryImport(Library, EntryPoint="gss_accept_sec_context")]
    internal static partial uint Accept(out uint minor, ref nint context, nint credential, ref Buffer input,
        ref ChannelBindings bindings, out nint source, out nint mechanism, out Buffer output,
        out uint flags, out uint lifetime, out nint delegatedCredential);
    [LibraryImport(Library, EntryPoint="gss_inquire_context")]
    internal static partial uint InquireContext(out uint minor, nint context, out nint source, out nint target,
        out uint lifetime, out nint mechanism, out uint flags, out int locallyInitiated, out int open);
    [LibraryImport(Library, EntryPoint="gss_display_name")]
    internal static partial uint DisplayName(out uint minor, nint name, out Buffer display, out nint nameType);
    [LibraryImport(Library, EntryPoint="gss_release_name")]
    internal static partial uint ReleaseName(out uint minor, ref nint name);
    [LibraryImport(Library, EntryPoint="gss_release_buffer")]
    internal static partial uint ReleaseBuffer(out uint minor, ref Buffer buffer);
    [LibraryImport(Library, EntryPoint="gss_release_cred")]
    internal static partial uint ReleaseCredential(out uint minor, ref nint credential);
    [LibraryImport(Library, EntryPoint="gss_release_oid_set")]
    internal static partial uint ReleaseOidSet(out uint minor, ref nint mechanisms);
    [LibraryImport(Library, EntryPoint="gss_delete_sec_context")]
    internal static partial uint DeleteContext(out uint minor, ref nint context, nint output);
}
