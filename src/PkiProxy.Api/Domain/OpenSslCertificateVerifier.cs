using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PkiProxy.Domain;

internal enum CertificatePurpose { Server, Client, Signing }

// Explicit fixed-source CRL verification for the direct-root LAB profile.
// OpenSSL performs chain, signature, purpose, validity and CRL checks together.
// No certificate-provided URL is fetched; unknown/stale/revoked state fails closed.
internal sealed class OpenSslCertificateVerifier
{
    private readonly byte[] rootPem;
    private readonly byte[] crlPem;

    internal OpenSslCertificateVerifier(X509Certificate2 trustedRoot, byte[] crlPem)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux OpenSSL verification required.");
        if (trustedRoot.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority != true ||
            crlPem.Length is 0 or > 2_097_152)
            throw new ArgumentException("Explicit CA and bounded signed CRL required.");
        rootPem = Encoding.ASCII.GetBytes(trustedRoot.ExportCertificatePem());
        this.crlPem = crlPem.ToArray();
    }

    internal static OpenSslCertificateVerifier Load(X509Certificate2 root, string crlPath)
    {
        if (!Path.IsPathFullyQualified(crlPath)) throw new ArgumentException("Absolute CRL path required.");
        using var stream = new FileStream(crlPath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length is 0 or > 2_097_152) throw new InvalidDataException("Bounded signed CRL required.");
        var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("CRL changed while reading.");
        return new(root, bytes);
    }

    internal bool Verify(X509Certificate2 certificate, CertificatePurpose purpose, string? serverName = null)
    {
        if (certificate.RawDataMemory.Length > 65_536 || certificate.HasPrivateKey ||
            certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority)) return false;
        if (purpose == CertificatePurpose.Server &&
            (serverName is null || Uri.CheckHostName(serverName) != UriHostNameType.Dns || !serverName.Contains('.'))) return false;
        var scratch = System.IO.Directory.CreateTempSubdirectory("pkiproxy-verify-");
        var leafPath = Path.Combine(scratch.FullName, "leaf.pem");
        var rootPath = Path.Combine(scratch.FullName, "root.pem");
        var crlPath = Path.Combine(scratch.FullName, "crl.pem");
        try
        {
            File.WriteAllText(leafPath, certificate.ExportCertificatePem());
            File.WriteAllBytes(rootPath, rootPem); File.WriteAllBytes(crlPath, crlPem);
            var start = new ProcessStartInfo("/usr/bin/openssl") {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            start.Environment.Remove("OPENSSL_CONF"); start.Environment.Remove("OPENSSL_MODULES"); start.Environment.Remove("OPENSSL_ENGINES");
            foreach (var argument in new[] { "verify", "-trusted", rootPath, "-no-CAfile", "-no-CApath", "-no-CAstore",
                "-CRLfile", crlPath, "-crl_check", "-x509_strict", "-auth_level", "2", "-purpose",
                purpose switch { CertificatePurpose.Server => "sslserver", CertificatePurpose.Client => "sslclient", CertificatePurpose.Signing => "any", _ => throw new ArgumentOutOfRangeException(nameof(purpose)) } })
                start.ArgumentList.Add(argument);
            if (purpose == CertificatePurpose.Server) { start.ArgumentList.Add("-verify_hostname"); start.ArgumentList.Add(serverName!); }
            start.ArgumentList.Add(leafPath);
            using var process = Process.Start(start) ?? throw new IOException("Cannot start OpenSSL verifier.");
            var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(10_000)) { process.Kill(entireProcessTree: true); process.WaitForExit(); return false; }
            Task.WhenAll(output, error).GetAwaiter().GetResult();
            return process.ExitCode == 0;
        }
        catch (Exception exception) when (exception is IOException or Win32Exception or CryptographicException or UnauthorizedAccessException)
        { return false; }
        finally
        {
            // Only the three public files in this newly created private directory.
            File.Delete(leafPath); File.Delete(rootPath); File.Delete(crlPath); scratch.Delete();
        }
    }
}
