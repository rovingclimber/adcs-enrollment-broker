using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;

namespace PkiProxy.Signing;

internal enum SigningOperation : byte
{
    DomainEnrollment = 1,
    DomainRenewal = 2,
    BootstrapEnrollment = 3,
    InternalSelfTest = 4
}

internal sealed record SigningIntentMetadata(SigningOperation Operation, byte[] CorrelationId)
{
    internal SigningIntentMetadata Snapshot()
    {
        if (!Enum.IsDefined(Operation) || Operation == SigningOperation.InternalSelfTest ||
            CorrelationId.Length != SignerProtocol.CorrelationLength)
            throw new CryptographicException("Invalid signing intent metadata.");
        return new(Operation, CorrelationId.ToArray());
    }

    internal static byte[] Correlate(SigningOperation operation, params ReadOnlyMemory<byte>[] components)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("pkiproxy-signing-correlation-v1\0"u8);
        hash.AppendData([(byte)operation]);
        Span<byte> length = stackalloc byte[4];
        foreach (var component in components)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, component.Length);
            hash.AppendData(length);
            hash.AppendData(component.Span);
        }
        return hash.GetHashAndReset();
    }
}

internal sealed record SigningIntentRequest(
    SigningOperation Operation,
    byte[] CorrelationId,
    byte[] CertificateSha256,
    string ProfileUrn,
    string TemplateOid,
    int TemplateMajorVersion,
    int TemplateMinorVersion,
    byte[] Payload,
    byte[] Digest);

internal sealed record SigningIntentPolicy(
    string ProfileUrn,
    string TemplateOid,
    int TemplateMajorVersion,
    int TemplateMinorVersion,
    int MaximumReplayEntries = 4096)
{
    internal const int MaximumPayloadBytes = 128 * 1024;
    internal static ReadOnlySpan<byte> SelfTestPayload => "pkiproxy-isolated-signer-provider-readiness-v2"u8;

    internal void ValidateConfiguration()
    {
        if (string.IsNullOrWhiteSpace(ProfileUrn) || ProfileUrn.Length > SignerProtocol.MaximumProfileBytes ||
            !Uri.TryCreate(ProfileUrn, UriKind.Absolute, out var profile) || profile.Scheme != "urn" ||
            Encoding.UTF8.GetByteCount(ProfileUrn) != ProfileUrn.Length)
            throw new InvalidOperationException("Invalid isolated signer profile policy.");
        try
        {
            var oid = new AsnWriter(AsnEncodingRules.DER);
            oid.WriteObjectIdentifier(TemplateOid);
        }
        catch (ArgumentException) { throw new InvalidOperationException("Invalid isolated signer template policy."); }
        if (TemplateOid.Length > SignerProtocol.MaximumTemplateBytes || TemplateMajorVersion < 0 ||
            TemplateMinorVersion < 0 || MaximumReplayEntries is < 16 or > 65_536)
            throw new InvalidOperationException("Invalid isolated signer policy bounds.");
    }

    internal void Validate(SigningIntentRequest request)
    {
        if (request.CorrelationId.Length != SignerProtocol.CorrelationLength ||
            request.CertificateSha256.Length != SignerProtocol.HashLength ||
            request.Digest.Length != SignerProtocol.HashLength || request.Payload.Length > MaximumPayloadBytes ||
            request.Payload.Length == 0)
            throw new CryptographicException("Signing intent rejected.");

        if (request.Operation == SigningOperation.InternalSelfTest)
        {
            var selfTestDigest = SHA256.HashData(request.Payload);
            var digestMatches = CryptographicOperations.FixedTimeEquals(selfTestDigest, request.Digest);
            CryptographicOperations.ZeroMemory(selfTestDigest);
            if (request.ProfileUrn.Length != 0 || request.TemplateOid.Length != 0 ||
                request.TemplateMajorVersion != 0 || request.TemplateMinorVersion != 0 ||
                !request.Payload.AsSpan().SequenceEqual(SelfTestPayload) || !digestMatches)
                throw new CryptographicException("Signing intent rejected.");
            return;
        }

        if (request.Operation is not (SigningOperation.DomainEnrollment or SigningOperation.DomainRenewal or SigningOperation.BootstrapEnrollment) ||
            !string.Equals(request.ProfileUrn, ProfileUrn, StringComparison.Ordinal) ||
            !string.Equals(request.TemplateOid, TemplateOid, StringComparison.Ordinal) ||
            request.TemplateMajorVersion != TemplateMajorVersion || request.TemplateMinorVersion != TemplateMinorVersion)
            throw new CryptographicException("Signing intent rejected.");

        var expectedDigest = ComputeCmsSignatureDigest(request.Payload);
        var matches = CryptographicOperations.FixedTimeEquals(expectedDigest, request.Digest);
        CryptographicOperations.ZeroMemory(expectedDigest);
        if (!matches) throw new CryptographicException("Signing intent rejected.");
        ValidatePkiData(request.Payload);
    }

    // System.Security.Cryptography.Pkcs adds the mandatory content-type and
    // message-digest signed attributes for non-id-data content. RFC 5652 signs
    // the DER SET OF form, so the sidecar can independently reconstruct the
    // exact hash presented to RSA from the admitted PkiData bytes.
    internal static byte[] ComputeCmsSignatureDigest(ReadOnlySpan<byte> payload)
    {
        var contentDigest = SHA256.HashData(payload);
        try
        {
            var attributes = new AsnWriter(AsnEncodingRules.DER);
            using (attributes.PushSetOf())
            {
                using (attributes.PushSequence())
                {
                    attributes.WriteObjectIdentifier("1.2.840.113549.1.9.4");
                    using (attributes.PushSetOf()) attributes.WriteOctetString(contentDigest);
                }
                using (attributes.PushSequence())
                {
                    attributes.WriteObjectIdentifier("1.2.840.113549.1.9.3");
                    using (attributes.PushSetOf()) attributes.WriteObjectIdentifier(PkiProxy.Protocol.Cmc.CmcEnrollmentRequestBuilder.PkiDataOid);
                }
            }
            var encoded = attributes.Encode();
            try { return SHA256.HashData(encoded); }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }
        finally { CryptographicOperations.ZeroMemory(contentDigest); }
    }

    private void ValidatePkiData(byte[] encoded)
    {
        var outer = new AsnReader(encoded, AsnEncodingRules.DER);
        var pkiData = outer.ReadSequence();
        pkiData.ReadSequence().ThrowIfNotEmpty();
        var requests = pkiData.ReadSequence();
        var tagged = requests.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        if (tagged.ReadInteger() != 1) throw new CryptographicException("Signing intent rejected.");

        var certificationRequest = tagged.ReadSequence();
        var infoDer = certificationRequest.ReadEncodedValue();
        var info = new AsnReader(infoDer, AsnEncodingRules.DER).ReadSequence();
        if (info.ReadInteger() != 0) throw new CryptographicException("Signing intent rejected.");
        var subject = info.ReadEncodedValue();
        var spki = info.ReadEncodedValue();
        if (subject.Length <= 2 || spki.Length <= 2) throw new CryptographicException("Signing intent rejected.");
        using (var publicKey = RSA.Create())
        {
            publicKey.ImportSubjectPublicKeyInfo(spki.Span, out var consumed);
            if (consumed != spki.Length || publicKey.KeySize is < 2048 or > 8192)
                throw new CryptographicException("Signing intent rejected.");
        }

        var attributes = info.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var attribute = attributes.ReadSequence();
        if (attribute.ReadObjectIdentifier() != "1.2.840.113549.1.9.14")
            throw new CryptographicException("Signing intent rejected.");
        var values = attribute.ReadSetOf();
        var extensions = values.ReadSequence();
        ValidateTemplateExtension(extensions.ReadSequence());
        ValidateSanExtension(extensions.ReadSequence());
        extensions.ThrowIfNotEmpty(); values.ThrowIfNotEmpty(); attribute.ThrowIfNotEmpty(); attributes.ThrowIfNotEmpty(); info.ThrowIfNotEmpty();

        var algorithm = certificationRequest.ReadSequence();
        if (algorithm.ReadObjectIdentifier() != "2.16.840.1.101.3.4.2.1")
            throw new CryptographicException("Signing intent rejected.");
        algorithm.ReadNull(); algorithm.ThrowIfNotEmpty();
        var nullSignature = certificationRequest.ReadBitString(out var unusedBits);
        var expected = SHA256.HashData(infoDer.Span);
        if (unusedBits != 0 || !CryptographicOperations.FixedTimeEquals(nullSignature, expected))
            throw new CryptographicException("Signing intent rejected.");
        CryptographicOperations.ZeroMemory(expected);
        certificationRequest.ThrowIfNotEmpty(); tagged.ThrowIfNotEmpty(); requests.ThrowIfNotEmpty();
        pkiData.ReadSequence().ThrowIfNotEmpty();
        pkiData.ReadSequence().ThrowIfNotEmpty();
        pkiData.ThrowIfNotEmpty(); outer.ThrowIfNotEmpty();
    }

    private void ValidateTemplateExtension(AsnReader extension)
    {
        if (extension.ReadObjectIdentifier() != "1.3.6.1.4.1.311.21.7")
            throw new CryptographicException("Signing intent rejected.");
        var value = extension.ReadOctetString(); extension.ThrowIfNotEmpty();
        var outer = new AsnReader(value, AsnEncodingRules.DER);
        var template = outer.ReadSequence();
        if (template.ReadObjectIdentifier() != TemplateOid || template.ReadInteger() != TemplateMajorVersion ||
            template.ReadInteger() != TemplateMinorVersion)
            throw new CryptographicException("Signing intent rejected.");
        template.ThrowIfNotEmpty(); outer.ThrowIfNotEmpty();
    }

    private void ValidateSanExtension(AsnReader extension)
    {
        if (extension.ReadObjectIdentifier() != "2.5.29.17")
            throw new CryptographicException("Signing intent rejected.");
        var value = extension.ReadOctetString(); extension.ThrowIfNotEmpty();
        var outer = new AsnReader(value, AsnEncodingRules.DER);
        var names = outer.ReadSequence();
        var count = 0;
        var profileCount = 0;
        while (names.HasData)
        {
            count++;
            var tag = names.PeekTag();
            string valueText;
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
                valueText = names.ReadCharacterString(UniversalTagNumber.IA5String, tag);
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                valueText = names.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                if (string.Equals(valueText, ProfileUrn, StringComparison.Ordinal)) profileCount++;
            }
            else throw new CryptographicException("Signing intent rejected.");
            if (valueText.Length is 0 or > 2048) throw new CryptographicException("Signing intent rejected.");
        }
        if (count is 0 or > 32 || profileCount != 1) throw new CryptographicException("Signing intent rejected.");
        outer.ThrowIfNotEmpty();
    }
}

[System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
    Justification = "The constructor rejects non-Linux platforms before any Unix file API is reached.")]
internal sealed class SigningReplayWindow
{
    private readonly object gate = new();
    private readonly int maximumEntries;
    private readonly string stateFile;
    private readonly Dictionary<string, byte[]> seen = new(StringComparer.Ordinal);
    private readonly Queue<string> order = new();

    internal SigningReplayWindow(int maximumEntries, string stateFile)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("The isolated signer replay store requires Linux.");
        this.maximumEntries = maximumEntries;
        if (!Path.IsPathFullyQualified(stateFile)) throw new InvalidOperationException("Absolute signer replay state path required.");
        this.stateFile = stateFile;
        var directory = Path.GetDirectoryName(stateFile) ?? throw new InvalidOperationException("Signer replay state directory required.");
        if (!System.IO.Directory.Exists(directory) || new DirectoryInfo(directory).LinkTarget is not null ||
            File.GetUnixFileMode(directory) != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute))
            throw new InvalidOperationException("Owner-only signer replay state directory required.");
        if (File.Exists(stateFile)) Load();
    }

    internal bool TryAdmit(SigningIntentRequest request)
    {
        if (request.Operation == SigningOperation.InternalSelfTest) return true;
        var key = Convert.ToHexString(request.CorrelationId);
        var fingerprint = Fingerprint(request);
        lock (gate)
        {
            if (seen.TryGetValue(key, out var existing))
            {
                var same = CryptographicOperations.FixedTimeEquals(existing, fingerprint);
                CryptographicOperations.ZeroMemory(fingerprint);
                return same;
            }
            var next = seen.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray(), StringComparer.Ordinal);
            var nextOrder = new Queue<string>(order);
            next.Add(key, fingerprint);
            nextOrder.Enqueue(key);
            while (nextOrder.Count > maximumEntries)
            {
                var removed = nextOrder.Dequeue();
                CryptographicOperations.ZeroMemory(next[removed]);
                next.Remove(removed);
            }
            Persist(next, nextOrder);
            foreach (var value in seen.Values) CryptographicOperations.ZeroMemory(value);
            seen.Clear(); order.Clear();
            foreach (var item in nextOrder)
            {
                order.Enqueue(item);
                seen.Add(item, next[item]);
            }
            return true;
        }
    }

    private void Load()
    {
        var info = new FileInfo(stateFile);
        if (info.LinkTarget is not null || File.GetUnixFileMode(stateFile) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
            throw new InvalidOperationException("Owner-only non-link signer replay state required.");
        var bytes = File.ReadAllBytes(stateFile);
        try
        {
            if (bytes.Length % 64 != 0 || bytes.Length / 64 > maximumEntries)
                throw new InvalidDataException("Invalid signer replay state.");
            for (var offset = 0; offset < bytes.Length; offset += 64)
            {
                var key = Convert.ToHexString(bytes.AsSpan(offset, 32));
                if (!seen.TryAdd(key, bytes.AsSpan(offset + 32, 32).ToArray()))
                    throw new InvalidDataException("Ambiguous signer replay state.");
                order.Enqueue(key);
            }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private void Persist(Dictionary<string, byte[]> values, IEnumerable<string> keys)
    {
        var temporary = stateFile + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.WriteThrough))
            {
                File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                foreach (var key in keys)
                {
                    var correlation = Convert.FromHexString(key);
                    try { stream.Write(correlation); stream.Write(values[key]); }
                    finally { CryptographicOperations.ZeroMemory(correlation); }
                }
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, stateFile, overwrite: true);
        }
        finally { try { File.Delete(temporary); } catch { } }
    }

    private static byte[] Fingerprint(SigningIntentRequest request)
    {
        var encoded = SignerProtocol.EncodeRequest(new byte[SignerProtocol.TokenLength], request);
        try { return SHA256.HashData(encoded); }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }
}
