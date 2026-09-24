using Microsoft.Extensions.Configuration;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PkiProxy.Signing;

internal sealed class Pkcs11IsolatedSignerKeyProvider : IIsolatedSignerKeyProvider
{
    private const ulong CkfSerialSession = 0x4;
    private const ulong CkfSign = 0x800;
    private const ulong CkuUser = 1;
    private const ulong CkoCertificate = 1;
    private const ulong CkoPublicKey = 2;
    private const ulong CkoPrivateKey = 3;
    private const ulong CkkRsa = 0;
    private const ulong CkmRsaPkcs = 1;
    private const ulong CkaClass = 0;
    private const ulong CkaToken = 1;
    private const ulong CkaPrivate = 2;
    private const ulong CkaLabel = 3;
    private const ulong CkaValue = 0x11;
    private const ulong CkaCertificateType = 0x80;
    private const ulong CkaKeyType = 0x100;
    private const ulong CkaId = 0x102;
    private const ulong CkaSensitive = 0x103;
    private const ulong CkaEncrypt = 0x104;
    private const ulong CkaDecrypt = 0x105;
    private const ulong CkaWrap = 0x106;
    private const ulong CkaSign = 0x108;
    private const ulong CkaDerive = 0x10c;
    private const ulong CkaModulus = 0x120;
    private const ulong CkaModulusBits = 0x121;
    private const ulong CkaPublicExponent = 0x122;
    private const ulong CkaExtractable = 0x162;
    private const ulong CkaUnwrap = 0x107;
    private static readonly byte[] Sha256DigestInfoPrefix = Convert.FromHexString("3031300D060960864801650304020105000420");

    internal static (ulong Token, ulong Private, ulong Id, ulong Sensitive, ulong Encrypt, ulong Decrypt,
        ulong Wrap, ulong Unwrap, ulong Sign, ulong Derive, ulong Modulus, ulong ModulusBits, ulong PublicExponent)
        AttributeConstantsForTests => (CkaToken, CkaPrivate, CkaId, CkaSensitive, CkaEncrypt, CkaDecrypt,
            CkaWrap, CkaUnwrap, CkaSign, CkaDerive, CkaModulus, CkaModulusBits, CkaPublicExponent);

    private readonly Pkcs11Module module;
    private readonly ulong slot;
    private readonly byte[] keyId;
    private readonly byte[] pin;
    private readonly SemaphoreSlim sessions;
    private readonly X509Certificate2 certificate;
    private readonly byte[] subjectPublicKeyInfo;
    private int failed;
    private int disposed;

    private Pkcs11IsolatedSignerKeyProvider(Pkcs11Module module, ulong slot, byte[] keyId, byte[] pin,
        int maximumSessions, X509Certificate2 certificate, byte[] subjectPublicKeyInfo)
    {
        this.module = module;
        this.slot = slot;
        this.keyId = keyId;
        this.pin = pin;
        sessions = new SemaphoreSlim(maximumSessions, maximumSessions);
        this.certificate = certificate;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
    }

    internal static Pkcs11IsolatedSignerKeyProvider Load(IConfigurationSection section)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The PKCS#11 signer provider requires Linux.");
        string Required(string key)
        {
            var value = section[key];
            if (string.IsNullOrWhiteSpace(value)) throw new InvalidOperationException($"Missing isolated signer setting {key}.");
            return value;
        }

        var modulePath = IsolatedSignerKeyProvider.RequiredAbsolute(section, "ModulePath");
        var pinPath = IsolatedSignerKeyProvider.RequiredAbsolute(section, "PinFile");
        var tokenLabel = Required("TokenLabel");
        var tokenSerial = Required("TokenSerial");
        var keyIdText = Required("KeyId");
        if (tokenLabel.Length > 32 || tokenSerial.Length > 16 || tokenLabel.Any(char.IsControl) || tokenSerial.Any(char.IsControl))
            throw new InvalidOperationException("Invalid PKCS#11 token selector.");
        byte[] keyId;
        try { keyId = Convert.FromHexString(keyIdText); }
        catch (FormatException) { throw new InvalidOperationException("Invalid PKCS#11 key identifier."); }
        if (keyId.Length is < 1 or > 64) throw new InvalidOperationException("Invalid PKCS#11 key identifier.");
        if (!int.TryParse(Required("MaximumSessions"), out var maximumSessions) || maximumSessions is < 1 or > 16)
            throw new InvalidOperationException("Invalid PKCS#11 session limit.");

        var pin = LoadPin(pinPath);
        Pkcs11Module? module = null;
        try
        {
            module = new Pkcs11Module(modulePath);
            var slots = module.FindTokenSlots(tokenLabel, tokenSerial);
            if (slots.Length != 1) throw Unavailable();
            var slot = slots[0];
            if (!module.SupportsRsaPkcsSigning(slot)) throw Unavailable();
            using var session = module.OpenSession(slot);
            session.Login(pin);
            {
                var privateKeys = session.FindObjects(CkoPrivateKey, keyId);
                var publicKeys = session.FindObjects(CkoPublicKey, keyId);
                var certificates = session.FindObjects(CkoCertificate, keyId);
                if (privateKeys.Length != 1 || publicKeys.Length != 1 || certificates.Length != 1) throw Unavailable();
                var privateKey = privateKeys[0];
                RequireAttribute(session, publicKeys[0], CkaToken, true);
                RequireAttribute(session, certificates[0], CkaToken, true);
                RequireAttribute(session, privateKey, CkaToken, true);
                RequireAttribute(session, privateKey, CkaPrivate, true);
                RequireAttribute(session, privateKey, CkaSensitive, true);
                RequireAttribute(session, privateKey, CkaExtractable, false);
                RequireAttribute(session, privateKey, CkaSign, true);
                RequireAttribute(session, privateKey, CkaDecrypt, false);
                RequireAttribute(session, privateKey, CkaUnwrap, false);
                RequireAttribute(session, privateKey, CkaDerive, false);
                if (session.ReadUlong(privateKey, CkaKeyType) != CkkRsa ||
                    session.ReadUlong(publicKeys[0], CkaKeyType) != CkkRsa ||
                    session.ReadUlong(certificates[0], CkaCertificateType) != 0 ||
                    session.ReadUlong(publicKeys[0], CkaModulusBits) < 3072)
                    throw Unavailable();

                var modulus = session.ReadBytes(publicKeys[0], CkaModulus);
                var exponent = session.ReadBytes(publicKeys[0], CkaPublicExponent);
                if (modulus.Length < 384 || exponent.Length is < 1 or > 8) throw Unavailable();
                using var rsa = RSA.Create(new RSAParameters { Modulus = modulus, Exponent = exponent });
                var spki = rsa.ExportSubjectPublicKeyInfo();
                var encodedCertificate = session.ReadBytes(certificates[0], CkaValue);
                var certificate = X509CertificateLoader.LoadCertificate(encodedCertificate);
                using var certificateKey = certificate.GetRSAPublicKey();
                if (certificateKey is null || certificateKey.KeySize < 3072 ||
                    !CryptographicOperations.FixedTimeEquals(spki, certificateKey.ExportSubjectPublicKeyInfo()))
                { certificate.Dispose(); throw Unavailable(); }
                return new Pkcs11IsolatedSignerKeyProvider(module, slot, keyId.ToArray(), pin, maximumSessions, certificate, spki);
            }
        }
        catch (Exception exception) when (exception is Pkcs11Exception or CryptographicException or IOException)
        {
            try { module?.Dispose(); } catch { }
            CryptographicOperations.ZeroMemory(pin);
            throw Unavailable();
        }
        finally { CryptographicOperations.ZeroMemory(keyId); }
    }

    public X509Certificate2 Certificate => certificate;
    public ReadOnlyMemory<byte> SubjectPublicKeyInfo => subjectPublicKeyInfo;

    public byte[] SignSha256Pkcs1(ReadOnlySpan<byte> hash)
    {
        if (hash.Length != 32) throw new CryptographicException("The signer accepts only SHA-256 hashes.");
        if (Volatile.Read(ref failed) != 0 || Volatile.Read(ref disposed) != 0) throw Unavailable();
        sessions.Wait();
        try
        {
            if (Volatile.Read(ref failed) != 0 || Volatile.Read(ref disposed) != 0) throw Unavailable();
            using var session = module.OpenSession(slot);
            session.Login(pin);
            {
                var keys = session.FindObjects(CkoPrivateKey, keyId);
                if (keys.Length != 1) throw new Pkcs11Exception();
                Span<byte> digestInfo = stackalloc byte[Sha256DigestInfoPrefix.Length + 32];
                Sha256DigestInfoPrefix.CopyTo(digestInfo);
                hash.CopyTo(digestInfo[Sha256DigestInfoPrefix.Length..]);
                try { return session.SignRsaPkcs(keys[0], digestInfo); }
                finally { CryptographicOperations.ZeroMemory(digestInfo); }
            }
        }
        catch (Exception exception) when (exception is Pkcs11Exception or ObjectDisposedException)
        {
            Interlocked.Exchange(ref failed, 1);
            throw Unavailable();
        }
        finally { sessions.Release(); }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        certificate.Dispose();
        CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
        CryptographicOperations.ZeroMemory(keyId);
        CryptographicOperations.ZeroMemory(pin);
        sessions.Dispose();
        module.Dispose();
    }

    private static void RequireAttribute(Pkcs11Session session, ulong objectHandle, ulong attribute, bool expected)
    {
        if (session.ReadBoolean(objectHandle, attribute) != expected) throw Unavailable();
    }

    [SupportedOSPlatform("linux")]
    private static byte[] LoadPin(string path)
    {
        var value = LinuxSecretFile.ReadAllBytes(path, 128, "Owner-only PKCS#11 PIN file required.");
        if (value.Length is < 4 or > 128) { CryptographicOperations.ZeroMemory(value); throw new InvalidOperationException("Invalid PKCS#11 PIN file."); }
        var length = value.Length;
        while (length > 0 && value[length - 1] is (byte)'\r' or (byte)'\n') length--;
        if (length is < 4 or > 64 || value.AsSpan(0, length).Contains((byte)0))
        { CryptographicOperations.ZeroMemory(value); throw new InvalidOperationException("Invalid PKCS#11 PIN file."); }
        var pin = value.AsSpan(0, length).ToArray();
        CryptographicOperations.ZeroMemory(value);
        return pin;
    }

    private static CryptographicException Unavailable() => new("PKCS#11 signer unavailable.");
}

internal sealed class Pkcs11Exception : CryptographicException
{
    internal Pkcs11Exception() : base("PKCS#11 signer unavailable.") { }
}

internal sealed class Pkcs11Module : IDisposable
{
    private const ulong CkrOk = 0;
    private const ulong CkrCryptokiAlreadyInitialized = 0x191;
    private const ulong CkfOsLockingOk = 0x2;
    private readonly IntPtr library;
    private readonly CFinalize finalize;
    private readonly CGetSlotList getSlotList;
    private readonly CGetTokenInfo getTokenInfo;
    private readonly CGetMechanismList getMechanismList;
    private readonly CGetMechanismInfo getMechanismInfo;
    private readonly COpenSession openSession;
    private readonly CCloseSession closeSession;
    private readonly CLogin login;
    private readonly CFindObjectsInit findObjectsInit;
    private readonly CFindObjects findObjects;
    private readonly CFindObjectsFinal findObjectsFinal;
    private readonly CGetAttributeValue getAttributeValue;
    private readonly CSignInit signInit;
    private readonly CSign sign;
    private readonly bool initializedHere;
    private int disposed;

    internal Pkcs11Module(string path)
    {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("The PKCS#11 signer requires a 64-bit Linux ABI.");
        if (!File.Exists(path) || new FileInfo(path).LinkTarget is not null) throw new InvalidOperationException("Regular PKCS#11 module file required.");
        try
        {
            library = NativeLibrary.Load(path);
            var initialize = Export<CInitialize>("C_Initialize");
            finalize = Export<CFinalize>("C_Finalize");
            getSlotList = Export<CGetSlotList>("C_GetSlotList");
            getTokenInfo = Export<CGetTokenInfo>("C_GetTokenInfo");
            getMechanismList = Export<CGetMechanismList>("C_GetMechanismList");
            getMechanismInfo = Export<CGetMechanismInfo>("C_GetMechanismInfo");
            openSession = Export<COpenSession>("C_OpenSession"); closeSession = Export<CCloseSession>("C_CloseSession");
            login = Export<CLogin>("C_Login");
            findObjectsInit = Export<CFindObjectsInit>("C_FindObjectsInit"); findObjects = Export<CFindObjects>("C_FindObjects");
            findObjectsFinal = Export<CFindObjectsFinal>("C_FindObjectsFinal"); getAttributeValue = Export<CGetAttributeValue>("C_GetAttributeValue");
            signInit = Export<CSignInit>("C_SignInit"); sign = Export<CSign>("C_Sign");
            var initializeArguments = new CkInitializeArgs
            {
                CreateMutex = IntPtr.Zero,
                DestroyMutex = IntPtr.Zero,
                LockMutex = IntPtr.Zero,
                UnlockMutex = IntPtr.Zero,
                Flags = CkfOsLockingOk,
                Reserved = IntPtr.Zero
            };
            var initializePointer = Marshal.AllocHGlobal(Marshal.SizeOf<CkInitializeArgs>());
            ulong result;
            try
            {
                Marshal.StructureToPtr(initializeArguments, initializePointer, false);
                result = initialize(initializePointer);
            }
            finally { Marshal.FreeHGlobal(initializePointer); }
            if (result != CkrOk && result != CkrCryptokiAlreadyInitialized) throw new Pkcs11Exception();
            initializedHere = result == CkrOk;
        }
        catch
        {
            if (library != IntPtr.Zero) NativeLibrary.Free(library);
            throw new Pkcs11Exception();
        }
    }

    internal ulong[] FindTokenSlots(string label, string serial)
    {
        ulong count = 0; Check(getSlotList(1, IntPtr.Zero, ref count));
        if (count > 256) throw new Pkcs11Exception();
        var slots = ReadUlongArray(count, pointer => Check(getSlotList(1, pointer, ref count)));
        return slots.Take(checked((int)count)).Where(slot =>
        {
            var info = ReadTokenInfo(slot);
            return info.Label == label && info.Serial == serial;
        }).ToArray();
    }

    internal bool SupportsRsaPkcsSigning(ulong slot)
    {
        ulong count = 0; Check(getMechanismList(slot, IntPtr.Zero, ref count));
        if (count > 1024) throw new Pkcs11Exception();
        var mechanisms = ReadUlongArray(count, pointer => Check(getMechanismList(slot, pointer, ref count)));
        if (!mechanisms.Take(checked((int)count)).Contains(1UL)) return false;
        Check(getMechanismInfo(slot, 1, out var info));
        return (info.Flags & 0x800UL) != 0 && info.MaxKeySize >= 3072;
    }

    internal Pkcs11Session OpenSession(ulong slot)
    {
        Check(openSession(slot, 0x4, IntPtr.Zero, IntPtr.Zero, out var handle));
        return new(this, handle);
    }

    internal Pkcs11Session OpenWritableSessionForTests(ulong slot)
    {
        Check(openSession(slot, 0x6, IntPtr.Zero, IntPtr.Zero, out var handle));
        return new(this, handle);
    }

    internal void Login(ulong session, byte[] pin)
    {
        var result = login(session, 1, pin, (ulong)pin.Length);
        if (result != 0 && result != 0x100) throw new Pkcs11Exception(); // CKR_USER_ALREADY_LOGGED_IN is valid across parallel token sessions.
    }
    internal void Close(ulong session) => Check(closeSession(session));
    internal ulong[] FindObjects(ulong session, ulong objectClass, byte[] id)
    {
        using var template = AttributeTemplate.Create((0, Ulong(objectClass)), (0x102, id));
        Check(findObjectsInit(session, template.Attributes, (ulong)template.Attributes.Length));
        try
        {
            const int maximum = 2;
            var pointer = Marshal.AllocHGlobal(maximum * IntPtr.Size);
            try
            {
                Check(findObjects(session, pointer, maximum, out var count));
                if (count > maximum) throw new Pkcs11Exception();
                return ReadUlongs(pointer, checked((int)count));
            }
            finally { Marshal.FreeHGlobal(pointer); }
        }
        finally { Check(findObjectsFinal(session)); }
    }

    internal byte[] ReadBytes(ulong session, ulong objectHandle, ulong attribute)
    {
        var attrs = new[] { new CkAttribute { Type = attribute, Value = IntPtr.Zero, ValueLength = 0 } };
        Check(getAttributeValue(session, objectHandle, attrs, 1));
        if (attrs[0].ValueLength == ulong.MaxValue || attrs[0].ValueLength > 1_048_576) throw new Pkcs11Exception();
        var value = new byte[checked((int)attrs[0].ValueLength)];
        var handle = GCHandle.Alloc(value, GCHandleType.Pinned);
        try { attrs[0].Value = handle.AddrOfPinnedObject(); Check(getAttributeValue(session, objectHandle, attrs, 1)); }
        finally { handle.Free(); }
        return value;
    }
    internal ulong ReadUlong(ulong session, ulong objectHandle, ulong attribute)
    { var bytes = ReadBytes(session, objectHandle, attribute); try { if (bytes.Length != 8) throw new Pkcs11Exception(); return BitConverter.ToUInt64(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); } }
    internal bool ReadBoolean(ulong session, ulong objectHandle, ulong attribute)
    { var bytes = ReadBytes(session, objectHandle, attribute); try { if (bytes.Length != 1 || bytes[0] > 1) throw new Pkcs11Exception(); return bytes[0] != 0; } finally { CryptographicOperations.ZeroMemory(bytes); } }
    internal void GenerateRsaKeyPairForTests(ulong session, byte[] id, string label, bool decrypt)
    {
        var text = Encoding.ASCII.GetBytes(label);
        try
        {
            using var publicTemplate = AttributeTemplate.Create(
                (0x1, [1]), (0x104, [0]), (0x10a, [1]), (0x106, [0]),
                (0x121, Ulong(3072)), (0x122, [1, 0, 1]), (0x102, id), (0x3, text));
            using var privateTemplate = AttributeTemplate.Create(
                (0x1, [1]), (0x2, [1]), (0x103, [1]), (0x105, [decrypt ? (byte)1 : (byte)0]), (0x108, [1]),
                (0x107, [0]), (0x10c, [0]), (0x162, [0]), (0x102, id), (0x3, text));
            var mechanism = new CkMechanism { Mechanism = 0 };
            var generateKeyPair = Export<CGenerateKeyPair>("C_GenerateKeyPair");
            Check(generateKeyPair(session, ref mechanism, publicTemplate.Attributes, (ulong)publicTemplate.Attributes.Length,
                privateTemplate.Attributes, (ulong)privateTemplate.Attributes.Length, out _, out _));
        }
        finally { CryptographicOperations.ZeroMemory(text); }
    }
    internal byte[] Sign(ulong session, ulong key, ReadOnlySpan<byte> data)
    {
        var mechanism = new CkMechanism { Mechanism = 1 };
        Check(signInit(session, ref mechanism, key));
        var input = data.ToArray();
        try
        {
            ulong length = 0; Check(sign(session, input, (ulong)input.Length, null, ref length));
            if (length is < 384 or > 1024) throw new Pkcs11Exception();
            var signature = new byte[checked((int)length)]; Check(sign(session, input, (ulong)input.Length, signature, ref length));
            return signature.Length == checked((int)length) ? signature : signature[..checked((int)length)];
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        try { if (initializedHere) _ = finalize(IntPtr.Zero); } finally { NativeLibrary.Free(library); }
    }

    private T Export<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
    private static void Check(ulong result) { if (result != 0) throw new Pkcs11Exception(); }
    private static byte[] Ulong(ulong value) => BitConverter.GetBytes(value);
    private static string Trim(byte[] value) => Encoding.ASCII.GetString(value).TrimEnd(' ', '\0');
    private static ulong[] ReadUlongArray(ulong count, Action<IntPtr> fill)
    {
        if (IntPtr.Size != sizeof(long)) throw new PlatformNotSupportedException("The PKCS#11 signer requires a 64-bit Linux ABI.");
        var pointer = Marshal.AllocHGlobal(checked((int)count * IntPtr.Size));
        try { fill(pointer); return ReadUlongs(pointer, checked((int)count)); }
        finally { Marshal.FreeHGlobal(pointer); }
    }
    private static ulong[] ReadUlongs(IntPtr pointer, int count) =>
        Enumerable.Range(0, count).Select(i => unchecked((ulong)Marshal.ReadInt64(pointer, i * IntPtr.Size))).ToArray();
    private (string Label, string Serial) ReadTokenInfo(ulong slot)
    {
        const int tokenInfoSize = 208; // 64-bit PKCS#11 CK_TOKEN_INFO.
        var pointer = Marshal.AllocHGlobal(tokenInfoSize);
        try
        {
            Span<byte> zero = stackalloc byte[tokenInfoSize];
            Marshal.Copy(zero.ToArray(), 0, pointer, tokenInfoSize);
            Check(getTokenInfo(slot, pointer));
            var fixedFields = new byte[96];
            Marshal.Copy(pointer, fixedFields, 0, fixedFields.Length);
            return (Trim(fixedFields[..32]), Trim(fixedFields[80..96]));
        }
        finally { Marshal.FreeHGlobal(pointer); }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CInitialize(IntPtr args);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CFinalize(IntPtr reserved);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CGetSlotList(byte tokenPresent, IntPtr slots, ref ulong count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CGetTokenInfo(ulong slot, IntPtr info);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CGetMechanismList(ulong slot, IntPtr list, ref ulong count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CGetMechanismInfo(ulong slot, ulong mechanism, out CkMechanismInfo info);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong COpenSession(ulong slot, ulong flags, IntPtr application, IntPtr notify, out ulong session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CCloseSession(ulong session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CLogin(ulong session, ulong userType, byte[] pin, ulong pinLength);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CFindObjectsInit(ulong session, CkAttribute[] attributes, ulong count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CFindObjects(ulong session, IntPtr objects, ulong maximum, out ulong count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CFindObjectsFinal(ulong session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CGetAttributeValue(ulong session, ulong objectHandle, [In, Out] CkAttribute[] attributes, ulong count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CGenerateKeyPair(ulong session, ref CkMechanism mechanism,
        CkAttribute[] publicTemplate, ulong publicCount, CkAttribute[] privateTemplate, ulong privateCount,
        out ulong publicKey, out ulong privateKey);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CSignInit(ulong session, ref CkMechanism mechanism, ulong key);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong CSign(ulong session, byte[] data, ulong dataLength, [Out] byte[]? signature, ref ulong signatureLength);

    [StructLayout(LayoutKind.Sequential)] private struct CkMechanismInfo { public ulong MinKeySize, MaxKeySize, Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct CkInitializeArgs
    {
        public IntPtr CreateMutex, DestroyMutex, LockMutex, UnlockMutex;
        public ulong Flags;
        public IntPtr Reserved;
    }
    [StructLayout(LayoutKind.Sequential)] private struct CkMechanism { public ulong Mechanism; public IntPtr Parameter; public ulong ParameterLength; }
    [StructLayout(LayoutKind.Sequential)] internal struct CkAttribute { public ulong Type; public IntPtr Value; public ulong ValueLength; }

    private sealed class AttributeTemplate : IDisposable
    {
        private readonly GCHandle[] handles;
        internal CkAttribute[] Attributes { get; }
        private AttributeTemplate((ulong Type, byte[] Value)[] values)
        {
            handles = new GCHandle[values.Length]; Attributes = new CkAttribute[values.Length];
            for (var i = 0; i < values.Length; i++) { handles[i] = GCHandle.Alloc(values[i].Value, GCHandleType.Pinned); Attributes[i] = new() { Type = values[i].Type, Value = handles[i].AddrOfPinnedObject(), ValueLength = (ulong)values[i].Value.Length }; }
        }
        internal static AttributeTemplate Create(params (ulong Type, byte[] Value)[] values) => new(values);
        public void Dispose() { foreach (var handle in handles) if (handle.IsAllocated) handle.Free(); }
    }
}

internal sealed class Pkcs11Session : IDisposable
{
    private readonly Pkcs11Module module; private readonly ulong handle; private int disposed;
    internal Pkcs11Session(Pkcs11Module module, ulong handle) { this.module = module; this.handle = handle; }
    internal void Login(byte[] pin) => module.Login(handle, pin);
    internal ulong[] FindObjects(ulong objectClass, byte[] id) => module.FindObjects(handle, objectClass, id);
    internal byte[] ReadBytes(ulong objectHandle, ulong attribute) => module.ReadBytes(handle, objectHandle, attribute);
    internal ulong ReadUlong(ulong objectHandle, ulong attribute) => module.ReadUlong(handle, objectHandle, attribute);
    internal bool ReadBoolean(ulong objectHandle, ulong attribute) => module.ReadBoolean(handle, objectHandle, attribute);
    internal void GenerateRsaKeyPairForTests(byte[] id, string label, bool decrypt = false) => module.GenerateRsaKeyPairForTests(handle, id, label, decrypt);
    internal byte[] SignRsaPkcs(ulong key, ReadOnlySpan<byte> data) => module.Sign(handle, key, data);
    public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) != 0) return; module.Close(handle); }
}
