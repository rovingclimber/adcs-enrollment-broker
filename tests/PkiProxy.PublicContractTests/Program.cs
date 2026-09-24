using System.Xml.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PkiProxy.Domain;
using PkiProxy.Protocol.Xcep;
using PkiProxy.Protocol.Wstep;
using PkiProxy.Protocol;

if (EnrollmentSubmissionJournalMarkerTests.Run(args)) return;

if (args.SequenceEqual(["--pkcs11-provider-contract"]))
{
    await Pkcs11SignerProviderTests.RunAsync();
    return;
}

if (args.Length > 0 && args[0] == "--bootstrap-consume-fixture")
{
    Environment.ExitCode = FileBootstrapStoreTests.ConsumeFixture(args);
    return;
}

if (args.SequenceEqual(["--disabled-host-smoke"]))
{
    await DisabledHostSmoke.RunAsync();
    return;
}
BrokerConfigurationBoundaryTests.Run();
LinuxLdapPolicyTests.Run();
CmcRenewalSignatureTests.Run();
IncomingRenewalCmcTests.Run();
await NativeDomainRenewalTests.RunAsync();
DeviceFactsEditorTests.Run();
await DeviceFactsPublisherTests.RunAsync();
await OperationalFactsManagementTests.RunAsync();
FactsWorkbenchHostedAccessTests.Run();
BootstrapIngressAdmissionTests.Run();
await FactsWorkbenchPublicationTests.RunAsync();
await BrokerReadinessTests.RunAsync();
await InboundSoapLimitsTests.RunAsync();
await FileBootstrapStoreTests.RunAsync();
await BootstrapAssetBindingTests.RunAsync();
BootstrapPairingTests.Run();
BootstrapTechnicianAuthenticationTests.Run();
await BootstrapKerberosAuthenticationTests.RunAsync();
FileBootstrapPairingTests.Run();
FileBootstrapIntakeLedgerTests.Run();
FileBootstrapEnrollmentTransactionStoreTests.Run();
await BootstrapEnrollmentWorkflowTests.RunAsync();
BootstrapHostingIntegrationTests.Run();
await BootstrapIssuanceWorkflowTests.RunAsync();
CertificateSubjectEncoderTests.Run();
NativeEnrollmentConfigurationTests.Run();
SignerRotationPolicyTests.Run();
await IsolatedSignerProtocolTests.RunAsync();
CertificateConfigurationTests.Run();
CesResponseReaderTests.Run();
OpenSslCertificateVerifierTests.Run();
BrokerPolicyConfigurationTests.Run();
BootstrapPolicyConfigurationTests.Run();
var xcep = (XNamespace)"http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy";
var xsi = (XNamespace)"http://www.w3.org/2001/XMLSchema-instance";

var requestElement = XDocument.Load("smoke/xcep-getpolicies.xml")
    .Descendants(xcep + "GetPolicies")
    .Single();
var parsedEnvelope = SoapEnvelopeReader.Parse(XDocument.Load("smoke/xcep-getpolicies.xml"));
Assert(parsedEnvelope.IsValid &&
    parsedEnvelope.WsAddressingAction == "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies" &&
    parsedEnvelope.WsAddressingMessageId == "urn:uuid:72a0b82e-6a79-4d22-b998-45cf61775e77",
    "SOAP parsing must retain WS-Addressing action and correlation ID.");

var ambiguousEnvelope = XDocument.Load("smoke/xcep-getpolicies.xml");
ambiguousEnvelope.Root!.AddFirst(new XElement((XNamespace)"urn:test:untrusted" + "InjectedEnvelopeChild"));
var ambiguousEnvelopeResult = SoapEnvelopeReader.Parse(ambiguousEnvelope);
Assert(!ambiguousEnvelopeResult.IsValid &&
    ambiguousEnvelopeResult.ErrorCode == "InvalidSoapEnvelopeStructure",
    "SOAP parsing must reject unrecognised Envelope children rather than ignoring them.");

Assert(GetPoliciesContract.TryParse(requestElement, out var request, out var error), error ?? "Expected valid request.");
Assert(request!.PreferredLanguage == "en-GB", "Preferred language was not preserved.");
Assert(request.PolicyOids.Count == 0, "A nil OID filter must mean no filter.");

var oidFilterRequest = new XElement(requestElement);
var oidFilter = oidFilterRequest.Element(xcep + "requestFilter")!.Element(xcep + "policyOIDs")!;
oidFilter.Attribute(xsi + "nil")!.Remove();
oidFilter.Add(new XElement(xcep + "oid", "1.3.6.1.4.1.311.21.8.1"));
Assert(GetPoliciesContract.TryParse(oidFilterRequest, out request, out error), error ?? "Expected valid OID filter.");
Assert(request!.PolicyOids.SetEquals(["1.3.6.1.4.1.311.21.8.1"]), "OID filter was not preserved.");

var duplicateOidRequest = new XElement(oidFilterRequest);
duplicateOidRequest.Element(xcep + "requestFilter")!
    .Element(xcep + "policyOIDs")!
    .Add(new XElement(xcep + "oid", "1.3.6.1.4.1.311.21.8.1"));
Assert(!GetPoliciesContract.TryParse(duplicateOidRequest, out _, out error) && error == "InvalidXcepRequestFilter",
    "Duplicate OID filters must be rejected.");

var response = GetPoliciesResponseWriter.CreatePoliciesNotChanged("lab-broker-policy-v1", 24);
Assert(response.Name == xcep + "GetPoliciesResponse", "Response has wrong root element.");
Assert((bool?)response.Element(xcep + "response")?.Element(xcep + "policiesNotChanged") == true,
    "Unchanged response must set policiesNotChanged.");
Assert((string?)response.Element(xcep + "cAs")?.Attribute(xsi + "nil") == "true",
    "Unchanged response must nil cAs.");
var responseEnvelope = SoapEnvelopeWriter.CreateResponse(
    response,
    SoapEnvelopeWriter.XcepGetPoliciesResponseAction,
    parsedEnvelope.WsAddressingMessageId);
var soap12 = (XNamespace)"http://www.w3.org/2003/05/soap-envelope";
var wsAddressing = (XNamespace)"http://www.w3.org/2005/08/addressing";
Assert(responseEnvelope.Root?.Element(soap12 + "Header")?.Element(wsAddressing + "Action")?.Value ==
       SoapEnvelopeWriter.XcepGetPoliciesResponseAction &&
    responseEnvelope.Root?.Element(soap12 + "Header")?.Element(wsAddressing + "RelatesTo")?.Value ==
       parsedEnvelope.WsAddressingMessageId,
    "XCEP responses must use the response action and correlate to the request message ID.");

using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var certificateRequest = new CertificateRequest(
    "CN=ignored-client-subject",
    key,
    HashAlgorithmName.SHA256);
var csr = certificateRequest.CreateSigningRequest();
var binding = CsrBinding.FromDer(csr);
Assert(binding.HasExpectedLengths(), "A CSR binding must contain two SHA-256 values.");
Assert(binding.Matches(CsrBinding.FromDer(csr)), "The exact CSR must match its binding.");

var alteredCsr = csr.ToArray();
alteredCsr[^1] ^= 0x01;
var alteredBinding = CsrBinding.FromDer(alteredCsr);
Assert(!binding.Matches(alteredBinding), "A changed signed CSR must not match its attestation binding.");

var wst = (XNamespace)"http://docs.oasis-open.org/ws-sx/ws-trust/200512";
var wsse = (XNamespace)"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
var wstep = (XNamespace)"http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
var issueRequest = new XElement(wst + "RequestSecurityToken",
    new XElement(wst + "TokenType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"),
    new XElement(wst + "RequestType", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"),
    new XElement(wsse + "BinarySecurityToken",
        new XAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"),
        Convert.ToBase64String(csr)));
Assert(WstepRequestContract.TryParse(issueRequest, WstepRequestContract.EnrollmentAction, out var parsedWstepRequest, out error),
    error ?? "Expected a valid WSTEP Issue request.");
Assert(parsedWstepRequest!.Kind == WstepRequestKind.Issue && parsedWstepRequest.CertificateRequestDer!.AsSpan().SequenceEqual(csr),
    "WSTEP Issue must retain the exact base64-decoded certificate request.");
var queryRequest = new XElement(wst + "RequestSecurityToken",
    new XElement(wst + "TokenType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"),
    new XElement(wst + "RequestType", "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/QueryTokenStatus"),
    new XElement(wstep + "RequestID", "42"));
Assert(WstepRequestContract.TryParse(queryRequest, WstepRequestContract.EnrollmentAction, out parsedWstepRequest, out error) &&
    parsedWstepRequest!.Kind == WstepRequestKind.QueryTokenStatus && parsedWstepRequest.RequestId == "42",
    error ?? "Expected a valid WSTEP pending-status query.");
Assert(!WstepRequestContract.TryParse(issueRequest, WstepRequestContract.KetAction, out _, out error) &&
    error == "InvalidWstepActionAndRequestType", "WSTEP Issue must reject the KET SOAP action.");
var duplicateKetRequest = new XElement(wst + "RequestSecurityToken",
    new XElement(wst + "TokenType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"),
    new XElement(wst + "RequestType", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/KET"),
    new XElement(wst + "RequestKET"),
    new XElement(wst + "RequestKET"));
Assert(!WstepRequestContract.TryParse(duplicateKetRequest, WstepRequestContract.KetAction, out _, out error) &&
    error == "DuplicateWstepExtension", "WSTEP must reject duplicate security-relevant extension elements.");
var issueWithIgnoredExtension = new XElement(issueRequest);
issueWithIgnoredExtension.Add(new XElement((XNamespace)"urn:test:extension" + "IgnoredByWstep"));
Assert(WstepRequestContract.TryParse(issueWithIgnoredExtension, WstepRequestContract.EnrollmentAction, out _, out error),
    error ?? "MS-WSTEP requires unrelated WS-Trust extensions to be ignored.");
var issuedWstepResponse = WstepResponseWriter.CreateIssued([0x30, 0x00], [0x30, 0x00], "42", "en-GB");
var issuedResponseTokens = issuedWstepResponse.Descendants(wsse + "BinarySecurityToken").ToArray();
Assert(issuedWstepResponse.Name == wst + "RequestSecurityTokenResponseCollection" &&
    issuedResponseTokens.Length == 2 &&
    issuedWstepResponse.Descendants(wstep + "RequestID").Single().Value == "42",
    "Issued WSTEP responses must contain a full response, leaf certificate and request ID.");
var issuedWithoutRequestId = WstepResponseWriter.CreateIssued([0x30, 0x00], [0x30, 0x00], null, "en-GB");
Assert((string?)issuedWithoutRequestId.Descendants(wstep + "RequestID").Single().Attribute(xsi + "nil") == "true",
    "MS-WSTEP requires a nil RequestID when the issuer supplies no request identifier.");
var pendingWstepResponse = WstepResponseWriter.CreatePending("42", "en-GB");
Assert(pendingWstepResponse.Descendants(wstep + "DispositionMessage").Single().Value == "Pending",
    "Pending WSTEP responses must carry the native WSTEP pending disposition.");
WstepResourceBoundsTests.Run();

var deviceFacts = new AuthoritativeDeviceFacts(
    "device-123",
    "CN=LAB-DEVICE-123,OU=Devices,DC=lab,DC=example,DC=test",
    "windows-client",
    "wireless",
    "lab-a",
    "lab",
    42);
var controlledIdentity = ControlledCertificateIdentityMapper.Create(
    deviceFacts,
    new CertificateClaimPolicy(
        "urn:example:pki-broker:lab:fact:v1:profile:broker-pilot",
        "urn:example:pki-broker:lab:fact:v1:"));
Assert(controlledIdentity.SubjectDistinguishedName == deviceFacts.DirectoryDistinguishedName,
    "The certificate subject must come from authoritative directory facts.");
Assert(controlledIdentity.SubjectAlternativeNameUris.Select(uri => uri.OriginalString).Contains(
        "urn:example:pki-broker:lab:fact:v1:profile:broker-pilot"),
    "The exact broker profile URN must be emitted independently of use-case authorization.");
Assert(controlledIdentity.SubjectAlternativeNameUris.Select(uri => uri.OriginalString).Contains(
        "urn:example:pki-broker:lab:fact:v1:asset:device-123"),
    "Asset identity must be encoded as an RFC-compliant SAN URN.");

using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var rootRequest = new CertificateRequest("CN=LAB TEST ROOT", rootKey, HashAlgorithmName.SHA256);
rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
using var rootCertificate = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
using var issuedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var issuedRequest = new CertificateRequest(new X500DistinguishedName(CertificateSubjectEncoder.Encode(controlledIdentity.SubjectDistinguishedName)), issuedKey, HashAlgorithmName.SHA256);
issuedRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
issuedRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
    new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") },
    false));
var issuedSanBuilder = new SubjectAlternativeNameBuilder();
foreach (var uri in controlledIdentity.SubjectAlternativeNameUris)
{
    issuedSanBuilder.AddUri(uri);
}

issuedRequest.CertificateExtensions.Add(issuedSanBuilder.Build());
var issuedCsr = issuedRequest.CreateSigningRequest();
using var issuedCertificate = issuedRequest.Create(
    rootCertificate,
    DateTimeOffset.UtcNow.AddMinutes(-1),
    DateTimeOffset.UtcNow.AddDays(1),
    RandomNumberGenerator.GetBytes(16));
Assert(IssuedCertificateValidator.Validate(
        issuedCertificate,
        issuedCsr,
        controlledIdentity,
        new IssuedCertificateValidationPolicy(rootCertificate),
        DateTimeOffset.UtcNow).Result == IssuedCertificateValidationResult.Valid,
    "The downstream certificate must match the controlled identity, CSR public key and trusted root.");

IssuedCertificateValidationTests.Run(rootCertificate, controlledIdentity);

using var renewalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var renewalRequest = new CertificateRequest("CN=renewal-test", renewalKey, HashAlgorithmName.SHA256);
var renewalEkus = new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") };
renewalRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(renewalEkus, false));
using var renewalCertificate = renewalRequest.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddMinutes(-1),
    DateTimeOffset.UtcNow.AddDays(1));
var certificateBindings = new InMemoryBrokerCertificateBindingStore();
certificateBindings.Register(new BrokerCertificateBinding(
    renewalCertificate.Thumbprint,
    "device-123",
    DateTimeOffset.UtcNow));
var renewalValidation = certificateBindings.ValidateForRenewal(renewalCertificate, DateTimeOffset.UtcNow);
Assert(renewalValidation.Result == CertificateRenewalResult.Valid && renewalValidation.AuthoritativeAssetId == "device-123",
    "Only a current broker-recorded client-auth certificate may renew for its bound asset.");
using var unregisteredKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var unregisteredRequest = new CertificateRequest("CN=unregistered", unregisteredKey, HashAlgorithmName.SHA256);
unregisteredRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(renewalEkus, false));
using var unregisteredCertificate = unregisteredRequest.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddMinutes(-1),
    DateTimeOffset.UtcNow.AddDays(1));
Assert(certificateBindings.ValidateForRenewal(unregisteredCertificate, DateTimeOffset.UtcNow).Result ==
       CertificateRenewalResult.NotBrokerIssued,
    "A trusted-but-unregistered certificate must not renew.");
using var missingEkuKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var missingEkuRequest = new CertificateRequest("CN=missing-eku", missingEkuKey, HashAlgorithmName.SHA256);
using var missingEkuCertificate = missingEkuRequest.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddMinutes(-1),
    DateTimeOffset.UtcNow.AddDays(1));
certificateBindings.Register(new BrokerCertificateBinding(
    missingEkuCertificate.Thumbprint,
    "device-124",
    DateTimeOffset.UtcNow));
Assert(certificateBindings.ValidateForRenewal(missingEkuCertificate, DateTimeOffset.UtcNow).Result ==
       CertificateRenewalResult.MissingClientAuthenticationEku,
    "A broker-recorded certificate without client-auth EKU must not renew.");

Assert(IncomingCsrPolicyValidator.Validate(csr, IncomingCsrPolicy.NoClientExtensions).Result ==
       IncomingCsrValidationResult.Valid,
    "A PKCS#10 request without client-controlled extensions must be accepted.");
using var extensionKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var extensionRequest = new CertificateRequest("CN=untrusted-extension", extensionKey, HashAlgorithmName.SHA256);
extensionRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
var extensionCsr = extensionRequest.CreateSigningRequest();
var extensionValidation = IncomingCsrPolicyValidator.Validate(extensionCsr, IncomingCsrPolicy.NoClientExtensions);
Assert(extensionValidation.Result == IncomingCsrValidationResult.DisallowedExtension && extensionValidation.ExtensionOid == "2.5.29.15",
    "A client-supplied extension must be rejected unless explicitly allowlisted.");

var domainAuthorizer = new DomainEnrollmentAuthorizer(
    new TestFactsSource(deviceFacts),
    new CertificateClaimPolicy(
        "urn:example:pki-broker:lab:fact:v1:profile:broker-pilot",
        "urn:example:pki-broker:lab:fact:v1:"),
    IncomingCsrPolicy.NoClientExtensions);
var domainAuthorization = await domainAuthorizer.AuthorizeAsync("directory-object-123", csr, CancellationToken.None);
Assert(domainAuthorization.Result == DomainEnrollmentAuthorizationResult.Authorized &&
    domainAuthorization.ControlledIdentity!.SubjectDistinguishedName == deviceFacts.DirectoryDistinguishedName,
    "A validated directory machine must resolve to authoritative controlled certificate identity.");
Assert((await domainAuthorizer.AuthorizeAsync("directory-object-123", extensionCsr, CancellationToken.None)).Result ==
       DomainEnrollmentAuthorizationResult.InvalidCsr,
    "Domain enrollment must reject client-controlled CSR extensions before SOT lookup.");

var attestationStore = new InMemoryBootstrapAttestationStore();
var createdAt = DateTimeOffset.UtcNow;
Assert(attestationStore.Record(binding, createdAt, TimeSpan.FromMinutes(15)) == BootstrapStoreResult.Recorded,
    "A new CSR binding must create one pending attestation.");
Assert(attestationStore.Attest(binding, "asset:itsm:device-123", createdAt.AddMinutes(1)) == BootstrapStoreResult.Attested,
    "Only the exact CSR/SPKI binding may be attested.");
var consumed = attestationStore.Consume(binding, createdAt.AddMinutes(2));
Assert(consumed.Result == BootstrapStoreResult.Consumed && consumed.AuthoritativeAssetId == "asset:itsm:device-123",
    "An attested CSR binding must be consumed once for the linked authoritative asset.");
Assert(attestationStore.Consume(binding, createdAt.AddMinutes(3)).Result == BootstrapStoreResult.InvalidState,
    "A bootstrap attestation must be single-use.");

var bootstrapStore = new InMemoryBootstrapAttestationStore();
Assert(bootstrapStore.Record(binding, createdAt, TimeSpan.FromMinutes(15)) == BootstrapStoreResult.Recorded,
    "The bootstrap authorization test requires a fresh pending attestation.");
Assert(bootstrapStore.Attest(binding, "device-123", createdAt.AddMinutes(1)) == BootstrapStoreResult.Attested,
    "The technician must bind the exact CSR/SPKI pair to an authoritative asset.");
var bootstrapAuthorizer = new BootstrapEnrollmentAuthorizer(
    bootstrapStore,
    new TestFactsSource(deviceFacts),
    new CertificateClaimPolicy(
        "urn:example:pki-broker:lab:fact:v1:profile:broker-pilot",
        "urn:example:pki-broker:lab:fact:v1:"),
    IncomingCsrPolicy.NoClientExtensions);
Assert((await bootstrapAuthorizer.AuthorizeAsync(csr, createdAt.AddMinutes(2), CancellationToken.None)).Result ==
       BootstrapEnrollmentAuthorizationResult.Authorized,
    "A technician-attested exact CSR/SPKI pair must authorize one broker-controlled enrollment.");
Assert((await bootstrapAuthorizer.AuthorizeAsync(csr, createdAt.AddMinutes(3), CancellationToken.None)).Result ==
       BootstrapEnrollmentAuthorizationResult.AttestationUnavailable,
    "Bootstrap authorization must consume the attestation exactly once.");

var brokerPolicy = new BrokerEnrollmentPolicy(
    "lab-broker-policy-v1",
    "ID Lab broker machine enrollment",
    "LabBrokerMachine",
    "1.3.6.1.4.1.311.21.8.12345.1",
    [0x30, 0x00],
    new Uri("https://broker.invalid/ces/kerberos/service.svc/CES"),
    2,
    2048,
    0x00010001,
    0,
    0,
    0x00000040,
    31_536_000,
    2_592_000,
    1,
    null,
    24,
    DateTimeOffset.Parse("2026-08-27T12:00:00Z"));
var fullPolicyResponse = BrokerEnrollmentPolicyResponseWriter.Create(brokerPolicy, new HashSet<string>());
Assert((bool)fullPolicyResponse.Descendants(xcep + "renewalOnly").Single() == false,
    "Existing Kerberos policy must continue to advertise initial enrollment and renewal.");
var renewalPolicyResponse = BrokerEnrollmentPolicyResponseWriter.Create(
    brokerPolicy with { RenewalOnly = true }, new HashSet<string>());
Assert((bool)renewalPolicyResponse.Descendants(xcep + "renewalOnly").Single(),
    "A renewal-only policy must explicitly advertise its restricted CA URI.");
Assert(renewalPolicyResponse.Descendants(xcep + "uri").Single().Value == brokerPolicy.EnrollmentUri.AbsoluteUri &&
       renewalPolicyResponse.Descendants(xcep + "clientAuthentication").Single().Value == "2",
    "The renewal-only flag must not silently change endpoint or authentication semantics.");
XcepProfileTests.Run(fullPolicyResponse, brokerPolicy);
var certificatePolicy = CertificateRenewalPolicy.Create(brokerPolicy,
    "{96d8cb07-4463-49f7-93bb-6ad66ab05171}", "broker.invalid", 9443).Policy;
Assert(certificatePolicy.RenewalOnly && certificatePolicy.ClientAuthentication == 8 &&
    certificatePolicy.EnrollmentUri.AbsoluteUri == "https://broker.invalid:9443/ces/certificate/service.svc/CES" &&
    certificatePolicy.TemplateOid == brokerPolicy.TemplateOid &&
    certificatePolicy.PolicyServerId != brokerPolicy.PolicyServerId,
    "Certificate renewal policy must preserve template authority with distinct identity and exact endpoint.");
var sharedBaseline = brokerPolicy with { PolicyServerId = "{47083904-e13c-4646-bc40-cf5a0383b115}" };
var sharedCertificatePolicy = CertificateRenewalPolicy.Create(sharedBaseline,
    sharedBaseline.PolicyServerId, "broker.invalid", 9443, sharedPolicyIdentity: true).Policy;
Assert(Guid.Parse(sharedCertificatePolicy.PolicyServerId) == Guid.Parse(sharedBaseline.PolicyServerId) &&
    sharedCertificatePolicy.RenewalOnly && sharedCertificatePolicy.ClientAuthentication == 8 &&
    sharedCertificatePolicy.EnrollmentUri == certificatePolicy.EnrollmentUri &&
    sharedCertificatePolicy.TemplateOid == brokerPolicy.TemplateOid,
    "Opt-in shared identity must preserve certificate-only renewal and template authority.");
foreach (var invalidProjection in new Action[] {
    () => CertificateRenewalPolicy.Create(brokerPolicy, certificatePolicy.PolicyServerId, "broker.invalid", 9443, true),
    () => CertificateRenewalPolicy.Create(brokerPolicy, brokerPolicy.PolicyServerId, "other.invalid", 9443, true),
    () => CertificateRenewalPolicy.Create(brokerPolicy, "not-a-guid", "broker.invalid", 9443),
    () => CertificateRenewalPolicy.Create(brokerPolicy, Guid.Empty.ToString(), "broker.invalid", 9443),
    () => CertificateRenewalPolicy.Create(brokerPolicy, certificatePolicy.PolicyServerId, "other.invalid", 9443),
    () => CertificateRenewalPolicy.Create(brokerPolicy, certificatePolicy.PolicyServerId, "broker.invalid", 0),
    () => CertificateRenewalPolicy.Create(brokerPolicy with { PolicyServerId = certificatePolicy.PolicyServerId }, certificatePolicy.PolicyServerId, "broker.invalid", 9443)
}) {
    var refused = false;
    try { invalidProjection(); } catch (InvalidOperationException) { refused = true; }
    Assert(refused, "Invalid or colliding certificate policy projection must reject.");
}
Assert(fullPolicyResponse.Descendants(xcep + "policy").Single().Name == xcep + "policy",
    "An unfiltered request must receive exactly one configured broker-only policy.");
Assert(fullPolicyResponse.Descendants(xcep + "certificate").Single().Value == "MAA=",
    "The configured CA certificate must be emitted as base64 DER.");
var filteredOutResponse = BrokerEnrollmentPolicyResponseWriter.Create(
    brokerPolicy,
    new HashSet<string>(["1.3.6.1.4.1.311.21.8.99999.1"]));
Assert(!filteredOutResponse.Descendants(xcep + "policy").Any(),
    "A non-matching template OID filter must not disclose the broker policy.");
var dispatchedPolicy = XcepPolicyDispatcher.Dispatch(
    requestElement,
    XcepPolicyDispatcher.GetPoliciesAction,
    parsedEnvelope.WsAddressingMessageId,
    brokerPolicy);
Assert(dispatchedPolicy.IsValid && dispatchedPolicy.ResponseEnvelope!.Descendants(xcep + "policy").Any(),
    "An initial GetPolicies request must return the broker policy response envelope.");
var cachedRequest = new XElement(requestElement);
cachedRequest.Element(xcep + "client")!.Element(xcep + "lastUpdate")!.Attribute(xsi + "nil")!.Remove();
cachedRequest.Element(xcep + "client")!.Element(xcep + "lastUpdate")!.Value = "2026-08-27T12:00:00Z";
var cachedResponse = XcepPolicyDispatcher.Dispatch(
    cachedRequest,
    XcepPolicyDispatcher.GetPoliciesAction,
    parsedEnvelope.WsAddressingMessageId,
    brokerPolicy);
Assert(cachedResponse.IsValid && (bool?)cachedResponse.ResponseEnvelope!
        .Descendants(xcep + "policiesNotChanged").Single() == true,
    "A current client policy timestamp must receive the MS-XCEP unchanged shape.");

Console.WriteLine("MS-XCEP GetPolicies contract checks passed.");
var cmcFixturePath = args.Length == 2 && args[0] == "--cmc-public-fixture" ? args[1] : null;
var incomingFixturePath = args.Length == 2 && args[0] == "--native-cmc-public-fixture" ? args[1] : null;
var incomingFixtureStdin = args.Length == 1 && args[0] == "--native-cmc-public-stdin";
if (args.Length != 0 && cmcFixturePath is null && incomingFixturePath is null && !incomingFixtureStdin) throw new ArgumentException("Unknown test-runner arguments.");
CmcEnrollmentRequestTests.Run(cmcFixturePath);
var nativePublicFixture = incomingFixtureStdin ? Convert.FromBase64String(Console.In.ReadToEnd()) :
    incomingFixturePath is not null ? File.ReadAllBytes(incomingFixturePath) : null;
IncomingCmcRequestTests.Run(nativeFixture: nativePublicFixture);
await NativeDomainEnrollmentTests.RunAsync(nativePublicFixture);
DirectoryIdentityTests.Run();
await DeviceFactsFileTests.RunAsync();

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

sealed class TestFactsSource(AuthoritativeDeviceFacts facts) : IAuthoritativeDeviceFactsSource
{
    public ValueTask<AuthoritativeDeviceFacts?> FindByDirectoryObjectIdAsync(
        string directoryObjectId,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult<AuthoritativeDeviceFacts?>(directoryObjectId == "directory-object-123" ? facts : null);

    public ValueTask<AuthoritativeDeviceFacts?> FindByAssetIdAsync(
        string assetId,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult<AuthoritativeDeviceFacts?>(assetId == facts.AssetId ? facts : null);
}
