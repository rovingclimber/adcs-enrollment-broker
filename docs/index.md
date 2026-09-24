# AD CS Enrollment Broker documentation

AD CS Enrollment Broker gives native Windows certificate-enrollment clients a
narrow policy boundary in front of Microsoft Active Directory Certificate
Services (AD CS). Windows keeps the client private key. The broker authenticates
the requester, resolves authoritative identity and facts, constructs the
approved certificate request, and validates the issued result.

Start with the [quick start](quick-start.md) and [concepts](concepts.md), then
use the [system context](architecture/system-context.md) and
[protocol flows](protocols/enrollment-flows.md) to follow domain enrollment,
bootstrap and renewal. The [threat model](security/threat-model.md) states the
trusted components and failure behavior. Operators should review the
[deployment topology](deployment/topology.md), [operations guide](operations.md)
and every item in the [configuration reference](reference/configuration.md)
before enabling an authenticated listener.

Security reports use the private process in the repository `SECURITY.md`.
The repository `SUPPORT.md` defines the maintained boundary, and
[release governance](security/release-governance.md) explains how a reviewed
history-free candidate becomes an exact public mirror.

This documentation describes the product boundary. It contains no live
deployment status or private operational evidence.
