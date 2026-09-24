# AD CS Enrollment Broker documentation

EAP-TLS proves possession of a trusted private key, but authorization often
depends on stable endpoint facts such as device class, use, or permitted access
role. Without those facts in the credential, a RADIUS service must maintain
large identity mappings or depend on a live inventory or policy API during
authentication.

AD CS Enrollment Broker moves that fact-resolution step to enrollment. It gives
native Windows certificate-enrollment clients a narrow policy boundary in front
of Microsoft Active Directory Certificate Services (AD CS). Windows keeps the
client private key. The broker authenticates the requester, resolves governed
identity and facts, constructs the approved certificate request, and validates
the issued result. RADIUS or another relying party can then apply compact local
rules to approved certificate claims without calling the broker during every
authentication.

Start with [why this exists](why.md), then use the
[quick start](quick-start.md), [concepts](concepts.md),
[system context](architecture/system-context.md), and
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
