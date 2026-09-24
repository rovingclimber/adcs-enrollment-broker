# AD CS Enrollment Broker

<figure class="docs-hero">
  <img src="assets/images/enrollment-architecture-hero.png"
       alt="Isometric endpoint, network switch, enrollment broker and certificate authority connected in sequence">
  <figcaption>Give the certificate useful facts. Let RADIUS keep making the decision.</figcaption>
</figure>

Your 802.1X deployment works. Certificates authenticate machines. RADIUS says
yes. Everyone celebrates until somebody asks for engineering devices in one
VLAN, kiosks in another, and the frightening projector laptop somewhere it can
do no harm.

Now you need more than identity. You need stable facts about what each endpoint
*is for*. The usual answers are a growing pile of RADIUS mappings, a live CMDB
lookup in every authentication, or an OU hierarchy pressed into service as an
asset taxonomy. There is also the traditional option of giving up and deciding
that flat networks build character.

AD CS Enrollment Broker moves that fact-resolution step to enrollment. It gives
native Windows certificate-enrollment clients a narrow policy boundary in front
of Microsoft Active Directory Certificate Services (AD CS). Windows keeps the
client private key. The broker authenticates the requester, resolves governed
identity and facts, constructs the approved certificate request, and validates
the issued result. RADIUS can then apply compact local rules to approved
certificate claims without calling the broker or your inventory system during
every authentication.

The broker is the useful kind of middle layer: absent from the live EAP-TLS
exchange, strict about what enters a certificate, and deeply unimpressed by a
client asking to choose its own identity.

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
