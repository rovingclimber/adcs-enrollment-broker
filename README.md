# AD CS Enrollment Broker

<p align="center">
  <img src="docs/assets/images/enrollment-architecture-hero.png"
       alt="Endpoint, network switch, enrollment broker and certificate authority"
       width="100%">
</p>

## Your 802.1X works. Then someone asks for useful VLANs.

EAP-TLS proves that an endpoint holds a trusted private key. Excellent. Network
policy still needs to know whether that endpoint is a workstation, kiosk, lab
instrument, or something that should be allowed near the finance VLAN only in
the broadest geographical sense.

You can teach RADIUS a mapping for every identity, hostname, or MAC address. You
can put a live CMDB API call in every authentication. You can bend your Active
Directory OU hierarchy around device purpose and hope the GPO consequences stay
interesting rather than catastrophic. You can also declare segmentation
overrated and go for lunch.

AD CS Enrollment Broker moves that policy step to certificate enrollment. It
authenticates the requester, reads governed endpoint facts, and places only
approved claims into a certificate issued by AD CS. RADIUS or another relying
party can then validate the certificate and apply compact rules to those claims
without depending on a live broker or inventory lookup for each authentication.
The relying party still makes the final authorization decision.

The endpoint keeps its private key. The client cannot select its own subject,
SAN claims, template, or issuer. The certificate carries a governed snapshot,
so certificate lifetime, renewal, and revocation still matter. Fun is welcome;
hand-waving is not.

See [Why this exists](docs/why.md) for the problem, tradeoffs, and certificate-
freshness model.

AD CS Enrollment Broker is a policy and registration-authority layer between
native Windows certificate-enrollment clients and Microsoft Active Directory
Certificate Services (AD CS). It implements the supported portions of MS-XCEP
and MS-WSTEP, derives certificate identity from authoritative server-side facts,
and submits restricted requests through AD CS enrollment services.

The broker supports three enrollment paths:

- domain computers authenticated with Kerberos;
- guarded bootstrap requests paired to an immutable asset by an authenticated
  technician;
- renewal authenticated with an existing broker-issued client certificate.

All paths validate proof of possession and replace client-supplied identity with
broker policy. The returned certificate is checked against the approved public
key, subject, SAN set, EKU, key usage, chain, and revocation policy before it is
released.

This snapshot contains product source, synthetic tests and publication-safe
documentation. It intentionally excludes deployment records, private topology,
operational evidence, credentials, certificate identifiers, and Git history.

## Documentation

- [Documentation home](docs/index.md), [why this exists](docs/why.md), and
  [quick start](docs/quick-start.md)
- [System context and trust boundaries](docs/architecture/system-context.md)
- [Component architecture](docs/architecture/components.md)
- [Trust boundaries and durable state](docs/architecture/trust-boundaries.md)
- [Protocol flows](docs/protocols/enrollment-flows.md)
- [Deployment topology and rollback](docs/deployment/topology.md)
- [Docker Hub image and Compose](docs/deployment/docker-hub.md)
- [Operations](docs/operations.md) and [troubleshooting](docs/troubleshooting.md)
- [Security model](docs/security/trust-model.md)
- [Threat model](docs/security/threat-model.md)
- [Security reporting](SECURITY.md)
- [Support policy](SUPPORT.md)
- [Contribution guide](CONTRIBUTING.md)
- [License](LICENSE) and [attribution notice](NOTICE)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Release governance](docs/security/release-governance.md)
- [Configuration reference](docs/reference/configuration.md)
- [Build and test](docs/development/build-and-test.md)
- [Glossary](docs/reference/glossary.md)
- [Protected-artifact image build](docs/development/build-and-test.md#build-the-protected-ci-artifact)

## Quick build

```bash
dotnet restore PkiProxy.slnx --locked-mode
dotnet run --no-restore --project tests/PkiProxy.PublicContractTests -c Release
dotnet publish src/PkiProxy.Api/PkiProxy.Api.csproj -c Release --no-restore \
  /p:PathMap="$(pwd)=/_/src"
```

The default application configuration exposes a loopback development listener
with enrollment disabled. A real deployment requires explicit authenticated
listener, directory, CA, signer, state-store, trust, and revocation settings.
Start from `.env.example`; its real application keys contain reserved placeholders
that startup rejects until an operator supplies reviewed deployment values.

## Docker Hub

Published releases can be pulled from
[`rovingclimber/adcs-enrollment-broker`](https://hub.docker.com/r/rovingclimber/adcs-enrollment-broker):

```bash
docker pull rovingclimber/adcs-enrollment-broker:latest
docker compose up -d --no-build
```

For controlled deployments, use the attested version to discover the image and
then pin its immutable digest. See the [Docker Hub guide](docs/deployment/docker-hub.md).

AD CS Enrollment Broker is licensed under the [Apache License 2.0](LICENSE). Public release
also requires completion of the [public release checklist](RELEASE_CHECKLIST.md).
